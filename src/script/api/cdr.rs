//! Python `cdr` namespace — write CDRs from scripts.
//!
//! Allows Python scripts to manually write CDRs with custom fields:
//! ```python
//! from siphon import cdr
//! cdr.write(request, extra={"billing_id": "B-12345"})
//! ```

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::cdr;

/// The fields a CDR needs, resolved from either a `Request` or a `Call`.
///
/// Both the proxy `Request` and the B2BUA `Call` expose the same `cdr_*`
/// accessors; this struct collapses them to one shape so `write_cdr` builds an
/// identical record regardless of which handler wrote it.
struct CdrFields {
    call_id: String,
    from_uri: String,
    to_uri: String,
    ruri: String,
    method: String,
    source_ip: String,
    transport: String,
    /// Candidate Rf-session storage keys for the auto-stamp lookup.
    dialog_keys: Vec<String>,
}

impl CdrFields {
    fn from_request(request: &super::request::PyRequest) -> Self {
        Self {
            call_id: request.cdr_call_id(),
            from_uri: request.cdr_from_uri(),
            to_uri: request.cdr_to_uri(),
            ruri: request.cdr_ruri(),
            method: request.cdr_method(),
            source_ip: request.cdr_source_ip(),
            transport: request.cdr_transport(),
            dialog_keys: request.cdr_rf_dialog_key_candidates(),
        }
    }

    fn from_call(call: &super::call::PyCall) -> Self {
        Self {
            call_id: call.cdr_call_id(),
            from_uri: call.cdr_from_uri(),
            to_uri: call.cdr_to_uri(),
            ruri: call.cdr_ruri(),
            method: call.cdr_method(),
            source_ip: call.cdr_source_ip(),
            transport: call.cdr_transport(),
            dialog_keys: call.cdr_rf_dialog_key_candidates(),
        }
    }
}

/// Build a CDR from resolved fields, apply the Rf auto-stamp and any script
/// `extra`, and queue it.  Returns whether the CDR was queued.
fn write_cdr(fields: CdrFields, extra: Option<&Bound<'_, PyDict>>) -> bool {
    let mut record = cdr::Cdr::new(
        fields.call_id,
        fields.from_uri,
        fields.to_uri,
        fields.ruri,
        fields.method,
        fields.source_ip,
        fields.transport,
    );

    // Auto-stamp Rf correlation when a session is tracked for this dialog.
    // Tries the caller's tag first (proxy ACR-START stored it under
    // <Call-ID>\0<From-tag>); falls back to the callee's tag for
    // callee-initiated BYE flows.  Manual `extra` overrides below, so scripts
    // can still set explicit values.
    for key in &fields.dialog_keys {
        if let Some((session_id, result_code)) =
            crate::diameter::rf_service::lookup_rf_for_dialog(key)
        {
            record = record.with_rf_session_id(session_id);
            if let Some(rc) = result_code {
                record = record.with_rf_result_code(rc);
            }
            break;
        }
    }

    if let Some(extra_dict) = extra {
        for (key, value) in extra_dict.iter() {
            if let (Ok(k), Ok(v)) = (key.extract::<String>(), value.extract::<String>()) {
                record = record.with_extra(k, v);
            }
        }
    }

    cdr::write(record)
}

/// Python-facing CDR namespace.
#[pyclass(name = "CdrNamespace")]
pub struct PyCdrNamespace;

impl Default for PyCdrNamespace {
    fn default() -> Self {
        Self
    }
}

impl PyCdrNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyCdrNamespace {
    /// Write a CDR from a Python script.
    ///
    /// Args:
    ///     source: The SIP `Request` (proxy handlers) OR the B2BUA `Call`
    ///         (`@b2bua.on_answer` / `on_bye` / … handlers).  Both carry the
    ///         Call-ID, From/To/R-URI, source IP and transport the CDR needs.
    ///     extra: Optional dict of extra fields to include in the CDR.
    ///
    /// Returns:
    ///     True if the CDR was queued, False if CDR system is not enabled or channel is full.
    ///
    /// Raises:
    ///     TypeError: if `source` is neither a `Request` nor a `Call`.
    ///
    /// **Rf auto-stamp:** when an Rf accounting session is currently
    /// tracked for this SIP dialog (proxy or B2BUA auto-emit hooks),
    /// the resulting CDR is automatically annotated with
    /// `rf_session_id` and `rf_result_code` so operators can correlate
    /// billing with the corresponding Diameter accounting record.
    /// Manual `extra={"rf_session_id": ...}` values take precedence.
    #[pyo3(signature = (source, extra=None))]
    fn write(&self, source: &Bound<'_, PyAny>, extra: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
        // Resolve the CDR fields from whichever object the script passed.
        // Type dispatch happens first so an unsupported object always raises a
        // clear TypeError, independent of whether the CDR system is enabled.
        let fields = if let Ok(request) = source.extract::<PyRef<super::request::PyRequest>>() {
            CdrFields::from_request(&request)
        } else if let Ok(call) = source.extract::<PyRef<super::call::PyCall>>() {
            CdrFields::from_call(&call)
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "cdr.write() expects a Request or Call object",
            ));
        };

        if !cdr::is_enabled() {
            return Ok(false);
        }

        Ok(write_cdr(fields, extra))
    }

    /// Check if the CDR system is enabled.
    #[getter]
    fn enabled(&self) -> bool {
        cdr::is_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::script::api::call::PyCall;
    use crate::script::api::request::PyRequest;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::{Method, SipMessage};
    use crate::sip::uri::SipUri;

    fn make_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-cdr".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("cdr-call-1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn write_accepts_request_and_call_and_rejects_others() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let namespace = PyCdrNamespace::new();

            // A proxy Request is accepted.  The CDR system is not initialized in
            // a lib test (no global sender), so is_enabled() is false and write
            // returns Ok(false) — but crucially NOT a TypeError.
            let request = PyRequest::new(
                Arc::new(Mutex::new(make_invite())),
                "udp".to_string(),
                "10.0.0.1".to_string(),
                5060,
            );
            let request_obj = pyo3::Py::new(python, request).unwrap();
            let request_result = namespace.write(request_obj.bind(python).as_any(), None);
            assert!(!request_result.unwrap());

            // A B2BUA Call is accepted too (this is the case that used to raise
            // "'Call' object is not an instance of 'Request'").
            let call = PyCall::new(
                "cdr-test".to_string(),
                Arc::new(Mutex::new(make_invite())),
                "10.0.0.1".to_string(),
                "tcp".to_string(),
            );
            let call_obj = pyo3::Py::new(python, call).unwrap();
            let call_result = namespace.write(call_obj.bind(python).as_any(), None);
            assert!(!call_result.unwrap());

            // Anything else is a clear TypeError, not a silent drop.
            let bogus = pyo3::types::PyString::new(python, "not a request or call");
            let bogus_result = namespace.write(bogus.as_any(), None);
            assert!(bogus_result.is_err());
        });
    }
}
