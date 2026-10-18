//! `call.failure_response`: the dialled leg's own final failure response,
//! read-only, as `@b2bua.on_failure` sees it.

use pyo3::prelude::*;

use crate::sip::message::SipMessage;

/// A dialled leg's own final failure response, read-only, as
/// `call.failure_response` shows it in `@b2bua.on_failure`.
#[pyclass(name = "FailureResponse", frozen, skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyFailureResponse {
    message: SipMessage,
}

impl PyFailureResponse {
    /// Wrap a B-leg final response.
    pub fn new(message: SipMessage) -> Self {
        Self { message }
    }
}

#[pymethods]
impl PyFailureResponse {
    /// The leg's own status code, e.g. ``503`` where the caller is sent ``500``.
    #[getter]
    pub(crate) fn status_code(&self) -> u16 {
        self.message.status_code().unwrap_or_default()
    }

    /// The leg's own reason phrase.
    #[getter]
    pub(crate) fn reason(&self) -> String {
        match &self.message.start_line {
            crate::sip::message::StartLine::Response(status_line) => {
                status_line.reason_phrase.clone()
            }
            crate::sip::message::StartLine::Request(_) => String::new(),
        }
    }

    /// The first value of a header, or ``None``.
    pub(crate) fn get_header(&self, name: &str) -> Option<String> {
        self.message.headers.get(name).cloned()
    }

    /// Every value of a header, in order; an empty list when it is absent.
    pub(crate) fn get_headers(&self, name: &str) -> Vec<String> {
        self.message
            .headers
            .get_all(name)
            .cloned()
            .unwrap_or_default()
    }

    /// The response body as ``bytes``, or ``None`` when it has none.
    #[getter]
    pub(crate) fn body<'py>(
        &self,
        python: Python<'py>,
    ) -> Option<Bound<'py, pyo3::types::PyBytes>> {
        if self.message.body.is_empty() {
            None
        } else {
            Some(pyo3::types::PyBytes::new(python, &self.message.body))
        }
    }

    /// The ``Content-Type`` header value, or ``None``.
    #[getter]
    pub(crate) fn content_type(&self) -> Option<String> {
        self.message.headers.content_type().cloned()
    }

    pub(crate) fn __repr__(&self) -> String {
        format!("<FailureResponse {} {}>", self.status_code(), self.reason())
    }
}
