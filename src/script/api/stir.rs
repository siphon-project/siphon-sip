//! PyO3 `stir` namespace — STIR/SHAKEN signing and verification.
//!
//! Exposed to scripts as `from siphon import stir`. Thin wrapper over the
//! protocol core in [`crate::stir`]:
//!
//! - `stir.sign(request, attestation=…)` — Authentication Service: add a
//!   SHAKEN `Identity` header to an outbound INVITE.
//! - `stir.sign_div(request, …)` — add a diverted-call (`div`) Identity header.
//! - `stir.verify(request) -> StirResult` — Verification Service.
//! - `stir.apply_verstat(request, result)` — stamp the `verstat` parameter on
//!   the asserted/From identity (ATIS-1000074 §5.3.1).
//!
//! The namespace is script-driven (the script owns attestation and
//! reject-on-fail policy), mirroring how `auth` and `ipsec` work.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::request::PyRequest;
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::{SipMessage, StartLine};
use crate::stir::{current_unix_time, Attestation, StirError, StirService, StirVerification};

/// Result of `stir.verify()`.
#[pyclass(name = "StirResult")]
pub struct StirResult {
    /// `"TN-Validation-Passed"` | `"TN-Validation-Failed"` | `"No-TN-Validation"`.
    #[pyo3(get)]
    verstat: String,
    /// `True` only when the SHAKEN PASSporT validated end to end.
    #[pyo3(get)]
    passed: bool,
    /// Attestation level (`"A"`/`"B"`/`"C"`) from the SHAKEN PASSporT.
    #[pyo3(get)]
    attestation: Option<String>,
    /// `origid` from the SHAKEN PASSporT.
    #[pyo3(get)]
    origid: Option<String>,
    /// Originating TN from the SHAKEN PASSporT.
    #[pyo3(get)]
    orig_tn: Option<String>,
    /// Human-readable diagnostic / failure cause.
    #[pyo3(get)]
    reason: String,
    /// Decoded PASSporT claim sets, stored as JSON strings.
    passports_json: Vec<String>,
}

impl StirResult {
    fn from_verification(verification: StirVerification) -> Self {
        Self {
            verstat: verification.verstat.as_str().to_string(),
            passed: verification.passed,
            attestation: verification.attestation,
            origid: verification.origid,
            orig_tn: verification.orig_tn,
            reason: verification.reason,
            passports_json: verification
                .passports
                .iter()
                .map(|claims| claims.to_string())
                .collect(),
        }
    }
}

#[pymethods]
impl StirResult {
    /// Decoded claim sets of every PASSporT that parsed, as a list of dicts.
    #[getter]
    fn passports<'py>(&self, python: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let loads = python.import("json")?.getattr("loads")?;
        let mut out = Vec::with_capacity(self.passports_json.len());
        for claims in &self.passports_json {
            out.push(loads.call1((claims.as_str(),))?);
        }
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!(
            "StirResult(verstat={:?}, passed={}, attestation={:?}, reason={:?})",
            self.verstat, self.passed, self.attestation, self.reason
        )
    }
}

/// Python-visible `stir` namespace.
#[pyclass(name = "StirNamespace")]
pub struct PyStir {
    service: Arc<StirService>,
}

impl PyStir {
    /// Build the namespace around a shared [`StirService`].
    pub fn new(service: Arc<StirService>) -> Self {
        Self { service }
    }
}

#[pymethods]
impl PyStir {
    /// Whether the Authentication Service (signing) is configured.
    #[getter]
    fn signing_enabled(&self) -> bool {
        self.service.signing_enabled()
    }

    /// Whether the Verification Service is configured.
    #[getter]
    fn verification_enabled(&self) -> bool {
        self.service.verification_enabled()
    }

    /// Build and add a SHAKEN `Identity` header to the request.
    ///
    /// Returns the `origid` (UUID) used. `attestation` defaults to the
    /// configured `default_attestation`; `orig_tn`/`dest_tn` default to the
    /// From and To/R-URI user parts.
    #[pyo3(signature = (request, attestation=None, origid=None, orig_tn=None, dest_tn=None))]
    fn sign(
        &self,
        request: &PyRequest,
        attestation: Option<&str>,
        origid: Option<String>,
        orig_tn: Option<String>,
        dest_tn: Option<String>,
    ) -> PyResult<String> {
        let attest = match attestation {
            Some(level) => Attestation::parse(level).map_err(stir_error_to_py)?,
            None => self
                .service
                .default_attestation()
                .ok_or_else(|| PyRuntimeError::new_err("STIR signing is not configured"))?,
        };

        let message_arc = request.message();
        let (orig, dest) = {
            let message = lock_message(&message_arc)?;
            let orig = orig_tn.or_else(|| header_uri_user(message.headers.from()));
            let dest = dest_tn
                .or_else(|| header_uri_user(message.headers.to()))
                .or_else(|| ruri_user(&message));
            (orig, dest)
        };

        let orig = orig.ok_or_else(|| {
            PyValueError::new_err(
                "could not determine originating TN (no From user; pass orig_tn=)",
            )
        })?;
        let dest = dest.ok_or_else(|| {
            PyValueError::new_err(
                "could not determine destination TN (no To/R-URI user; pass dest_tn=)",
            )
        })?;

        let signed = self
            .service
            .sign(attest, &orig, &dest, origid, current_unix_time())
            .map_err(stir_error_to_py)?;

        {
            let mut message = lock_message(&message_arc)?;
            message.headers.add("Identity", signed.header_value);
        }
        Ok(signed.origid)
    }

    /// Build and add a diverted-call (`div`) `Identity` header (RFC 8946).
    ///
    /// `orig_tn`/`dest_tn` default to From and To/R-URI; `div_tn` defaults to
    /// the History-Info / Diversion diverting number.
    #[pyo3(signature = (request, orig_tn=None, dest_tn=None, div_tn=None))]
    fn sign_div(
        &self,
        request: &PyRequest,
        orig_tn: Option<String>,
        dest_tn: Option<String>,
        div_tn: Option<String>,
    ) -> PyResult<()> {
        let message_arc = request.message();
        let (orig, dest, div) = {
            let message = lock_message(&message_arc)?;
            let orig = orig_tn.or_else(|| header_uri_user(message.headers.from()));
            let dest = dest_tn
                .or_else(|| header_uri_user(message.headers.to()))
                .or_else(|| ruri_user(&message));
            let div = div_tn.or_else(|| diverting_tn(&message));
            (orig, dest, div)
        };

        let orig =
            orig.ok_or_else(|| PyValueError::new_err("could not determine originating TN"))?;
        let dest =
            dest.ok_or_else(|| PyValueError::new_err("could not determine destination TN"))?;
        let div = div.ok_or_else(|| {
            PyValueError::new_err(
                "could not determine diverting TN (no History-Info/Diversion; pass div_tn=)",
            )
        })?;

        let header_value = self
            .service
            .sign_div(&orig, &dest, &div, current_unix_time())
            .map_err(stir_error_to_py)?;

        {
            let mut message = lock_message(&message_arc)?;
            message.headers.add("Identity", header_value);
        }
        Ok(())
    }

    /// Verify the `Identity` header(s) on the request.
    fn verify(&self, request: &PyRequest) -> PyResult<StirResult> {
        let message_arc = request.message();
        let (values, orig, dest) = {
            let message = lock_message(&message_arc)?;
            let values = message
                .headers
                .get_all("Identity")
                .cloned()
                .unwrap_or_default();
            let orig = header_uri_user(message.headers.from());
            let dest = header_uri_user(message.headers.to()).or_else(|| ruri_user(&message));
            (values, orig, dest)
        };

        // `service.verify` blocks on the x5u SHAKEN-cert HTTP fetch internally.
        // Release the interpreter for it: blocking while attached stalls the
        // free-threaded GC stop-the-world and wedges the engine (see
        // `crate::script::blocking`). `verify` is pure Rust (no Python refs).
        let verification = pyo3::Python::attach(|python| {
            python.detach(|| {
                self.service.verify(
                    &values,
                    orig.as_deref(),
                    dest.as_deref(),
                    current_unix_time(),
                )
            })
        })
        .map_err(stir_error_to_py)?;
        Ok(StirResult::from_verification(verification))
    }

    /// Stamp the `verstat` parameter onto the asserted identity (P-Asserted-
    /// Identity if present, else From) per ATIS-1000074 §5.3.1.
    fn apply_verstat(&self, request: &PyRequest, result: &StirResult) -> PyResult<()> {
        let message_arc = request.message();
        let mut message = lock_message(&message_arc)?;
        let header_name = if message.headers.has("P-Asserted-Identity") {
            "P-Asserted-Identity"
        } else {
            "From"
        };
        if let Some(raw) = message.headers.get(header_name).cloned() {
            if let Ok(mut name_addr) = NameAddr::parse(&raw) {
                name_addr.uri.params.retain(|(name, _)| name != "verstat");
                name_addr
                    .uri
                    .params
                    .push(("verstat".to_string(), Some(result.verstat.clone())));
                message.headers.set(header_name, name_addr.to_string());
            }
        }
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "StirNamespace(signing_enabled={}, verification_enabled={})",
            self.service.signing_enabled(),
            self.service.verification_enabled()
        )
    }
}

/// Lock the shared SIP message, mapping a poisoned lock to a Python error.
fn lock_message(
    message: &Arc<std::sync::Mutex<SipMessage>>,
) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
    message
        .lock()
        .map_err(|error| PyRuntimeError::new_err(format!("message lock poisoned: {error}")))
}

/// Extract the user part of a From/To-style header URI.
fn header_uri_user(raw: Option<&String>) -> Option<String> {
    let raw = raw?;
    NameAddr::parse(raw)
        .ok()
        .and_then(|name_addr| name_addr.uri.user)
}

/// Extract the user part of the Request-URI.
fn ruri_user(message: &SipMessage) -> Option<String> {
    match &message.start_line {
        StartLine::Request(request_line) => request_line.request_uri.user.clone(),
        _ => None,
    }
}

/// Best-effort extraction of the diverting number from History-Info or
/// Diversion (RFC 7044 / RFC 5806) for `div` PASSporTs.
fn diverting_tn(message: &SipMessage) -> Option<String> {
    if let Some(diversion) = message.headers.get("Diversion") {
        if let Some(user) = NameAddr::parse(diversion).ok().and_then(|na| na.uri.user) {
            return Some(user);
        }
    }
    if let Some(history) = message.headers.get("History-Info") {
        // History-Info may be multi-valued in one line; take the first entry.
        let first = history.split(',').next().unwrap_or(history);
        if let Some(user) = NameAddr::parse(first).ok().and_then(|na| na.uri.user) {
            return Some(user);
        }
    }
    None
}

/// Map a [`StirError`] to an appropriate Python exception.
fn stir_error_to_py(error: StirError) -> PyErr {
    match error {
        StirError::SigningNotConfigured | StirError::VerificationNotConfigured => {
            PyRuntimeError::new_err(error.to_string())
        }
        StirError::MissingTn(_) | StirError::Encode(_) => PyValueError::new_err(error.to_string()),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

/// Suppress an unused-import warning for `PyDict` in builds where only the
/// `json.loads` path is exercised; kept for future structured returns.
#[allow(dead_code)]
fn _assert_pydict_in_scope(python: Python<'_>) -> Bound<'_, PyDict> {
    PyDict::new(python)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::headers::SipHeaders;
    use crate::sip::message::{Method, RequestLine, SipMessage, StartLine, Version};
    use crate::sip::uri::SipUri;

    fn message_with(from: &str, to: &str, ruri_user: &str) -> SipMessage {
        let mut headers = SipHeaders::new();
        headers.set("From", from.to_string());
        headers.set("To", to.to_string());
        SipMessage {
            start_line: StartLine::Request(RequestLine {
                method: Method::Invite,
                request_uri: SipUri::new("example.com".to_string())
                    .with_user(ruri_user.to_string()),
                version: Version::new(2, 0),
            }),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn header_uri_user_extracts_tn() {
        let raw = "\"Alice\" <sip:12155550112@example.com>;tag=abc".to_string();
        assert_eq!(header_uri_user(Some(&raw)).as_deref(), Some("12155550112"));
        assert_eq!(header_uri_user(None), None);
    }

    #[test]
    fn ruri_user_extracted() {
        let message = message_with(
            "<sip:12155550112@a.com>",
            "<sip:12025550100@b.com>",
            "12025550100",
        );
        assert_eq!(ruri_user(&message).as_deref(), Some("12025550100"));
    }

    #[test]
    fn diverting_tn_from_diversion_header() {
        let mut message = message_with(
            "<sip:12155550112@a.com>",
            "<sip:12025550100@b.com>",
            "12025550100",
        );
        message.headers.set(
            "Diversion",
            "<sip:12155550199@a.com>;reason=unconditional".to_string(),
        );
        assert_eq!(diverting_tn(&message).as_deref(), Some("12155550199"));
    }

    #[test]
    fn stir_error_mapping() {
        // Just ensure the mapper runs without panicking for each arm.
        let _ = stir_error_to_py(StirError::SigningNotConfigured);
        let _ = stir_error_to_py(StirError::MissingTn("orig".to_string()));
        let _ = stir_error_to_py(StirError::Parse("x".to_string()));
    }
}
