//! PyO3 wrapper for Initial Filter Criteria (iFC) evaluation — exposed to Python as `isc`.
//!
//! Scripts use:
//! ```python
//! from siphon import isc
//!
//! # Store per-user iFC profile (from Cx SAR user_data XML)
//! count = isc.store_profile("sip:alice@ims.example.com", user_data_xml)
//!
//! # Evaluate iFCs for a request
//! matches = isc.evaluate("sip:alice@ims.example.com", "INVITE",
//!                        "sip:bob@example.com",
//!                        [("P-Asserted-Identity", "sip:alice@ims.example.com")],
//!                        "originating")
//! for entry in matches:
//!     log.info(f"Route via AS: {entry['server_name']}")
//! ```

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::warn;

use crate::ifc::{IfcStore, SessionCase};

/// Python-visible ISC (IMS Service Control) namespace.
#[pyclass(name = "IscNamespace", skip_from_py_object)]
pub struct PyIsc {
    store: Arc<IfcStore>,
}

impl PyIsc {
    pub fn new(store: Arc<IfcStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PyIsc {
    /// Parse and store an iFC XML profile for an Address of Record.
    ///
    /// Typically called after a successful Cx SAR when the HSS returns
    /// ``user_data`` containing ``<ServiceProfile>`` XML.
    ///
    /// Args:
    ///     aor: Address of Record (e.g. ``"sip:alice@ims.example.com"``).
    ///     ifc_xml: Raw XML string containing ``<ServiceProfile>`` with iFCs.
    ///
    /// A service profile may name shared iFC sets (``<SharedIFCSetID>``,
    /// TS 29.228 Annex B.2 / Annex E) instead of, or next to, its own iFCs;
    /// each is resolved against ``isc.shared_ifc_sets`` in ``siphon.yaml``,
    /// and an id with no local set is logged at ``warn`` with the AoR.
    ///
    /// Returns:
    ///     The number of iFC rules the profile now applies: its own plus those
    ///     of the shared sets it names that this S-CSCF has.
    ///
    /// Raises:
    ///     ValueError: If the XML cannot be parsed, or holds a
    ///         ``<SessionCase>`` that is not 0 to 4 or a ``<SharedIFCSetID>``
    ///         that is not an integer of at least 0.
    fn store_profile(&self, aor: &str, ifc_xml: &str) -> PyResult<usize> {
        self.store.store_profile_xml(aor, ifc_xml).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("iFC XML parse error: {error}"))
        })
    }

    /// Remove the stored iFC profile for an AoR.
    ///
    /// Args:
    ///     aor: Address of Record.
    ///
    /// Returns:
    ///     ``True`` if a profile was removed, ``False`` if none existed.
    fn remove_profile(&self, aor: &str) -> bool {
        self.store.remove_profile(aor)
    }

    /// The SharedIFCSetIDs the stored profile of an AoR names, for logging.
    ///
    /// Args:
    ///     aor: Address of Record.
    ///
    /// Returns:
    ///     The ids in profile order; empty when it names none or no profile
    ///     is stored.
    fn shared_set_ids(&self, aor: &str) -> Vec<u32> {
        self.store.shared_set_ids(aor)
    }

    /// Check whether a profile is stored for an AoR.
    ///
    /// Args:
    ///     aor: Address of Record.
    ///
    /// Returns:
    ///     ``True`` if a profile exists.
    fn has_profile(&self, aor: &str) -> bool {
        self.store.has_profile(aor)
    }

    /// Evaluate iFCs for a request and return matching Application Servers.
    ///
    /// Checks per-user profile first (stored via ``store_profile``), its own
    /// iFCs and those of the shared iFC sets it names merged by priority;
    /// falls back to global rules loaded from the ``isc:`` config section.
    ///
    /// Args:
    ///     aor: Address of Record to look up the iFC profile for.
    ///     method: SIP method (e.g. ``"INVITE"``, ``"REGISTER"``).
    ///     ruri: Request-URI string (e.g. ``"sip:bob@example.com"``).
    ///     headers: List of ``(name, value)`` tuples for header matching.
    ///     session_case: One of ``"originating"``, ``"terminating"``,
    ///         ``"originating_unregistered"``, ``"terminating_unregistered"``,
    ///         ``"originating_cdiv"`` (TS 29.228 Annex E value 4: the
    ///         originating services after retargeting, TS 24.229 §5.4.3.3
    ///         NOTE 4). Short forms ``orig``, ``term``, ``orig_unreg``,
    ///         ``term_unreg``, ``orig_cdiv``.
    ///     start_after_priority: Only iFCs with a higher priority, to resume
    ///         after the AS the request came back from.
    ///     body: The request's SDP (``str`` or ``bytes``), for
    ///         ``<SessionDescription>`` trigger points (TS 29.228 Annex F:
    ///         ``Line`` matched against each field's type, ``Content``
    ///         against its value). ``None`` for a request without SDP, which
    ///         such a trigger point does not match. For a multipart body,
    ///         pass the ``application/sdp`` part.
    ///
    /// Returns:
    ///     List of dicts, each with keys: ``server_name`` (str),
    ///     ``default_handling`` (int: 0=SESSION_CONTINUED, 1=SESSION_TERMINATED),
    ///     ``service_info`` (str or None), ``priority`` (int).
    ///     Ordered by priority ascending (lowest first).
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (aor, method, ruri, headers, session_case="originating", start_after_priority=None, body=None))]
    fn evaluate<'py>(
        &self,
        python: Python<'py>,
        aor: &str,
        method: &str,
        ruri: &str,
        headers: Vec<(String, String)>,
        session_case: &str,
        start_after_priority: Option<i32>,
        body: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let case = parse_session_case(session_case).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid session_case: {session_case:?} — expected one of: \
                 originating, terminating, originating_unregistered, terminating_unregistered, \
                 originating_cdiv"
            ))
        })?;
        let body = match body {
            None => None,
            Some(body) if body.is_none() => None,
            Some(body) => Some(sdp_text(body)?),
        };

        let matches = self.store.evaluate(
            aor,
            method,
            ruri,
            &headers,
            case,
            start_after_priority,
            body.as_deref(),
        );

        let mut results = Vec::with_capacity(matches.len());
        for matched in &matches {
            let dict = PyDict::new(python);
            dict.set_item("server_name", &matched.server_name)?;
            dict.set_item("default_handling", matched.default_handling)?;
            dict.set_item("service_info", matched.service_info.as_deref())?;
            dict.set_item("priority", matched.priority)?;
            results.push(dict);
        }
        Ok(results)
    }

    /// Number of stored per-user iFC profiles.
    fn profile_count(&self) -> usize {
        self.store.profile_count()
    }
}

/// A body handed to `isc.evaluate` as text: `str` as it is, `bytes` read as
/// UTF-8 (an SDP is ASCII, RFC 4566 §5, with UTF-8 allowed in some values).
fn sdp_text(body: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(text) = body.extract::<String>() {
        return Ok(text);
    }
    if let Ok(bytes) = body.extract::<Vec<u8>>() {
        return String::from_utf8(bytes).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("body is not UTF-8: {error}"))
        });
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "body must be str, bytes or None",
    ))
}

/// Parse a Python session case string to the Rust enum.
fn parse_session_case(value: &str) -> Option<SessionCase> {
    match value.to_ascii_lowercase().as_str() {
        "originating" | "orig" => Some(SessionCase::Originating),
        "terminating" | "term" => Some(SessionCase::Terminating),
        "originating_unregistered" | "orig_unreg" => Some(SessionCase::OriginatingUnregistered),
        "terminating_unregistered" | "term_unreg" => Some(SessionCase::TerminatingUnregistered),
        "originating_cdiv" | "orig_cdiv" => Some(SessionCase::OriginatingCdiv),
        _ => {
            warn!(session_case = value, "unknown session case");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_case_names_map_to_the_matching_case() {
        for (name, expected) in [
            ("originating", SessionCase::Originating),
            ("orig", SessionCase::Originating),
            ("terminating", SessionCase::Terminating),
            ("term", SessionCase::Terminating),
            (
                "originating_unregistered",
                SessionCase::OriginatingUnregistered,
            ),
            ("orig_unreg", SessionCase::OriginatingUnregistered),
            (
                "terminating_unregistered",
                SessionCase::TerminatingUnregistered,
            ),
            ("term_unreg", SessionCase::TerminatingUnregistered),
            (
                "Terminating_Unregistered",
                SessionCase::TerminatingUnregistered,
            ),
            ("originating_cdiv", SessionCase::OriginatingCdiv),
            ("orig_cdiv", SessionCase::OriginatingCdiv),
        ] {
            assert_eq!(parse_session_case(name), Some(expected), "{name}");
        }
    }

    #[test]
    fn a_body_is_read_from_str_or_utf8_bytes_only() {
        Python::initialize();
        Python::attach(|python| {
            let text = pyo3::types::PyString::new(python, "v=0\r\n");
            assert_eq!(sdp_text(text.as_any()).unwrap(), "v=0\r\n");
            let bytes = pyo3::types::PyBytes::new(python, b"m=video 0 RTP/AVP 96\r\n");
            assert_eq!(
                sdp_text(bytes.as_any()).unwrap(),
                "m=video 0 RTP/AVP 96\r\n"
            );
            let invalid = pyo3::types::PyBytes::new(python, &[0xff, 0xfe]);
            assert!(sdp_text(invalid.as_any()).is_err());
            let number = 5i64.into_pyobject(python).unwrap();
            assert!(sdp_text(number.as_any()).is_err());
        });
    }

    #[test]
    fn unknown_session_case_name_is_rejected() {
        assert_eq!(parse_session_case("cdiv"), None);
        assert_eq!(parse_session_case(""), None);
    }
}
