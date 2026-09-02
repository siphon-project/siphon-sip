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
    /// Returns:
    ///     The number of iFC rules parsed and stored.
    ///
    /// Raises:
    ///     ValueError: If the XML cannot be parsed.
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
    /// Checks per-user profile first (stored via ``store_profile``); falls
    /// back to global rules loaded from the ``isc:`` config section.
    ///
    /// Args:
    ///     aor: Address of Record to look up the iFC profile for.
    ///     method: SIP method (e.g. ``"INVITE"``, ``"REGISTER"``).
    ///     ruri: Request-URI string (e.g. ``"sip:bob@example.com"``).
    ///     headers: List of ``(name, value)`` tuples for header matching.
    ///     session_case: One of ``"originating"``, ``"terminating"``,
    ///         ``"originating_unregistered"``, ``"terminating_unregistered"``.
    ///
    /// Returns:
    ///     List of dicts, each with keys: ``server_name`` (str),
    ///     ``default_handling`` (int: 0=SESSION_CONTINUED, 1=SESSION_TERMINATED),
    ///     ``service_info`` (str or None), ``priority`` (int).
    ///     Ordered by priority ascending (lowest first).
    #[pyo3(signature = (aor, method, ruri, headers, session_case="originating", start_after_priority=None))]
    fn evaluate<'py>(
        &self,
        python: Python<'py>,
        aor: &str,
        method: &str,
        ruri: &str,
        headers: Vec<(String, String)>,
        session_case: &str,
        start_after_priority: Option<i32>,
    ) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let case = parse_session_case(session_case).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid session_case: {session_case:?} — expected one of: \
                 originating, terminating, originating_unregistered, terminating_unregistered"
            ))
        })?;

        let matches = self
            .store
            .evaluate(aor, method, ruri, &headers, case, start_after_priority);

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

/// Parse a Python session case string to the Rust enum.
fn parse_session_case(value: &str) -> Option<SessionCase> {
    match value.to_ascii_lowercase().as_str() {
        "originating" | "orig" => Some(SessionCase::Originating),
        "terminating" | "term" => Some(SessionCase::Terminating),
        "originating_unregistered" | "orig_unreg" => Some(SessionCase::OriginatingUnregistered),
        "terminating_unregistered" | "term_unreg" => Some(SessionCase::TerminatingUnregistered),
        _ => {
            warn!(session_case = value, "unknown session case");
            None
        }
    }
}
