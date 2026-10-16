//! The Contact a script names for the calls it answers itself
//! (`call.answer(contact=…)` / `call.progress(contact=…)`): the check that
//! turns it into a header value, and handing it to the caller's dialog.

use pyo3::prelude::*;

/// The Contact a script named for `call.answer()` / `call.progress()`, as the
/// header value siphon will advertise. `Ok(None)` with no `contact`;
/// `ValueError` for a URI or parameters siphon would not put in a Contact, or
/// `contact_params` without a `contact`.
pub(super) fn checked_contact(
    method: &str,
    contact: Option<&str>,
    contact_params: Option<&str>,
) -> PyResult<Option<String>> {
    let Some(uri) = contact else {
        if contact_params.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{method}(contact_params=…) needs contact=, the URI they go with"
            )));
        }
        return Ok(None);
    };
    crate::b2bua::uas_headers::script_contact(uri, contact_params)
        .map(Some)
        .map_err(|why| {
            pyo3::exceptions::PyValueError::new_err(format!("{method}(contact=…): {why}"))
        })
}

/// Make a checked script Contact the caller's dialog's local target, before
/// the response that first carries it goes out.
pub(super) fn set_local_contact(method: &str, call_id: &str, contact: Option<String>) {
    if let Some(contact) = contact {
        if !crate::dispatcher::b2bua_set_local_contact(call_id, contact) {
            tracing::error!(call_id = %call_id, "{method}(contact=…): no live B2BUA call to name the Contact of");
        }
    }
}
