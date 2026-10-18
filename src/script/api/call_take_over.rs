//! `call.take_over()`: the checks that turn the script's naming of a dialog
//! into the takeover action the dispatcher carries out once the handler
//! returns.

use pyo3::prelude::*;

use super::call::CallAction;

/// The `CallAction::TakeOver` for the dialog the script named, or the
/// `ValueError` that refuses it: an empty identifier, a call already answered,
/// or `reinvite=False` on a media-anchored call (the takeover moves the
/// survivor onto a new media session, and only a re-INVITE tells it so).
/// `headers` are already checked as `answer(headers=…)` checks them.
pub(super) fn take_over_action(
    current: &CallAction,
    call_key: &str,
    call_id: &str,
    local_tag: &str,
    remote_tag: &str,
    reinvite: bool,
    headers: Vec<(String, String)>,
) -> PyResult<CallAction> {
    for (name, value) in [
        ("call_id", call_id),
        ("local_tag", local_tag),
        ("remote_tag", remote_tag),
    ] {
        if value.trim().is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "call.take_over() requires a non-empty {name}"
            )));
        }
    }
    if matches!(current, CallAction::Answered) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "call.take_over() after call.answer(): the INVITE is already answered",
        ));
    }
    if !reinvite
        && crate::dispatcher::b2bua_take_over_is_anchored(call_key, call_id, local_tag, remote_tag)
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "call.take_over(reinvite=False) on a media-anchored call: the takeover moves the \
             surviving party onto a new media session, so it has to be re-INVITEd",
        ));
    }
    Ok(CallAction::TakeOver {
        call_id: call_id.to_string(),
        local_tag: local_tag.to_string(),
        remote_tag: remote_tag.to_string(),
        reinvite,
        headers,
    })
}
