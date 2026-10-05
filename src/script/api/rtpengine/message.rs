//! Reading what a media command needs off a SIP message, and writing the
//! engine's SDP back into it.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;

use crate::sip::message::SipMessage;

pub(super) fn lock_message(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
    message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })
}

/// Extract the SDP body from a SIP message, handling multipart bodies.
///
/// If the Content-Type is a `multipart/*`, extracts the `application/sdp` part
/// from it (RFC 5621 §3). Otherwise returns the raw body as-is.
pub(in crate::script::api) fn extract_sdp_body(message: &SipMessage) -> PyResult<Vec<u8>> {
    let body = &message.body;
    if body.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "message has no SDP body",
        ));
    }

    let empty_string = String::new();
    let content_type = message
        .headers
        .get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .unwrap_or(&empty_string);

    if crate::media::body::is_multipart(content_type) {
        crate::media::body::sdp_from_body(content_type, body)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    } else {
        // Unchanged for every other body: handed over as-is, including one that
        // arrived with no Content-Type at all.
        Ok(body.clone())
    }
}

/// Extract call-id, from-tag, and SDP body from a SIP message (offer direction).
pub(super) fn extract_offer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, Vec<u8>)> {
    let message = lock_message(message)?;
    let (call_id, from_tag) = dialog_ids(&message)?;
    let sdp = extract_sdp_body(&message)?;
    Ok((call_id, from_tag, sdp))
}

/// The Call-ID and From-tag of a SIP message: what the engine keys a call and
/// its offerer on.
pub(super) fn dialog_ids(message: &SipMessage) -> PyResult<(String, String)> {
    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing Call-ID header"))?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing From header"))?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    Ok((call_id, from_tag))
}

/// Extract call-id, from-tag, to-tag, and SDP body from a SIP message (answer direction).
pub(super) fn extract_answer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, String, Vec<u8>)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing Call-ID header"))?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing From header"))?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    let to_raw = message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing To header"))?;

    let to_tag = extract_tag(to_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("To header missing tag parameter")
    })?;

    let sdp = extract_sdp_body(&message)?;

    Ok((call_id, from_tag, to_tag, sdp))
}

/// Extract call-id and from-tag from a SIP message (delete direction — no SDP required).
pub(super) fn extract_delete_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing Call-ID header"))?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("message missing From header"))?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    Ok((call_id, from_tag))
}

/// Extract the `tag=` parameter from a From/To header value.
pub(super) fn extract_tag(header_value: &str) -> Option<String> {
    // Look for ";tag=" (case-insensitive).
    let lower = header_value.to_lowercase();
    let tag_start = lower.find(";tag=")?;
    let value_start = tag_start + 5; // skip ";tag="
    let rest = &header_value[value_start..];
    // Tag ends at next ';', '>', or end of string.
    let end = rest.find([';', '>']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Replace the SIP message body with new SDP and update Content-Length.
pub(in crate::script::api) fn replace_body(
    message: &Arc<Mutex<SipMessage>>,
    new_body: &[u8],
) -> PyResult<()> {
    let mut message = message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;
    message.body = new_body.to_vec();
    message
        .headers
        .set("Content-Length", new_body.len().to_string());
    message
        .headers
        .set("Content-Type", "application/sdp".to_string());
    Ok(())
}
