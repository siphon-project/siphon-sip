//! The split bridge verbs of the `rtpengine` namespace
//! (`attach_ws_split` / `detach_ws_split`): what a script says, resolved to
//! what the engine is sent, and what comes back to the script when the engine
//! refuses.
//!
//! The verbs themselves are methods of [`super::PyRtpEngine`], which keeps all
//! of them in one `#[pymethods]` block; this holds what they share.

use pyo3::prelude::*;

use crate::rtpengine::profile::{NgFlags, ProfileRegistry};
use crate::rtpengine::RtpEngineError;

/// A split's wire rate, checked before the engine is touched: one of 8000,
/// 16000, 24000 or 48000, or `None` for the engine's default. `ValueError`
/// otherwise, since a rate the engine does not serve is refused rather than
/// clamped.
pub(super) fn check_sample_rate(sample_rate: Option<u32>) -> PyResult<()> {
    siphon_rtp_proto::resolve_ws_split_sample_rate(sample_rate)
        .map(drop)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(format!("sample_rate: {error}")))
}

/// The uplink options of one party's split profile: the `answer` half of the
/// named media profile, as a takeover bridge's profile is read. `None` when
/// no profile was named; `ValueError` for a name the deployment has not got.
/// Which of the profile's settings the engine accepts is its own rule (only
/// `noise_suppression` applies to a split), and its refusal comes back to the
/// script as it is.
pub(super) fn party_profile(
    registry: &ProfileRegistry,
    party: &str,
    name: Option<&str>,
) -> PyResult<Option<NgFlags>> {
    let Some(name) = name else {
        return Ok(None);
    };
    registry
        .get(name)
        .map(|entry| Some(entry.answer.clone()))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "{party}_profile: unknown RTP profile '{name}'; valid profiles: {}",
                registry.profile_names().join(", ")
            ))
        })
}

/// The engine call-id a split verb addresses for the call stored under
/// `call_id`: the session's own, when a bridge or a siphon-terminated transfer
/// put the pair on an engine call of its own while the store key stayed the SIP
/// Call-ID (`offer` and `answer` address it the same way). `None` when it is the
/// Call-ID itself, which the call's leg then names (with its scope).
pub(super) fn moved_engine_call_id(
    sessions: &crate::rtpengine::MediaSessionStore,
    call_id: &str,
) -> Option<String> {
    sessions
        .get(call_id)
        .map(|session| session.rtpengine_id().to_string())
        .filter(|engine_id| engine_id != call_id)
}

/// What a split verb's failure is to the script: a `RuntimeError` reading
/// `rtpengine.<verb> failed: <reason>`, carrying the engine's refusal token
/// (`ws-split-renegotiation`, `ws-split-already-bridged`, ...) as its `token`
/// attribute so a script branches on it without parsing the text. `token` is
/// `None` for a failure that is not a token refusal (no such call, an engine
/// that does not list `ws_split`, a transport error).
pub(super) fn verb_failure(verb: &str, error: &RtpEngineError) -> PyErr {
    let failure =
        pyo3::exceptions::PyRuntimeError::new_err(format!("rtpengine.{verb} failed: {error}"));
    let token = error.refusal_token().map(str::to_string);
    // Setting an attribute needs the interpreter for a moment and blocks on
    // nothing; no Rust lock is held here.
    Python::attach(|python| {
        if let Err(attribute) = failure.value(python).setattr("token", token) {
            tracing::error!(
                error = %attribute,
                verb,
                "could not expose the refusal token on the exception"
            );
        }
    });
    failure
}

#[cfg(test)]
mod tests;
