//! How `rtpengine.answer_local()` maps the engine's result to what the script
//! sees: an answer, a deferred 488 on the call, or a Python exception.

use crate::rtpengine::RtpEngineError;

/// The engine's exact `CmdResult::Error` reason when the offer carries no codec
/// this build can encode (RFC 3264 §6.1) — the signal to render a 488.
const NO_ENCODABLE_CODEC: &str = "no-encodable-codec";

/// What `answer_local` should do with the backend's [`answer_local`] result,
/// factored out of the async closure so the mapping is unit-testable without
/// driving the `future_into_py` awaitable.
///
/// [`answer_local`]: crate::rtpengine::MediaBackend::answer_local
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AnswerLocalOutcome {
    /// Engine synthesised an answer — record the session, resolve to the SDP.
    Answered(String),
    /// No encodable codec and the caller opted into auto-reject on a `Call` —
    /// set a deferred 488 on the call and resolve to `None`.
    Reject488,
    /// No encodable codec but no auto-reject target — raise `ValueError`.
    ValueError,
    /// Transport / protocol / other engine error — raise `RuntimeError`.
    RuntimeError(String),
}

/// Map an `answer_local` backend result to the Python-visible outcome.
///
/// `can_reject` is `true` only when the script asked for `auto_reject` *and*
/// the target was a `Call` (the auto-488 path is defined for the B2BUA call
/// object — a bare `Request` has no deferred-reject channel).
pub(super) fn classify_answer_local(
    result: Result<String, RtpEngineError>,
    can_reject: bool,
) -> AnswerLocalOutcome {
    match result {
        Ok(answer_sdp) => AnswerLocalOutcome::Answered(answer_sdp),
        Err(RtpEngineError::EngineError(reason)) if reason == NO_ENCODABLE_CODEC => {
            if can_reject {
                AnswerLocalOutcome::Reject488
            } else {
                AnswerLocalOutcome::ValueError
            }
        }
        Err(error) => {
            AnswerLocalOutcome::RuntimeError(format!("rtpengine.answer_local failed: {error}"))
        }
    }
}
