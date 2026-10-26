//! `no_response_ms=` on `request.relay()` / `request.fork()`: the check that a
//! branch's bound on drawing any response sits below the transaction timeout
//! it is meant to beat.

use pyo3::prelude::*;

use crate::sip::message::Method;

/// How long a client transaction lasts with no final response, as the running
/// transaction layer is configured: the ceiling a `no_response_ms=` has to stay
/// under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimeouts {
    /// Timer B (RFC 3261 §17.1.1.2): an INVITE's, 64*T1.
    pub timer_b: std::time::Duration,
    /// Timer F (RFC 3261 §17.1.2.2): any other request's, 64*T1 unless
    /// `transaction.timeout_secs` sets it.
    pub timer_f: std::time::Duration,
}

impl ClientTimeouts {
    /// The ceilings of a transaction layer running `timers`.
    pub fn of(timers: &crate::transaction::timer::TimerConfig) -> Self {
        Self {
            timer_b: timers.timer_b(),
            timer_f: timers.timer_f(),
        }
    }
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self::of(&crate::transaction::timer::TimerConfig::default())
    }
}

/// Validate a `no_response_ms=` argument for a request with `method`.
///
/// TS 24.229 §5.4.3.3 NOTE 24: "The configurable time needs to be less than
/// timer B and timer F." A bound at or past the transaction's own timeout
/// could never fire first, so it is refused with `ValueError` rather than
/// clamped: a script that asked for 40 s and silently got 31.9 s would be
/// running on a number it never wrote. A whole number of milliseconds above
/// zero, under Timer B for an INVITE and under Timer F for anything else; an
/// ACK has no response to wait for.
pub fn validate_no_response(
    no_response_ms: Option<i64>,
    method: Option<&Method>,
    timeouts: ClientTimeouts,
) -> PyResult<Option<std::time::Duration>> {
    let Some(milliseconds) = no_response_ms else {
        return Ok(None);
    };
    let refuse = |message: String| Err(pyo3::exceptions::PyValueError::new_err(message));
    if milliseconds <= 0 {
        return refuse(format!(
            "no_response_ms={milliseconds}: must be a positive number of milliseconds"
        ));
    }
    let (ceiling, timer) = match method {
        Some(Method::Ack) => {
            return refuse(
                "no_response_ms: an ACK draws no response, so there is nothing to time".to_string(),
            )
        }
        Some(Method::Invite) => (timeouts.timer_b, "Timer B"),
        _ => (timeouts.timer_f, "Timer F"),
    };
    let requested = std::time::Duration::from_millis(milliseconds.unsigned_abs());
    if requested >= ceiling {
        return refuse(format!(
            "no_response_ms={milliseconds}: must be below {timer} ({} ms), which ends the transaction first",
            ceiling.as_millis()
        ));
    }
    Ok(Some(requested))
}
