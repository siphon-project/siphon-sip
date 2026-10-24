//! What a script takes in from a call it answered itself: the caller's audio
//! as a file (`start_recording`, `record`, `wait_recording`,
//! `stop_recording`) and the digits the caller keys (`read_digits`).
//!
//! A voicemail box or an IVR is the far end of the call (`answer_local`), so
//! the engine holds the caller's decoded audio and detects the RFC 4733
//! events; these verbs hand both to the script. The waiting is done in Rust,
//! keyed by the recording or the call (the media backend's waiters), not in
//! script state shared between workers. siphon-rtp only; the other backends
//! answer "not supported by this media backend".

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::debug;

use crate::rtpengine::events::{
    RecordingChannels, RecordingDirection, RecordingFinished, RecordingRequest,
};
use crate::rtpengine::siphon_rtp::DigitReadLimits;
use crate::rtpengine::MediaBackend;

/// How long `record` waits when neither `timeout_ms` nor `max_duration_ms`
/// bounds it: a recording that runs until the call ends.
const DEFAULT_RECORD_WAIT_MS: u64 = 3_600_000;
/// What `record` adds to `max_duration_ms`: the engine closes the file after
/// the cap, and the event follows the close.
const RECORD_WAIT_MARGIN_MS: u64 = 10_000;

/// The recording options a script passes, checked.
pub(super) struct RecordingOptions {
    pub path: Option<String>,
    pub direction: RecordingDirection,
    pub channels: RecordingChannels,
    pub max_duration_ms: Option<u64>,
    pub silence_ms: Option<u64>,
}

impl RecordingOptions {
    pub fn parse(
        path: Option<String>,
        direction: &str,
        channels: &str,
        max_duration_ms: Option<u64>,
        silence_ms: Option<u64>,
    ) -> PyResult<Self> {
        let direction = match direction {
            "ingress" => RecordingDirection::Ingress,
            "egress" => RecordingDirection::Egress,
            "both" => RecordingDirection::Both,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "direction {other:?} is ingress, egress or both"
                )))
            }
        };
        let channels = match channels {
            "mono" => RecordingChannels::Mono,
            "stereo" => RecordingChannels::Stereo,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "channels {other:?} is mono or stereo"
                )))
            }
        };
        if max_duration_ms == Some(0) || silence_ms == Some(0) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_duration_ms and silence_ms are positive when given",
            ));
        }
        Ok(Self {
            path,
            direction,
            channels,
            max_duration_ms,
            silence_ms,
        })
    }

    /// How long `record` waits for the end by default.
    pub fn default_wait_ms(&self) -> u64 {
        self.max_duration_ms
            .map(|cap| cap.saturating_add(RECORD_WAIT_MARGIN_MS))
            .unwrap_or(DEFAULT_RECORD_WAIT_MS)
    }
}

fn runtime_error(verb: &str, error: impl std::fmt::Display) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("rtpengine.{verb} failed: {error}"))
}

/// Start a recording; the engine's `recording_id`.
pub(super) async fn start(
    client: &MediaBackend,
    call_id: &str,
    from_tag: &str,
    options: &RecordingOptions,
    verb: &str,
) -> PyResult<String> {
    let request = RecordingRequest {
        direction: options.direction,
        channels: options.channels,
        max_duration_ms: options.max_duration_ms,
        silence_ms: options.silence_ms,
        path: options.path.as_deref(),
    };
    let recording_id = client
        .start_recording(call_id, from_tag, &request)
        .await
        .map_err(|error| runtime_error(verb, error))?;
    debug!(call_id, recording_id = %recording_id, "rtpengine recording started");
    Ok(recording_id)
}

/// Wait for a recording to end: its result as a dict, or `None`.
///
/// The dict is built in the completion step ([`crate::script::Deferred`]),
/// never on the tokio worker the wait ran on: attaching there would hold a
/// garbage collection's stop-the-world open behind a worker.
pub(super) async fn wait(
    client: &MediaBackend,
    call_id: &str,
    recording_id: &str,
    wait_ms: u64,
    verb: &str,
) -> PyResult<crate::script::Deferred> {
    let finished = client
        .wait_recording(call_id, recording_id, Duration::from_millis(wait_ms.max(1)))
        .await
        .map_err(|error| runtime_error(verb, error))?;
    match finished {
        Some(finished) => Ok(crate::script::Deferred::build(move |python| {
            finished_dict(python, &finished)
        })),
        None => Ok(crate::script::Deferred::none()),
    }
}

/// The dict a script reads a finished recording from.
pub(super) fn finished_dict(
    python: Python<'_>,
    finished: &RecordingFinished,
) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(python);
    dict.set_item("recording_id", &finished.recording_id)?;
    dict.set_item("path", finished.path.as_deref())?;
    dict.set_item("duration_ms", finished.duration_ms)?;
    dict.set_item("reason", finished.reason)?;
    dict.set_item("call_id", &finished.call_id)?;
    dict.set_item("from_tag", &finished.from_tag)?;
    Ok(dict.into_any().unbind())
}

/// Read the limits of `read_digits`.
pub(super) fn digit_limits(
    terminators: String,
    max_digits: Option<usize>,
    timeout_ms: u64,
    inter_digit_timeout_ms: u64,
) -> PyResult<DigitReadLimits> {
    if max_digits == Some(0) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "max_digits is at least 1 when given",
        ));
    }
    if let Some(bad) = terminators
        .chars()
        .find(|character| !"0123456789*#ABCD".contains(*character))
    {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "terminator {bad:?} is not a DTMF digit (0-9, *, #, A-D)"
        )));
    }
    if timeout_ms == 0 || inter_digit_timeout_ms == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "timeout_ms and inter_digit_timeout_ms are positive",
        ));
    }
    Ok(DigitReadLimits {
        terminators,
        max_digits,
        timeout: Duration::from_millis(timeout_ms),
        inter_digit_timeout: Duration::from_millis(inter_digit_timeout_ms),
    })
}

/// Collect digits: `(digits, reason)`.
pub(super) async fn read_digits(
    client: Arc<MediaBackend>,
    call_id: String,
    limits: DigitReadLimits,
) -> PyResult<(String, &'static str)> {
    let read = client
        .read_digits(&call_id, &limits)
        .await
        .map_err(|error| runtime_error("read_digits", error))?;
    debug!(call_id = %call_id, digits = %read.digits, end = read.end.as_str(), "rtpengine read_digits");
    Ok((read.digits, read.end.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_options_are_checked() {
        let options = RecordingOptions::parse(None, "ingress", "mono", Some(120_000), Some(5000))
            .expect("valid");
        assert_eq!(options.direction, RecordingDirection::Ingress);
        assert_eq!(options.default_wait_ms(), 130_000);
        let unbounded = RecordingOptions::parse(None, "both", "stereo", None, None).expect("valid");
        assert_eq!(unbounded.default_wait_ms(), DEFAULT_RECORD_WAIT_MS);
        assert!(RecordingOptions::parse(None, "inbound", "mono", None, None).is_err());
        assert!(RecordingOptions::parse(None, "ingress", "quad", None, None).is_err());
        assert!(RecordingOptions::parse(None, "ingress", "mono", Some(0), None).is_err());
    }

    #[test]
    fn digit_limits_are_checked() {
        let limits = digit_limits("#*".into(), Some(4), 5000, 3000).expect("valid");
        assert_eq!(limits.max_digits, Some(4));
        assert!(digit_limits("x".into(), None, 5000, 3000).is_err());
        assert!(digit_limits("#".into(), Some(0), 5000, 3000).is_err());
        assert!(digit_limits("#".into(), None, 0, 3000).is_err());
        assert!(digit_limits(String::new(), None, 5000, 3000).is_ok());
    }
}
