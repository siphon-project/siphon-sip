//! Python `srs` namespace — Session Recording Server hooks from scripts.
//!
//! Allows Python scripts to accept/reject SIPREC recordings and enrich metadata:
//! ```python
//! from siphon import srs
//!
//! @srs.on_invite
//! async def on_recording(request, metadata):
//!     log.info(f"Recording: {metadata.session_id}")
//!     return True  # accept
//!
//! @srs.on_session_end
//! async def on_recording_end(session):
//!     log.info(f"Recording {session.session_id} complete")
//! ```

use pyo3::prelude::*;

/// Python-facing SRS session metadata (read-only view of RecordingMetadata).
#[pyclass(name = "RecordingMetadata", skip_from_py_object)]
#[derive(Clone)]
pub struct PyRecordingMetadata {
    session_id: String,
    sip_session_ids: Vec<String>,
    participants: Vec<PyParticipant>,
    streams: Vec<PyStreamInfo>,
}

#[pymethods]
impl PyRecordingMetadata {
    /// Recording session ID from the SIPREC metadata.
    #[getter]
    fn session_id(&self) -> &str {
        &self.session_id
    }

    /// SIP Session-IDs from the original call dialog(s) being recorded (RFC 7865).
    #[getter]
    fn sip_session_ids(&self) -> Vec<String> {
        self.sip_session_ids.clone()
    }

    /// Original call-id of the recorded dialog (first sipSessionID, if any).
    #[getter]
    fn original_call_id(&self) -> Option<String> {
        self.sip_session_ids.first().cloned()
    }

    /// List of participants in the recorded call.
    #[getter]
    fn participants(&self) -> Vec<PyParticipant> {
        self.participants.clone()
    }

    /// List of media streams being recorded.
    #[getter]
    fn streams(&self) -> Vec<PyStreamInfo> {
        self.streams.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "RecordingMetadata(session_id='{}', participants={}, streams={})",
            self.session_id,
            self.participants.len(),
            self.streams.len(),
        )
    }
}

impl PyRecordingMetadata {
    /// Create from the Rust-side parsed metadata.
    pub fn from_metadata(metadata: &crate::siprec::metadata::RecordingMetadata) -> Self {
        Self {
            session_id: metadata.session_id.clone(),
            sip_session_ids: metadata.sip_session_ids.clone(),
            participants: metadata
                .participants
                .iter()
                .map(|participant| PyParticipant {
                    participant_id: participant.participant_id.clone(),
                    aor: participant.aor.clone(),
                    name: participant.name.clone(),
                })
                .collect(),
            streams: metadata
                .streams
                .iter()
                .map(|stream| PyStreamInfo {
                    stream_id: stream.stream_id.clone(),
                    label: stream.label.clone(),
                })
                .collect(),
        }
    }
}

/// Python-facing participant info.
#[pyclass(name = "SrsParticipant", skip_from_py_object)]
#[derive(Clone)]
pub struct PyParticipant {
    participant_id: String,
    aor: String,
    name: Option<String>,
}

#[pymethods]
impl PyParticipant {
    #[getter]
    fn participant_id(&self) -> &str {
        &self.participant_id
    }

    #[getter]
    fn aor(&self) -> &str {
        &self.aor
    }

    #[getter]
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn __repr__(&self) -> String {
        format!("SrsParticipant(aor='{}')", self.aor)
    }
}

/// Python-facing stream info.
#[pyclass(name = "SrsStreamInfo", skip_from_py_object)]
#[derive(Clone)]
pub struct PyStreamInfo {
    stream_id: String,
    label: String,
}

#[pymethods]
impl PyStreamInfo {
    #[getter]
    fn stream_id(&self) -> &str {
        &self.stream_id
    }

    #[getter]
    fn label(&self) -> &str {
        &self.label
    }

    fn __repr__(&self) -> String {
        format!("SrsStreamInfo(label='{}')", self.label)
    }
}

/// Python-facing completed recording session info.
#[pyclass(name = "SrsSession", skip_from_py_object)]
#[derive(Clone)]
pub struct PySrsSession {
    session_id: String,
    recording_call_id: String,
    original_call_id: Option<String>,
    participants: Vec<PyParticipant>,
    duration_secs: u64,
    recording_dir: Option<String>,
}

#[pymethods]
impl PySrsSession {
    #[getter]
    fn session_id(&self) -> &str {
        &self.session_id
    }

    #[getter]
    fn recording_call_id(&self) -> &str {
        &self.recording_call_id
    }

    #[getter]
    fn original_call_id(&self) -> Option<&str> {
        self.original_call_id.as_deref()
    }

    #[getter]
    fn participants(&self) -> Vec<PyParticipant> {
        self.participants.clone()
    }

    #[getter]
    fn duration(&self) -> u64 {
        self.duration_secs
    }

    #[getter]
    fn recording_dir(&self) -> Option<&str> {
        self.recording_dir.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "SrsSession(session_id='{}', duration={}s)",
            self.session_id, self.duration_secs,
        )
    }
}

impl PySrsSession {
    /// Create from a recording record.
    pub fn from_record(record: &crate::srs::RecordingRecord) -> Self {
        Self {
            session_id: record.session_id.clone(),
            recording_call_id: record.recording_call_id.clone(),
            original_call_id: record.original_call_id.clone(),
            participants: record
                .participants
                .iter()
                .map(|participant| PyParticipant {
                    participant_id: participant.participant_id.clone(),
                    aor: participant.aor.clone(),
                    name: participant.name.clone(),
                })
                .collect(),
            duration_secs: record.duration_secs,
            recording_dir: record.recording_dir.clone(),
        }
    }
}
