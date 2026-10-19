//! The `call.media` handle: what a script asks of media anchoring for a call.

use pyo3::prelude::*;

/// Media handle — sub-object on `Call` for media anchoring.
///
/// Usage in Python:
///   call.media.anchor()                    # anchor through RTPEngine
///   call.media.anchor(engine="rtpengine")  # explicit engine name
///   call.media.release()                   # release media anchor
#[pyclass(name = "MediaHandle", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyMediaHandle {
    anchored: bool,
    engine: String,
    profile: String,
}

impl Default for PyMediaHandle {
    fn default() -> Self {
        Self {
            anchored: false,
            engine: "rtpengine".to_string(),
            profile: "srtp_to_rtp".to_string(),
        }
    }
}

impl PyMediaHandle {
    /// Check if media is anchored (for the B2BUA core to read after script runs).
    pub fn is_anchored(&self) -> bool {
        self.anchored
    }

    /// Get the media engine name.
    pub fn engine(&self) -> &str {
        &self.engine
    }

    /// Get the RTP profile name.
    pub fn profile_name(&self) -> &str {
        &self.profile
    }
}

#[pymethods]
impl PyMediaHandle {
    /// Anchor media through a media proxy.
    #[pyo3(signature = (engine="rtpengine", profile="srtp_to_rtp"))]
    fn anchor(&mut self, engine: &str, profile: &str) {
        self.anchored = true;
        self.engine = engine.to_string();
        self.profile = profile.to_string();
    }

    /// Release the media anchor.
    fn release(&mut self) {
        self.anchored = false;
    }

    /// Whether media is currently anchored.
    #[getter]
    fn is_active(&self) -> bool {
        self.anchored
    }
}

/// Raise `ValueError` for a dial that cannot go out behind an early answer
/// siphon already gave the caller (see `dispatcher::b2bua::early_dial`): one
/// that is not a media engine session, or a parallel `fork`.
pub(super) fn refuse_dial_behind_early_answer(call_id: &str, fork: bool) -> PyResult<()> {
    match crate::dispatcher::b2bua_dial_refusal(call_id, fork) {
        Some(refusal) => Err(pyo3::exceptions::PyValueError::new_err(refusal)),
        None => Ok(()),
    }
}
