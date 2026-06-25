//! PyO3 wrapper for SDP manipulation — the `sdp` namespace in Python scripts.
//!
//! Scripts interact via:
//!   from siphon import sdp
//!   s = sdp.parse(request)
//!   s.get_attr("group")               # session-level
//!   s.media[0].get_attr("des")        # media-level
//!   s.media[0].set_attr("des", "qos optional local sendrecv")
//!   s.apply(request)

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;

use crate::media::sdp::SdpBody;
use crate::sip::message::SipMessage;

use super::rtpengine::{extract_message, extract_sdp_body, replace_body};

// ---------------------------------------------------------------------------
// PySdpNamespace — the singleton injected as `siphon.sdp`
// ---------------------------------------------------------------------------

/// Stateless SDP parsing namespace.
///
/// Injected as `siphon.sdp` at startup (always available, no config needed).
#[pyclass(name = "SdpNamespace")]
pub struct PySdpNamespace;

impl Default for PySdpNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl PySdpNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PySdpNamespace {
    /// Parse SDP from a Request/Reply/Call message, a string, or bytes.
    ///
    /// Returns an `Sdp` object for structured inspection and manipulation.
    ///
    /// Raises `ValueError` if the message has no body or the body is not
    /// valid UTF-8. Raises `TypeError` if the source type is unsupported.
    fn parse(&self, source: &Bound<'_, PyAny>) -> PyResult<PySdp> {
        // Try str first.
        if let Ok(text) = source.extract::<String>() {
            let sdp = SdpBody::parse(&text);
            return Ok(PySdp {
                inner: Arc::new(Mutex::new(sdp)),
            });
        }

        // Try bytes.
        if let Ok(raw) = source.extract::<Vec<u8>>() {
            let text = String::from_utf8(raw).map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "SDP body is not valid UTF-8: {error}"
                ))
            })?;
            let sdp = SdpBody::parse(&text);
            return Ok(PySdp {
                inner: Arc::new(Mutex::new(sdp)),
            });
        }

        // Try extracting a SIP message (Request, Reply, or Call).
        let message_arc = extract_message(source).map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "sdp.parse() expects a Request, Reply, Call, str, or bytes",
            )
        })?;
        let sdp_bytes = extract_sdp_from_message(&message_arc)?;
        let text = String::from_utf8(sdp_bytes).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "SDP body is not valid UTF-8: {error}"
            ))
        })?;
        let sdp = SdpBody::parse(&text);
        Ok(PySdp {
            inner: Arc::new(Mutex::new(sdp)),
        })
    }

    fn __repr__(&self) -> &'static str {
        "<SdpNamespace>"
    }
}

// ---------------------------------------------------------------------------
// PySdp — wraps SdpBody
// ---------------------------------------------------------------------------

/// Parsed SDP object with structured access to session and media attributes.
#[pyclass(name = "Sdp")]
pub struct PySdp {
    inner: Arc<Mutex<SdpBody>>,
}

impl PySdp {
    fn lock(&self) -> PyResult<std::sync::MutexGuard<'_, SdpBody>> {
        self.inner.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })
    }
}

#[pymethods]
impl PySdp {
    // -----------------------------------------------------------------
    // Session-level read-only properties
    // -----------------------------------------------------------------

    /// Origin line value (`o=`), or `None`.
    #[getter]
    fn origin(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.origin().map(|s| s.to_string()))
    }

    /// Session name (`s=`), or `None`.
    #[getter]
    fn session_name(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.session_name().map(|s| s.to_string()))
    }

    /// Session-level connection (`c=`), or `None`.
    #[getter]
    fn connection(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.connection().map(|s| s.to_string()))
    }

    // -----------------------------------------------------------------
    // Session-level attribute (a=) API
    // -----------------------------------------------------------------

    /// Get the value of the first session-level attribute matching `name`.
    ///
    /// For `a=group:BUNDLE audio video`, `get_attr("group")` returns
    /// `"BUNDLE audio video"`. For flags like `a=ice-lite`, returns `""`.
    /// Returns `None` if not found.
    fn get_attr(&self, name: &str) -> PyResult<Option<String>> {
        Ok(self.lock()?.session_get_attr(name).map(|s| s.to_string()))
    }

    /// Get all session-level attribute values matching ``name``.
    fn get_attrs_by_name(&self, name: &str) -> PyResult<Vec<String>> {
        Ok(self.lock()?.session_get_attrs_by_name(name)
            .into_iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Replace all session-level attributes matching ``name`` with new values.
    fn set_attrs_by_name(&self, name: &str, values: Vec<String>) -> PyResult<()> {
        let str_values: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        self.lock()?.session_set_attrs_by_name(name, &str_values);
        Ok(())
    }

    /// Set (replace or append) a session-level attribute.
    ///
    /// `set_attr("group", "BUNDLE audio")` → `a=group:BUNDLE audio`.
    /// `set_attr("ice-lite", "")` → `a=ice-lite` (flag).
    #[pyo3(signature = (name, value=""))]
    fn set_attr(&self, name: &str, value: &str) -> PyResult<()> {
        self.lock()?.session_set_attr(name, value);
        Ok(())
    }

    /// Remove all session-level attributes matching `name`.
    fn remove_attr(&self, name: &str) -> PyResult<()> {
        self.lock()?.session_remove_attr(name);
        Ok(())
    }

    /// Check whether a session-level attribute with `name` exists.
    fn has_attr(&self, name: &str) -> PyResult<bool> {
        Ok(self.lock()?.session_has_attr(name))
    }

    /// All session-level `a=` values as a list of strings.
    #[getter]
    fn attrs(&self) -> PyResult<Vec<String>> {
        Ok(self
            .lock()?
            .session_attrs()
            .into_iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Replace all session-level `a=` lines.
    #[setter]
    fn set_attrs(&self, values: Vec<String>) -> PyResult<()> {
        let str_values: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        self.lock()?.set_session_attrs(&str_values);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Media sections
    // -----------------------------------------------------------------

    /// List of media sections.
    #[getter]
    fn media(&self) -> PyResult<Vec<PyMediaSection>> {
        let sdp = self.lock()?;
        let count = sdp.media_sections.len();
        drop(sdp);
        Ok((0..count)
            .map(|index| PyMediaSection {
                inner: Arc::clone(&self.inner),
                index,
            })
            .collect())
    }

    // -----------------------------------------------------------------
    // Codec filtering
    // -----------------------------------------------------------------

    /// Keep only codecs whose names match the given list (case-insensitive).
    fn filter_codecs(&self, keep: Vec<String>) -> PyResult<()> {
        let keep_refs: Vec<&str> = keep.iter().map(|s| s.as_str()).collect();
        self.lock()?.filter_codecs(&keep_refs);
        Ok(())
    }

    /// Remove codecs by name (case-insensitive).
    fn remove_codecs(&self, remove: Vec<String>) -> PyResult<()> {
        let remove_refs: Vec<&str> = remove.iter().map(|s| s.as_str()).collect();
        self.lock()?.remove_codecs(&remove_refs);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Media section removal
    // -----------------------------------------------------------------

    /// Remove all media sections with the given type (e.g. `"video"`).
    fn remove_media(&self, media_type: &str) -> PyResult<()> {
        self.lock()?.remove_media_by_type(media_type);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Apply / serialization
    // -----------------------------------------------------------------

    /// Write the SDP back into a Request/Reply/Call message.
    ///
    /// Sets the body, updates `Content-Length`, and ensures `Content-Type`
    /// is `application/sdp`.
    fn apply(&self, target: &Bound<'_, PyAny>) -> PyResult<()> {
        let message_arc = extract_message(target)?;
        let serialized = self.lock()?.to_string();
        replace_body(&message_arc, serialized.as_bytes())
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.lock()?.to_string())
    }

    fn __bytes__(&self) -> PyResult<Vec<u8>> {
        Ok(self.lock()?.to_string().into_bytes())
    }

    fn __repr__(&self) -> PyResult<String> {
        let sdp = self.lock()?;
        let media_count = sdp.media_sections.len();
        let session_name = sdp.session_name().unwrap_or("-");
        Ok(format!(
            "<Sdp session_name={session_name:?} media_sections={media_count}>"
        ))
    }
}

// ---------------------------------------------------------------------------
// PyMediaSection — view into a single media section
// ---------------------------------------------------------------------------

/// A single media section within an SDP body.
///
/// Shares state with the parent `Sdp` object — mutations are immediately
/// visible from either side.
#[pyclass(name = "MediaSection")]
pub struct PyMediaSection {
    inner: Arc<Mutex<SdpBody>>,
    index: usize,
}

impl PyMediaSection {
    fn lock(&self) -> PyResult<std::sync::MutexGuard<'_, SdpBody>> {
        self.inner.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })
    }

    /// Verify the index is still valid and return a useful error if not.
    fn check_index(&self, sdp: &SdpBody) -> PyResult<()> {
        if self.index >= sdp.media_sections.len() {
            return Err(pyo3::exceptions::PyIndexError::new_err(
                "media section was removed",
            ));
        }
        Ok(())
    }
}

#[pymethods]
impl PyMediaSection {
    /// Media type: `"audio"`, `"video"`, `"application"`, etc.
    #[getter]
    fn media_type(&self) -> PyResult<String> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index].media_type.clone())
    }

    /// Port number.
    #[getter]
    fn port(&self) -> PyResult<u16> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index].port)
    }

    /// Set the port number (e.g. `0` for hold/disabled).
    #[setter]
    fn set_port(&self, value: u16) -> PyResult<()> {
        let mut sdp = self.lock()?;
        self.check_index(&sdp)?;
        sdp.media_sections[self.index].port = value;
        Ok(())
    }

    /// Protocol: `"RTP/AVP"`, `"RTP/SAVPF"`, etc.
    #[getter]
    fn protocol(&self) -> PyResult<String> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index].protocol.clone())
    }

    /// Codec names derived from rtpmap and static payload types.
    #[getter]
    fn codecs(&self) -> PyResult<Vec<String>> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index].codec_names())
    }

    /// Media-level connection (`c=`), or `None`.
    #[getter]
    fn connection(&self) -> PyResult<Option<String>> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index]
            .connection()
            .map(|s| s.to_string()))
    }

    // -----------------------------------------------------------------
    // Attribute API (a= lines)
    // -----------------------------------------------------------------

    /// Get the value of the first attribute matching `name`.
    ///
    /// For `a=des:qos mandatory local sendrecv`, `get_attr("des")` returns
    /// `"qos mandatory local sendrecv"`. For flags, returns `""`.
    fn get_attr(&self, name: &str) -> PyResult<Option<String>> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index]
            .get_attr(name)
            .map(|s| s.to_string()))
    }

    /// Get all values of ``a=`` attributes matching ``name``, preserving order.
    ///
    /// ```python,ignore
    /// vals = m.get_attrs_by_name("des")
    /// # ["qos optional local sendrecv", "qos mandatory remote sendrecv"]
    /// ```
    fn get_attrs_by_name(&self, name: &str) -> PyResult<Vec<String>> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index]
            .get_attrs_by_name(name)
            .into_iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Replace all ``a=`` attributes matching ``name`` with new values.
    ///
    /// Preserves position of the first original match. If no match existed, appends.
    ///
    /// ```python,ignore
    /// vals = m.get_attrs_by_name("des")
    /// vals = [v.replace("mandatory", "optional") for v in vals]
    /// m.set_attrs_by_name("des", vals)
    /// ```
    fn set_attrs_by_name(&self, name: &str, values: Vec<String>) -> PyResult<()> {
        let str_values: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        let mut sdp = self.lock()?;
        self.check_index(&sdp)?;
        sdp.media_sections[self.index].set_attrs_by_name(name, &str_values);
        Ok(())
    }

    /// Set (replace first or append) a media-level attribute.
    #[pyo3(signature = (name, value=""))]
    fn set_attr(&self, name: &str, value: &str) -> PyResult<()> {
        let mut sdp = self.lock()?;
        self.check_index(&sdp)?;
        sdp.media_sections[self.index].set_attr(name, value);
        Ok(())
    }

    /// Remove all media-level attributes matching `name`.
    fn remove_attr(&self, name: &str) -> PyResult<()> {
        let mut sdp = self.lock()?;
        self.check_index(&sdp)?;
        sdp.media_sections[self.index].remove_attr(name);
        Ok(())
    }

    /// Check whether a media-level attribute with `name` exists.
    fn has_attr(&self, name: &str) -> PyResult<bool> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index].has_attr(name))
    }

    /// All `a=` attribute values for this media section.
    #[getter]
    fn attrs(&self) -> PyResult<Vec<String>> {
        let sdp = self.lock()?;
        self.check_index(&sdp)?;
        Ok(sdp.media_sections[self.index]
            .attrs()
            .into_iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Replace all `a=` lines in this media section.
    #[setter]
    fn set_attrs(&self, values: Vec<String>) -> PyResult<()> {
        let str_values: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        let mut sdp = self.lock()?;
        self.check_index(&sdp)?;
        sdp.media_sections[self.index].set_attrs(&str_values);
        Ok(())
    }

    fn __repr__(&self) -> PyResult<String> {
        let sdp = self.lock()?;
        if self.index >= sdp.media_sections.len() {
            return Ok("<MediaSection (removed)>".to_string());
        }
        let media = &sdp.media_sections[self.index];
        Ok(format!(
            "<MediaSection type={:?} port={} protocol={:?}>",
            media.media_type, media.port, media.protocol,
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract SDP bytes from a SIP message, handling multipart/mixed bodies.
fn extract_sdp_from_message(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<Vec<u8>> {
    let message = message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;
    extract_sdp_body(&message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SDP: &str = concat!(
        "v=0\r\n",
        "o=alice 123 123 IN IP4 10.0.0.1\r\n",
        "s=SIPhon\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE audio\r\n",
        "m=audio 49170 RTP/AVP 0 8\r\n",
        "a=sendrecv\r\n",
        "a=des:qos mandatory local sendrecv\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
    );

    #[test]
    fn parse_from_string() {
        let sdp = SdpBody::parse(TEST_SDP);
        assert_eq!(sdp.session_name(), Some("SIPhon"));
        assert_eq!(sdp.media_sections.len(), 1);
        assert_eq!(sdp.media_sections[0].media_type, "audio");
    }

    #[test]
    fn session_and_media_attrs() {
        let sdp = SdpBody::parse(TEST_SDP);
        assert_eq!(sdp.session_get_attr("group"), Some("BUNDLE audio"));
        assert_eq!(
            sdp.media_sections[0].get_attr("des"),
            Some("qos mandatory local sendrecv")
        );
        assert_eq!(sdp.media_sections[0].get_attr("sendrecv"), Some(""));
    }

    #[test]
    fn mutate_and_serialize() {
        let mut sdp = SdpBody::parse(TEST_SDP);
        sdp.media_sections[0].set_attr("des", "qos optional local sendrecv");

        let output = sdp.to_string();
        assert!(output.contains("a=des:qos optional local sendrecv"));
        assert!(!output.contains("mandatory"));
    }

    #[test]
    fn arc_mutex_shared_state() {
        let sdp = SdpBody::parse(TEST_SDP);
        let shared = Arc::new(Mutex::new(sdp));

        // Simulate PySdp and PyMediaSection sharing state.
        let sdp_ref = Arc::clone(&shared);
        let media_ref = Arc::clone(&shared);

        // Mutate through media reference.
        {
            let mut guard = media_ref.lock().unwrap();
            guard.media_sections[0].set_attr("ptime", "30");
        }

        // Visible through sdp reference.
        {
            let guard = sdp_ref.lock().unwrap();
            assert_eq!(guard.media_sections[0].get_attr("ptime"), Some("30"));
        }
    }
}
