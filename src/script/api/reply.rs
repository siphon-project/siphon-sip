//! PyO3 wrapper for SIP responses — exposed to Python scripts as `Reply`.
//!
//! The `Reply` object is passed to `@proxy.on_reply`, `@proxy.on_failure`,
//! and `@proxy.on_register_reply` handlers alongside the original request.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;

use crate::sip::message::{SipMessage, StartLine};
use crate::sip::uri::SipUri;
use crate::sip::headers::nameaddr::NameAddr;
use super::sip_uri::PySipUri;

/// Python-visible SIP reply object.
///
/// Wraps an `Arc<Mutex<SipMessage>>` so mutations from Python
/// (e.g. `reply.set_header()`) are visible to the Rust core when
/// it later forwards the response.
#[pyclass(name = "Reply")]
pub struct PyReply {
    message: Arc<Mutex<SipMessage>>,
    forwarded: bool,
    /// Source IP of the entity that sent this response (for NAT fixup).
    response_source_ip: Option<String>,
    /// Source port of the entity that sent this response (for NAT fixup).
    response_source_port: Option<u16>,
    /// In B2BUA mode, the A-leg INVITE message.  Used by `rtpengine.answer()`
    /// to automatically correlate with the earlier `offer()` (which used the
    /// A-leg Call-ID/From-tag).
    a_leg_message: Option<Arc<Mutex<SipMessage>>>,
    /// Reply-time reject requested by the script (`reply.reject(code, reason)`).
    /// `Some((code, reason))` only when the script rejected an in-progress
    /// proxied INVITE from a provisional (1xx) response — the dispatcher then
    /// sends `code reason` upstream to the UAC and CANCELs the pending
    /// downstream branch(es).  Stays `None` for a 2xx (a proxy cannot retract a
    /// final answer) so the normal forward path runs unchanged.
    reject_action: Option<(u16, String)>,
}

impl PyReply {
    /// Create a new `PyReply` wrapping a response `SipMessage`.
    ///
    /// # Panics
    /// Panics if the message is not a response (has no `StatusLine`).
    pub fn new(message: Arc<Mutex<SipMessage>>) -> Self {
        if cfg!(debug_assertions) {
            if let Ok(guard) = message.lock() {
                debug_assert!(guard.is_response());
            }
        }
        Self {
            message,
            forwarded: false,
            response_source_ip: None,
            response_source_port: None,
            a_leg_message: None,
            reject_action: None,
        }
    }

    /// Set the source address of the entity that sent this response.
    ///
    /// Used by `fix_nated_contact()` to rewrite the Contact URI with
    /// the observed source address (NAT traversal).
    pub fn with_response_source(mut self, ip: String, port: u16) -> Self {
        self.response_source_ip = Some(ip);
        self.response_source_port = Some(port);
        self
    }

    /// Attach the A-leg INVITE so `rtpengine.answer()` can look up the
    /// original Call-ID/From-tag transparently (B2BUA mode).
    pub fn with_a_leg(mut self, a_leg: Arc<Mutex<SipMessage>>) -> Self {
        self.a_leg_message = Some(a_leg);
        self
    }

    /// Whether the script called `relay()` or `forward()`.
    pub fn was_forwarded(&self) -> bool {
        self.forwarded
    }

    /// The reply-time reject the script requested, if any.
    ///
    /// `Some((code, reason))` when the script called `reply.reject(code,
    /// reason)` on a provisional (1xx) response.  The dispatcher consumes this
    /// to send a final error upstream and CANCEL the pending downstream
    /// branch(es).  Takes precedence over `relay()`/`forward()`.
    pub fn reject_action(&self) -> Option<(u16, String)> {
        self.reject_action.clone()
    }

    /// Get the underlying message (for Rust-side forwarding).
    pub fn message(&self) -> Arc<Mutex<SipMessage>> {
        Arc::clone(&self.message)
    }

    /// Get the A-leg message, if set (B2BUA mode).
    pub fn a_leg_message(&self) -> Option<Arc<Mutex<SipMessage>>> {
        self.a_leg_message.as_ref().map(Arc::clone)
    }
}

#[pymethods]
impl PyReply {
    /// Response status code (e.g. 200, 404, 503).
    #[getter]
    fn status_code(&self) -> PyResult<u16> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message.status_code().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("not a response message")
        })
    }

    /// Reason phrase (e.g. "OK", "Not Found").
    #[getter]
    fn reason(&self) -> PyResult<String> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        match &message.start_line {
            StartLine::Response(status_line) => Ok(status_line.reason_phrase.clone()),
            _ => Err(pyo3::exceptions::PyRuntimeError::new_err("not a response")),
        }
    }

    /// From URI parsed from the From header.
    #[getter]
    #[allow(clippy::wrong_self_convention)]
    fn from_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.from().and_then(|value| {
            extract_uri_from_header(value).map(PySipUri::new)
        }))
    }

    /// To URI parsed from the To header.
    #[getter]
    fn to_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.to().and_then(|value| {
            extract_uri_from_header(value).map(PySipUri::new)
        }))
    }

    /// Call-ID header value.
    #[getter]
    fn call_id(&self) -> PyResult<Option<String>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.call_id().cloned())
    }

    /// Message body as bytes, or None if empty.
    ///
    /// Mirrors `request.body` so SDP-handling scripts can read a response
    /// body symmetrically (e.g. `answer = reply.body` in a `@proxy.on_reply`
    /// media-authorization handler).
    #[getter]
    fn body(&self) -> PyResult<Option<Vec<u8>>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        if message.body.is_empty() {
            Ok(None)
        } else {
            Ok(Some(message.body.clone()))
        }
    }

    /// Content-Type header value.
    #[getter]
    fn content_type(&self) -> PyResult<Option<String>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.content_type().cloned())
    }

    /// Check if a header exists.
    fn has_header(&self, name: &str) -> PyResult<bool> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.has(name))
    }

    /// Get the first value of a header, or None.
    fn get_header(&self, name: &str) -> PyResult<Option<String>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.get(name).cloned())
    }

    /// Alias for `get_header` (used in CNAM-AS script).
    fn header(&self, name: &str) -> PyResult<Option<String>> {
        self.get_header(name)
    }

    /// Set (replace) a header value.
    fn set_header(&self, name: &str, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message.headers.set(name, value.to_string());
        Ok(())
    }

    /// Remove a header entirely.
    fn remove_header(&self, name: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message.headers.remove(name);
        Ok(())
    }

    /// Remove all headers whose names start with a given prefix (case-insensitive).
    fn remove_headers_matching(&self, prefix: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let prefix_lower = prefix.to_lowercase();
        let names_to_remove: Vec<String> = message.headers.names()
            .iter()
            .filter(|name| name.to_lowercase().starts_with(&prefix_lower))
            .map(|name| name.to_string())
            .collect();
        for name in names_to_remove {
            message.headers.remove(&name);
        }
        Ok(())
    }

    /// Check if the body matches a given content type.
    fn has_body(&self, content_type: &str) -> PyResult<bool> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        if message.body.is_empty() {
            return Ok(false);
        }
        Ok(message.headers.content_type()
            .map(|ct| ct.starts_with(content_type))
            .unwrap_or(false))
    }

    /// Extract the IMS-AKA authentication vector (CK/IK) from any auth
    /// header on this 401 and **strip** the ``ck=`` / ``ik=`` parameters
    /// in place.
    ///
    /// Scans ``WWW-Authenticate``, ``Proxy-Authenticate`` and
    /// ``Authentication-Info`` (in that order — RFC 3310 §3.2 / TS 33.203
    /// §6.1.4 allow CK/IK to appear in any of them).  Returns an opaque
    /// :class:`AuthVectorHandle` only when **both** ``ck`` and ``ik`` parsed
    /// cleanly; otherwise leaves the headers untouched and returns
    /// ``None``.
    ///
    /// Idempotent: after the AV has been stripped, a second call returns
    /// ``None`` because no header still carries ``ck``/``ik``.
    fn take_av(&self, python: Python<'_>) -> PyResult<Option<Py<super::ipsec::PyAuthVectorHandle>>> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        for header_name in ["WWW-Authenticate", "Proxy-Authenticate", "Authentication-Info"] {
            let original = match message.headers.get(header_name).cloned() {
                Some(value) => value,
                None => continue,
            };
            let (rewritten, parsed) = super::ipsec::strip_ck_ik(&original);
            if let Some((ck, ik)) = parsed {
                message.headers.set(header_name, rewritten);
                drop(message);
                let handle = super::ipsec::PyAuthVectorHandle::new(ck, ik);
                return Ok(Some(Py::new(python, handle)?));
            }
        }
        Ok(None)
    }

    /// Mark this reply for forwarding upstream.
    fn relay(&mut self) {
        self.forwarded = true;
    }

    /// Alias for `relay()` (used in P-CSCF and S-CSCF scripts).
    fn forward(&mut self) {
        self.forwarded = true;
    }

    /// Reject an in-progress proxied INVITE from the reply context.
    ///
    /// Fail the leg with a SIP error (e.g. ``503``) from inside
    /// ``@proxy.on_reply``.  This is the proxy-side equivalent of the B2BUA's
    /// ``call.reject()`` — needed because media authorization
    /// (``sbi.create_session`` / ``diameter.rx_aar``) necessarily runs at
    /// answer time, when the negotiated SDP is available, and the P-CSCF spec
    /// says a media-authorization failure MUST reject the leg rather than
    /// proceed medialess.
    ///
    /// Behaviour depends on the stage of the response this handler is running
    /// for:
    ///
    /// - **Provisional (1xx) — no final answer yet:** records the reject and
    ///   returns ``True``.  After the handler returns, siphon sends ``code
    ///   reason`` upstream to the UAC and CANCELs the pending downstream
    ///   branch(es), reusing the fork/CANCEL machinery.  This is the clean
    ///   path — typically reached on a reliable ``183 Session Progress`` in the
    ///   VoLTE preconditions / early-media flow, where the SDP answer the
    ///   authorization needs rides the provisional.
    /// - **Final (>= 200) — UAS already answered:** a proxy cannot retract a
    ///   2xx, so this is a no-op and returns ``False``.  The script should
    ///   branch on the return value — log the failed authorization and
    ///   ``reply.relay()`` to let the answer through (best-effort, no dedicated
    ///   bearer).
    ///
    /// Takes precedence over ``relay()`` / ``forward()`` when it returns
    /// ``True``.
    ///
    /// Args:
    ///     code: SIP final-response code in the 400–699 range (e.g. ``503``).
    ///     reason: optional reason phrase; a sensible default is derived from
    ///         ``code`` when omitted.
    ///
    /// Raises:
    ///     ValueError: if ``code`` is outside 400–699.
    ///
    /// Example:
    ///
    /// ```python,ignore
    /// @proxy.on_reply
    /// async def on_reply(request, reply):
    ///     if request.method == "INVITE" and reply.has_body("application/sdp"):
    ///         authorized = await authorize_media(request, reply)
    ///         if not authorized:
    ///             if reply.reject(503, "Media Authorization Failed"):
    ///                 return            # 503 + CANCEL sent by siphon
    ///             log.warn("could not reject answered call; proceeding best-effort")
    ///     reply.relay()
    /// ```
    #[pyo3(signature = (code, reason=None))]
    fn reject(&mut self, code: u16, reason: Option<&str>) -> PyResult<bool> {
        if !(400..=699).contains(&code) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "reply.reject() code must be a 400–699 SIP error code, got {code}"
            )));
        }

        let status_code = {
            let message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            message.status_code().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("not a response message")
            })?
        };

        // A proxy can only fail a leg before the UAS commits a final response.
        // Once a 2xx (or any final) is on the wire it cannot be retracted, so
        // the reject is a no-op the script must handle.
        if status_code >= 200 {
            return Ok(false);
        }

        let reason = reason
            .map(str::to_string)
            .unwrap_or_else(|| default_reject_reason(code).to_string());
        self.reject_action = Some((code, reason));
        Ok(true)
    }

    /// Fix NAT for Contact in this response: rewrite Contact URI host:port
    /// with the observed source IP:port of the entity that sent this reply.
    ///
    /// This is the reply-side equivalent of `request.fix_nated_contact()`.
    /// Use it when the downstream UAS is behind NAT and its Contact URI
    /// contains a private address that the upstream UAC cannot reach.
    fn fix_nated_contact(&self) -> PyResult<()> {
        let (source_ip, source_port) = match (&self.response_source_ip, self.response_source_port) {
            (Some(ip), Some(port)) => (ip.clone(), port),
            _ => {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "response source address not available for fix_nated_contact"
                ));
            }
        };
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        if let Some(raw) = message.headers.get("Contact").cloned() {
            if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
                nameaddr.uri.host = format_sip_host(&source_ip);
                nameaddr.uri.port = Some(source_port);
                message.headers.set("Contact", nameaddr.to_string());
            }
        }
        Ok(())
    }
}

/// Default reason phrase for a reject code when the script omits one.
///
/// Covers the codes a media-authorization reject realistically uses; anything
/// else falls back to a generic phrase per response class.
fn default_reject_reason(code: u16) -> &'static str {
    match code {
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        480 => "Temporarily Unavailable",
        486 => "Busy Here",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        600 => "Busy Everywhere",
        603 => "Decline",
        _ => match code {
            400..=499 => "Client Error",
            500..=599 => "Server Error",
            _ => "Global Failure",
        },
    }
}

/// Format a host string for SIP URIs (bracket IPv6 addresses).
fn format_sip_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a `SipUri` from a From/To header value.
///
/// Header values look like:
///   `"Display Name" <sip:user@host:port;param=val>;tag=abc`
///   `<sip:user@host>`
///   `sip:user@host`
fn extract_uri_from_header(header_value: &str) -> Option<SipUri> {
    // Find URI between angle brackets if present.
    let uri_str = if let Some(start) = header_value.find('<') {
        let end = header_value[start..].find('>')?;
        &header_value[start + 1..start + end]
    } else {
        // No angle brackets — take everything before any `;` params.
        header_value.split(';').next()?
    };

    // Parse "sip:user@host:port" or "sips:user@host"
    let uri_str = uri_str.trim();
    let (scheme, rest) = uri_str.split_once(':')?;
    if scheme != "sip" && scheme != "sips" {
        return None;
    }

    // Split user@host:port from URI params (after semicolons within the URI).
    let (addr_part, _params_part) = rest.split_once(';').unwrap_or((rest, ""));

    let (user, host_port) = if let Some((user, host_port)) = addr_part.split_once('@') {
        (Some(user.to_string()), host_port)
    } else {
        (None, addr_part)
    };

    let (host, port) = if let Some((host, port_str)) = host_port.rsplit_once(':') {
        (host.to_string(), port_str.parse::<u16>().ok())
    } else {
        (host_port.to_string(), None)
    };

    Some(SipUri {
        scheme: scheme.to_string(),
        user,
        host,
        port,
        params: Vec::new(),
        headers: Vec::new(),
        user_params: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::headers::SipHeaders;
    use crate::sip::message::{Version, StatusLine, StartLine};

    fn make_response(status_code: u16, reason: &str) -> SipMessage {
        let mut headers = SipHeaders::new();
        headers.add("From", "<sip:alice@example.com>;tag=abc123".to_string());
        headers.add("To", "<sip:bob@example.com>;tag=def456".to_string());
        headers.add("Call-ID", "call-42@host".to_string());
        headers.add("CSeq", "1 INVITE".to_string());
        headers.add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776".to_string());

        SipMessage {
            start_line: StartLine::Response(StatusLine {
                version: Version::sip_2_0(),
                status_code,
                reason_phrase: reason.to_string(),
            }),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn status_code_and_reason() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert_eq!(reply.status_code().unwrap(), 200);
        assert_eq!(reply.reason().unwrap(), "OK");
    }

    #[test]
    fn from_and_to_uri() {
        let message = Arc::new(Mutex::new(make_response(180, "Ringing")));
        let reply = PyReply::new(message);

        let from = reply.from_uri().unwrap().unwrap();
        assert_eq!(from.inner().user.as_deref(), Some("alice"));
        assert_eq!(from.inner().host, "example.com");

        let to = reply.to_uri().unwrap().unwrap();
        assert_eq!(to.inner().user.as_deref(), Some("bob"));
        assert_eq!(to.inner().host, "example.com");
    }

    #[test]
    fn call_id() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert_eq!(reply.call_id().unwrap(), Some("call-42@host".to_string()));
    }

    #[test]
    fn header_operations() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert!(reply.has_header("Via").unwrap());
        assert!(!reply.has_header("X-Custom").unwrap());

        reply.set_header("X-Custom", "value").unwrap();
        assert!(reply.has_header("X-Custom").unwrap());
        assert_eq!(reply.get_header("X-Custom").unwrap(), Some("value".to_string()));
        assert_eq!(reply.header("X-Custom").unwrap(), Some("value".to_string()));

        reply.remove_header("X-Custom").unwrap();
        assert!(!reply.has_header("X-Custom").unwrap());
    }

    #[test]
    fn has_body_checks_content_type() {
        let mut response = make_response(200, "OK");
        response.headers.set("Content-Type", "application/sdp".to_string());
        response.body = b"v=0\r\n".to_vec();

        let message = Arc::new(Mutex::new(response));
        let reply = PyReply::new(message);

        assert!(reply.has_body("application/sdp").unwrap());
        assert!(!reply.has_body("text/plain").unwrap());
    }

    #[test]
    fn has_body_false_when_empty() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert!(!reply.has_body("application/sdp").unwrap());
    }

    #[test]
    fn body_returns_bytes_when_present() {
        let mut response = make_response(200, "OK");
        response.headers.set("Content-Type", "application/sdp".to_string());
        response.body = b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n".to_vec();

        let message = Arc::new(Mutex::new(response));
        let reply = PyReply::new(message);

        assert_eq!(
            reply.body().unwrap(),
            Some(b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n".to_vec())
        );
    }

    #[test]
    fn body_is_none_when_empty() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert_eq!(reply.body().unwrap(), None);
    }

    #[test]
    fn content_type_getter() {
        let mut response = make_response(200, "OK");
        response.headers.set("Content-Type", "application/sdp".to_string());

        let message = Arc::new(Mutex::new(response));
        let reply = PyReply::new(message);

        assert_eq!(reply.content_type().unwrap(), Some("application/sdp".to_string()));
    }

    #[test]
    fn content_type_none_when_absent() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert_eq!(reply.content_type().unwrap(), None);
    }

    #[test]
    fn relay_and_forward_set_forwarded() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let mut reply = PyReply::new(message);

        assert!(!reply.was_forwarded());
        reply.relay();
        assert!(reply.was_forwarded());
    }

    #[test]
    fn forward_is_alias_for_relay() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let mut reply = PyReply::new(message);

        reply.forward();
        assert!(reply.was_forwarded());
    }

    #[test]
    fn reject_on_provisional_records_action_and_returns_true() {
        let message = Arc::new(Mutex::new(make_response(183, "Session Progress")));
        let mut reply = PyReply::new(message);

        assert_eq!(reply.reject_action(), None);
        let took = reply.reject(503, Some("Media Authorization Failed")).unwrap();
        assert!(took, "reject on a provisional must take");
        assert_eq!(
            reply.reject_action(),
            Some((503, "Media Authorization Failed".to_string()))
        );
    }

    #[test]
    fn reject_default_reason_when_omitted() {
        let message = Arc::new(Mutex::new(make_response(180, "Ringing")));
        let mut reply = PyReply::new(message);

        assert!(reply.reject(503, None).unwrap());
        assert_eq!(
            reply.reject_action(),
            Some((503, "Service Unavailable".to_string()))
        );
    }

    #[test]
    fn reject_on_final_is_noop_and_returns_false() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let mut reply = PyReply::new(message);

        let took = reply.reject(503, Some("Service Unavailable")).unwrap();
        assert!(!took, "a 2xx cannot be retracted");
        assert_eq!(reply.reject_action(), None);
    }

    #[test]
    fn reject_on_error_final_is_noop() {
        // An already-final error response is moot to reject — the leg is failing
        // anyway.  Return false and record nothing.
        let message = Arc::new(Mutex::new(make_response(486, "Busy Here")));
        let mut reply = PyReply::new(message);

        assert!(!reply.reject(503, None).unwrap());
        assert_eq!(reply.reject_action(), None);
    }

    #[test]
    fn reject_rejects_out_of_range_code() {
        let message = Arc::new(Mutex::new(make_response(183, "Session Progress")));
        let mut reply = PyReply::new(message);

        // Below 400 (provisional/success/redirect) and above 699 are invalid.
        assert!(reply.reject(200, None).is_err());
        assert!(reply.reject(100, None).is_err());
        assert!(reply.reject(700, None).is_err());
        // Nothing recorded after the errors.
        assert_eq!(reply.reject_action(), None);
    }

    #[test]
    fn reject_takes_precedence_over_relay() {
        let message = Arc::new(Mutex::new(make_response(183, "Session Progress")));
        let mut reply = PyReply::new(message);

        reply.relay();
        assert!(reply.reject(503, None).unwrap());
        // Both signals are set; the dispatcher checks reject_action() first.
        assert!(reply.was_forwarded());
        assert!(reply.reject_action().is_some());
    }

    #[test]
    fn default_reject_reason_covers_classes_and_known_codes() {
        assert_eq!(default_reject_reason(503), "Service Unavailable");
        assert_eq!(default_reject_reason(403), "Forbidden");
        assert_eq!(default_reject_reason(488), "Not Acceptable Here");
        assert_eq!(default_reject_reason(603), "Decline");
        // Unmapped codes fall back to a per-class phrase.
        assert_eq!(default_reject_reason(451), "Client Error");
        assert_eq!(default_reject_reason(599), "Server Error");
        assert_eq!(default_reject_reason(699), "Global Failure");
    }

    #[test]
    fn mutations_visible_on_underlying_message() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(Arc::clone(&message));

        reply.set_header("P-Asserted-Identity", "sip:alice@example.com").unwrap();

        // Verify mutation is visible through the original Arc.
        let locked = message.lock().unwrap();
        assert_eq!(
            locked.headers.get("P-Asserted-Identity").map(|s| s.as_str()),
            Some("sip:alice@example.com")
        );
    }

    #[test]
    fn fix_nated_contact_rewrites_uri() {
        let mut response = make_response(200, "OK");
        response.headers.set("Contact", "<sip:alice@192.168.1.100:6000>".to_string());

        let message = Arc::new(Mutex::new(response));
        let reply = PyReply::new(Arc::clone(&message))
            .with_response_source("203.0.113.50".to_string(), 54321);

        reply.fix_nated_contact().unwrap();

        let locked = message.lock().unwrap();
        let contact = locked.headers.get("Contact").unwrap();
        assert!(contact.contains("203.0.113.50"), "Contact should contain NATed IP: {contact}");
        assert!(contact.contains("54321"), "Contact should contain NATed port: {contact}");
    }

    #[test]
    fn fix_nated_contact_without_source_returns_error() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message);

        assert!(reply.fix_nated_contact().is_err());
    }

    #[test]
    fn fix_nated_contact_no_contact_header_is_noop() {
        let message = Arc::new(Mutex::new(make_response(200, "OK")));
        let reply = PyReply::new(message)
            .with_response_source("10.0.0.1".to_string(), 5060);

        // Should not error even without Contact header
        reply.fix_nated_contact().unwrap();
    }

    // -----------------------------------------------------------------------
    // extract_uri_from_header tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_uri_with_angle_brackets_and_tag() {
        let uri = extract_uri_from_header("<sip:alice@example.com>;tag=abc").unwrap();
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.scheme, "sip");
    }

    #[test]
    fn extract_uri_with_display_name() {
        let uri = extract_uri_from_header("\"Alice\" <sip:alice@host.com:5060>").unwrap();
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host, "host.com");
        assert_eq!(uri.port, Some(5060));
    }

    #[test]
    fn extract_uri_without_angle_brackets() {
        let uri = extract_uri_from_header("sip:bob@proxy.example.com").unwrap();
        assert_eq!(uri.user.as_deref(), Some("bob"));
        assert_eq!(uri.host, "proxy.example.com");
    }

    #[test]
    fn extract_uri_no_user() {
        let uri = extract_uri_from_header("<sip:proxy.example.com>").unwrap();
        assert_eq!(uri.user, None);
        assert_eq!(uri.host, "proxy.example.com");
    }

    #[test]
    fn extract_sips_uri() {
        let uri = extract_uri_from_header("<sips:secure@tls.example.com>").unwrap();
        assert_eq!(uri.scheme, "sips");
        assert_eq!(uri.user.as_deref(), Some("secure"));
    }

    #[test]
    fn extract_uri_with_uri_params() {
        let uri = extract_uri_from_header("<sip:user@host;transport=tcp>;tag=xyz").unwrap();
        assert_eq!(uri.user.as_deref(), Some("user"));
        assert_eq!(uri.host, "host");
    }
}
