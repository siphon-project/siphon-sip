//! PyO3 `registrar` namespace — bridges Python `registrar.save(request)` to the
//! Rust [`Registrar`] backend.
//!
//! The Python-side `registrar` singleton is replaced at startup with this Rust
//! object so that calls like `registrar.lookup(uri)` execute in Rust, not Python.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::registrar::{Contact, Registrar, RegistrarError, normalize_aor, reginfo};
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::SipMessage;
use super::request::PyRequest;

/// Python-visible contact object returned from `registrar.lookup()`.
#[pyclass(name = "Contact", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyContact {
    /// The contact URI as a string.
    uri_string: String,
    /// Quality value (0.0–1.0).
    q_value: f32,
    /// Seconds remaining until this contact expires.
    expires_remaining: u64,
    /// Source address of the REGISTER (for NAT traversal routing).
    /// Format: "sip:ip:port;transport=proto" — like OpenSIPS received_avp.
    received_string: Option<String>,
    /// RFC 3327 Path headers stored with this binding.
    path_headers: Vec<String>,
    /// Stable identity of the siphon instance that originally accepted this
    /// REGISTER (typically StatefulSet pod name).  `None` for legacy
    /// bindings or when the deployment doesn't tag identity.
    instance_id_value: Option<String>,
    /// Boot-time epoch UUID of the process that accepted this REGISTER.
    /// Combined with `instance_id_value`, distinguishes "this pod, current
    /// process" from "this pod, previous process".  `None` for legacy.
    instance_epoch_value: Option<String>,
    /// True when the binding's `(instance_id, instance_epoch)` matches the
    /// running siphon process — i.e. this process accepted the REGISTER.
    is_local_value: bool,
}

#[pymethods]
impl PyContact {
    /// The contact URI as a string.
    #[getter]
    fn uri(&self) -> &str {
        &self.uri_string
    }

    /// Quality value (0.0–1.0).
    #[getter]
    fn q(&self) -> f32 {
        self.q_value
    }

    /// Seconds remaining until this contact expires.
    #[getter]
    fn expires(&self) -> u64 {
        self.expires_remaining
    }

    /// The received address (source IP:port of the REGISTER).
    ///
    /// Returns `None` if the contact was not saved with source address info.
    /// When present, this should be used for routing instead of `uri` — the
    /// Contact URI may contain a private/NAT address, while `received` has
    /// the actual reachable address (like OpenSIPS `received_avp`).
    #[getter]
    fn received(&self) -> Option<&str> {
        self.received_string.as_deref()
    }

    /// RFC 3327 Path headers stored with this contact binding.
    ///
    /// Returns the Path values from the REGISTER that created this binding.
    /// Use these as Route headers when routing terminating requests to this contact.
    #[getter]
    fn path(&self) -> Vec<String> {
        self.path_headers.clone()
    }

    /// Stable identity of the siphon instance that accepted this REGISTER.
    ///
    /// Typically the StatefulSet pod name (e.g. ``"siphon-0"``) when
    /// configured via ``server.instance_id`` in ``siphon.yaml``.  Returns
    /// ``None`` for bindings created before identity tagging was enabled or
    /// when the deployment does not configure it.
    #[getter]
    fn instance_id(&self) -> Option<&str> {
        self.instance_id_value.as_deref()
    }

    /// Boot-time epoch UUID of the process that accepted this REGISTER.
    ///
    /// Distinguishes successive runs of the same logical replica — pod
    /// ``siphon-0`` after a restart shares ``instance_id`` with its previous
    /// life but gets a fresh ``instance_epoch``.  Use ``is_local`` to test
    /// "did *this* process accept the binding".  Returns ``None`` for
    /// legacy entries.
    #[getter]
    fn instance_epoch(&self) -> Option<&str> {
        self.instance_epoch_value.as_deref()
    }

    /// True when this binding was accepted by the *current* siphon process.
    ///
    /// Useful for graceful-shutdown deregister, NAT keepalive ownership,
    /// and (later) RFC 5626 outbound flow tokens.  False for bindings
    /// restored from another instance, from a previous boot of this
    /// instance, or with no identity tag.
    #[getter]
    fn is_local(&self) -> bool {
        self.is_local_value
    }

    fn __str__(&self) -> &str {
        &self.uri_string
    }

    fn __repr__(&self) -> String {
        format!(
            "Contact(uri={}, q={}, expires={})",
            self.uri_string, self.q_value, self.expires_remaining
        )
    }
}

impl PyContact {
    pub fn from_rust_contact(contact: &Contact) -> Self {
        Self::from_rust_contact_with_registrar(contact, None)
    }

    /// Same as [`from_rust_contact`] but resolves `is_local` against the
    /// running registrar's instance identity when one is available.
    pub fn from_rust_contact_with_registrar(
        contact: &Contact,
        registrar: Option<&Registrar>,
    ) -> Self {
        let received_string = contact.source_addr.map(|addr| {
            // Build a SIP URI from source address + transport, matching the
            // format OpenSIPS uses for its received_avp / $param(received).
            let transport = contact.source_transport.as_deref().unwrap_or("udp");
            format!("sip:{}:{};transport={}", addr.ip(), addr.port(), transport)
        });
        let is_local_value = registrar
            .map(|registrar| registrar.is_local_contact(contact))
            .unwrap_or(false);
        Self {
            uri_string: contact.uri.to_string(),
            q_value: contact.q,
            expires_remaining: contact.remaining_seconds(),
            received_string,
            path_headers: contact.path.clone(),
            instance_id_value: contact.instance_id.clone(),
            instance_epoch_value: contact.instance_epoch.clone(),
            is_local_value,
        }
    }
}

/// Python-visible registrar namespace.
///
/// Scripts use: `from siphon import registrar` then `registrar.save(request)`.
#[pyclass(name = "RegistrarNamespace")]
pub struct PyRegistrar {
    inner: Arc<Registrar>,
}

impl PyRegistrar {
    pub fn new(registrar: Arc<Registrar>) -> Self {
        Self { inner: registrar }
    }

    /// Access the inner Registrar for event subscription.
    pub fn registrar(&self) -> &Arc<Registrar> {
        &self.inner
    }

    /// Rust-side lookup by string (for tests and internal use).
    pub fn lookup_str(&self, uri: &str) -> Vec<PyContact> {
        let aor = normalize_aor(uri);
        let inner = &self.inner;
        inner
            .lookup(&aor)
            .iter()
            .map(|c| PyContact::from_rust_contact_with_registrar(c, Some(inner)))
            .collect()
    }

    /// Rust-side is_registered by string (for tests and internal use).
    pub fn is_registered_str(&self, uri: &str) -> bool {
        let aor = normalize_aor(uri);
        self.inner.is_registered(&aor)
    }
}

#[pymethods]
impl PyRegistrar {
    /// Save contact bindings from a REGISTER and send 200 OK with granted
    /// Expires (like OpenSIPS `save("location")`).
    ///
    /// Stores the contacts under the AoR derived from the To header,
    /// sets the Expires header to the granted value (capped by
    /// `max_expires`), and sends a 200 OK reply.  The script should
    /// **not** call `request.reply()` after `save()`.
    ///
    /// `aliases` declares the IMS implicit registration set: every URI
    /// in the list becomes an alias of this AoR, so subsequent
    /// `registrar.lookup(alias)` calls resolve to the same contacts.
    /// Empty list (the default) is a no-op — call
    /// `registrar.set_associated_uris(aor, [])` to clear an existing set.
    #[pyo3(signature = (request, force=false, aliases=Vec::new()))]
    fn save(
        &self,
        request: &mut PyRequest,
        force: bool,
        aliases: Vec<String>,
    ) -> PyResult<bool> {
        let message = request.message();
        let mut message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // AoR from To header, normalized to strip transport params etc.
        let aor = normalize_aor(&extract_aor(&message)?);

        if force {
            self.inner.clear_bindings(&aor);
        }

        // Check for wildcard Contact: *
        if let Some(contact_raw) = message.headers.get("Contact") {
            if contact_raw.trim() == "*" {
                self.inner.remove_all(&aor);
                message.headers.set("Expires", "0".to_string());
                drop(message);
                request.set_reply(200, "OK".to_string());
                return Ok(true);
            }
        }

        // Extract source address for NAT traversal (like OpenSIPS received_avp).
        let source_addr = request.source_socket_addr();
        let source_transport = Some(request.transport_name().to_string());

        // Extract expires from Expires header or default
        let default_expires = message
            .headers
            .get("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(self.inner.config.default_expires);

        // Extract CSeq sequence number
        let cseq_seq = message
            .headers
            .cseq()
            .and_then(|raw| {
                crate::sip::headers::cseq::CSeq::parse(raw)
                    .ok()
                    .map(|cseq| cseq.sequence)
            })
            .unwrap_or(1);

        let call_id = message
            .headers
            .call_id()
            .cloned()
            .unwrap_or_default();

        // Extract Path headers (RFC 3327) — stored per-contact binding so
        // terminating requests can be routed through the proxy chain.
        let path: Vec<String> = message
            .headers
            .get_all("Path")
            .cloned()
            .unwrap_or_default();

        // Parse Contact headers
        let contact_values = message
            .headers
            .get_all("Contact")
            .cloned()
            .unwrap_or_default();

        // Track the granted expires (capped by max_expires) for the response.
        let mut granted_expires = 0u32;

        for raw in &contact_values {
            let nameaddrs = match NameAddr::parse_multi(raw) {
                Ok(addrs) => addrs,
                Err(_) => continue,
            };

            for nameaddr in nameaddrs {
                let expires = nameaddr
                    .expires
                    .unwrap_or(default_expires);
                let q = nameaddr.q.unwrap_or(1.0);

                // The registrar caps expires at max_expires internally.
                let capped = std::cmp::min(expires, self.inner.config.max_expires);
                granted_expires = std::cmp::max(granted_expires, capped);

                // Extract +sip.instance and reg-id from Contact header params
                // (RFC 5627 §3) for GRUU support and contact replacement.
                let sip_instance = nameaddr.other_params.iter()
                    .find(|(name, _)| name == "+sip.instance")
                    .and_then(|(_, value)| value.clone());
                let reg_id = nameaddr.other_params.iter()
                    .find(|(name, _)| name == "reg-id")
                    .and_then(|(_, value)| value.as_ref()?.parse::<u32>().ok());

                self.inner
                    .save_full(
                        &aor,
                        nameaddr.uri,
                        expires,
                        q,
                        call_id.clone(),
                        cseq_seq,
                        source_addr,
                        source_transport.clone(),
                        sip_instance,
                        reg_id,
                        path.clone(),
                    )
                    .map_err(|error| match error {
                        RegistrarError::IntervalTooBrief { min_expires } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "423 Interval Too Brief (min: {min_expires}s)"
                            ))
                        }
                        RegistrarError::TooManyContacts { max } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "too many contacts (max: {max})"
                            ))
                        }
                    })?;
            }
        }

        // Set the Expires header to the granted value so build_response()
        // copies it into the 200 OK (RFC 3261 §10.3 step 8).
        message.headers.set("Expires", granted_expires.to_string());
        drop(message);

        // Declare the implicit registration set (3GPP TS 23.228) — each
        // alias URI becomes resolvable to this AoR for subsequent
        // `registrar.lookup(alias)` calls.  Empty list is intentionally
        // a no-op: callers clear via `set_associated_uris(aor, [])`.
        if !aliases.is_empty() {
            self.inner.set_associated_uris(&aor, aliases);
        }

        // Send 200 OK — the dispatcher's build_response() will include
        // the Expires header we just set.
        request.set_reply(200, "OK".to_string());

        Ok(true)
    }

    /// Look up contacts for a URI string or SipUri.
    ///
    /// Returns a list of `Contact` objects sorted by q-value descending.
    /// Accepts either a string ("sip:alice@example.com") or a SipUri object.
    fn lookup(&self, uri: &Bound<'_, PyAny>) -> PyResult<Vec<PyContact>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        let inner = &self.inner;
        Ok(inner
            .lookup(&aor)
            .iter()
            .map(|c| PyContact::from_rust_contact_with_registrar(c, Some(inner)))
            .collect())
    }

    /// Force-expire (remove) all contacts for a URI.
    ///
    /// Used for explicit de-REGISTER handling (Expires: 0).
    /// Accepts either a string or a SipUri object.
    fn expire(&self, uri: &Bound<'_, PyAny>) -> PyResult<()> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        self.inner.remove_all(&aor);
        Ok(())
    }

    /// Remove all contacts for a URI (deregistration).
    ///
    /// Alias for `expire()` — used from RTR handlers and manual deregistration.
    /// Accepts either a string or a SipUri object.
    fn remove(&self, uri: &Bound<'_, PyAny>) -> PyResult<()> {
        self.expire(uri)
    }

    /// Check if a URI has any registered contacts.
    /// Accepts either a string or a SipUri object.
    fn is_registered(&self, uri: &Bound<'_, PyAny>) -> PyResult<bool> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.is_registered(&aor))
    }

    /// Number of currently registered AoRs across the deployment.
    ///
    /// Async — when a persistent backend (Redis, Postgres) is configured this
    /// queries the backend so the count is authoritative across all siphon
    /// instances sharing it.  Without a backend, returns the local in-memory
    /// count for this instance.  Backend errors are surfaced as Python
    /// exceptions; fall back with `try/except` if you prefer best-effort.
    fn aor_count<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let registrar = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            registrar.aor_count_distributed().await.map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "registrar backend aor_count failed: {error}"
                ))
            })
        })
    }

    /// Get stored Service-Route headers for a URI (RFC 3608).
    ///
    /// Returns a list of Route URI strings, or an empty list if none stored.
    fn service_route(&self, uri: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.service_routes(&aor))
    }

    /// Store Service-Route headers for an AoR (RFC 3608).
    ///
    /// Called after SAR success in the S-CSCF to record the routes that
    /// subsequent requests from this UE should traverse.
    ///
    /// Args:
    ///     aor: Address-of-record string (e.g. ``"sip:alice@ims.example.com"``).
    ///     routes: List of Route URI strings.
    fn set_service_routes(&self, aor: &str, routes: Vec<String>) -> PyResult<()> {
        self.inner.set_service_routes(aor, routes);
        Ok(())
    }

    /// Save a contact in pending state (IMS: awaiting SAR confirmation).
    ///
    /// The contact is stored but marked as pending until `confirm_pending()`
    /// is called after SAR success.
    #[pyo3(signature = (request))]
    fn save_pending(&self, request: &PyRequest) -> PyResult<()> {
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        let aor = extract_aor(&message)?;

        let default_expires = message
            .headers
            .get("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(self.inner.config.default_expires);

        let cseq_seq = message
            .headers
            .cseq()
            .and_then(|raw| {
                crate::sip::headers::cseq::CSeq::parse(raw)
                    .ok()
                    .map(|cseq| cseq.sequence)
            })
            .unwrap_or(1);

        let call_id = message
            .headers
            .call_id()
            .cloned()
            .unwrap_or_default();

        let contact_values = message
            .headers
            .get_all("Contact")
            .cloned()
            .unwrap_or_default();

        for raw in &contact_values {
            let nameaddrs = match NameAddr::parse_multi(raw) {
                Ok(addrs) => addrs,
                Err(_) => continue,
            };
            for nameaddr in nameaddrs {
                let expires = nameaddr.expires.unwrap_or(default_expires);
                let q = nameaddr.q.unwrap_or(1.0);
                self.inner.save_pending(
                    &aor,
                    nameaddr.uri,
                    expires,
                    q,
                    call_id.clone(),
                    cseq_seq,
                );
            }
        }
        Ok(())
    }

    /// Confirm pending contacts for a URI (IMS: SAR succeeded).
    ///
    /// Promotes all pending contacts to active state.
    fn confirm_pending(&self, uri: &Bound<'_, PyAny>) -> PyResult<()> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        self.inner.confirm_pending(&aor);
        Ok(())
    }

    /// Look up stored P-Asserted-Identity for a URI.
    ///
    /// Returns the identity string if one was stored via SAR user profile,
    /// or None if not available.
    fn asserted_identity(&self, uri: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.asserted_identity(&aor))
    }

    /// Store P-Associated-URI list for an AoR.
    ///
    /// Called from reply handlers to cache the public identities returned
    /// by the upstream S-CSCF in the 200 OK to REGISTER.
    fn set_associated_uris(&self, aor: &str, uris: Vec<String>) -> PyResult<()> {
        let aor = normalize_aor(aor);
        self.inner.set_associated_uris(&aor, uris);
        Ok(())
    }

    /// Retrieve stored P-Associated-URI list for a URI.
    ///
    /// Returns the list of public identities cached from the upstream
    /// 200 OK to REGISTER, or an empty list if none stored.
    fn associated_uris(&self, uri: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
        let uri_string = extract_uri_string(uri)?;
        let aor = normalize_aor(&uri_string);
        Ok(self.inner.associated_uris(&aor))
    }

    /// Decorator to register a handler for registration state changes.
    ///
    /// The handler receives (aor, event_type, contacts) where:
    ///   - aor: str — Address of Record (e.g. "sip:alice@example.com")
    ///   - event_type: str — "registered", "refreshed", "deregistered", or "expired"
    ///   - contacts: list[Contact] — current contact bindings
    #[staticmethod]
    fn on_change(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            ("registrar.on_change", python.None(), func.bind(python), is_async),
        )?;
        Ok(func)
    }

    /// Generate RFC 3680 reginfo XML for an AoR.
    ///
    /// Returns the XML document as a string. Used to build NOTIFY bodies
    /// for reg event subscriptions.
    ///
    /// Args:
    ///     aor: Address of Record (e.g. "sip:alice@example.com")
    ///     state: "full" or "partial" (default "full")
    ///     version: reginfo version counter (default 0)
    #[pyo3(signature = (aor, state="full", version=0))]
    fn reginfo_xml(&self, aor: &str, state: &str, version: u32) -> PyResult<String> {
        let aor = normalize_aor(aor);
        let contacts = self.inner.lookup(&aor);
        let reginfo_state = match state {
            "partial" => reginfo::ReginfoState::Partial,
            _ => reginfo::ReginfoState::Full,
        };
        let body = reginfo::build_full_reginfo(&aor, &contacts, version);
        // Override the state from the builder (which always uses Full)
        let body = reginfo::ReginfoBody {
            state: reginfo_state,
            ..body
        };
        Ok(body.to_xml())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the AoR (Address of Record) from the To header of a SIP message.
fn extract_aor(message: &SipMessage) -> PyResult<String> {
    let to_raw = message.headers.to().ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("missing To header in REGISTER")
    })?;

    let nameaddr = NameAddr::parse(to_raw).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid To header: {error}"))
    })?;

    Ok(nameaddr.uri.to_string())
}

/// Extract a URI string from a Python argument.
///
/// Accepts either a plain string or any object with `__str__()` (e.g. PySipUri).
fn extract_uri_string(uri: &Bound<'_, PyAny>) -> PyResult<String> {
    // Try extracting as &str first (most common case)
    if let Ok(s) = uri.extract::<String>() {
        return Ok(s);
    }
    // Fall back to calling str() / __str__()
    let string_repr = uri.str()?;
    Ok(string_repr.to_string())
}

// AoR canonicalization lives in `crate::registrar::normalize_aor` (imported
// at module scope) so the script-API boundary and the alias-index inside the
// registrar agree on the same keying.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::RegistrarConfig;
    use crate::script::api::request::RequestAction;
    use crate::sip::uri::SipUri;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use std::sync::Mutex;

    fn make_registrar() -> Arc<Registrar> {
        Arc::new(Registrar::new(RegistrarConfig {
            default_expires: 3600,
            max_expires: 7200,
            min_expires: 60,
            max_contacts: 10,
        }))
    }

    fn make_register_request(
        to: &str,
        contact: &str,
        registrar: &Arc<Registrar>,
    ) -> (PyRequest, PyRegistrar) {
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to(to.to_string())
            .from(format!("{to};tag=reg-tag"))
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", contact.to_string())
            .content_length(0)
            .build()
            .unwrap();

        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        let py_registrar = PyRegistrar::new(Arc::clone(registrar));
        (request, py_registrar)
    }

    #[test]
    fn save_and_lookup() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1:5060>", &registrar);

        py_reg.save(&mut request, false, vec![]).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("alice"));
        assert!(contacts[0].uri().contains("10.0.0.1"));
        assert_eq!(contacts[0].q(), 1.0);
        assert!(contacts[0].expires() > 3500);
    }

    #[test]
    fn is_registered_after_save() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:bob@example.com>", "<sip:bob@10.0.0.2>", &registrar);

        assert!(!py_reg.is_registered_str("sip:bob@example.com"));
        py_reg.save(&mut request, false, vec![]).unwrap();
        assert!(py_reg.is_registered_str("sip:bob@example.com"));
    }

    #[test]
    fn wildcard_deregister() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);

        py_reg.save(&mut request, false, vec![]).unwrap();
        assert!(py_reg.is_registered_str("sip:alice@example.com"));

        // Wildcard Contact: *
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dereg".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=dereg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("2 REGISTER".to_string())
            .header("Contact", "*".to_string())
            .header("Expires", "0".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let mut dereg_request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        py_reg.save(&mut dereg_request, false, vec![]).unwrap();
        assert!(!py_reg.is_registered_str("sip:alice@example.com"));
    }

    #[test]
    fn force_save_clears_existing() {
        let registrar = make_registrar();
        let (mut request1, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);
        py_reg.save(&mut request1, false, vec![]).unwrap();

        let (mut request2, _) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.2>", &registrar);
        py_reg.save(&mut request2, true, vec![]).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("10.0.0.2"));
    }

    #[test]
    fn lookup_returns_empty_for_unknown() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(registrar);
        assert!(py_reg.lookup_str("sip:nobody@example.com").is_empty());
    }

    /// Drive `Registrar::aor_count_distributed()` through the local-only path
    /// (no backend configured) — Python `aor_count()` ultimately calls this.
    #[tokio::test]
    async fn aor_count_distributed_local_path() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 0);

        let (mut alice, _) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg.save(&mut alice, false, vec![]).unwrap();

        let (mut bob, _) = make_register_request(
            "<sip:bob@example.com>",
            "<sip:bob@10.0.0.2>",
            &registrar,
        );
        py_reg.save(&mut bob, false, vec![]).unwrap();
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 2);

        // Refreshing alice does not change the AoR count.
        let (mut alice_refresh, _) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg.save(&mut alice_refresh, false, vec![]).unwrap();
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 2);

        registrar.remove_all("sip:alice@example.com");
        registrar.remove_all("sip:bob@example.com");
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 0);
    }

    #[test]
    fn normalize_aor_adds_sip_prefix() {
        assert_eq!(normalize_aor("sip:alice@example.com"), "sip:alice@example.com");
        assert_eq!(normalize_aor("sips:alice@example.com"), "sips:alice@example.com");
        assert_eq!(normalize_aor("alice@example.com"), "sip:alice@example.com");
    }

    #[test]
    fn normalize_aor_strips_default_port() {
        assert_eq!(normalize_aor("sip:bob@127.0.0.1:5060"), "sip:bob@127.0.0.1");
        assert_eq!(normalize_aor("sip:bob@127.0.0.1:5080"), "sip:bob@127.0.0.1:5080");
        assert_eq!(normalize_aor("sips:bob@host:5061"), "sips:bob@host");
        assert_eq!(normalize_aor("sips:bob@host:5060"), "sips:bob@host:5060");
    }

    #[test]
    fn normalize_aor_strips_uri_params() {
        assert_eq!(
            normalize_aor("sip:alice@example.com;transport=tcp"),
            "sip:alice@example.com"
        );
        assert_eq!(
            normalize_aor("sip:alice@example.com:5060;transport=tls"),
            "sip:alice@example.com"
        );
        assert_eq!(
            normalize_aor("sip:alice@example.com:5061;transport=tls"),
            "sip:alice@example.com:5061"
        );
        assert_eq!(
            normalize_aor("<sip:alice@example.com;transport=tcp>"),
            "sip:alice@example.com"
        );
    }

    #[test]
    fn lookup_ignores_transport_param() {
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1:5060>",
            &registrar,
        );
        py_reg.save(&mut request, false, vec![]).unwrap();

        // Lookup with transport param should still find the contact
        let contacts = py_reg.lookup_str("sip:alice@example.com;transport=tcp");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("alice"));
    }

    #[test]
    fn py_contact_display() {
        let contact = PyContact {
            uri_string: "sip:alice@10.0.0.1".to_string(),
            q_value: 1.0,
            expires_remaining: 3600,
            received_string: None,
            path_headers: vec![],
            instance_id_value: None,
            instance_epoch_value: None,
            is_local_value: false,
        };
        assert_eq!(contact.__str__(), "sip:alice@10.0.0.1");
        assert!(contact.__repr__().contains("q=1"));
    }

    #[test]
    fn contact_with_q_and_expires_params() {
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1>;q=0.7;expires=1800",
            &registrar,
        );

        py_reg.save(&mut request, false, vec![]).unwrap();
        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!((contacts[0].q() - 0.7).abs() < 0.01);
        // expires should be ~1800, not the default 3600
        assert!(contacts[0].expires() <= 1800);
        assert!(contacts[0].expires() > 1790);
    }

    #[test]
    fn expire_removes_all_contacts() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:carol@example.com>", "<sip:carol@10.0.0.3>", &registrar);

        py_reg.save(&mut request, false, vec![]).unwrap();
        assert!(py_reg.is_registered_str("sip:carol@example.com"));

        // expire() should remove all contacts
        registrar.remove_all("sip:carol@example.com");
        assert!(!py_reg.is_registered_str("sip:carol@example.com"));
        assert!(py_reg.lookup_str("sip:carol@example.com").is_empty());
    }

    #[test]
    fn save_caps_expires_and_sets_reply() {
        // Registrar with max_expires=600 — client requests 3600, should get 600.
        let registrar = Arc::new(Registrar::new(RegistrarConfig {
            default_expires: 3600,
            max_expires: 600,
            min_expires: 60,
            max_contacts: 10,
        }));

        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bK-reg".to_string())
            .to("<sip:trunk@carrier.com>".to_string())
            .from("<sip:trunk@carrier.com>;tag=reg-tag".to_string())
            .call_id("reg-trunk@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:trunk@10.0.0.1:5061;transport=tls>".to_string())
            .header("Expires", "3600".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let mut request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "tls".to_string(),
            "10.0.0.1".to_string(),
            5061,
        );
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        // save() should return true and set the reply action
        let result = py_reg.save(&mut request, false, vec![]).unwrap();
        assert!(result);

        // The reply action should be 200 OK
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 200,
                reason: "OK".to_string(),
                reliable: false,
            }
        );

        // The Expires header on the request should be capped to 600
        // (build_response copies it to the 200 OK)
        let message = request.message();
        let message = message.lock().unwrap();
        assert_eq!(
            message.headers.get("Expires").unwrap(),
            "600",
            "Expires should be capped to max_expires (600), not the requested 3600"
        );

        // The contact should be stored with the capped expires
        let contacts = py_reg.lookup_str("sip:trunk@carrier.com");
        assert_eq!(contacts.len(), 1);
        assert!(
            contacts[0].expires() <= 600,
            "stored contact expires should be capped at 600, got {}",
            contacts[0].expires()
        );
    }

    #[test]
    fn save_sends_reply_for_wildcard_deregister() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);

        py_reg.save(&mut request, false, vec![]).unwrap();
        assert!(py_reg.is_registered_str("sip:alice@example.com"));

        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dereg2".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=dereg2-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("3 REGISTER".to_string())
            .header("Contact", "*".to_string())
            .header("Expires", "0".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let mut dereg_request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );

        let result = py_reg.save(&mut dereg_request, false, vec![]).unwrap();
        assert!(result);

        // save() should have sent 200 OK for wildcard deregister
        assert_eq!(
            *dereg_request.action(),
            RequestAction::Reply {
                code: 200,
                reason: "OK".to_string(),
                reliable: false,
            }
        );

        // Expires should be 0 for deregistration
        let message = dereg_request.message();
        let message = message.lock().unwrap();
        assert_eq!(message.headers.get("Expires").unwrap(), "0");
    }

    /// `save(aliases=…)` declares the IMS implicit registration set: the
    /// contacts saved under the To-header AoR must be reachable via
    /// `lookup(alias)` for every URI in `aliases`.
    #[test]
    fn save_with_aliases_registers_implicit_set() {
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg
            .save(
                &mut request,
                false,
                vec!["tel:+15551234".to_string(), "sip:wildcard@ims.example.com".to_string()],
            )
            .unwrap();

        // The primary AoR is registered.
        assert!(py_reg.is_registered_str("sip:alice@ims.example.com"));
        // Both alias IMPUs resolve to the same contact.
        let by_tel = py_reg.lookup_str("tel:+15551234");
        assert_eq!(by_tel.len(), 1);
        assert!(by_tel[0].uri().contains("10.0.0.1"));

        let by_wildcard = py_reg.lookup_str("sip:wildcard@ims.example.com");
        assert_eq!(by_wildcard.len(), 1);
        assert!(by_wildcard[0].uri().contains("10.0.0.1"));

        // The AU list is queryable from any IMPU in the set — internal
        // callers pass already-normalized AoR keys, so the tel-URI
        // becomes "sip:tel:+15551234" via `normalize_aor`.
        assert_eq!(
            registrar.associated_uris("sip:tel:+15551234"),
            vec!["tel:+15551234".to_string(), "sip:wildcard@ims.example.com".to_string()],
        );
    }
}
