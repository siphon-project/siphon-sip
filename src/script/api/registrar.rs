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
use super::reply::PyReply;
use super::request::PyRequest;

/// Grace seconds added to the registrar's granted Expires when caching a
/// binding on a proxy. Sized to one SIP non-INVITE transaction timeout
/// (RFC 3261 Timer F = 64·T1 = 32 s) so a NOTIFY[reg-event;state=terminated]
/// emitted by the registrar of record at expiry has a full retransmission
/// window to land before the proxy's cached binding evaporates.
const PROXY_BINDING_GRACE_SECS: u32 = 32;

/// Python-visible contact object returned from `registrar.lookup()`.
/// Opaque view of an inbound flow captured at REGISTER time.  Carries the
/// transport, the UE's source address, the listener local address, and the
/// accepted-connection id — enough for `request.relay(flow=...)` to bypass
/// DNS resolution and write directly to the listener that received the
/// REGISTER.  Treat as opaque from Python: scripts pass it back to
/// `request.relay(flow=)` and read `is_alive` to defend against dead
/// stream connections.
#[pyclass(name = "Flow", from_py_object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyFlow {
    /// Lowercase transport name ("udp", "tcp", "tls", "ws", "wss").
    pub transport: String,
    /// UE's source address (where the REGISTER came from).
    pub source_addr: std::net::SocketAddr,
    /// Listener local address the REGISTER landed on.  Used by the
    /// outbound router (`OutboundRouter::send`) to egress from the same
    /// socket — load-bearing for IPSec where `pcscf_port_s` is non-default.
    pub local_addr: std::net::SocketAddr,
    /// `ConnectionId.0` of the accepted inbound connection.  For UDP this
    /// is the deterministic `(local_addr, remote_addr)` hash; for stream
    /// transports it identifies the live write half in `connection_map`.
    pub connection_id: u64,
}

#[pymethods]
impl PyFlow {
    /// Lowercase transport name ("udp", "tcp", "tls", "ws", "wss").
    #[getter]
    fn transport(&self) -> &str {
        &self.transport
    }

    /// String form of the captured remote (UE) address.
    #[getter]
    fn remote_addr(&self) -> String {
        self.source_addr.to_string()
    }

    /// String form of the captured listener local address.
    #[getter]
    fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    /// Whether the flow is still usable.
    ///
    /// For UDP this is always ``True``: the listener socket survives
    /// any individual exchange, and a stale `(local, remote)` tuple
    /// just means the next datagram will land on a UE that may or
    /// may not still be listening.
    ///
    /// For stream transports (TCP/TLS/WS/WSS) this is a real liveness
    /// check against the process-global stream-connection registry:
    /// ``True`` only while the *exact* accepted connection that
    /// delivered the REGISTER is still open on **this** process.  A UE
    /// that reconnected (new connection id) or whose socket closed
    /// reports ``False``.  When the registry isn't wired (unit tests /
    /// headless contexts) it stays conservatively ``True``.
    /// Cross-instance bindings should additionally be gated on
    /// :attr:`Contact.is_local` before ``request.relay(flow=...)``.
    #[getter]
    fn is_alive(&self) -> bool {
        if self.transport == "udp" {
            return true;
        }
        let transport = match self.transport.as_str() {
            "tcp" => crate::transport::Transport::Tcp,
            "tls" => crate::transport::Transport::Tls,
            "ws" => crate::transport::Transport::WebSocket,
            "wss" => crate::transport::Transport::WebSocketSecure,
            _ => return true, // unknown transport — stay conservative
        };
        match crate::script::api::stream_connections() {
            Some(registry) => registry.is_alive(
                self.source_addr,
                transport,
                crate::transport::ConnectionId(self.connection_id),
            ),
            // Registry not wired (unit tests / headless) — conservative,
            // matching the pre-registry behaviour.
            None => true,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Flow(transport={}, remote={}, local={})",
            self.transport, self.source_addr, self.local_addr
        )
    }
}

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
    /// Opaque proxy-side token attached at REGISTER time via
    /// `registrar.save(flow_token=...)`.  `None` when the script didn't
    /// request a token (or the binding pre-dates flow-token support).
    flow_token_value: Option<String>,
    /// Captured inbound flow as a `Flow` view, when `flow_token_value`
    /// is set.  `None` when this binding was loaded from a backend
    /// without a complete flow capture (e.g. an older entry without
    /// `inbound_local_addr`).  Pass to `request.relay(flow=...)` to
    /// send a request back over the same listener that received the
    /// REGISTER (RFC 3327 §5 / TS 24.229 §5.2.7.2 MT routing).
    flow_value: Option<PyFlow>,
    /// Contact-header parameters beyond `tag/q/expires/+sip.instance/reg-id`.
    /// Holds RFC 3840 feature tags etc., preserved from the originating
    /// REGISTER so reg-event NOTIFY bodies can surface them.
    params_value: Vec<(String, Option<String>)>,
    /// UE-side binding (default) vs application-server capability
    /// record captured from a 3PR 200 OK.
    kind_value: crate::registrar::ContactKind,
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

    /// Opaque proxy-side token attached at REGISTER time via
    /// `registrar.save(flow_token=...)`.  Returns `None` when the binding
    /// wasn't tagged with a token (or was loaded from a backend without
    /// the field).
    #[getter]
    fn flow_token(&self) -> Option<&str> {
        self.flow_token_value.as_deref()
    }

    /// Captured inbound flow (`Flow` view) — pass to
    /// `request.relay(flow=...)` to send a request back over the same
    /// listener that received the REGISTER.  Returns `None` when this
    /// binding lacks a captured flow (no `flow_token=` on save, or the
    /// `inbound_local_addr`/`inbound_connection_id` fields were absent
    /// in the persisted record).
    #[getter]
    fn flow(&self) -> Option<PyFlow> {
        self.flow_value.clone()
    }

    /// What kind of binding this is — ``"ue"`` (default) or ``"as"``.
    ///
    /// ``"as"`` contacts come from
    /// :meth:`PyRegistrar.save_as_contact` (typically called by the S-CSCF
    /// after a 3PR 200 OK).  They surface in :func:`registrar.reginfo_xml`
    /// for reg-event NOTIFY emission but are intentionally excluded from
    /// :meth:`PyRegistrar.lookup` so an MT INVITE never gets routed to an
    /// AS by mistake (TS 24.229 §5.4.2.1.2).
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind_value.as_str()
    }

    /// Contact-header parameters preserved from the originating REGISTER.
    ///
    /// Returns a list of ``(name, value)`` tuples — ``value`` is ``None``
    /// for flag parameters (e.g. ``+g.3gpp.smsip``) and a string for
    /// valued parameters (e.g.
    /// ``+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"``).
    ///
    /// The framework already breaks ``tag``, ``q``, ``expires``,
    /// ``+sip.instance``, and ``reg-id`` out into dedicated fields, so
    /// they are excluded from this list.  Everything else round-trips
    /// verbatim — RFC 3840 feature tags, RCS capability flags, vendor
    /// params — including case-insensitive parameter names (lowercased
    /// at parse time per RFC 3261 §19.1).
    #[getter]
    fn params(&self) -> Vec<(String, Option<String>)> {
        self.params_value.clone()
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

    /// `(uri, flow)` for flow-aware `request.fork()` / `call.fork()`.
    ///
    /// The captured flow is only surfaced when this binding was accepted by the
    /// **local** process (`is_local`); a binding restored from a shared backend
    /// on another instance carries a `connection_id` that is meaningless here,
    /// so it falls back to URI routing.  The URI is always the Contact URI.
    pub fn fork_target(&self) -> (String, Option<PyFlow>) {
        let flow = if self.is_local_value {
            self.flow_value.clone()
        } else {
            None
        };
        (self.uri_string.clone(), flow)
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
        // Reconstitute the `Flow` view from the stored tuple.  Requires
        // both source_addr (the UE) and inbound_local_addr (our listener)
        // to be present — otherwise the flow is incomplete and we can't
        // honor `relay(flow=...)`, so expose `None`.
        let flow_value = match (contact.source_addr, contact.inbound_local_addr) {
            (Some(source_addr), Some(local_addr)) => {
                let transport = contact
                    .source_transport
                    .as_deref()
                    .unwrap_or("udp")
                    .to_ascii_lowercase();
                let connection_id = match contact.inbound_connection_id {
                    Some(id) => id,
                    // For UDP, the connection_id is a deterministic hash of
                    // `(local_addr, remote_addr)` — recompute on demand if
                    // the stored binding lacks it (older record).  For
                    // stream transports, no captured id means no flow.
                    None if transport == "udp" => {
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let mut hasher = DefaultHasher::new();
                        local_addr.hash(&mut hasher);
                        source_addr.hash(&mut hasher);
                        hasher.finish()
                    }
                    None => return Self {
                        uri_string: contact.uri.to_string(),
                        q_value: contact.q,
                        expires_remaining: contact.remaining_seconds(),
                        received_string,
                        path_headers: contact.path.clone(),
                        instance_id_value: contact.instance_id.clone(),
                        instance_epoch_value: contact.instance_epoch.clone(),
                        is_local_value,
                        flow_token_value: contact.flow_token.clone(),
                        flow_value: None,
                        params_value: contact.params.clone(),
                        kind_value: contact.kind,
                    },
                };
                Some(PyFlow {
                    transport,
                    source_addr,
                    local_addr,
                    connection_id,
                })
            }
            _ => None,
        };
        Self {
            uri_string: contact.uri.to_string(),
            q_value: contact.q,
            expires_remaining: contact.remaining_seconds(),
            received_string,
            path_headers: contact.path.clone(),
            instance_id_value: contact.instance_id.clone(),
            instance_epoch_value: contact.instance_epoch.clone(),
            is_local_value,
            flow_token_value: contact.flow_token.clone(),
            flow_value,
            params_value: contact.params.clone(),
            kind_value: contact.kind,
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
    ///
    /// `flow_token` (optional) tags every contact saved by this call with
    /// an opaque proxy-side token plus the captured inbound flow
    /// (source address, listener local address, accepted-connection id).
    /// On a mobile-terminating request whose topmost Route was inserted
    /// by this proxy with the same token in its userpart, the script can
    /// `registrar.lookup_by_token(token)` to resolve back to this binding
    /// and `request.relay(flow=binding.flow)` to send the request over
    /// the captured flow without DNS-resolving the Contact URI
    /// (RFC 3327 §5 / TS 24.229 §5.2.7.2 — Path-token MT routing).
    #[pyo3(signature = (request, force=false, aliases=Vec::new(), flow_token=None))]
    fn save(
        &self,
        request: &mut PyRequest,
        force: bool,
        aliases: Vec<String>,
        flow_token: Option<String>,
    ) -> PyResult<bool> {
        let message = request.message();
        let mut message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // AoR from To header, normalized to strip transport params etc.
        let aor = normalize_aor(&extract_aor(&message)?);

        // F4: bind the registration to the authenticated identity. Without this,
        // a subscriber authenticated as user A can REGISTER a Contact under user
        // B's AoR (To header) — silently hijacking B's incoming calls, or
        // deregistering B (Contact:* / Expires:0). Checked BEFORE the force-clear
        // below so a spoofed AoR cannot first wipe the victim's bindings.
        // Opt-in (default off) so IMS deployments (public identity != private
        // auth identity, authorized via the implicit set) are unaffected.
        if self.inner.config.enforce_auth_aor_match {
            if let Some(auth_user) = request.get_auth_user() {
                let aor_user = crate::sip::parser::parse_uri_standalone(&aor)
                    .ok()
                    .and_then(|uri| uri.user);
                if aor_user.as_deref() != Some(auth_user) {
                    tracing::warn!(
                        auth_user = %auth_user,
                        aor = %aor.escape_debug(),
                        "rejecting REGISTER: AoR does not match authenticated user"
                    );
                    drop(message);
                    request.set_reply(403, "Forbidden".to_string());
                    return Ok(false);
                }
            }
        }

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

        // Capture the inbound flow for every binding this process accepts —
        // `inbound_local_addr` + `inbound_connection_id` together let
        // `Contact.flow` drive RFC 5626 §5.3 connection reuse on the MT side
        // (`request.relay(flow=...)` / `fork`), which is the *only* way to
        // reach a WebSocket UE (RFC 7118 §5).  Previously `inbound_local_addr`
        // was gated on `flow_token`, so a plain `registrar.save()` left
        // `Contact.flow == None` and WS MT routing silently failed.  Capturing
        // it unconditionally is additive: scripts that ignore `contact.flow`
        // are unaffected, and cross-instance staleness is guarded by
        // `Contact.is_local` (the relay path only uses a flow for bindings the
        // local process holds).  `inbound_connection_id` was already captured
        // always (RFC 5626 §4.2.2 flow-failure deregistration relies on it).
        let flow_capture = crate::registrar::FlowCapture {
            flow_token: flow_token.clone(),
            inbound_local_addr: request.inbound_local_addr(),
            inbound_connection_id: request.inbound_connection_id_u64(),
        };

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

                // Remaining Contact params (RFC 3840 feature tags etc.)
                // are stored verbatim on the binding so reg-event NOTIFY
                // bodies can surface them to watchers.  Skip the two we
                // already broke out into typed fields to avoid duplication.
                let extra_params: Vec<(String, Option<String>)> = nameaddr
                    .other_params
                    .iter()
                    .filter(|(name, _)| name != "+sip.instance" && name != "reg-id")
                    .cloned()
                    .collect();

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
                        flow_capture.clone(),
                        extra_params,
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
                        RegistrarError::InvalidAor => {
                            pyo3::exceptions::PyValueError::new_err(
                                "invalid AoR (unsafe storage key)".to_string(),
                            )
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

        // RFC 3261 §10.3 step 8: the 200 OK MUST enumerate all current bindings
        // as Contact headers, each with an `expires` parameter.  Strict UAs
        // (sip.js / JsSIP / browser WebRTC clients) drop a REGISTER 200 OK that
        // carries no Contact and the registration fails — the top-level Expires
        // header set above is not sufficient for them.
        for binding in self.inner.lookup(&aor) {
            let mut value = format!("<{}>;expires={}", binding.uri, binding.remaining_seconds());
            if (binding.q - 1.0).abs() > f32::EPSILON {
                value.push_str(&format!(";q={}", binding.q));
            }
            request.push_reply_header_add("Contact", value);
        }

        // Send 200 OK — build_response() includes the Expires header set above
        // and the Contact bindings queued here.
        request.set_reply(200, "OK".to_string());

        Ok(true)
    }

    /// Cache a binding on a proxy after the upstream registrar accepted it.
    ///
    /// Use this on a proxy (e.g. P-CSCF in IMS) that wants a local copy of
    /// a UE's binding for routing terminating requests, where the actual
    /// REGISTER was forwarded to a registrar of record (e.g. S-CSCF) and a
    /// 200 OK has just come back.
    ///
    /// Differs from [`save`](Self::save) in three ways:
    ///
    /// 1. The contact lifetime is read from the **reply's** `Expires` header
    ///    (the registrar's grant per RFC 3261 §10.3 step 8), not the
    ///    request's (the UE's ask). UEs commonly ask for 600000 s and the
    ///    registrar caps to a sensible value; mirroring the cap locally is
    ///    incorrect — the proxy must trust the upstream's decision.
    /// 2. The local `max_expires` cap is **not** applied. The registrar of
    ///    record has already capped, and a tighter local cap would expire
    ///    the proxy cache before the upstream binding, opening a window
    ///    where MT requests would 404 against an entry the registrar still
    ///    considers live.
    /// 3. No 200 OK is generated — the proxy will relay the upstream's
    ///    response itself.
    ///
    /// A grace of [`PROXY_BINDING_GRACE_SECS`] (32 s) is added on top so a
    /// `NOTIFY[reg-event;state=terminated]` from the registrar at expiry
    /// has a transaction-timer window to land before the proxy forgets.
    ///
    /// `aliases` declares the IMS implicit registration set the same way
    /// `save()` does — see that method's docs.
    ///
    /// `flow_token` (optional) tags every cached contact with an opaque
    /// proxy-side token plus the captured inbound flow — same semantics
    /// as `save(flow_token=...)`.  Use this from a P-CSCF script that
    /// proxies REGISTER to an upstream registrar of record (S-CSCF) and
    /// caches the granted bindings locally for Path-token MT routing.
    #[pyo3(signature = (request, reply, aliases=Vec::new(), flow_token=None))]
    fn save_proxy(
        &self,
        request: &PyRequest,
        reply: &PyReply,
        aliases: Vec<String>,
        flow_token: Option<String>,
    ) -> PyResult<bool> {
        let granted_expires = {
            let reply_msg = reply.message();
            let reply_msg = reply_msg.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            reply_msg
                .headers
                .get("Expires")
                .and_then(|value| value.trim().parse::<u32>().ok())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "save_proxy: reply has no parseable Expires header — \
                         the registrar of record must include the granted \
                         Expires per RFC 3261 §10.3 step 8",
                    )
                })?
        };

        // Wildcard de-REGISTER (`Contact: *` with `Expires: 0`) handled by
        // the upstream — clear our cache and we're done. No need to walk
        // contacts.
        let request_msg = request.message();
        let request_msg = request_msg.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let aor = normalize_aor(&extract_aor(&request_msg)?);

        if granted_expires == 0 {
            self.inner.remove_all(&aor);
            return Ok(true);
        }

        let source_addr = request.source_socket_addr();
        let source_transport = Some(request.transport_name().to_string());

        // Capture the inbound flow unconditionally (same rationale as `save()`):
        // `inbound_local_addr` + `inbound_connection_id` populate `Contact.flow`
        // so RFC 5626 §5.3 connection reuse works on the MT side without
        // requiring `flow_token`.  Additive and guarded by `Contact.is_local`.
        let flow_capture = crate::registrar::FlowCapture {
            flow_token: flow_token.clone(),
            inbound_local_addr: request.inbound_local_addr(),
            inbound_connection_id: request.inbound_connection_id_u64(),
        };

        let cseq_seq = request_msg
            .headers
            .cseq()
            .and_then(|raw| {
                crate::sip::headers::cseq::CSeq::parse(raw)
                    .ok()
                    .map(|cseq| cseq.sequence)
            })
            .unwrap_or(1);

        let call_id = request_msg
            .headers
            .call_id()
            .cloned()
            .unwrap_or_default();

        let path: Vec<String> = request_msg
            .headers
            .get_all("Path")
            .cloned()
            .unwrap_or_default();

        let contact_values = request_msg
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
                // Per-contact `expires=` param overrides only when *shorter*
                // than the registrar's grant. UEs sometimes carry a longer
                // value here than they put in the top-level Expires header;
                // the registrar's grant is the ceiling.
                let contact_expires = nameaddr
                    .expires
                    .map(|e| std::cmp::min(e, granted_expires))
                    .unwrap_or(granted_expires)
                    .saturating_add(PROXY_BINDING_GRACE_SECS);
                let q = nameaddr.q.unwrap_or(1.0);

                let sip_instance = nameaddr.other_params.iter()
                    .find(|(name, _)| name == "+sip.instance")
                    .and_then(|(_, value)| value.clone());
                let reg_id = nameaddr.other_params.iter()
                    .find(|(name, _)| name == "reg-id")
                    .and_then(|(_, value)| value.as_ref()?.parse::<u32>().ok());

                let extra_params: Vec<(String, Option<String>)> = nameaddr
                    .other_params
                    .iter()
                    .filter(|(name, _)| name != "+sip.instance" && name != "reg-id")
                    .cloned()
                    .collect();

                self.inner
                    .save_full_uncapped(
                        &aor,
                        nameaddr.uri,
                        contact_expires,
                        q,
                        call_id.clone(),
                        cseq_seq,
                        source_addr,
                        source_transport.clone(),
                        sip_instance,
                        reg_id,
                        path.clone(),
                        flow_capture.clone(),
                        extra_params,
                    )
                    .map_err(|error| match error {
                        RegistrarError::IntervalTooBrief { min_expires } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "registrar grant ({granted_expires}s) below local \
                                 min_expires ({min_expires}s) — registrar of record \
                                 misconfigured?"
                            ))
                        }
                        RegistrarError::TooManyContacts { max } => {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "too many contacts (max: {max})"
                            ))
                        }
                        RegistrarError::InvalidAor => {
                            pyo3::exceptions::PyValueError::new_err(
                                "invalid AoR (unsafe storage key)".to_string(),
                            )
                        }
                    })?;
            }
        }

        if !aliases.is_empty() {
            self.inner.set_associated_uris(&aor, aliases);
        }

        Ok(true)
    }

    /// Save AS-side capability contacts from a 3PR 200 OK
    /// (3GPP TS 24.229 §5.4.2.1.2).
    ///
    /// The S-CSCF runs iFC, fires a third-party REGISTER at each matched
    /// AS, receives a 200 OK whose `Contact:` header carries the AS's URI
    /// plus RFC 3840 feature tags (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`,
    /// …).  Calling this from `@proxy.on_reply` (or after a
    /// `proxy.send_request(..., wait_for_response=True)`) caches every
    /// such Contact alongside the UE's own bindings so the next
    /// reg-event NOTIFY surfaces them to watchers.
    ///
    /// AS contacts are stored with `kind=As`; they are **excluded** from
    /// `registrar.lookup()` and routing decisions — they only exist to
    /// be advertised in reg-event NOTIFY bodies.
    ///
    /// Args:
    ///     aor: IMPU the AS responded for (typically the To URI of the
    ///         3PR REGISTER, i.e. the user being registered).
    ///     reply: 200 OK from the AS.  Its `Contact:` headers are walked;
    ///         `+sip.instance` and `reg-id` are intentionally not broken
    ///         out (they have no GRUU semantic on the AS side).
    ///     expires_secs: lifetime to give the cached AS contact.  When
    ///         `None`, falls back to the reply's `Expires` header.
    ///         Required when the reply omits Expires (raises
    ///         ``ValueError`` in that case).
    ///
    /// Returns ``True`` if at least one Contact was stored; ``False`` if
    /// the reply had no Contact headers or if the AoR has no UE-side
    /// binding (the registrar refuses to store an AS capability record
    /// against an unregistered user — TS 24.229 §5.4.2.1.2 keeps AS
    /// records' lifetime tied to the registration).
    ///
    /// Example:
    ///
    /// ```python,ignore
    /// @proxy.on_reply
    /// def on_reply(request, reply):
    ///     if request.method == "REGISTER" and reply.status_code == 200:
    ///         impu = str(request.to_uri)
    ///         registrar.save_as_contact(impu, reply)
    ///     reply.relay()
    /// ```
    #[pyo3(signature = (aor, reply, expires_secs=None))]
    fn save_as_contact(
        &self,
        aor: &str,
        reply: &PyReply,
        expires_secs: Option<u32>,
    ) -> PyResult<bool> {
        let reply_msg = reply.message();
        let reply_msg = reply_msg.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // Lifetime: explicit kwarg wins; else fall back to reply Expires.
        let granted: u32 = match expires_secs {
            Some(value) => value,
            None => reply_msg
                .headers
                .get("Expires")
                .and_then(|value| value.trim().parse::<u32>().ok())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "save_as_contact: pass expires_secs= explicitly or \
                         include an Expires header on the AS's 200 OK",
                    )
                })?,
        };

        let contact_values = reply_msg
            .headers
            .get_all("Contact")
            .cloned()
            .unwrap_or_default();
        drop(reply_msg);

        let aor = normalize_aor(aor);

        let mut wrote = false;
        for raw in &contact_values {
            let nameaddrs = match NameAddr::parse_multi(raw) {
                Ok(addrs) => addrs,
                Err(_) => continue,
            };
            for nameaddr in nameaddrs {
                // Per-contact `expires=` shortens vs the explicit/derived
                // grant when set — same conservative rule as save_proxy.
                let contact_expires = nameaddr
                    .expires
                    .map(|e| std::cmp::min(e, granted))
                    .unwrap_or(granted);
                let q = nameaddr.q.unwrap_or(1.0);

                // Everything except tag/q/expires (already broken out by
                // NameAddr) is a capability/feature tag for our purposes.
                // We do NOT special-case `+sip.instance` or `reg-id` for
                // AS contacts — those are meaningful only on the UE side.
                let params: Vec<(String, Option<String>)> = nameaddr
                    .other_params.to_vec();

                let saved = self
                    .inner
                    .save_as_contact(&aor, nameaddr.uri, contact_expires, q, params)
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
                        RegistrarError::InvalidAor => {
                            pyo3::exceptions::PyValueError::new_err(
                                "invalid AoR (unsafe storage key)".to_string(),
                            )
                        }
                    })?;
                wrote = wrote || saved;
            }
        }
        Ok(wrote)
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

    /// Look up a binding by the opaque token previously attached via
    /// `registrar.save(flow_token=...)`.
    ///
    /// Returns the matching `Contact` (with `.flow` reconstituted from the
    /// stored capture) or `None` when the token is unknown, the binding
    /// has expired, or the underlying contact was removed.
    ///
    /// Used by P-CSCF MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2): the
    /// proxy advertised a Path URI of the form `<sip:TOKEN@pcscf;lr>`;
    /// on the MT request, after `loose_route()` has consumed that Route,
    /// `request.consumed_route_user` exposes the token and this method
    /// resolves it back to the binding so the script can call
    /// `request.relay(flow=binding.flow)`.
    fn lookup_by_token(&self, token: &str) -> Option<PyContact> {
        let inner = &self.inner;
        let (_aor, contact) = inner.lookup_by_token(token)?;
        Some(PyContact::from_rust_contact_with_registrar(&contact, Some(inner)))
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
        // Merged UE + AS view — without this the NOTIFY would drop every
        // iFC-matched AS feature tag (`+g.3gpp.smsip`,
        // `+g.3gpp.icsi-ref`, …) the S-CSCF captured on the 3PR 200 OK
        // (TS 24.229 §5.4.2.1.2).  `lookup_all` returns UE-first then AS,
        // each sorted by q descending.
        let contacts = self.inner.lookup_all(&aor);
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
            ..Default::default()
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

        py_reg.save(&mut request, false, vec![], None).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].uri().contains("alice"));
        assert!(contacts[0].uri().contains("10.0.0.1"));
        assert_eq!(contacts[0].q(), 1.0);
        assert!(contacts[0].expires() > 3500);
    }

    #[test]
    fn save_without_token_captures_connection_id_for_flow_failure() {
        // RFC 5626 §4.2.2: an ordinary stream registration (no flow_token)
        // must still record its inbound connection id so a connection close
        // can deregister it via Registrar::unregister_flow.
        let registrar = make_registrar();
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=reg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:alice@10.0.0.1:5060;transport=tcp>".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let mut request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "tcp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        request.set_inbound_flow("127.0.0.1:5060".parse().unwrap(), 4242);
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        // No flow_token passed — the residential/general registrar path.
        py_reg.save(&mut request, false, vec![], None).unwrap();
        assert!(registrar.is_registered("sip:alice@example.com"));

        // A flow failure on connection 4242 deregisters the binding.
        assert_eq!(registrar.unregister_flow(4242), 1);
        assert!(!registrar.is_registered("sip:alice@example.com"));
    }

    #[test]
    fn save_without_token_populates_contact_flow_for_stream() {
        // RFC 5626 §5.3 connection reuse: a plain `registrar.save()` (no
        // flow_token) must still expose `Contact.flow` so the MT side can
        // `relay(flow=...)` back over the captured connection.  Before the
        // unconditional-capture fix, `inbound_local_addr` was gated on
        // flow_token and `Contact.flow` came back `None`, silently breaking
        // WS/WSS MT routing.
        let registrar = make_registrar();
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/WSS 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to("<sip:bob@example.com>".to_string())
            .from("<sip:bob@example.com>;tag=reg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:bob@df7jal23ls0d.invalid;transport=wss>".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let mut request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "wss".to_string(),
            "10.0.0.1".to_string(),
            50000,
        );
        request.set_inbound_flow("127.0.0.1:443".parse().unwrap(), 4242);
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        // No flow_token — the plain residential/WebRTC path.
        py_reg.save(&mut request, false, vec![], None).unwrap();

        let contacts = py_reg.lookup_str("sip:bob@example.com");
        assert_eq!(contacts.len(), 1);
        let flow = contacts[0]
            .flow()
            .expect("Contact.flow must be populated without flow_token");
        assert_eq!(flow.transport, "wss");
        assert_eq!(flow.source_addr.to_string(), "10.0.0.1:50000");
        assert_eq!(flow.local_addr.to_string(), "127.0.0.1:443");
        assert_eq!(flow.connection_id, 4242);
        // No token was passed, so flow_token stays absent.
        assert_eq!(contacts[0].flow_token(), None);
    }

    #[test]
    fn save_enumerates_contact_in_register_ok() {
        // RFC 3261 §10.3 step 8: the REGISTER 200 OK must enumerate the bound
        // Contact(s) with an `expires` param.  Strict UAs (sip.js) drop a 200
        // with no Contact, so the registration silently fails without this.
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1:5060>",
            &registrar,
        );
        py_reg.save(&mut request, false, vec![], None).unwrap();

        let reply_headers = request.take_reply_headers();
        let contact = reply_headers
            .iter()
            .find(|(_, name, _)| name == "Contact")
            .map(|(_, _, value)| value)
            .expect("REGISTER 200 OK must carry a Contact binding (RFC 3261 §10.3 step 8)");
        assert!(contact.contains("alice@10.0.0.1"), "contact value: {contact}");
        assert!(contact.contains("expires="), "contact must carry an expires param: {contact}");
    }

    #[test]
    fn save_captures_feature_tags_into_params() {
        // The Python-side `registrar.save(request)` must extract RFC 3840
        // feature tags from the Contact header (everything beyond `tag`,
        // `q`, `expires`, `+sip.instance`, `reg-id`) into the stored
        // binding so reg-event NOTIFY emission can surface them later.
        // Models the 3PR 200 OK shape the IMS ASes (ip-sm-gw, mmtel-as,
        // ussd-as) emit, but applies equally to UE-side feature tags.
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1>;+g.3gpp.smsip;\
             +g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"",
            &registrar,
        );

        py_reg.save(&mut request, false, vec![], None).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@ims.example.com");
        assert_eq!(contacts.len(), 1);
        let params = contacts[0].params();
        // Param names are lowercased by NameAddr (RFC 3261 §19.1).
        // The flag tag survives as `(name, None)` and the valued tag
        // as `(name, Some(value))`.
        assert!(
            params.iter().any(|(n, v)| n == "+g.3gpp.smsip" && v.is_none()),
            "expected flag tag +g.3gpp.smsip; got params={params:?}"
        );
        assert!(
            params.iter().any(|(n, v)| n == "+g.3gpp.icsi-ref" && v.is_some()),
            "expected valued tag +g.3gpp.icsi-ref; got params={params:?}"
        );
    }

    fn make_as_reply(contact: &str, expires_secs: u32) -> PyReply {
        // Synthesize a 200 OK that mimics what an AS would emit in
        // response to the S-CSCF's 3PR REGISTER.
        let message = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .from("<sip:alice@ims.example.com>;tag=reg-tag".to_string())
            .to("<sip:alice@ims.example.com>;tag=as-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", contact.to_string())
            .header("Expires", expires_secs.to_string())
            .content_length(0)
            .build()
            .unwrap();
        PyReply::new(Arc::new(Mutex::new(message)))
    }

    #[test]
    fn save_as_contact_captures_feature_tags() {
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg.save(&mut request, false, vec![], None).unwrap();

        let reply = make_as_reply(
            "<sip:mmtel.ims.example.com:8060>;\
             +g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"",
            3600,
        );
        let saved = py_reg
            .save_as_contact("sip:alice@ims.example.com", &reply, None)
            .unwrap();
        assert!(saved);

        // Routing-side lookup() must still return UE only.
        let routes = py_reg.lookup_str("sip:alice@ims.example.com");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].kind(), "ue");

        // reginfo XML must surface the AS feature tag.
        let xml = py_reg.reginfo_xml("sip:alice@ims.example.com", "full", 0).unwrap();
        assert!(
            xml.contains("mmtel.ims.example.com:8060"),
            "AS contact URI missing from reginfo XML:\n{xml}"
        );
        assert!(
            xml.contains("<unknown-param name=\"+g.3gpp.icsi-ref\">"),
            "AS feature tag missing from reginfo XML:\n{xml}"
        );
    }

    #[test]
    fn save_as_contact_refuses_without_ue_binding() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(registrar);
        let reply = make_as_reply(
            "<sip:mmtel.ims.example.com:8060>;+g.3gpp.smsip",
            3600,
        );
        let saved = py_reg
            .save_as_contact("sip:alice@ims.example.com", &reply, None)
            .unwrap();
        assert!(!saved, "must refuse when no UE binding exists");
    }

    #[test]
    fn save_as_contact_falls_back_to_reply_expires() {
        // No explicit kwarg → fall back to the reply's Expires header.
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg.save(&mut request, false, vec![], None).unwrap();

        let reply = make_as_reply(
            "<sip:mmtel.ims.example.com:8060>;+g.3gpp.smsip",
            1800,
        );
        assert!(py_reg
            .save_as_contact("sip:alice@ims.example.com", &reply, None)
            .unwrap());

        // Find the AS contact and check its expiry was honored.
        let xml = py_reg.reginfo_xml("sip:alice@ims.example.com", "full", 0).unwrap();
        // The exact Expires value lands in the reginfo XML for the AS
        // contact (with the grace cap left to the registrar layer).
        // Looser check: presence + non-zero.
        assert!(xml.contains("expires=\""));
    }

    #[test]
    fn save_excludes_sip_instance_and_reg_id_from_params() {
        // `+sip.instance` and `reg-id` are already broken out into
        // dedicated Contact fields — the params list must not
        // duplicate them, or a NOTIFY emitter would emit them twice
        // (once as a typed `<gr>` / outbound element and once as an
        // `<unknown-param>`).
        let registrar = make_registrar();
        let (mut request, py_reg) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1>;+sip.instance=\"<urn:uuid:abc>\";\
             reg-id=1;+g.3gpp.smsip",
            &registrar,
        );

        py_reg.save(&mut request, false, vec![], None).unwrap();
        let contacts = py_reg.lookup_str("sip:alice@ims.example.com");
        assert_eq!(contacts.len(), 1);
        let params = contacts[0].params();
        assert!(params.iter().all(|(n, _)| n != "+sip.instance"));
        assert!(params.iter().all(|(n, _)| n != "reg-id"));
        // The non-special tag survives.
        assert!(params.iter().any(|(n, _)| n == "+g.3gpp.smsip"));
    }

    #[test]
    fn is_registered_after_save() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:bob@example.com>", "<sip:bob@10.0.0.2>", &registrar);

        assert!(!py_reg.is_registered_str("sip:bob@example.com"));
        py_reg.save(&mut request, false, vec![], None).unwrap();
        assert!(py_reg.is_registered_str("sip:bob@example.com"));
    }

    #[test]
    fn wildcard_deregister() {
        let registrar = make_registrar();
        let (mut request, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);

        py_reg.save(&mut request, false, vec![], None).unwrap();
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
        py_reg.save(&mut dereg_request, false, vec![], None).unwrap();
        assert!(!py_reg.is_registered_str("sip:alice@example.com"));
    }

    #[test]
    fn force_save_clears_existing() {
        let registrar = make_registrar();
        let (mut request1, py_reg) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.1>", &registrar);
        py_reg.save(&mut request1, false, vec![], None).unwrap();

        let (mut request2, _) =
            make_register_request("<sip:alice@example.com>", "<sip:alice@10.0.0.2>", &registrar);
        py_reg.save(&mut request2, true, vec![], None).unwrap();

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
        py_reg.save(&mut alice, false, vec![], None).unwrap();

        let (mut bob, _) = make_register_request(
            "<sip:bob@example.com>",
            "<sip:bob@10.0.0.2>",
            &registrar,
        );
        py_reg.save(&mut bob, false, vec![], None).unwrap();
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 2);

        // Refreshing alice does not change the AoR count.
        let (mut alice_refresh, _) = make_register_request(
            "<sip:alice@example.com>",
            "<sip:alice@10.0.0.1>",
            &registrar,
        );
        py_reg.save(&mut alice_refresh, false, vec![], None).unwrap();
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
        py_reg.save(&mut request, false, vec![], None).unwrap();

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
            flow_token_value: None,
            flow_value: None,
            params_value: vec![],
            kind_value: crate::registrar::ContactKind::Ue,
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

        py_reg.save(&mut request, false, vec![], None).unwrap();
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

        py_reg.save(&mut request, false, vec![], None).unwrap();
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
            ..Default::default()
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
        let result = py_reg.save(&mut request, false, vec![], None).unwrap();
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

        py_reg.save(&mut request, false, vec![], None).unwrap();
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

        let result = py_reg.save(&mut dereg_request, false, vec![], None).unwrap();
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
                None,
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

    /// Build a 200 OK reply with a given Expires header to feed `save_proxy`.
    fn make_reply_with_expires(expires: &str) -> PyReply {
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-rep".to_string())
            .to("<sip:alice@ims.example.com>".to_string())
            .from("<sip:alice@ims.example.com>;tag=reg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:alice@10.0.0.1:5060>".to_string())
            .header("Expires", expires.to_string())
            .content_length(0)
            .build()
            .unwrap();
        let _ = uri;
        PyReply::new(Arc::new(Mutex::new(message)))
    }

    /// `save_proxy` must use the **reply's** granted Expires (3600), not the
    /// request's UE-asked value (600000). Local `max_expires` (here 7200) is
    /// not applied either — only the upstream's grant + 32 s grace.
    #[test]
    fn save_proxy_uses_reply_expires_not_request() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        // UE asks for 600000 (7 days). This is what would be in the request.
        let uri = SipUri::new("ims.example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg".to_string())
            .to("<sip:alice@ims.example.com>".to_string())
            .from("<sip:alice@ims.example.com>;tag=reg-tag".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:alice@10.0.0.1:5060>".to_string())
            .header("Expires", "600000".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );

        // Upstream registrar capped to 3600.
        let reply = make_reply_with_expires("3600");

        py_reg.save_proxy(&request, &reply, vec![], None).unwrap();

        let contacts = py_reg.lookup_str("sip:alice@ims.example.com");
        assert_eq!(contacts.len(), 1);
        // 3600 grant + 32s grace = 3632; tolerate 1s drift from Instant::now.
        let exp = contacts[0].expires();
        assert!(
            (3625..=3632).contains(&exp),
            "expires {exp} should be ~3632 (grant 3600 + grace 32), \
             not request's 600000 nor capped to local max 7200"
        );
    }

    /// `save_proxy` with `Expires: 0` in the reply must clear the binding
    /// (de-REGISTER path).
    #[test]
    fn save_proxy_zero_expires_clears_binding() {
        let registrar = make_registrar();
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        // Pre-populate.
        let (mut req1, _) = make_register_request(
            "<sip:alice@ims.example.com>",
            "<sip:alice@10.0.0.1:5060>",
            &registrar,
        );
        py_reg.save(&mut req1, false, vec![], None).unwrap();
        assert!(py_reg.is_registered_str("sip:alice@ims.example.com"));

        // De-REGISTER via proxy save.
        let uri = SipUri::new("ims.example.com".to_string());
        let dereg = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-d".to_string())
            .to("<sip:alice@ims.example.com>".to_string())
            .from("<sip:alice@ims.example.com>;tag=d".to_string())
            .call_id("reg-call@host".to_string())
            .cseq("2 REGISTER".to_string())
            .header("Contact", "*".to_string())
            .header("Expires", "0".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let dereg_req = PyRequest::new(
            Arc::new(Mutex::new(dereg)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        let reply = make_reply_with_expires("0");

        py_reg.save_proxy(&dereg_req, &reply, vec![], None).unwrap();
        assert!(!py_reg.is_registered_str("sip:alice@ims.example.com"));
    }

    /// Local `max_expires` cap is **not** applied by `save_proxy`. Even if
    /// the local config is more conservative than the upstream's grant, the
    /// upstream wins (it's the registrar of record).
    #[test]
    fn save_proxy_ignores_local_max_expires_cap() {
        // Local cap: 600s. Upstream grants 3600s.
        let registrar = Arc::new(Registrar::new(RegistrarConfig {
            default_expires: 600,
            max_expires: 600,
            min_expires: 60,
            max_contacts: 10,
            ..Default::default()
        }));
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        let uri = SipUri::new("ims.example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK".to_string())
            .to("<sip:bob@ims.example.com>".to_string())
            .from("<sip:bob@ims.example.com>;tag=t".to_string())
            .call_id("c@h".to_string())
            .cseq("1 REGISTER".to_string())
            .header("Contact", "<sip:bob@10.0.0.2:5060>".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.2".to_string(),
            5060,
        );
        let reply = make_reply_with_expires("3600");

        py_reg.save_proxy(&request, &reply, vec![], None).unwrap();

        let contacts = py_reg.lookup_str("sip:bob@ims.example.com");
        let exp = contacts[0].expires();
        // Upstream's 3600 + 32s grace; local cap of 600 must NOT have
        // truncated this.
        assert!(
            exp > 3500,
            "expires {exp} should be ~3632, local max_expires cap of 600 \
             must not apply on save_proxy"
        );
    }

    #[test]
    fn save_enforces_auth_aor_match_when_configured() {
        let registrar = Arc::new(Registrar::new(RegistrarConfig {
            enforce_auth_aor_match: true,
            ..Default::default()
        }));
        let py_reg = PyRegistrar::new(Arc::clone(&registrar));

        let build_register = |to_user: &str| {
            let uri = SipUri::new("example.com".to_string());
            let message = SipMessageBuilder::new()
                .request(Method::Register, uri)
                .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK".to_string())
                .to(format!("<sip:{to_user}@example.com>"))
                .from(format!("<sip:{to_user}@example.com>;tag=t"))
                .call_id("c@h".to_string())
                .cseq("1 REGISTER".to_string())
                .header("Contact", "<sip:x@10.0.0.2:5060>".to_string())
                .content_length(0)
                .build()
                .unwrap();
            PyRequest::new(
                Arc::new(Mutex::new(message)),
                "udp".to_string(),
                "10.0.0.2".to_string(),
                5060,
            )
        };

        // Authenticated as "attacker" but REGISTER binds victim's AoR → rejected,
        // and the victim's keyspace is left empty (no binding, no force-clear).
        let mut spoof = build_register("victim");
        spoof.set_auth_user("attacker".to_string());
        assert!(matches!(py_reg.save(&mut spoof, true, vec![], None), Ok(false)));
        assert!(py_reg.lookup_str("sip:victim@example.com").is_empty());

        // Authenticated as "victim" binding own AoR → allowed.
        let mut legit = build_register("victim");
        legit.set_auth_user("victim".to_string());
        assert!(matches!(py_reg.save(&mut legit, true, vec![], None), Ok(true)));
        assert!(!py_reg.lookup_str("sip:victim@example.com").is_empty());
    }

    // -----------------------------------------------------------------------
    // Phase 2 — Path-token MT routing: Python surface
    // -----------------------------------------------------------------------

    #[test]
    fn pycontact_reconstitutes_flow_for_udp() {
        let contact = Contact {
            uri: SipUri::new("10.0.0.1".to_string()).with_user("alice".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".parse().unwrap()),
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: Some(0xc0ffee),
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        let py = PyContact::from_rust_contact(&contact);
        let flow = py.flow().expect("flow should be present");
        assert_eq!(flow.transport, "udp");
        assert_eq!(flow.source_addr.to_string(), "10.0.0.1:50000");
        assert_eq!(flow.local_addr.to_string(), "127.0.0.1:5066");
        assert_eq!(flow.connection_id, 0xc0ffee);
        assert_eq!(py.flow_token(), Some("tok"));
    }

    #[test]
    fn flow_is_alive_udp_true_and_stream_conservative_without_registry() {
        // UDP: always alive (listener socket survives; deterministic id).
        let udp = PyFlow {
            transport: "udp".into(),
            source_addr: "10.0.0.1:5060".parse().unwrap(),
            local_addr: "127.0.0.1:5060".parse().unwrap(),
            connection_id: 1,
        };
        assert!(udp.is_alive());
        // Stream transport with no process-global registry wired (the unit-test
        // context): stays conservatively alive, matching pre-registry behaviour.
        // The registry-backed liveness path is covered by
        // `transport::tests::stream_connections_is_alive_tracks_exact_triple`.
        let wss = PyFlow {
            transport: "wss".into(),
            source_addr: "10.0.0.1:50000".parse().unwrap(),
            local_addr: "127.0.0.1:443".parse().unwrap(),
            connection_id: 2,
        };
        assert!(wss.is_alive());
    }

    #[test]
    fn fork_target_surfaces_flow_only_for_local_binding() {
        // The safety guard: fork/relay route over a captured flow ONLY for a
        // binding this process holds (is_local).  A cross-instance binding
        // (is_local=false) falls back to URI routing — its connection_id is
        // meaningless on this process.
        let contact = Contact {
            uri: SipUri::new("df7jal23ls0d.invalid".to_string()).with_user("bob".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".parse().unwrap()),
            source_transport: Some("wss".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: Some("127.0.0.1:443".parse().unwrap()),
            inbound_connection_id: Some(0xc0ffee),
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        let mut py = PyContact::from_rust_contact(&contact);

        // Non-local → flow withheld, URI carried for DNS routing.
        py.is_local_value = false;
        let (uri, flow) = py.fork_target();
        assert!(flow.is_none(), "non-local binding must not surface its flow");
        assert!(uri.contains("bob@df7jal23ls0d.invalid"));

        // Local → flow surfaced for connection reuse.
        py.is_local_value = true;
        let (_, flow) = py.fork_target();
        let flow = flow.expect("local binding must surface its captured flow");
        assert_eq!(flow.transport, "wss");
        assert_eq!(flow.connection_id, 0xc0ffee);
    }

    #[test]
    fn pycontact_recomputes_udp_connection_id_when_missing() {
        // Stored binding may pre-date the inbound_connection_id field
        // (None) — for UDP, the connection_id is a deterministic hash
        // of (local, remote) so we can recover it on demand.
        let contact = Contact {
            uri: SipUri::new("10.0.0.1".to_string()).with_user("alice".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".parse().unwrap()),
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: None,
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        let py = PyContact::from_rust_contact(&contact);
        let flow = py.flow().expect("UDP flow should reconstitute");
        // Recomputed from (local, remote) — must be non-zero and stable.
        assert_ne!(flow.connection_id, 0);
        let py2 = PyContact::from_rust_contact(&contact);
        assert_eq!(flow.connection_id, py2.flow().unwrap().connection_id);
    }

    #[test]
    fn pycontact_omits_flow_for_stream_without_connection_id() {
        // For TCP/TLS/WS/WSS, no captured connection_id means we
        // can't reach the UE — surface flow=None so the script can
        // fall back instead of relay()ing into a void.
        let contact = Contact {
            uri: SipUri::new("10.0.0.1".to_string()).with_user("alice".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".parse().unwrap()),
            source_transport: Some("tcp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: None,
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        let py = PyContact::from_rust_contact(&contact);
        assert!(py.flow().is_none());
        // flow_token still surfaces — the binding *exists*, the
        // script just can't relay over the dead stream.
        assert_eq!(py.flow_token(), Some("tok"));
    }

    #[test]
    fn pycontact_omits_flow_when_no_local_addr() {
        let contact = Contact {
            uri: SipUri::new("10.0.0.1".to_string()).with_user("alice".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".parse().unwrap()),
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok".into()),
            inbound_local_addr: None,
            inbound_connection_id: Some(42),
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        let py = PyContact::from_rust_contact(&contact);
        assert!(py.flow().is_none());
    }

    #[test]
    fn pyflow_is_alive_returns_true() {
        // Conservative stub until cross-transport connection registry
        // lands.  Tests the contract — if this assertion changes,
        // the docstring on PyFlow.is_alive must change too.
        let flow = PyFlow {
            transport: "udp".into(),
            source_addr: "10.0.0.1:50000".parse().unwrap(),
            local_addr: "127.0.0.1:5066".parse().unwrap(),
            connection_id: 1,
        };
        assert!(flow.is_alive());
    }
}
