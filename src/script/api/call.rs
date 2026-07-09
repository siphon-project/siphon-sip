//! PyO3 wrapper for B2BUA calls — the `Call` object passed to Python scripts.
//!
//! Scripts interact with this object via `@b2bua.on_invite`, `@b2bua.on_answer`,
//! `@b2bua.on_failure`, and `@b2bua.on_bye` handlers.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;

use crate::sip::message::SipMessage;
use super::sip_uri::PySipUri;

/// Per-call session timer override set by Python scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimerOverride {
    pub session_expires: u32,
    pub min_se: u32,
    pub refresher: String,
}

/// The action the script chose for this call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallAction {
    /// No action taken yet.
    None,
    /// Reject the call with a status code and reason.
    Reject { code: u16, reason: String },
    /// Dial a single B-leg target.
    Dial {
        target: String,
        /// When set, used as the routing destination instead of `target`.
        /// `target` continues to drive the B-leg R-URI (so scripts can keep
        /// the IMPU shape on R-URI while routing through a fixed next-hop —
        /// IMS BGCF/I-CSCF, outbound proxy, edge-NAT bridge, etc.).
        next_hop: Option<String>,
        /// When set, the B-leg INVITE is sent over this captured inbound flow
        /// (RFC 5626 §5.3 connection reuse — the only way to reach a WebSocket
        /// callee, RFC 7118 §5) instead of DNS-resolving `target`/`next_hop`.
        flow: Option<super::registrar::PyFlow>,
        /// Route header set prepended to the B-leg INVITE (after the A-leg
        /// Route/Record-Route are stripped). Used to carry the captured IMS
        /// Service-Route on MO calls so they traverse the originating S-CSCF
        /// (RFC 3608). Each entry is a full route value, e.g. `<sip:scscf;lr>`.
        route: Vec<String>,
        timeout: u32,
    },
    /// Fork to multiple targets.
    ///
    /// `flows` is parallel to `targets`: a `Some` entry routes that branch over
    /// the captured inbound flow (connection reuse) instead of resolving the
    /// URI.  Only attached for a `Contact` the local process accepted
    /// (`Contact.is_local`).
    Fork {
        targets: Vec<String>,
        flows: Vec<Option<super::registrar::PyFlow>>,
        strategy: String,
        timeout: u32,
    },
    /// Terminate the call (BYE both legs).
    Terminate,
    /// Accept a REFER (call transfer).
    AcceptRefer,
    /// Reject a REFER with a status code.
    RejectRefer { code: u16, reason: String },
    /// UAS-mode answer — siphon sends the final response to the A-leg
    /// INVITE directly instead of bridging to a B-leg.  ``code`` must
    /// be 2xx.  ``body`` is an optional answer body (SDP for audio,
    /// could also be XML for future simservs-Ut responses).
    Answer {
        code: u16,
        reason: String,
        body: Option<Vec<u8>>,
        content_type: Option<String>,
    },
}

/// Which side initiated a BYE.
#[pyclass(name = "ByeInitiator", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyByeInitiator {
    /// "a" (caller) or "b" (callee).
    #[pyo3(get)]
    pub side: String,
}

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

/// Python-visible B2BUA call object.
#[pyclass(name = "Call")]
pub struct PyCall {
    /// Unique call identifier (UUID).
    id: String,
    /// The original A-leg INVITE message.
    message: Arc<Mutex<SipMessage>>,
    /// Source IP of the A-leg.
    source_ip: String,
    /// Transport the A-leg arrived on ("udp"/"tcp"/"tls"/"ws"/"wss"), for CDRs.
    transport_name: String,
    /// Current call state.
    state: String,
    /// The action chosen by the script.
    action: CallAction,
    /// Media anchoring handle.
    media_handle: PyMediaHandle,
    /// Per-call session timer override (set by Python script).
    session_timer_override: Option<SessionTimerOverride>,
    /// Refer-To URI (set when the handler is on_refer).
    refer_to_uri: Option<String>,
    /// Replaces info from Refer-To (for attended transfer).
    refer_replaces_info: Option<crate::sip::headers::refer::Replaces>,
    /// Credentials for B-leg digest auth retry (set by Python script).
    outbound_credentials: Option<(String, String)>,
    /// Whether li.record() was called for this call.
    li_record_flag: bool,
    /// When true, copy the A-leg Call-ID to B-leg instead of generating a new one.
    preserve_call_id_flag: bool,
    /// When set, pin the B-leg From URI host to this value instead of the
    /// B2BUA advertised address (opts out of From topology-hiding — needed
    /// for multitenant edges where the downstream selects the tenant from the
    /// From domain). Set via `set_from_host()`.
    from_host_override: Option<String>,
    /// When set, pin the B-leg To URI host to this value instead of the
    /// dial-target host. Set via `set_to_host()`.
    to_host_override: Option<String>,
    /// When set, inject this userpart into the B-leg Contact URI (keeping
    /// siphon's advertised host:port). Set via `set_contact_user()`.
    contact_user_override: Option<String>,
    /// When set, replace the whole B-leg Contact URI. Set via `set_contact_uri()`.
    contact_override: Option<String>,
    /// Per-call header policy input captured from `call.dial(header_policy=…, …)`
    /// or `call.fork(…)`.  The dispatcher resolves `policy_name` against
    /// the preset registry and applies deltas to produce a
    /// [`crate::b2bua::header_policy::ResolvedPolicy`] on the call actor.
    header_policy_input: Option<HeaderPolicyInput>,
}

/// Per-call header policy input from `call.dial(header_policy=…, copy=…, strip=…, translate=…)`.
/// Held on [`PyCall`] during the script handler; the dispatcher resolves
/// `policy_name` against the preset registry and stitches deltas into a
/// [`crate::b2bua::header_policy::ResolvedPolicy`] on the call actor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderPolicyInput {
    /// Qualified preset name (e.g. `"ims-trust-domain-boundary@2026"`).
    /// `None` → use `b2bua.default_header_policy`.
    pub policy_name: Option<String>,
    /// Headers to copy verbatim regardless of preset.
    pub deltas_copy: Vec<String>,
    /// Headers to strip regardless of preset.
    pub deltas_strip: Vec<String>,
    /// Per-call translates: `(header_name, op_name)` — the op name is
    /// resolved against the engine's [`TranslateOp`](crate::b2bua::header_policy::TranslateOp)
    /// catalogue.  Unknown ops are logged and dropped.
    pub deltas_translate: Vec<(String, String)>,
}

/// Replace the URI inside a From/To/Contact header value while preserving the
/// display-name and header params (tag/q/expires/…). Returns the parsed host of
/// the new URI so B2BUA callers can pin the matching `*_host_override` (the
/// B-leg builder rewrites the host otherwise). A no-op when the header is
/// absent; the parsed host is still returned so the override is set either way.
fn replace_header_uri(
    message: &mut SipMessage,
    primary: &str,
    alias: &str,
    new_uri: &str,
) -> PyResult<String> {
    let parsed = crate::sip::parser::parse_uri_standalone(new_uri).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid SIP URI: {error}"))
    })?;
    let host = parsed.host.clone();
    let raw = message
        .headers
        .get(primary)
        .or_else(|| message.headers.get(alias))
        .cloned();
    if let Some(raw) = raw {
        let mut nameaddr =
            crate::sip::headers::nameaddr::NameAddr::parse(&raw).map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "cannot parse {primary} header: {error}"
                ))
            })?;
        nameaddr.uri = parsed;
        message.headers.set(primary, nameaddr.to_string());
    }
    Ok(host)
}

impl PyCall {
    pub fn new(
        id: String,
        message: Arc<Mutex<SipMessage>>,
        source_ip: String,
        transport_name: String,
    ) -> Self {
        Self {
            id,
            message,
            source_ip,
            transport_name,
            state: "calling".to_string(),
            action: CallAction::None,
            media_handle: PyMediaHandle::default(),
            session_timer_override: None,
            refer_to_uri: None,
            refer_replaces_info: None,
            outbound_credentials: None,
            li_record_flag: false,
            preserve_call_id_flag: false,
            from_host_override: None,
            to_host_override: None,
            contact_user_override: None,
            contact_override: None,
            header_policy_input: None,
        }
    }

    /// Per-call header policy input (preset name + deltas) — read by the
    /// dispatcher after the script handler returns so the resolved policy
    /// can be attached to the [`crate::b2bua::actor::CallActor`].
    pub fn header_policy_input(&self) -> Option<&HeaderPolicyInput> {
        self.header_policy_input.as_ref()
    }

    /// Internal helper — called from `dial()` and `fork()` to record the
    /// header policy arguments.  Skipped entirely when no policy-related
    /// kwarg was supplied, so existing scripts pay zero cost.
    fn update_header_policy_input(
        &mut self,
        header_policy: Option<&str>,
        copy: Vec<String>,
        strip: Vec<String>,
        translate: Vec<(String, String)>,
    ) {
        if header_policy.is_none() && copy.is_empty() && strip.is_empty() && translate.is_empty() {
            return;
        }
        self.header_policy_input = Some(HeaderPolicyInput {
            policy_name: header_policy.map(String::from),
            deltas_copy: copy,
            deltas_strip: strip,
            deltas_translate: translate,
        });
    }

    /// Get the action the script chose.
    pub fn action(&self) -> &CallAction {
        &self.action
    }

    /// Get the media handle (for the B2BUA core to check after script runs).
    pub fn media_handle(&self) -> &PyMediaHandle {
        &self.media_handle
    }

    /// Get the underlying SIP message.
    pub fn message(&self) -> Arc<Mutex<SipMessage>> {
        Arc::clone(&self.message)
    }

    /// Update the call state (called by the B2BUA core).
    pub fn set_state(&mut self, state: &str) {
        self.state = state.to_string();
    }

    /// Get the per-call session timer override (if set by the script).
    pub fn session_timer_override(&self) -> Option<&SessionTimerOverride> {
        self.session_timer_override.as_ref()
    }

    /// Get outbound credentials for B-leg auth retry (username, password).
    pub fn outbound_credentials(&self) -> Option<(&str, &str)> {
        self.outbound_credentials
            .as_ref()
            .map(|(user, password)| (user.as_str(), password.as_str()))
    }

    /// Whether li.record() was called for this call.
    pub fn li_record(&self) -> bool {
        self.li_record_flag
    }

    /// Set the li_record flag (called by li.record(call)).
    pub fn set_li_record(&mut self) {
        self.li_record_flag = true;
    }

    // --- LI helper accessors (Rust-side, no PyResult) ---

    /// SIP method for LI (always INVITE for B2BUA calls).
    pub fn li_method(&self) -> String {
        "INVITE".to_string()
    }

    /// Call-ID for LI correlation.
    pub fn li_call_id(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        message.headers.call_id().cloned().unwrap_or_default()
    }

    /// From URI for LI target matching.
    pub fn li_from_uri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        message.headers.from()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
    }

    /// To URI for LI target matching.
    pub fn li_to_uri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        message.headers.to()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
    }

    /// Request-URI for LI target matching.
    pub fn li_ruri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match &message.start_line {
            crate::sip::message::StartLine::Request(request_line) => {
                Some(request_line.request_uri.to_string())
            }
            _ => None,
        }
    }

    /// Source IP for LI target matching.
    pub fn li_source_ip(&self) -> Option<std::net::IpAddr> {
        self.source_ip.parse().ok()
    }

    /// Source-membership predicate shared by the `from_gateway` pymethod and
    /// its unit tests. Kept infallible: an unparseable source IP, a missing
    /// manager, or an unknown group all resolve to `false`. The `manager`
    /// seam lets tests inject a `DispatcherManager` without touching the
    /// process singleton (a first-writer-wins `OnceLock`).
    #[allow(clippy::wrong_self_convention)]
    fn from_gateway_impl(
        &self,
        group_name: &str,
        manager: Option<&Arc<crate::gateway::DispatcherManager>>,
    ) -> bool {
        let Ok(source_ip) = self.source_ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        match manager {
            Some(manager) => manager.source_in_group(group_name, source_ip),
            None => false,
        }
    }

    // --- CDR helper accessors (Rust-side, no PyResult) ---
    //
    // Mirror the `cdr_*` accessors on `PyRequest` so `cdr.write(call)` from a
    // B2BUA handler produces the same record shape as `cdr.write(request)` from
    // a proxy handler.  The B2BUA `Call` is always driven by the A-leg INVITE,
    // so `cdr_method()` is INVITE and the URIs/Call-ID come off that INVITE.

    /// SIP method string for CDR (always INVITE for a B2BUA call).
    pub fn cdr_method(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_method, using poisoned guard");
                poisoned.into_inner()
            }
        };
        match &message.start_line {
            crate::sip::message::StartLine::Request(request_line) => {
                request_line.method.as_str().to_string()
            }
            _ => "INVITE".to_string(),
        }
    }

    /// Call-ID for CDR.
    pub fn cdr_call_id(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_call_id, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message.headers.call_id().cloned().unwrap_or_default()
    }

    /// From URI string for CDR.
    pub fn cdr_from_uri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_from_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message
            .headers
            .from()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
            .unwrap_or_default()
    }

    /// To URI string for CDR.
    pub fn cdr_to_uri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_to_uri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        message
            .headers
            .to()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
            .unwrap_or_default()
    }

    /// Request-URI string for CDR.
    pub fn cdr_ruri(&self) -> String {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("lock poisoned in cdr_ruri, using poisoned guard");
                poisoned.into_inner()
            }
        };
        match &message.start_line {
            crate::sip::message::StartLine::Request(request_line) => {
                request_line.request_uri.to_string()
            }
            _ => String::new(),
        }
    }

    /// Source IP for CDR.
    pub fn cdr_source_ip(&self) -> String {
        self.source_ip.clone()
    }

    /// Transport name for CDR (the A-leg's arrival transport).
    pub fn cdr_transport(&self) -> String {
        self.transport_name.clone()
    }

    /// Candidate Rf-session storage keys for the CDR auto-stamp lookup.
    ///
    /// Mirrors [`PyRequest::cdr_rf_dialog_key_candidates`](super::request::PyRequest)
    /// so a `cdr.write(call)` from a B2BUA handler is annotated with the same
    /// `rf_session_id` / `rf_result_code` the proxy path stamps.
    pub fn cdr_rf_dialog_key_candidates(&self) -> Vec<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "lock poisoned in cdr_rf_dialog_key_candidates, using poisoned guard"
                );
                poisoned.into_inner()
            }
        };
        let icid = message
            .headers
            .get("P-Charging-Vector")
            .and_then(|v| crate::sip::headers::charging::ChargingVector::parse(v).icid);
        let call_id = message.headers.call_id();
        let from_tag = message
            .headers
            .from()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .and_then(|na| na.tag);
        let to_tag = message
            .headers
            .to()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .and_then(|na| na.tag);

        crate::diameter::rf_service::rf_lookup_candidates(
            icid.as_deref(),
            call_id.map(|s| s.as_str()),
            from_tag.as_deref(),
            to_tag.as_deref(),
        )
    }

    /// Whether the script wants to preserve the A-leg Call-ID on the B-leg.
    pub fn preserve_call_id(&self) -> bool {
        self.preserve_call_id_flag
    }

    /// Script-pinned B-leg From host, if `set_from_host()` was called.
    /// Read by the dispatcher when building the B-leg INVITE — when `Some`,
    /// it replaces the advertised-address rewrite of the From URI host.
    pub fn from_host_override(&self) -> Option<&str> {
        self.from_host_override.as_deref()
    }

    /// Script-pinned B-leg To host, if `set_to_host()` was called.
    /// Read by the dispatcher when building the B-leg INVITE — when `Some`,
    /// it replaces the dial-target rewrite of the To URI host.
    pub fn to_host_override(&self) -> Option<&str> {
        self.to_host_override.as_deref()
    }

    /// Script-set B-leg Contact userpart, if `set_contact_user()` was called.
    /// Read by the dispatcher when building the B-leg Contact — injected into
    /// the URI while siphon's advertised host:port is preserved.
    pub fn contact_user_override(&self) -> Option<&str> {
        self.contact_user_override.as_deref()
    }

    /// Script-set B-leg Contact URI, if `set_contact_uri()` was called — a full
    /// override of siphon's advertised Contact. Takes precedence over
    /// `contact_user_override()`.
    pub fn contact_override(&self) -> Option<&str> {
        self.contact_override.as_deref()
    }

    /// Set the Refer-To information (called by B2BUA core before firing on_refer).
    pub fn set_refer_to(
        &mut self,
        uri: String,
        replaces: Option<crate::sip::headers::refer::Replaces>,
    ) {
        self.refer_to_uri = Some(uri);
        self.refer_replaces_info = replaces;
    }
}

#[pymethods]
impl PyCall {
    /// Unique call identifier.
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Call state: "calling", "ringing", "answered", "terminated".
    #[getter]
    fn state(&self) -> &str {
        &self.state
    }

    /// Source IP of the A-leg caller.
    #[getter]
    fn source_ip(&self) -> &str {
        &self.source_ip
    }

    /// True when the A-leg source IP is a member of the resolved addresses
    /// of the gateway group named `group_name`.
    ///
    /// The B2BUA equivalent of `request.from_gateway` — a routing-direction /
    /// trust predicate (siphon's answer to Kamailio `ds_is_from_list()` /
    /// OpenSIPS `ds_is_in_list()`) that replaces hardcoded source CIDRs.
    /// Matches on IP only (source port ignored) against every resolved A/AAAA
    /// candidate of every destination in the group.
    ///
    /// Infallible — returns `false` (never raises) when the group does not
    /// exist, no gateway is configured, or the source IP does not parse.
    ///
    /// Security: on connection-oriented transports (TCP/TLS/WS/WSS) the source
    /// IP is handshake-verified and trustworthy as an authorization signal; on
    /// UDP it is spoofable, so `from_gateway` there is a best-effort direction
    /// hint, not an auth gate.
    ///
    /// Example: `if call.from_gateway("teams"): call.dial(...)`
    #[allow(clippy::wrong_self_convention)]
    fn from_gateway(&self, group_name: &str) -> bool {
        self.from_gateway_impl(group_name, super::gateway_manager())
    }

    /// Media anchoring handle.
    ///
    /// Usage:
    ///   call.media.anchor()
    ///   call.media.anchor(engine="rtpengine", profile="wss_to_rtp")
    ///   call.media.release()
    #[getter]
    fn media(&mut self) -> PyMediaHandle {
        self.media_handle.clone()
    }

    /// Set media handle (called internally after Python modifies it).
    #[setter]
    fn set_media(&mut self, handle: &Bound<'_, PyMediaHandle>) {
        self.media_handle = handle.borrow().clone();
    }

    /// From URI of the A-leg.
    #[getter]
    #[allow(clippy::wrong_self_convention)]
    fn from_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let from_raw = message.headers.get("From")
            .or_else(|| message.headers.get("f"));
        match from_raw {
            Some(raw) => {
                match crate::sip::headers::nameaddr::NameAddr::parse(raw) {
                    Ok(nameaddr) => Ok(Some(PySipUri::new(nameaddr.uri))),
                    Err(_) => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// To URI of the A-leg.
    #[getter]
    fn to_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let to_raw = message.headers.get("To")
            .or_else(|| message.headers.get("t"));
        match to_raw {
            Some(raw) => {
                match crate::sip::headers::nameaddr::NameAddr::parse(raw) {
                    Ok(nameaddr) => Ok(Some(PySipUri::new(nameaddr.uri))),
                    Err(_) => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Request-URI of the A-leg INVITE.
    #[getter]
    fn ruri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        match &message.start_line {
            crate::sip::message::StartLine::Request(request_line) => {
                Ok(Some(PySipUri::new(request_line.request_uri.clone())))
            }
            _ => Ok(None),
        }
    }

    /// Call-ID header value.
    #[getter]
    fn call_id(&self) -> PyResult<Option<String>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.get("Call-ID")
            .or_else(|| message.headers.get("i"))
            .map(|v| v.to_string()))
    }

    /// Get a header value by name.
    fn get_header(&self, name: &str) -> PyResult<Option<String>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.get(name).map(|v| v.to_string()))
    }

    /// Alias for get_header.
    fn header(&self, name: &str) -> PyResult<Option<String>> {
        self.get_header(name)
    }

    /// Check if a header exists.
    fn has_header(&self, name: &str) -> PyResult<bool> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(message.headers.get(name).is_some())
    }

    /// Set a header value (for B-leg INVITE generation).
    fn set_header(&self, name: &str, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message.headers.set(name, value.to_string());
        Ok(())
    }

    /// Stash a charging-param the dispatcher's Rf B2BUA auto-emit hook
    /// will read when building the IMS-Information block for this call.
    ///
    /// Mirrors `request.set_charging_param` for B2BUA scripts that
    /// receive a `Call` object instead of a `Request`.  Recognised
    /// names map to TS 32.299 IMS-Information AVPs:
    ///
    /// - `"outgoing-trunk-group-id"` — `Outgoing-Trunk-Group-Id` (BGCF/MGCF)
    /// - `"incoming-trunk-group-id"` — `Incoming-Trunk-Group-Id`
    /// - `"application-server"`     — `Application-Server` inside `Application-Server-Information`
    /// - `"application-provided-called-party-address"`
    ///
    /// Typical BGCF (B2BUA) use:
    ///
    /// ```python,ignore
    /// @b2bua.on_invite
    /// async def on_invite(call):
    ///     gw = gateway.select("connect")
    ///     call.set_charging_param("outgoing-trunk-group-id", gw.attrs["group"])
    ///     call.dial(gw.uri)
    /// ```
    ///
    /// Keyed by the A-leg's `<Call-ID>\0<From-tag>` — the same dialog
    /// key `spawn_rf_b2bua_start` reads when the call answers.
    fn set_charging_param(&self, name: &str, value: &str) -> PyResult<()> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let call_id = message.headers.call_id().cloned();
        let from_tag = message
            .headers
            .from()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .and_then(|na| na.tag);
        drop(message);
        if let (Some(call_id), Some(from_tag)) = (call_id, from_tag) {
            let dialog_key = format!("{}\0{}", call_id, from_tag);
            crate::diameter::rf_service::set_rf_charging_param(
                &dialog_key,
                name.to_string(),
                value.to_string(),
            );
        }
        Ok(())
    }

    /// Remove a header.
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

    /// SDP body content, if present.
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

    /// Reject the call with a status code.
    fn reject(&mut self, code: u16, reason: &str) {
        self.action = CallAction::Reject {
            code,
            reason: reason.to_string(),
        };
    }

    /// UAS-mode answer — send a final 2xx response to the A-leg INVITE
    /// directly instead of bridging to a B-leg.  Useful for MRF /
    /// announcement servers that own the dialog themselves.
    ///
    /// Args:
    ///     code: Final response status (must be 2xx).
    ///     reason: Reason phrase (e.g. ``"OK"``).
    ///     body: Optional response body (``bytes`` or ``str``) — typically SDP.
    ///     content_type: Content-Type for the body (e.g. ``"application/sdp"``).
    #[pyo3(signature = (code, reason, body=None, content_type=None))]
    fn answer(
        &mut self,
        code: u16,
        reason: &str,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
    ) -> PyResult<()> {
        if !(200..300).contains(&code) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "call.answer() requires a 2xx status code; use call.reject() for failure responses (got {code})"
            )));
        }

        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };

        self.action = CallAction::Answer {
            code,
            reason: reason.to_string(),
            body: body_bytes,
            content_type: content_type.map(|s| s.to_string()),
        };
        Ok(())
    }

    /// Dial a single target (simple B-leg).
    ///
    /// `next_hop` (optional) decouples R-URI construction from routing:
    /// the new INVITE's R-URI is still built from `uri` (so the IMPU shape
    /// is preserved), but the message is sent to `next_hop`.  Mirrors the
    /// `next_hop` parameter on `proxy.send_request`.
    ///
    /// `header_policy` (optional) selects which versioned built-in preset
    /// the framework applies when building the B-leg INVITE and forwarding
    /// responses back to the A-leg.  Defaults to `b2bua.default_header_policy`
    /// from `siphon.yaml` (which itself defaults to `"transparent-b2bua@2026"` —
    /// behaviour-equivalent to siphon's pre-policy B2BUA).
    ///
    /// `copy` / `strip` / `translate` (optional) layer per-call deltas on
    /// top of the preset.  Use them for per-route exceptions (emergency calls,
    /// aggregator-specific headers, etc.) that the YAML preset can't express.
    /// `translate` entries are `(header_name, op_name)` tuples — `op_name` is
    /// looked up against the engine's `TranslateOp` catalogue (`"rfc7044"` /
    /// `"diversion-to-history-info"` in v1).
    ///
    /// Example:
    ///     call.dial(
    ///         "sip:5112@ims.mnc088.mcc204.3gppnetwork.org",
    ///         next_hop="sip:172.16.0.111:4060",
    ///         header_policy="ims-trust-domain-boundary@2026",
    ///         copy=["X-Operator-Tag"],
    ///         strip=["History-Info"],
    ///     )
    #[pyo3(signature = (uri, timeout=30, next_hop=None, flow=None, header_policy=None, copy=Vec::new(), strip=Vec::new(), translate=Vec::new(), route=Vec::new()))]
    fn dial(
        &mut self,
        uri: &str,
        timeout: u32,
        next_hop: Option<&str>,
        flow: Option<super::registrar::PyFlow>,
        header_policy: Option<&str>,
        copy: Vec<String>,
        strip: Vec<String>,
        translate: Vec<(String, String)>,
        route: Vec<String>,
    ) {
        self.action = CallAction::Dial {
            target: uri.to_string(),
            next_hop: next_hop.map(String::from),
            flow,
            route,
            timeout,
        };
        self.update_header_policy_input(header_policy, copy, strip, translate);
    }

    /// Fork to multiple targets.
    ///
    /// Each target is a bare URI string or a `Contact` (from
    /// `registrar.lookup()`).  A `Contact` the local process accepted
    /// (`Contact.is_local`) routes its branch over the captured inbound flow —
    /// connection reuse, mandatory for WebSocket callees (RFC 7118 §5 / RFC
    /// 5626 §5.3).  `header_policy` / `copy` / `strip` / `translate` apply to
    /// every branch — per-branch policy is a follow-up enhancement.
    #[pyo3(signature = (targets, strategy="parallel", timeout=30, header_policy=None, copy=Vec::new(), strip=Vec::new(), translate=Vec::new()))]
    fn fork(
        &mut self,
        targets: Vec<Bound<'_, PyAny>>,
        strategy: &str,
        timeout: u32,
        header_policy: Option<&str>,
        copy: Vec<String>,
        strip: Vec<String>,
        translate: Vec<(String, String)>,
    ) -> PyResult<()> {
        let mut target_uris: Vec<String> = Vec::with_capacity(targets.len());
        let mut flows: Vec<Option<super::registrar::PyFlow>> = Vec::with_capacity(targets.len());
        for item in targets {
            if let Ok(contact) = item.extract::<PyRef<super::registrar::PyContact>>() {
                let (uri, flow) = contact.fork_target();
                target_uris.push(uri);
                flows.push(flow);
            } else {
                target_uris.push(item.extract::<String>()?);
                flows.push(None);
            }
        }
        self.action = CallAction::Fork {
            targets: target_uris,
            flows,
            strategy: strategy.to_string(),
            timeout,
        };
        self.update_header_policy_input(header_policy, copy, strip, translate);
        Ok(())
    }

    /// Terminate the call (send BYE to both legs).
    fn terminate(&mut self) {
        self.action = CallAction::Terminate;
    }

    /// Set per-call session timer parameters (overrides global config).
    ///
    /// Usage in Python:
    ///   call.session_timer(expires=1800, min_se=90, refresher="b2bua")
    #[pyo3(signature = (expires=1800, min_se=90, refresher="b2bua"))]
    pub fn session_timer(&mut self, expires: u32, min_se: u32, refresher: &str) {
        self.session_timer_override = Some(SessionTimerOverride {
            session_expires: expires,
            min_se,
            refresher: refresher.to_string(),
        });
    }

    /// The Refer-To URI (only set during @b2bua.on_refer handler).
    #[getter]
    fn refer_to(&self) -> Option<&str> {
        self.refer_to_uri.as_deref()
    }

    /// Replaces info from the Refer-To header (for attended transfer).
    ///
    /// Returns a dict with keys: call_id, from_tag, to_tag, early_only.
    /// Returns None if this is an unattended (blind) transfer.
    #[getter]
    fn refer_replaces(&self, python: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.refer_replaces_info {
            Some(replaces) => {
                let dict = pyo3::types::PyDict::new(python);
                dict.set_item("call_id", &replaces.call_id)?;
                dict.set_item("from_tag", &replaces.from_tag)?;
                dict.set_item("to_tag", &replaces.to_tag)?;
                dict.set_item("early_only", replaces.early_only)?;
                Ok(Some(dict.into_any().unbind()))
            }
            None => Ok(None),
        }
    }

    /// Set outbound credentials for B-leg digest auth.
    ///
    /// When the B-leg returns 401/407, SIPhon will automatically retry
    /// the INVITE with these credentials instead of firing on_failure.
    ///
    /// Usage in Python:
    ///   call.set_credentials("alice", "secret123")
    fn set_credentials(&mut self, username: &str, password: &str) {
        self.outbound_credentials = Some((username.to_string(), password.to_string()));
    }

    /// Set the user part of the Request-URI.
    ///
    /// Usage in Python:
    ///   call.set_ruri_user("+33123456789")
    fn set_ruri_user(&self, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        if let crate::sip::message::StartLine::Request(ref mut request_line) = message.start_line {
            request_line.request_uri.user = Some(value.to_string());
        }
        Ok(())
    }

    /// Set the user part of the From header URI.
    ///
    /// Usage in Python:
    ///   call.set_from_user("+33123456789")
    fn set_from_user(&self, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let from_raw = message.headers.get("From")
            .or_else(|| message.headers.get("f"))
            .cloned();
        if let Some(raw) = from_raw {
            if let Ok(nameaddr) = crate::sip::headers::nameaddr::NameAddr::parse(&raw) {
                let mut uri = nameaddr.uri;
                uri.user = Some(value.to_string());
                let mut new_from = if let Some(ref display) = nameaddr.display_name {
                    format!("\"{display}\" <{uri}>")
                } else {
                    format!("<{uri}>")
                };
                if let Some(ref tag) = nameaddr.tag {
                    new_from.push_str(&format!(";tag={tag}"));
                }
                message.headers.set("From", new_from);
            }
        }
        Ok(())
    }

    /// Set the user part of the To header URI.
    ///
    /// Mirrors [`set_from_user`] / [`set_ruri_user`] for the To header.  Useful at
    /// IMS edges (BGCF inbound) where the B-leg R-URI gets rewritten from a
    /// public E.164 to a short-code IMPU and downstream nodes expect To to
    /// match (RFC 3261 §8.1.1.2 doesn't mandate it, but pickier IMS
    /// elements treat the asymmetry as malformed).
    ///
    /// Only the userpart changes; scheme/host/port/params and any existing
    /// To-tag are preserved.  Must be called before [`dial`] for the change
    /// to take effect on the B-leg INVITE — same model as [`set_from_user`].
    ///
    /// Usage in Python:
    ///   call.set_to_user("5112")
    ///   call.dial("sip:5112@ims.mnc088.mcc204.3gppnetwork.org")
    fn set_to_user(&self, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let to_raw = message.headers.get("To")
            .or_else(|| message.headers.get("t"))
            .cloned();
        if let Some(raw) = to_raw {
            if let Ok(nameaddr) = crate::sip::headers::nameaddr::NameAddr::parse(&raw) {
                let mut uri = nameaddr.uri;
                uri.user = Some(value.to_string());
                let mut new_to = if let Some(ref display) = nameaddr.display_name {
                    format!("\"{display}\" <{uri}>")
                } else {
                    format!("<{uri}>")
                };
                if let Some(ref tag) = nameaddr.tag {
                    new_to.push_str(&format!(";tag={tag}"));
                }
                message.headers.set("To", new_to);
            }
        }
        Ok(())
    }

    /// Pin the host part of the B-leg From header URI.
    ///
    /// By default the B2BUA rewrites the From URI host to its own advertised
    /// address (topology hiding — masking the A-leg identity).  At a
    /// multitenant edge the downstream selects the tenant from the From
    /// domain: a domainless call lands in an unauthenticated/default routing
    /// context, so the tenant domain must survive.  `set_from_host()` opts
    /// this leg out of the From host-rewrite and pins the host to `value`.
    ///
    /// Only the host changes; scheme/user/port/params and the From-tag are
    /// preserved.  `value` is a bare host (no port) — the existing port is
    /// kept.  Must be called before [`dial`] to take effect on the B-leg
    /// INVITE — same model as [`set_from_user`].
    ///
    /// Usage in Python:
    ///   call.set_from_host("tenant.example.com")
    ///   call.dial(str(call.ruri), next_hop="sip:pbx.example.com:5060")
    fn set_from_host(&mut self, value: &str) -> PyResult<()> {
        {
            let mut message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            let from_raw = message.headers.get("From")
                .or_else(|| message.headers.get("f"))
                .cloned();
            if let Some(raw) = from_raw {
                if let Ok(nameaddr) = crate::sip::headers::nameaddr::NameAddr::parse(&raw) {
                    let mut uri = nameaddr.uri;
                    uri.host = value.to_string();
                    let mut new_from = if let Some(ref display) = nameaddr.display_name {
                        format!("\"{display}\" <{uri}>")
                    } else {
                        format!("<{uri}>")
                    };
                    if let Some(ref tag) = nameaddr.tag {
                        new_from.push_str(&format!(";tag={tag}"));
                    }
                    message.headers.set("From", new_from);
                }
            }
        }
        self.from_host_override = Some(value.to_string());
        Ok(())
    }

    /// Pin the host part of the B-leg To header URI.
    ///
    /// By default the B2BUA rewrites the To URI host to the dial-target host.
    /// `set_to_host()` pins it to `value` instead, so the To domain does what
    /// the script says regardless of the routing next-hop (declarative
    /// replacement for the raw `set_header("To", "<sip:user@host>")` idiom).
    ///
    /// Only the host changes; scheme/user/port/params and any To-tag are
    /// preserved.  `value` is a bare host (no port).  Must be called before
    /// [`dial`] — same model as [`set_to_user`].
    ///
    /// Usage in Python:
    ///   call.set_to_user(callee)
    ///   call.set_to_host(TRUNK_DOMAIN)
    fn set_to_host(&mut self, value: &str) -> PyResult<()> {
        {
            let mut message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            let to_raw = message.headers.get("To")
                .or_else(|| message.headers.get("t"))
                .cloned();
            if let Some(raw) = to_raw {
                if let Ok(nameaddr) = crate::sip::headers::nameaddr::NameAddr::parse(&raw) {
                    let mut uri = nameaddr.uri;
                    uri.host = value.to_string();
                    let mut new_to = if let Some(ref display) = nameaddr.display_name {
                        format!("\"{display}\" <{uri}>")
                    } else {
                        format!("<{uri}>")
                    };
                    if let Some(ref tag) = nameaddr.tag {
                        new_to.push_str(&format!(";tag={tag}"));
                    }
                    message.headers.set("To", new_to);
                }
            }
        }
        self.to_host_override = Some(value.to_string());
        Ok(())
    }

    /// Replace the entire From header URI on the B-leg INVITE — scheme, user,
    /// host, port and URI params — in one call, preserving the display name and
    /// From-tag.
    ///
    /// The whole-URI form of [`set_from_user`]/[`set_from_host`]. The host is
    /// also pinned (the B-leg builder would otherwise rewrite it to the
    /// advertised address for topology hiding — same opt-out as
    /// [`set_from_host`]). Must be called before [`dial`].
    ///
    /// Usage in Python:
    ///   call.set_from_uri("sip:+31123@tenant.example.com:5060;transport=tcp")
    fn set_from_uri(&mut self, uri: &str) -> PyResult<()> {
        let host = {
            let mut message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            replace_header_uri(&mut message, "From", "f", uri)?
        };
        self.from_host_override = Some(host);
        Ok(())
    }

    /// Replace the entire To header URI on the B-leg INVITE — scheme, user,
    /// host, port and URI params — preserving the display name and any To-tag.
    ///
    /// The whole-URI form of [`set_to_user`]/[`set_to_host`]. The host is also
    /// pinned (the B-leg builder would otherwise rewrite it to the dial-target
    /// host — same opt-out as [`set_to_host`]). Must be called before [`dial`].
    ///
    /// Usage in Python:
    ///   call.set_to_uri("sip:5112@ims.mnc088.mcc204.3gppnetwork.org")
    fn set_to_uri(&mut self, uri: &str) -> PyResult<()> {
        let host = {
            let mut message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            replace_header_uri(&mut message, "To", "t", uri)?
        };
        self.to_host_override = Some(host);
        Ok(())
    }

    /// Inject a userpart into the B-leg Contact URI, keeping siphon's advertised
    /// host:port (and transport).
    ///
    /// The B2BUA advertises its own address as the Contact so in-dialog requests
    /// (BYE, re-INVITE) route back through siphon. By default that Contact is
    /// userless — `set_contact_user()` adds a userpart while leaving the
    /// host:port untouched, so in-dialog routing still works and the userpart
    /// rides along (e.g. a downstream that keys a tenant/extension off the
    /// Contact userpart, the way it does for a REGISTER Contact).
    ///
    /// Pass an empty string to force a userless Contact even when transparent
    /// carry-through would otherwise apply. Must be called before [`dial`].
    ///
    /// Usage in Python:
    ///   call.set_contact_user(extension)
    fn set_contact_user(&mut self, user: &str) -> PyResult<()> {
        self.contact_user_override = Some(user.to_string());
        Ok(())
    }

    /// Replace the entire B-leg Contact URI — a full override of siphon's
    /// advertised Contact.
    ///
    /// Power tool for edge deployments that front siphon (GRUU, edge SBC).
    /// Overriding the host/port moves the in-dialog anchor off siphon, so the
    /// deployment must route the far side's in-dialog requests back to siphon or
    /// the dialog breaks. Takes precedence over [`set_contact_user`]. `uri` is a
    /// bare URI (no angle brackets). Must be called before [`dial`].
    ///
    /// Usage in Python:
    ///   call.set_contact_uri("sip:gruu-token@edge.example.com:5060")
    fn set_contact_uri(&mut self, uri: &str) -> PyResult<()> {
        crate::sip::parser::parse_uri_standalone(uri).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid SIP URI: {error}"))
        })?;
        self.contact_override = Some(uri.to_string());
        Ok(())
    }

    /// Copy the A-leg Call-ID to the B-leg instead of generating a new one.
    ///
    /// By default the B2BUA generates a fresh Call-ID for each B-leg to fully
    /// decouple the two SIP dialogs. Call this method if you need the trunk to
    /// see the same Call-ID as the originating side.
    ///
    /// Note: From-tag is always regenerated regardless — it must be unique per leg.
    ///
    /// Usage in Python:
    ///   call.keep_call_id()
    fn keep_call_id(&mut self) {
        self.preserve_call_id_flag = true;
    }

    /// Accept the REFER and proceed with the transfer.
    fn accept_refer(&mut self) {
        self.action = CallAction::AcceptRefer;
    }

    /// Reject the REFER with a status code and reason.
    fn reject_refer(&mut self, code: u16, reason: &str) {
        self.action = CallAction::RejectRefer {
            code,
            reason: reason.to_string(),
        };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn make_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("call-test-1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn call_initial_state() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.id, "test-id");
        assert_eq!(call.state, "calling");
        assert_eq!(call.action(), &CallAction::None);
    }

    #[test]
    fn call_reject() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.reject(404, "Not Found");
        assert_eq!(
            call.action(),
            &CallAction::Reject {
                code: 404,
                reason: "Not Found".to_string()
            }
        );
    }

    #[test]
    fn call_dial() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.dial("sip:bob@10.0.0.2:5060", 30, None, None, None, vec![], vec![], vec![], vec![]);
        assert_eq!(
            call.action(),
            &CallAction::Dial {
                target: "sip:bob@10.0.0.2:5060".to_string(),
                next_hop: None,
                flow: None,
                route: vec![],
                timeout: 30,
            }
        );
        // No policy kwargs → no input captured (existing scripts pay zero cost)
        assert!(call.header_policy_input().is_none());
    }

    #[test]
    fn call_dial_with_route() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.dial(
            "sip:5112@ims.mnc01.mcc001.3gppnetwork.org",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec!["<sip:scscf.ims.mnc01.mcc001.3gppnetwork.org:6060;lr>".to_string()],
        );
        match call.action() {
            CallAction::Dial { route, .. } => {
                assert_eq!(route, &vec!["<sip:scscf.ims.mnc01.mcc001.3gppnetwork.org:6060;lr>".to_string()]);
            }
            other => panic!("expected Dial, got {other:?}"),
        }
    }

    #[test]
    fn call_dial_next_hop() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.dial(
            "sip:5112@ims.mnc088.mcc204.3gppnetwork.org",
            30,
            Some("sip:172.16.0.111:4060"),
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            call.action(),
            &CallAction::Dial {
                target: "sip:5112@ims.mnc088.mcc204.3gppnetwork.org".to_string(),
                next_hop: Some("sip:172.16.0.111:4060".to_string()),
                flow: None,
                route: vec![],
                timeout: 30,
            }
        );
    }

    #[test]
    fn call_dial_with_header_policy_and_deltas() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.dial(
            "sip:bob@10.0.0.2:5060",
            30,
            None,
            None,
            Some("ims-trust-domain-boundary@2026"),
            vec!["X-Operator-Tag".to_string()],
            vec!["History-Info".to_string()],
            vec![("Diversion".to_string(), "rfc7044".to_string())],
            vec![],
        );
        let input = call.header_policy_input().expect("policy input must be captured");
        assert_eq!(input.policy_name.as_deref(), Some("ims-trust-domain-boundary@2026"));
        assert_eq!(input.deltas_copy, vec!["X-Operator-Tag".to_string()]);
        assert_eq!(input.deltas_strip, vec!["History-Info".to_string()]);
        assert_eq!(
            input.deltas_translate,
            vec![("Diversion".to_string(), "rfc7044".to_string())]
        );
    }

    #[test]
    fn call_fork() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
            let targets: Vec<Bound<'_, PyAny>> = vec![
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.2").into_any(),
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.3").into_any(),
            ];
            call.fork(targets, "parallel", 30, None, vec![], vec![], vec![]).unwrap();
            assert_eq!(
                call.action(),
                &CallAction::Fork {
                    targets: vec!["sip:bob@10.0.0.2".to_string(), "sip:bob@10.0.0.3".to_string()],
                    flows: vec![None, None],
                    strategy: "parallel".to_string(),
                    timeout: 30,
                }
            );
        });
    }

    #[test]
    fn call_fork_with_header_policy() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
            let targets: Vec<Bound<'_, PyAny>> = vec![
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.2").into_any(),
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.3").into_any(),
            ];
            call.fork(targets, "parallel", 30, Some("sip-trunk-edge@2026"), vec![], vec!["X-Internal-Tag".to_string()], vec![]).unwrap();
            let input = call.header_policy_input().expect("policy input must be captured");
            assert_eq!(input.policy_name.as_deref(), Some("sip-trunk-edge@2026"));
            assert_eq!(input.deltas_strip, vec!["X-Internal-Tag".to_string()]);
        });
    }

    #[test]
    fn call_terminate() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.terminate();
        assert_eq!(call.action(), &CallAction::Terminate);
    }

    #[test]
    fn call_state_transition() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.state, "calling");
        call.set_state("ringing");
        assert_eq!(call.state, "ringing");
        call.set_state("answered");
        assert_eq!(call.state, "answered");
    }

    #[test]
    fn call_header_access() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.get_header("Call-ID").unwrap(), Some("call-test-1".to_string()));
        assert!(call.has_header("Via").unwrap());
        assert!(!call.has_header("X-Custom").unwrap());
    }

    #[test]
    fn call_session_timer_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert!(call.session_timer_override().is_none());

        call.session_timer(3600, 120, "uas");
        let override_config = call.session_timer_override().unwrap();
        assert_eq!(override_config.session_expires, 3600);
        assert_eq!(override_config.min_se, 120);
        assert_eq!(override_config.refresher, "uas");
    }

    #[test]
    fn call_accept_refer() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.accept_refer();
        assert_eq!(call.action(), &CallAction::AcceptRefer);
    }

    #[test]
    fn call_reject_refer() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.reject_refer(403, "Forbidden");
        assert_eq!(
            call.action(),
            &CallAction::RejectRefer {
                code: 403,
                reason: "Forbidden".to_string()
            }
        );
    }

    #[test]
    fn call_refer_to_initially_none() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert!(call.refer_to_uri.is_none());
        assert!(call.refer_replaces_info.is_none());
    }

    #[test]
    fn call_set_refer_to_blind() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.set_refer_to("sip:carol@example.com".to_string(), None);
        assert_eq!(call.refer_to_uri.as_deref(), Some("sip:carol@example.com"));
        assert!(call.refer_replaces_info.is_none());
    }

    #[test]
    fn call_set_refer_to_attended() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        let replaces = crate::sip::headers::refer::Replaces {
            call_id: "other-call@host".to_string(),
            from_tag: "ft".to_string(),
            to_tag: "tt".to_string(),
            early_only: false,
        };
        call.set_refer_to("sip:carol@example.com".to_string(), Some(replaces.clone()));
        assert_eq!(call.refer_to_uri.as_deref(), Some("sip:carol@example.com"));
        let stored = call.refer_replaces_info.as_ref().unwrap();
        assert_eq!(stored.call_id, "other-call@host");
        assert_eq!(stored.from_tag, "ft");
        assert_eq!(stored.to_tag, "tt");
    }

    #[test]
    fn call_set_ruri_user() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_ruri_user("+33123456789").unwrap();
        let msg = message.lock().unwrap();
        if let crate::sip::message::StartLine::Request(ref rl) = msg.start_line {
            assert_eq!(rl.request_uri.user.as_deref(), Some("+33123456789"));
        } else {
            panic!("expected request start line");
        }
    }

    #[test]
    fn call_set_from_user() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_from_user("+33999888777").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("+33999888777@atlanta.com"), "From should contain new user: {from}");
        assert!(from.contains(";tag=abc"), "From should preserve tag: {from}");
    }

    #[test]
    fn call_set_to_user() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_to_user("5112").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("5112@example.com"), "To should contain new user: {to}");
        assert!(!to.contains(";tag="), "Initial INVITE To must not gain a tag: {to}");
    }

    #[test]
    fn call_set_to_user_preserves_tag() {
        let mut invite = make_invite();
        invite.headers.set("To", "<sip:bob@example.com>;tag=remote-tag".to_string());
        let message = Arc::new(Mutex::new(invite));
        let call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_to_user("5112").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("5112@example.com"), "To should contain new user: {to}");
        assert!(to.contains(";tag=remote-tag"), "To should preserve existing tag: {to}");
    }

    #[test]
    fn call_set_from_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_from_host("tenant.example.com").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("alice@tenant.example.com"), "From host should change: {from}");
        assert!(!from.contains("atlanta.com"), "old From host must be gone: {from}");
        assert!(from.contains(";tag=abc"), "From should preserve tag: {from}");
        drop(msg);
        assert_eq!(call.from_host_override(), Some("tenant.example.com"));
    }

    #[test]
    fn call_set_from_host_preserves_display_user_port_tag() {
        let mut invite = make_invite();
        invite.headers.set(
            "From",
            "\"Alice\" <sip:1001@old.example.com:5060>;tag=xyz".to_string(),
        );
        let message = Arc::new(Mutex::new(invite));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_from_host("tenant.example.com").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("\"Alice\""), "display name preserved: {from}");
        assert!(from.contains("1001@tenant.example.com:5060"), "user+host+port: {from}");
        assert!(from.contains(";tag=xyz"), "tag preserved: {from}");
        assert!(!from.contains("old.example.com"), "old host gone: {from}");
    }

    #[test]
    fn call_set_to_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_to_host("trunk.example.com").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("bob@trunk.example.com"), "To host should change: {to}");
        assert!(!to.contains("example.com>") || to.contains("trunk.example.com"), "old host replaced: {to}");
        assert!(!to.contains(";tag="), "initial INVITE To must not gain a tag: {to}");
        drop(msg);
        assert_eq!(call.to_host_override(), Some("trunk.example.com"));
    }

    #[test]
    fn call_set_from_host_none_by_default() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.from_host_override(), None);
        assert_eq!(call.to_host_override(), None);
    }

    #[test]
    fn call_set_from_uri_replaces_uri_and_pins_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_from_uri("sip:1001@tenant.example.com:5070;transport=tcp").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("1001@tenant.example.com:5070"), "user+host+port: {from}");
        assert!(from.contains("transport=tcp"), "uri params preserved: {from}");
        assert!(from.contains(";tag=abc"), "From tag preserved: {from}");
        assert!(!from.contains("atlanta.com"), "old host gone: {from}");
        drop(msg);
        // Host is pinned so the B-leg builder's topology-hiding rewrite honours it.
        assert_eq!(call.from_host_override(), Some("tenant.example.com"));
    }

    #[test]
    fn call_set_to_uri_replaces_uri_and_pins_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_to_uri("sip:5112@ims.example.org").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("5112@ims.example.org"), "user+host: {to}");
        assert!(!to.contains("example.com"), "old host gone: {to}");
        assert!(!to.contains(";tag="), "initial INVITE To must not gain a tag: {to}");
        drop(msg);
        assert_eq!(call.to_host_override(), Some("ims.example.org"));
    }

    #[test]
    fn call_set_to_uri_preserves_display_and_tag() {
        let mut invite = make_invite();
        invite.headers.set("To", "\"Bob\" <sip:bob@example.com>;tag=remote".to_string());
        let message = Arc::new(Mutex::new(invite));
        let mut call = PyCall::new("test-id".to_string(), message.clone(), "10.0.0.1".to_string(), "udp".to_string());
        call.set_to_uri("sip:5112@ims.example.org").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("\"Bob\""), "display preserved: {to}");
        assert!(to.contains("5112@ims.example.org"), "uri replaced: {to}");
        assert!(to.contains(";tag=remote"), "tag preserved: {to}");
    }

    #[test]
    fn call_set_contact_user_sets_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.contact_user_override(), None);
        call.set_contact_user("1001").unwrap();
        assert_eq!(call.contact_user_override(), Some("1001"));
    }

    #[test]
    fn call_set_contact_uri_sets_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert_eq!(call.contact_override(), None);
        call.set_contact_uri("sip:gruu-token@edge.example.com:5060").unwrap();
        assert_eq!(call.contact_override(), Some("sip:gruu-token@edge.example.com:5060"));
    }

    #[test]
    fn call_set_contact_uri_rejects_invalid() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert!(call.set_contact_uri("not-a-uri").is_err());
        assert_eq!(call.contact_override(), None);
    }

    #[test]
    fn call_set_and_remove_header() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        call.set_header("X-Custom", "test-value").unwrap();
        assert_eq!(call.get_header("X-Custom").unwrap(), Some("test-value".to_string()));
        call.remove_header("X-Custom").unwrap();
        assert_eq!(call.get_header("X-Custom").unwrap(), None);
    }

    // --- from_gateway (source-membership predicate) ---

    fn gateway_manager_with_group() -> Arc<crate::gateway::DispatcherManager> {
        use crate::gateway::{Algorithm, Destination, DispatcherGroup};
        use crate::transport::Transport;

        let manager = Arc::new(crate::gateway::DispatcherManager::new());
        manager.add_group(DispatcherGroup::new(
            "trunks".to_string(),
            Algorithm::Weighted,
            vec![Destination::new(
                "sip:gw1.example.com".to_string(),
                "10.0.0.1:5060".parse().unwrap(),
                Transport::Udp,
                1,
                1,
            )],
        ));
        manager
    }

    #[test]
    fn call_from_gateway_true_for_member_source() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        let manager = gateway_manager_with_group();
        assert!(call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_for_non_member_source() {
        let message = Arc::new(Mutex::new(make_invite()));
        // RFC 5737 TEST-NET-1 — not a member of the group.
        let call = PyCall::new("test-id".to_string(), message, "192.0.2.7".to_string(), "udp".to_string());
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_for_unknown_group() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("nonexistent", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_when_no_manager() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "10.0.0.1".to_string(), "udp".to_string());
        assert!(!call.from_gateway_impl("trunks", None));
    }

    #[test]
    fn call_from_gateway_false_for_unparseable_source_ip() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new("test-id".to_string(), message, "not-an-ip".to_string(), "udp".to_string());
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_cdr_accessors() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "tcp".to_string(),
        );
        assert_eq!(call.cdr_method(), "INVITE");
        assert_eq!(call.cdr_call_id(), "call-test-1");
        assert_eq!(call.cdr_from_uri(), "sip:alice@atlanta.com");
        assert_eq!(call.cdr_to_uri(), "sip:bob@example.com");
        assert_eq!(call.cdr_ruri(), "sip:bob@example.com");
        assert_eq!(call.cdr_source_ip(), "10.0.0.1");
        // Transport is threaded from the A-leg, not hard-coded.
        assert_eq!(call.cdr_transport(), "tcp");
    }

    #[test]
    fn call_cdr_rf_dialog_keys_include_from_tag() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let keys = call.cdr_rf_dialog_key_candidates();
        // make_invite() has Call-ID "call-test-1" and From-tag "abc"; the
        // dialog-keyed candidate must be present so the Rf auto-stamp can hit.
        assert!(
            keys.iter().any(|k| k.contains("call-test-1") && k.contains("abc")),
            "expected a dialog key with Call-ID + From-tag, got {keys:?}"
        );
    }
}
