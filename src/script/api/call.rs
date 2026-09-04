//! PyO3 wrapper for B2BUA calls — the `Call` object passed to Python scripts.
//!
//! Scripts interact with this object via `@b2bua.on_invite`, `@b2bua.on_answer`,
//! `@b2bua.on_failure`, and `@b2bua.on_bye` handlers.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::sip_uri::PySipUri;
use crate::sip::message::SipMessage;

/// Per-call session timer override set by Python scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimerOverride {
    pub session_expires: u32,
    pub min_se: u32,
    pub refresher: String,
}

/// The action the script chose for this call.
///
/// Not `Eq`: [`CallAction::RouteSequence`] carries `lcr::Route`s whose `rate`
/// is an `f64`. `PartialEq` is retained for tests.
#[derive(Debug, Clone, PartialEq)]
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
        /// Force-send-socket egress pin (`send_socket="udp:10.0.0.1:5060"`).
        /// Selects which configured listener the B-leg INVITE leaves from on a
        /// multi-homed host.  Validated for format at API-call time; resolved
        /// against the configured listeners in the dispatcher.  Ignored when
        /// `flow` is set (the flow already pins the egress listener).
        send_socket: Option<String>,
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
        /// Also parallel to `targets`: the RFC 3327 Path vector stored with that
        /// binding, becoming that branch's Route header set (and, with no
        /// explicit next-hop, its destination — RFC 3261 §16.6 step 6).
        ///
        /// Two bindings of one AoR generally carry different Path vectors, so a
        /// shared route set would send every branch through the first binding's
        /// proxy chain.  Bare-string targets carry an empty vector and keep
        /// pure Request-URI routing.
        routes: Vec<Vec<String>>,
        strategy: String,
        /// Force-send-socket egress pin applied to every B-leg branch (see
        /// [`CallAction::Dial::send_socket`]).  A per-branch flow still takes
        /// precedence over it for that branch.
        send_socket: Option<String>,
        timeout: u32,
    },
    /// Terminate the call (BYE both legs).
    Terminate,
    /// Accept a REFER (call transfer). `mode` selects siphon-terminated
    /// (`Terminate`) vs transparent forward (`Transparent`); `None` defers to
    /// the configured `b2bua.default_refer_mode`. `target` optionally rewrites
    /// the transfer destination before it is honored; `next_hop` steers egress.
    AcceptRefer {
        target: Option<String>,
        next_hop: Option<String>,
        mode: Option<ReferMode>,
        /// Media profile for the pairing the transfer creates. `None` inherits
        /// the profile the original call was anchored with, which is only
        /// correct when that profile is symmetric — see
        /// `ProfileEntry::is_direction_bound`.
        profile: Option<String>,
    },
    /// Reject a REFER with a status code.
    RejectRefer { code: u16, reason: String },
    /// Originate an outbound REFER on a connected leg (`call.refer(...)`) —
    /// siphon is the referrer (IVR / UAS-mode offload). Carries the target and
    /// an optional Replaces (attended transfer).
    SendRefer {
        refer_to: crate::sip::headers::refer::ReferTo,
    },
    /// UAS-mode answer already sent imperatively by `call.answer()` — the final
    /// 2xx went on the wire during the handler (see `dispatcher::b2bua_answer_call`).
    /// This marker only tells the dispatcher the call was answered so it keeps
    /// the actor alive instead of removing it as a silent (no-action) drop.
    Answered,
    /// Hand the call over to an out-of-process control application
    /// (`call.handover("app")`, the ARI *Stasis* model). The dispatcher holds the
    /// INVITE transaction un-dialed, sends a keep-alive 180, registers the call
    /// with the control plane, emits `StasisStart` with the full SIP context, and
    /// arms a handoff deadline whose default action (503 / fallback) fires if no
    /// controller accepts and acts in time.
    Handover {
        /// The target control app (must be configured in `control.apps`).
        app: String,
        /// Control-loss policy: "hangup" (default) / "continue" / "fallback".
        on_lost: Option<String>,
        /// Handoff deadline in ms; `None` uses `control.limits.handoff_deadline_ms`.
        deadline_ms: Option<u64>,
        /// Per-call variables seeded into the control plane's channel entry.
        vars: std::collections::HashMap<String, String>,
        /// Answer-first (AI-park) mode: when `true`, siphon answers with `200 OK`
        /// and anchors media to the `voice_ai` bridge *before* handing over, so
        /// the controller drives an already-connected channel. When `false`
        /// (default), the call is parked un-answered (deferred mode) and the
        /// controller decides how to respond.
        answer: bool,
        /// Answer-first only: the media profile to anchor with (default
        /// `"voice_ai"`). Ignored when `answer` is `false`.
        profile: Option<String>,
        /// Answer-first only: the per-call WebSocket bridge URI the media engine
        /// dials out for this leg's audio. Supports `{call_id}` / `{from_tag}` /
        /// `{from_user}` / `{to_user}` templating (RFC-3264-answer side). Falls
        /// back to the profile's own `ws_uri` when omitted. Ignored when `answer`
        /// is `false`.
        ws_uri: Option<String>,
    },
    /// Sequential failover across an ordered list of carrier routes — LCR
    /// (`call.route(...)`) or `call.fork(strategy="sequential")`. The dispatcher
    /// dials the first routable carrier, stores the rest as the call's failover
    /// queue, and advances to the next on B-leg reject/timeout, forwarding the
    /// best error to the A-leg only once the list is exhausted. Each attempt is
    /// a fresh B-leg dialog (no reused Call-ID — the serial-fork footgun a proxy
    /// can't avoid).
    RouteSequence {
        /// Ordered carriers, cheapest/most-preferred first.
        routes: Vec<crate::lcr::Route>,
        /// Call-level send-socket egress pin applied to every attempt.
        send_socket: Option<String>,
        /// Default ring timeout (seconds) for a route without `timeout_secs`.
        default_timeout: u32,
    },
}

/// REFER transfer mode selected by `call.accept_refer(mode=...)` (and the
/// configured `b2bua.default_refer_mode` fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferMode {
    /// siphon terminates the transfer: answer 202 locally, re-resolve the
    /// Refer-To through the dial plan as a new leg, re-bridge the media, and BYE
    /// the referred-away leg. Correct for trunk-facing SBCs (the far end need not
    /// support REFER) and keeps media anchored.
    Terminate,
    /// siphon forwards the REFER transparently on the far leg's own dialog and
    /// relays the far end's 202 + `message/sipfrag` NOTIFYs back to the referrer.
    /// Correct for UA-to-UA (PBX / softphone) topologies where both ends handle
    /// REFER themselves.
    Transparent,
}

/// Parse a Python Replaces dict (`{call_id, from_tag, to_tag, early_only?}`)
/// into the internal [`Replaces`](crate::sip::headers::refer::Replaces). Shared
/// by `call.refer(replaces=…)` and the imperative `b2bua.refer(...)`. Returns
/// `None` when `dict` is `None` (a blind transfer).
pub(crate) fn parse_replaces_dict(
    dict: Option<&Bound<'_, pyo3::types::PyDict>>,
) -> PyResult<Option<crate::sip::headers::refer::Replaces>> {
    let Some(dict) = dict else {
        return Ok(None);
    };
    let required = |key: &str| -> PyResult<String> {
        match dict.get_item(key)? {
            Some(value) => value.extract::<String>(),
            None => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "replaces dict requires a '{key}' key"
            ))),
        }
    };
    let call_id = required("call_id")?;
    let from_tag = required("from_tag")?;
    let to_tag = required("to_tag")?;
    let early_only = match dict.get_item("early_only")? {
        Some(value) => value.extract::<bool>()?,
        None => false,
    };
    Ok(Some(crate::sip::headers::refer::Replaces {
        call_id,
        from_tag,
        to_tag,
        early_only,
    }))
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
    /// The inbound flow the A-leg INVITE arrived on, when the dispatcher had
    /// the A-leg's transport binding to build it from. `None` for a `Call`
    /// constructed without one (tests, internally-originated calls).
    flow: Option<super::registrar::PyFlow>,
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
    /// Which leg the REFER arrived on — `Some(true)` for the A-leg. The party
    /// that survives a transfer is the *peer* of this one, which is what decides
    /// the media profile the surviving pair needs.
    refer_from_a_leg: Option<bool>,
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
    /// When true (set via `call.dial(auth_passthrough=True)` / `call.fork(...)`),
    /// this call relays B-leg auth challenges to the caller end-to-end instead
    /// of siphon answering them. It copies `Proxy-Authenticate`/`Proxy-Authorization`
    /// across the B2BUA (injected into `header_policy_input.deltas_copy`) AND, on
    /// a B-leg 401/407 with no siphon-side credentials, tells the dispatcher to
    /// forward the challenge without firing `@b2bua.on_failure`, deleting media,
    /// or tearing the call down — so the caller can authenticate and re-INVITE.
    auth_passthrough_flag: bool,
    /// The carrier route that won (LCR) — injected by the dispatcher when it
    /// builds the `@b2bua.on_answer` / `on_bye` `Call` from the call actor's
    /// `route_sequence.active`. Read by scripts via `call.active_route` to stamp
    /// the winning carrier onto a CDR / charging record.
    active_route: Option<crate::lcr::Route>,
    /// Every carrier that FAILED before the sequence settled — injected by the
    /// dispatcher from the call actor's `route_sequence.attempts`. Read by
    /// scripts via `call.route_attempts`, the counterpart to `active_route`:
    /// that one names the carrier that carried the call, this one names the
    /// carriers it had to burn to get there.
    route_attempts: Vec<crate::b2bua::actor::RouteAttempt>,
    /// Username verified by `auth.require_proxy_digest(call, …)` /
    /// `require_www_digest` on the A-leg INVITE. `None` until a challenge is
    /// answered correctly. The B2BUA twin of `request.auth_user`; the
    /// dispatcher stamps it onto the call's CDR session after `on_invite`
    /// returns.
    auth_user: Option<String>,
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

/// Extract the bare URI string from a From/To-style header (drops the display
/// name and header params/tag). `None` if the header is absent or unparseable.
fn header_uri(message: &SipMessage, name: &str) -> Option<String> {
    let raw = message.headers.get(name)?;
    crate::sip::headers::nameaddr::NameAddr::parse(raw)
        .ok()
        .map(|nameaddr| nameaddr.uri.to_string())
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
            flow: None,
            transport_name,
            state: "calling".to_string(),
            action: CallAction::None,
            media_handle: PyMediaHandle::default(),
            session_timer_override: None,
            refer_to_uri: None,
            refer_from_a_leg: None,
            refer_replaces_info: None,
            outbound_credentials: None,
            li_record_flag: false,
            preserve_call_id_flag: false,
            from_host_override: None,
            to_host_override: None,
            contact_user_override: None,
            contact_override: None,
            header_policy_input: None,
            auth_passthrough_flag: false,
            active_route: None,
            route_attempts: Vec::new(),
            auth_user: None,
        }
    }

    /// Source IP of the A-leg caller (Rust-side accessor — the `source_ip`
    /// getter lives in `#[pymethods]`). Used by the digest helpers for
    /// auto-ban bookkeeping.
    pub fn source_ip_str(&self) -> &str {
        &self.source_ip
    }

    /// Transport the A-leg INVITE arrived on (Rust-side accessor). Used by the
    /// digest helpers to decide whether a bad-credentials attempt is a strong
    /// auto-ban signal (it is not over spoofable UDP).
    pub fn transport_str(&self) -> &str {
        &self.transport_name
    }

    /// Record the username verified by `auth.require_*_digest(call, …)`.
    /// Attach the inbound flow the A-leg INVITE arrived on. Called by the
    /// dispatcher, which builds it from the A-leg's `TransportInfo`.
    pub fn with_flow(mut self, flow: Option<super::registrar::PyFlow>) -> Self {
        self.flow = flow;
        self
    }

    pub fn set_auth_user(&mut self, username: String) {
        self.auth_user = Some(username);
    }

    /// The verified username, if the A-leg answered a digest challenge
    /// (Rust-side accessor behind the `auth_user` getter).
    pub fn get_auth_user(&self) -> Option<&str> {
        self.auth_user.as_deref()
    }

    /// Attach the winning carrier route (from the call actor's
    /// `route_sequence.active`) so the script can read `call.active_route` in
    /// `@b2bua.on_answer` / `on_bye`. Called by the dispatcher when it builds
    /// the handler `Call`.
    pub fn set_active_route(&mut self, route: crate::lcr::Route) {
        self.active_route = Some(route);
    }

    /// Attach the failed carrier attempts read off the call actor, for
    /// `call.route_attempts`.
    pub fn set_route_attempts(&mut self, attempts: Vec<crate::b2bua::actor::RouteAttempt>) {
        self.route_attempts = attempts;
    }

    /// Build an [`LcrRequest`](crate::lcr::LcrRequest) from this call for
    /// `lcr.route(...)`. `dialed_number` is the R-URI userpart (the script is
    /// expected to have normalized it, e.g. via `rewrite_identities`), falling
    /// back to the To userpart. `from`/`to` are the bare URIs.
    pub fn lcr_request(
        &self,
        trunk_group: Option<String>,
        attributes: std::collections::HashMap<String, String>,
    ) -> PyResult<crate::lcr::LcrRequest> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let call_id = message
            .headers
            .get("Call-ID")
            .map(|value| value.to_string())
            .unwrap_or_default();
        let from_uri = header_uri(&message, "From").unwrap_or_default();
        let to_uri = header_uri(&message, "To").unwrap_or_default();
        let ruri_user = match &message.start_line {
            crate::sip::message::StartLine::Request(request_line) => {
                request_line.request_uri.user.clone()
            }
            _ => None,
        };
        let dialed_number = ruri_user
            .or_else(|| {
                crate::sip::parser::parse_uri_standalone(&to_uri)
                    .ok()
                    .and_then(|uri| uri.user)
            })
            .unwrap_or_default();
        Ok(crate::lcr::LcrRequest {
            version: crate::lcr::LCR_CONTRACT_VERSION.to_string(),
            call_id,
            from: from_uri,
            to: to_uri,
            dialed_number,
            source: crate::lcr::LcrSource {
                ip: self.source_ip.clone(),
                trunk_group,
                transport: self.transport_name.clone(),
            },
            attributes,
        })
    }

    /// Per-call header policy input (preset name + deltas) — read by the
    /// dispatcher after the script handler returns so the resolved policy
    /// can be attached to the [`crate::b2bua::actor::CallActor`].
    pub fn header_policy_input(&self) -> Option<&HeaderPolicyInput> {
        self.header_policy_input.as_ref()
    }

    /// Whether this call relays B-leg auth challenges to the caller
    /// (`call.dial(auth_passthrough=True)`). Read by the dispatcher's 401/407
    /// handling so a relayed challenge does not tear the call down.
    pub fn auth_passthrough(&self) -> bool {
        self.auth_passthrough_flag
    }

    /// Append the two auth headers to `copy` for `auth_passthrough`, unless the
    /// script already listed them (case-insensitive) — so the challenge
    /// (`Proxy-Authenticate`, B→A) and the credentials (`Proxy-Authorization`,
    /// A→B) both cross the B2BUA verbatim (RFC 3261 §22.3).
    fn add_auth_passthrough_copies(copy: &mut Vec<String>) {
        for header in ["Proxy-Authenticate", "Proxy-Authorization"] {
            if !copy.iter().any(|h| h.eq_ignore_ascii_case(header)) {
                copy.push(header.to_string());
            }
        }
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

    /// Set a deferred reject action on this call — the same effect as the
    /// Python-level `call.reject(code, reason)`, exposed so the media namespace
    /// can apply an auto-488 after its async engine round-trip (see
    /// `rtpengine.answer_local(auto_reject=True)`).  The dispatcher applies the
    /// deferred [`CallAction::Reject`] when the `on_invite` handler returns.
    pub fn set_reject(&mut self, code: u16, reason: impl Into<String>) {
        self.action = CallAction::Reject {
            code,
            reason: reason.into(),
        };
    }

    /// Get the media handle (for the B2BUA core to check after script runs).
    pub fn media_handle(&self) -> &PyMediaHandle {
        &self.media_handle
    }

    /// Get the underlying SIP message.
    pub fn message(&self) -> Arc<Mutex<SipMessage>> {
        Arc::clone(&self.message)
    }

    /// Lock and clone the A-leg INVITE — the source for an imperative
    /// `answer()` / `progress()` UAS response. The dispatcher can't read the
    /// INVITE off the actor during `on_invite` (it's stored only after the
    /// handler returns), so the `PyCall` supplies it.
    fn locked_invite(&self) -> PyResult<SipMessage> {
        let guard = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(guard.clone())
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
        message
            .headers
            .from()
            .and_then(|v| crate::sip::headers::nameaddr::NameAddr::parse(v).ok())
            .map(|na| na.uri.to_string())
    }

    /// To URI for LI target matching.
    pub fn li_to_uri(&self) -> Option<String> {
        let message = match self.message.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        message
            .headers
            .to()
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

    /// Candidate `cdr_sessions` key for this call's auto-emit CDR.
    ///
    /// A B2BUA call is tracked under its internal call UUID (both legs carry
    /// different Call-IDs and resolve to one record), which is exactly what
    /// `call.id` exposes.
    pub fn cdr_session_key_candidates(&self) -> Vec<String> {
        vec![self.id.clone()]
    }

    /// Candidate Rf-session storage keys for the CDR auto-stamp lookup.
    ///
    /// Mirrors [`PyRequest::cdr_rf_dialog_key_candidates`](super::request::PyRequest)
    /// so a `cdr.write(call)` from a B2BUA handler is annotated with the same
    /// `rf_session_id` / `rf_result_code` the proxy path stamps.
    ///
    /// The B2BUA record itself is keyed on the internal call UUID
    /// (`rf_b2bua_key`), so that is offered first; the dialog-derived
    /// candidates follow for a call whose Rf record was opened on the proxy
    /// path (an AS leg, a call that changed mode mid-flight).
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

        let mut keys = vec![crate::diameter::rf_service::rf_b2bua_key(&self.id)];
        keys.extend(crate::diameter::rf_service::rf_lookup_candidates(
            icid.as_deref(),
            call_id.map(|s| s.as_str()),
            from_tag.as_deref(),
            to_tag.as_deref(),
        ));
        keys
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

    /// Record which leg the REFER arrived on (called by B2BUA core before
    /// firing on_refer).
    pub fn set_refer_from_a_leg(&mut self, from_a_leg: bool) {
        self.refer_from_a_leg = Some(from_a_leg);
    }
}

#[pymethods]
impl PyCall {
    /// Unique call identifier.
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Reserve prepaid credit (Ro CCR-INITIAL) for this call BEFORE dialing the
    /// B-leg — the reserve-before-connect gate. Call it from `@b2bua.on_invite`
    /// and branch on the result:
    ///
    /// ```python
    /// @b2bua.on_invite
    /// async def on_invite(call):
    ///     decision = await call.ro_authorize()
    ///     if not decision["authorized"]:
    ///         call.reject(402, "Payment Required")   # no B-leg is dialed
    ///         return
    ///     call.dial("sip:bob@carrier")               # credit reserved -> connect
    /// ```
    ///
    /// On a grant siphon opens the credit-control session, runs the re-auth loop
    /// (CCR-UPDATE on the OCS-granted cadence), disconnects the call mid-stream
    /// if the OCS later refuses credit, and sends CCR-TERMINATION on BYE — all
    /// autonomously. `subscription_id` overrides the charged identity; when
    /// omitted, the party is derived from the `ro.charge` config (orig = caller,
    /// term = callee) and a `sip:` URI is typed as a SIP URI, never mislabeled
    /// as an E.164 number. The rating group, requested quota and Service-Context
    /// come from the `ro:` config block.
    ///
    /// Returns a dict `{"authorized": bool, "result_code": int|None,
    /// "granted_time": int|None, "session_id": str|None}`. When Ro is not
    /// configured the gate is a no-op that authorizes (uncharged).
    #[pyo3(signature = (*, subscription_id=None, subscription_id_type=None))]
    fn ro_authorize<'py>(
        &self,
        python: Python<'py>,
        subscription_id: Option<String>,
        subscription_id_type: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let invite = match self.message.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let internal_call_id = self.id.clone();
        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let outcome = crate::dispatcher::ro_authorize_b2bua(
                internal_call_id,
                invite,
                subscription_id,
                subscription_id_type,
            )
            .await;
            Python::attach(|py| {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("authorized", outcome.authorized)?;
                dict.set_item("result_code", outcome.result_code)?;
                dict.set_item("granted_time", outcome.granted_time)?;
                dict.set_item("session_id", outcome.session_id)?;
                Ok(dict.into_any().unbind())
            })
        })
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

    /// The inbound flow this call's INVITE arrived on — the B2BUA twin of
    /// `request.flow`.
    ///
    /// `None` when the dispatcher had no transport binding to build it from
    /// (an internally-originated call, or a `Call` constructed in a test).
    ///
    /// The point of it is RFC 5626 connection reuse: a `Contact` saved at
    /// REGISTER time carries the flow the registration arrived on, so a call
    /// can be authorised by matching the two rather than by challenging every
    /// INVITE with a 407:
    ///
    /// ```python
    /// @b2bua.on_invite
    /// def on_invite(call):
    ///     bindings = registrar.lookup(str(call.from_uri))
    ///     if any(c.flow == call.flow for c in bindings):
    ///         call.dial(str(call.ruri))      # same connection as the REGISTER
    ///     else:
    ///         call.reject(403, "Forbidden")
    /// ```
    ///
    /// On a stream transport (TCP/TLS/WS/WSS) that comparison is an exact match
    /// on one accepted socket, which is why it is worth doing: a source-address
    /// check is worthless behind carrier NAT, where every subscriber on the
    /// network shares an address. On UDP there is no connection, so the flow is
    /// derived from the address pair and carries no more assurance than the
    /// address does.
    ///
    /// The match survives the UE reusing the connection across many calls —
    /// the connection id identifies the socket, not the transaction.
    #[getter]
    fn flow(&self) -> Option<super::registrar::PyFlow> {
        self.flow.clone()
    }

    /// Username the A-leg authenticated as, or `None` if it was never
    /// challenged (the B2BUA twin of `request.auth_user`).
    ///
    /// Set by `auth.require_proxy_digest(call, realm)` /
    /// `auth.require_www_digest(call, realm)` in `@b2bua.on_invite` once the
    /// caller answers the challenge correctly. Carried onto the call's CDR as
    /// `auth_user`.
    #[getter]
    fn auth_user(&self) -> Option<&str> {
        self.auth_user.as_deref()
    }

    /// Overwrite the username the A-leg authenticated as (the B2BUA twin of
    /// `request.auth_user`'s setter).
    ///
    /// The digest helpers set this to the username exactly as it appeared in
    /// the `Proxy-Authorization` header, because that is the string the
    /// response was computed over. A deployment whose authentication identity
    /// is not its subscriber identity — an IMS private identity authenticating
    /// a public one, or any username carrying a validity prefix or tenant
    /// qualifier — reduces it here, after verification:
    ///
    /// ```python
    /// @b2bua.on_invite
    /// def on_invite(call):
    ///     if not auth.require_proxy_digest(call, "example.com"):
    ///         return
    ///     call.auth_user = normalise(call.auth_user)
    /// ```
    ///
    /// The value is carried onto the call's CDR as `auth_user`. Setting it
    /// before the challenge is answered asserts an identity that was never
    /// proven, so assign it only on the success path.
    #[setter(auth_user)]
    fn py_set_auth_user(&mut self, username: Option<String>) {
        self.auth_user = username;
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

    /// Check if the A-leg source IP is within any of the given CIDR ranges.
    ///
    /// The B2BUA counterpart of `request.source_ip_in`. Use it to gate on a
    /// peer's published source subnets directly, when that peer sources SIP from
    /// a whole range rather than only the IPs its signalling FQDNs resolve to —
    /// the case `from_gateway` (which tracks the destinations' DNS) cannot cover.
    /// Same trust semantics as `from_gateway`: handshake-verified on
    /// TCP/TLS/WS/WSS, a best-effort direction hint on UDP.
    ///
    /// Raises `ValueError` only if the A-leg source IP itself is unparseable;
    /// malformed CIDR entries in the list are skipped.
    ///
    /// Example: `if call.source_ip_in(["203.0.113.0/24"]): ...`
    fn source_ip_in(&self, cidr_list: Vec<String>) -> PyResult<bool> {
        let source_ip: std::net::IpAddr = self.source_ip.parse().map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("bad source IP: {error}"))
        })?;
        for cidr in &cidr_list {
            if let Ok(network) = cidr.parse::<ipnet::IpNet>() {
                if network.contains(&source_ip) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
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
        let from_raw = message
            .headers
            .get("From")
            .or_else(|| message.headers.get("f"));
        match from_raw {
            Some(raw) => match crate::sip::headers::nameaddr::NameAddr::parse(raw) {
                Ok(nameaddr) => Ok(Some(PySipUri::new(nameaddr.uri))),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// To URI of the A-leg.
    #[getter]
    fn to_uri(&self) -> PyResult<Option<PySipUri>> {
        let message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let to_raw = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"));
        match to_raw {
            Some(raw) => match crate::sip::headers::nameaddr::NameAddr::parse(raw) {
                Ok(nameaddr) => Ok(Some(PySipUri::new(nameaddr.uri))),
                Err(_) => Ok(None),
            },
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
        Ok(message
            .headers
            .get("Call-ID")
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
        let names_to_remove: Vec<String> = message
            .headers
            .names()
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

    /// Hand this call over to an out-of-process control application (ARI
    /// *Stasis* model). siphon holds the INVITE transaction un-dialed, sends a
    /// keep-alive ``180``, registers the call with the control plane and emits a
    /// ``StasisStart`` carrying the full SIP context to the owning connection.
    /// The out-of-process app then drives the call (answer / play / dtmf /
    /// bridge / hangup) over the control WebSocket.
    ///
    /// A handoff deadline protects against an absent/slow controller: if no
    /// controller accepts and acts in time, ``on_lost``'s sibling default action
    /// fires (a ``503`` by default, or a fallback re-dispatch), so a dead
    /// controller degrades instead of hanging calls.
    ///
    /// Args:
    ///     app: The control app name (must be configured in ``control.apps``).
    ///     on_lost: What to do if the owning connection is lost mid-call —
    ///         ``"hangup"`` (default), ``"continue"``, or ``"fallback"``.
    ///     deadline_ms: Handoff deadline in milliseconds; ``None`` uses
    ///         ``control.limits.handoff_deadline_ms``.
    ///     vars: Per-call variables seeded into the control channel, readable +
    ///         writable by the app via ``get_var`` / ``set_var``.
    ///     answer: Answer-first (AI-park) mode. When ``True``, siphon answers the
    ///         call (``200 OK``) and anchors media to the ``voice_ai`` bridge
    ///         before handing over, so the controller drives an already-connected
    ///         channel — answering commits the call (CDR answer-time starts;
    ///         declining is a BYE, not a 4xx). When ``False`` (default), the call
    ///         is parked un-answered and the controller decides how to respond.
    ///     profile: Answer-first only — the media profile to anchor with (default
    ///         ``"voice_ai"``).
    ///     ws_uri: Answer-first only — the per-call WebSocket bridge URI the media
    ///         engine dials out for this leg's audio, so the app computes it per
    ///         session/tenant. Supports ``{call_id}`` / ``{from_tag}`` /
    ///         ``{from_user}`` / ``{to_user}`` templating; falls back to the
    ///         profile's own ``ws_uri`` when omitted.
    ///
    /// Example:
    ///     @b2bua.on_invite
    ///     async def route(call):
    ///         if is_ai_number(call.to_uri):
    ///             call.handover("ai-app", answer=True,
    ///                           ws_uri="wss://ai.example/stream/{call_id}")
    ///         elif is_ivr_number(call.to_uri):
    ///             call.handover("ivr-app", on_lost="hangup", deadline_ms=3000,
    ///                           vars={"queue": "support"})
    ///         else:
    ///             call.dial(call.ruri)
    #[pyo3(signature = (app, on_lost=None, deadline_ms=None, vars=None, answer=false, profile=None, ws_uri=None))]
    #[allow(clippy::too_many_arguments)]
    fn handover(
        &mut self,
        app: &str,
        on_lost: Option<&str>,
        deadline_ms: Option<u64>,
        vars: Option<std::collections::HashMap<String, String>>,
        answer: bool,
        profile: Option<&str>,
        ws_uri: Option<&str>,
    ) -> PyResult<()> {
        if app.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "call.handover() requires a non-empty app name",
            ));
        }
        if let Some(policy) = on_lost {
            if !matches!(policy, "hangup" | "continue" | "fallback") {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "call.handover(on_lost=…) must be 'hangup', 'continue', or 'fallback' (got '{policy}')"
                )));
            }
        }
        if !answer && (profile.is_some() || ws_uri.is_some()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "call.handover(profile=…/ws_uri=…) requires answer=True (they only apply to answer-first mode)",
            ));
        }
        self.action = CallAction::Handover {
            app: app.to_string(),
            on_lost: on_lost.map(String::from),
            deadline_ms,
            vars: vars.unwrap_or_default(),
            answer,
            profile: profile.map(String::from),
            ws_uri: ws_uri.map(String::from),
        };
        Ok(())
    }

    /// UAS-mode answer — send a final 2xx response to the A-leg INVITE
    /// **immediately**, instead of bridging to a B-leg. Useful for MRF /
    /// announcement / echo / IVR servers that own the dialog themselves.
    ///
    /// The response goes on the wire the moment this is called (not deferred to
    /// when the handler returns), so an `async` handler can answer and then keep
    /// working — e.g. play a prompt to completion before starting echo —
    /// without delaying the 200 OK:
    ///
    /// ```python,ignore
    /// @b2bua.on_invite
    /// async def on_invite(call):
    ///     await rtpengine.offer(call, profile="ivr")
    ///     call.answer(200, "OK", body=call.body, content_type="application/sdp")
    ///     await rtpengine.play_media(call, file=prompt)   # 200 already sent
    ///     await rtpengine.echo(call)
    /// ```
    ///
    /// Synchronous — no `await` needed (the send is a queue push). The A-leg
    /// dialog is confirmed and `@b2bua.on_bye` takes over when the UAC BYEs.
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

        let invite = self.locked_invite()?;
        let sent = crate::dispatcher::b2bua_answer_call(
            &self.id,
            &invite,
            code,
            reason,
            body_bytes,
            content_type,
        );
        if !sent {
            tracing::error!(call_id = %self.id, "call.answer(): no live B2BUA call to answer");
        }
        // Marker so the dispatcher keeps the actor alive after the handler
        // returns (the 2xx has already been sent by b2bua_answer_call).
        self.action = CallAction::Answered;
        Ok(())
    }

    /// UAS-mode provisional — send a 1xx response to the A-leg INVITE
    /// **immediately** (e.g. a ``183 Session Progress`` with early-media SDP, or
    /// ``180 Ringing``). Does not answer the call: the handler must still
    /// ``answer()`` / ``dial()`` / ``reject()`` to reach a final response.
    ///
    /// Like ``answer()``, the response goes on the wire the moment this is
    /// called, so a script can send ringback / an announcement as early media
    /// and then ``answer()`` later. An 18x with SDP opens an early dialog and
    /// carries the same UAS To-tag ``answer()`` will use.
    ///
    /// Args:
    ///     code: Provisional status (must be 1xx; 100 sends no To-tag).
    ///     reason: Reason phrase (e.g. ``"Session Progress"``).
    ///     body: Optional response body (``bytes`` or ``str``) — early-media SDP.
    ///     content_type: Content-Type for the body (e.g. ``"application/sdp"``).
    #[pyo3(signature = (code, reason="Ringing", body=None, content_type=None))]
    fn progress(
        &mut self,
        code: u16,
        reason: &str,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
    ) -> PyResult<()> {
        if !(100..200).contains(&code) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "call.progress() requires a 1xx status code (got {code}); use call.answer() for the final response"
            )));
        }

        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };

        let invite = self.locked_invite()?;
        let sent = crate::dispatcher::b2bua_progress_call(
            &self.id,
            &invite,
            code,
            reason,
            body_bytes,
            content_type,
        );
        if !sent {
            tracing::error!(call_id = %self.id, "call.progress(): no live B2BUA call");
        }
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
    ///         "sip:1000@ims.mnc001.mcc001.3gppnetwork.org",
    ///         next_hop="sip:192.0.2.178:4060",
    ///         header_policy="ims-trust-domain-boundary@2026",
    ///         copy=["X-Operator-Tag"],
    ///         strip=["History-Info"],
    ///     )
    #[pyo3(signature = (uri, timeout=30, next_hop=None, flow=None, header_policy=None, copy=Vec::new(), strip=Vec::new(), translate=Vec::new(), route=Vec::new(), send_socket=None, auth_passthrough=false, number_policy=None))]
    #[allow(clippy::too_many_arguments)]
    fn dial(
        &mut self,
        uri: &str,
        timeout: u32,
        next_hop: Option<&str>,
        flow: Option<super::registrar::PyFlow>,
        header_policy: Option<&str>,
        mut copy: Vec<String>,
        strip: Vec<String>,
        translate: Vec<(String, String)>,
        route: Vec<String>,
        send_socket: Option<String>,
        auth_passthrough: bool,
        number_policy: Option<&str>,
    ) -> PyResult<()> {
        super::request::validate_send_socket(send_socket.as_deref())?;
        // Number normalization (explicit `number_policy=`, else the configured
        // `b2bua.default_number_policy`): reformat the A-leg identity headers
        // that flow to the B-leg, plus the dial target itself.
        let target = {
            if let Some(policy) = super::numbers::resolve_dial_policy(number_policy)? {
                let mut message = self.message.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
                })?;
                super::numbers::apply_for_dial(&mut message, &policy, uri)
            } else {
                uri.to_string()
            }
        };
        self.action = CallAction::Dial {
            target,
            next_hop: next_hop.map(String::from),
            flow,
            route,
            send_socket,
            timeout,
        };
        if auth_passthrough {
            self.auth_passthrough_flag = true;
            Self::add_auth_passthrough_copies(&mut copy);
        }
        self.update_header_policy_input(header_policy, copy, strip, translate);
        Ok(())
    }

    /// Fork to multiple targets.
    ///
    /// Each target is a bare URI string or a `Contact` (from
    /// `registrar.lookup()`).  A `Contact` the local process accepted
    /// (`Contact.is_local`) routes its branch over the captured inbound flow —
    /// connection reuse, mandatory for WebSocket callees (RFC 7118 §5 / RFC
    /// 5626 §5.3).  `header_policy` / `copy` / `strip` / `translate` apply to
    /// every branch — per-branch policy is a follow-up enhancement.
    ///
    /// A `Contact` that carries an RFC 3327 Path vector additionally gets its
    /// **own** Route header set on that branch, built from the Path in order
    /// (§5.3), and that route set is where the branch is sent (RFC 3261 §16.6
    /// step 6).  Without it a callee registered through an edge proxy is
    /// unreachable — the B-leg would go to the UE's own Contact, which is the
    /// address the Path exists to route around (NAT, IPsec, a userless or
    /// `.invalid` contact) — and two bindings of one AoR would share the first
    /// one's route set.  Bare-string targets keep pure Request-URI routing.
    ///
    /// `strategy="sequential"` carries the same route set per carrier (as an
    /// explicit next-hop plus a `Route` header), so serial failover across an
    /// AoR's bindings reaches each binding's own proxy chain.
    #[pyo3(signature = (targets, strategy="parallel", timeout=30, header_policy=None, copy=Vec::new(), strip=Vec::new(), translate=Vec::new(), send_socket=None, auth_passthrough=false, number_policy=None))]
    #[allow(clippy::too_many_arguments)]
    fn fork(
        &mut self,
        targets: Vec<Bound<'_, PyAny>>,
        strategy: &str,
        timeout: u32,
        header_policy: Option<&str>,
        mut copy: Vec<String>,
        strip: Vec<String>,
        translate: Vec<(String, String)>,
        send_socket: Option<String>,
        auth_passthrough: bool,
        number_policy: Option<&str>,
    ) -> PyResult<()> {
        super::request::validate_send_socket(send_socket.as_deref())?;
        let mut target_uris: Vec<String> = Vec::with_capacity(targets.len());
        let mut flows: Vec<Option<super::registrar::PyFlow>> = Vec::with_capacity(targets.len());
        let mut branch_paths: Vec<Vec<String>> = Vec::with_capacity(targets.len());
        for item in targets {
            if let Ok(contact) = item.extract::<PyRef<super::registrar::PyContact>>() {
                let (uri, flow, path) = contact.fork_target();
                target_uris.push(uri);
                flows.push(flow);
                branch_paths.push(path);
            } else {
                target_uris.push(item.extract::<String>()?);
                flows.push(None);
                branch_paths.push(Vec::new());
            }
        }
        // Number normalization applies to every branch target plus the A-leg
        // identity headers (explicit `number_policy=`, else the b2bua default).
        if let Some(policy) = super::numbers::resolve_dial_policy(number_policy)? {
            let mut message = self.message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            super::numbers::apply_for_fork(&mut message, &policy, &mut target_uris);
        }
        if strategy.eq_ignore_ascii_case("sequential") {
            // Sequential fork = LCR-style serial failover: reuse the
            // RouteSequence engine so the strategy is actually honored (it was
            // silently ignored before). Each target becomes a routable-by-R-URI
            // carrier; captured inbound flows are not carried on the sequential
            // path (use parallel for WebSocket connection reuse).
            //
            // A binding registered through an edge proxy carries its route set
            // as an explicit next-hop plus a `Route` header on that carrier, so
            // serial failover across an AoR's bindings reaches each binding's
            // own proxy chain — and the per-registration Path token that tells
            // that proxy which binding the call is for.
            let routes = target_uris
                .into_iter()
                .zip(branch_paths.iter())
                .map(|(uri, path)| {
                    let routing = crate::proxy::core::branch_routing(path, &uri);
                    let mut route = crate::lcr::Route {
                        ruri: Some(uri),
                        ..Default::default()
                    };
                    if let Some(routing) = routing {
                        if let Some(route_set) = routing.route_set {
                            route.headers.insert("Route".to_string(), route_set);
                            route.next_hop = Some(routing.next_hop);
                        }
                    }
                    route
                })
                .collect();
            self.action = CallAction::RouteSequence {
                routes,
                send_socket,
                default_timeout: timeout,
            };
        } else {
            self.action = CallAction::Fork {
                targets: target_uris,
                flows,
                routes: branch_paths,
                strategy: strategy.to_string(),
                send_socket,
                timeout,
            };
        }
        if auth_passthrough {
            self.auth_passthrough_flag = true;
            Self::add_auth_passthrough_copies(&mut copy);
        }
        self.update_header_policy_input(header_policy, copy, strip, translate);
        Ok(())
    }

    /// Route this call across an ordered list of carrier `Route`s with
    /// **sequential failover** — B2BUA-only LCR execution.
    ///
    /// The carriers (from `await lcr.route(call)`, optionally filtered/reordered
    /// by the script — routing policy stays in Python) are tried cheapest-first:
    /// siphon dials the first routable carrier (resolving a `gateway_group` to a
    /// healthy member, skipping a carrier whose group is entirely down) and, on a
    /// reject / ring-timeout, advances to the next — each attempt a **fresh
    /// B-leg dialog** (new Call-ID / From-tag / CSeq), so no carrier ever sees a
    /// reused Call-ID. The A-leg receives the best error only once every carrier
    /// is exhausted. On answer, `call.active_route` is the carrier that won (read
    /// it in `@b2bua.on_answer` to stamp the carrier onto a CDR).
    ///
    /// Call from `@b2bua.on_invite`. Per-carrier shaping (tech-prefix, injected
    /// headers, R-URI override) and reroute causes are honored per route.
    #[pyo3(signature = (routes, timeout=30, send_socket=None))]
    fn route(
        &mut self,
        routes: Vec<Bound<'_, PyAny>>,
        timeout: u32,
        send_socket: Option<String>,
    ) -> PyResult<()> {
        super::request::validate_send_socket(send_socket.as_deref())?;
        let mut collected: Vec<crate::lcr::Route> = Vec::with_capacity(routes.len());
        for item in routes {
            let route: PyRef<super::lcr::PyRoute> = item.extract().map_err(|_| {
                pyo3::exceptions::PyTypeError::new_err(
                    "call.route() expects a list of Route objects from lcr.route(...)",
                )
            })?;
            collected.push(route.inner().clone());
        }
        if collected.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "call.route() requires at least one route",
            ));
        }
        self.action = CallAction::RouteSequence {
            routes: collected,
            send_socket,
            default_timeout: timeout,
        };
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

    /// The carrier route that won an LCR sequence (`call.route(...)`), or `None`
    /// for a non-LCR call. Available in `@b2bua.on_answer` / `on_bye` to stamp
    /// the winning carrier onto a CDR / charging record.
    ///
    /// ```python
    /// @b2bua.on_answer
    /// def answered(call, reply):
    ///     route = call.active_route
    ///     if route:
    ///         cdr.write(call, extra={"carrier_id": route.carrier_id,
    ///                                "rate": f"{route.rate:.5f}"})
    /// ```
    #[getter]
    fn active_route(&self) -> Option<super::lcr::PyRoute> {
        self.active_route
            .as_ref()
            .map(|route| super::lcr::PyRoute::from_route(route.clone()))
    }

    /// Every carrier attempt that FAILED before this call settled, oldest first
    /// — the counterpart to `active_route`, which names only the winner.
    ///
    /// Each entry is a dict with `carrier_id`, `status`, `elapsed_ms` and
    /// `dialed`. Empty for a non-LCR call, and for an LCR call whose first
    /// carrier answered.
    ///
    /// `dialed` is `False` when siphon never put an INVITE on the wire for that
    /// carrier — its gateway group was unknown or entirely down, or its
    /// destination would not resolve. `status` is then siphon's own verdict on
    /// the route, not the carrier's answer, so filter on it before counting a
    /// failure against a carrier: a local DNS or gateway problem is not the
    /// carrier's fault and does not belong in their quality figures.
    /// Available wherever the `Call` is (`@b2bua.on_answer`, `on_failure`,
    /// `on_bye`, `on_route_failure`), so a call that answered *after* burning a
    /// carrier can still record which one it burned — siphon stamps the same
    /// list onto the CDR as `lcr_attempts`.
    ///
    /// ```python
    /// @b2bua.on_answer
    /// def answered(call, reply):
    ///     for attempt in call.route_attempts:
    ///         if not attempt["dialed"]:
    ///             continue        # siphon never reached this carrier
    ///         log.warn(f"carrier {attempt['carrier_id']} failed "
    ///                  f"{attempt['status']} after {attempt['elapsed_ms']}ms")
    /// ```
    #[getter]
    fn route_attempts<'py>(&self, python: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.route_attempts
            .iter()
            .map(|attempt| {
                let entry = PyDict::new(python);
                entry.set_item("carrier_id", &attempt.carrier_id)?;
                entry.set_item("status", attempt.status)?;
                entry.set_item("elapsed_ms", attempt.elapsed_ms)?;
                entry.set_item("dialed", attempt.dialed)?;
                Ok(entry)
            })
            .collect()
    }

    /// The Refer-To URI (only set during @b2bua.on_refer handler).
    #[getter]
    fn refer_to(&self) -> Option<&str> {
        self.refer_to_uri.as_deref()
    }

    /// Which side sent the REFER: `"a"` (the caller's leg) or `"b"` (the
    /// callee's), matching the `initiator.side` convention in
    /// `@b2bua.on_bye`. `None` outside an `@b2bua.on_refer` handler.
    ///
    /// The party that SURVIVES the transfer is the peer of this one, which is
    /// what decides the media profile the surviving pair needs — see
    /// `accept_refer(profile=…)`. At a mixed edge (SRTP one side, plain RTP the
    /// other) the answer differs depending on which side is leaving, so this is
    /// what a script keys that decision on:
    ///
    /// ```python
    /// @b2bua.on_refer
    /// def on_refer(call):
    ///     a_leg_is_secure = call.from_gateway("teams")
    ///     referrer_is_secure = a_leg_is_secure == (call.refer_side == "a")
    ///     # The secure party leaving means both survivors are plain RTP.
    ///     profile = "rtp_passthrough" if referrer_is_secure else "srtp_to_rtp"
    ///     call.accept_refer(mode="terminate", profile=profile)
    /// ```
    #[getter]
    fn refer_side(&self) -> Option<&str> {
        self.refer_from_a_leg
            .map(|from_a_leg| if from_a_leg { "a" } else { "b" })
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

    /// Rewrite dialable identity userparts into a target E.164 shape.
    ///
    /// Walks From, To, P-Asserted-Identity, P-Preferred-Identity (and any
    /// opted-in header) on the A-leg INVITE, which flows to the B-leg. Pass
    /// **either** a named `policy` from `number_policies:` **or** an inline
    /// `format` (`"e164"` | `"plain"` | `"international"` | `"national"`) with
    /// an optional `headers` list and `home` country-code override. Returns the
    /// number of headers changed. Must be called before `dial()`.
    ///
    /// ```python
    /// call.rewrite_identities("ims-e164@2026")
    /// call.rewrite_identities(format="e164")
    /// ```
    #[pyo3(signature = (policy=None, format=None, headers=None, home=None))]
    fn rewrite_identities(
        &self,
        policy: Option<&str>,
        format: Option<&str>,
        headers: Option<Vec<String>>,
        home: Option<&str>,
    ) -> PyResult<usize> {
        let resolved = super::numbers::resolve_rewrite_policy(policy, format, headers, home)?;
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(super::numbers::apply_to_message(&mut message, &resolved))
    }

    /// Withhold the calling party's identity on the B-leg (CLIR), per
    /// RFC 3323 §4.1 and 3GPP TS 24.607.
    ///
    /// ```python
    /// @b2bua.on_invite
    /// def route(call):
    ///     if caller_withheld(call):
    ///         call.restrict_caller_id()
    ///     call.dial(str(call.ruri))
    /// ```
    ///
    /// - `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`,
    ///   keeping its dialog tag.
    /// - `Privacy: id` is asserted (RFC 3325 §7), appended to any existing
    ///   `Privacy` value rather than replacing it.
    /// - `P-Asserted-Identity` is left intact, carrying the real identity to
    ///   the trusted next hop — that is how the network stays able to identify
    ///   the caller for regulatory and emergency purposes.
    /// - `P-Preferred-Identity` is removed: it is the UA's *request* for what
    ///   to assert, and forwarding it past a privacy boundary re-leaks the
    ///   number.
    ///
    /// Setting `Privacy: id` by hand while leaving the real number in `From`
    /// leaks it to every carrier that renders `From` rather than
    /// `P-Asserted-Identity` — which defeats CLIR while looking like it works.
    /// This moves both together.
    ///
    /// Call it *after* any identity reshaping: anonymisation is the last step,
    /// or a number policy will try to reformat `anonymous` as a number. The
    /// LCR twin is a route's `caller_id_presentation: "restricted"`.
    fn restrict_caller_id(&self) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        crate::sip::privacy::restrict_calling_identity(&mut message);
        Ok(())
    }

    /// Present `number` as the calling party, on `From` and on
    /// `P-Asserted-Identity` / `P-Preferred-Identity` where present.
    ///
    /// The dialog tag is preserved, which is why this exists rather than a
    /// `set_header("From", ...)`: the B-leg From host is rewritten after the
    /// script runs, and a `From` set without a tag drops the mandatory dialog
    /// tag (RFC 3261 §8.1.1.3) — a failure that only surfaces later, on the
    /// ACK.
    ///
    /// Unlike a number policy, which reshapes the *format* of whatever number
    /// is already there, this substitutes a different one. The LCR twin is a
    /// route's `caller_id`.
    fn set_caller_id(&self, number: &str) -> PyResult<bool> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        Ok(crate::sip::privacy::set_calling_number(
            &mut message,
            number,
        ))
    }

    /// Set the user part of the From header URI.
    ///
    /// Usage in Python:
    ///   call.set_from_user("+33123456789")
    fn set_from_user(&self, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let from_raw = message
            .headers
            .get("From")
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
    ///   call.set_to_user("1000")
    ///   call.dial("sip:1000@ims.mnc001.mcc001.3gppnetwork.org")
    fn set_to_user(&self, value: &str) -> PyResult<()> {
        let mut message = self.message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let to_raw = message
            .headers
            .get("To")
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
            let from_raw = message
                .headers
                .get("From")
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
            let to_raw = message
                .headers
                .get("To")
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
    ///   call.set_to_uri("sip:1000@ims.mnc001.mcc001.3gppnetwork.org")
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
    ///
    /// `mode` selects how siphon honors the transfer:
    ///   - `"terminate"`   — siphon terminates the transfer: answer 202 locally,
    ///     re-resolve the Refer-To through the dial plan as a new leg, re-bridge
    ///     the media, and BYE the referred-away leg. Works even when the far end
    ///     cannot handle REFER; keeps media anchored.
    ///   - `"transparent"` — siphon re-emits the REFER on the far leg's own
    ///     dialog and relays the far end's 202 + sipfrag NOTIFYs back.
    ///   - `None` (default) — use the configured `b2bua.default_refer_mode`.
    ///
    /// `target` optionally rewrites the transfer destination (e.g. E.164
    /// canonicalization or gateway selection) before it is honored; it defaults
    /// to `call.refer_to`. `next_hop` steers egress without changing the target
    /// URI shape (same semantics as `call.dial(next_hop=...)`).
    ///
    /// Usage in Python:
    ///   call.accept_refer()
    ///   call.accept_refer(mode="transparent")
    ///   call.accept_refer(target="sip:+15550142@example.com", mode="terminate")
    ///
    /// `profile` names the media profile for the pairing the transfer creates.
    /// **Required whenever the call is anchored with a direction-bound profile**
    /// — one whose offer and answer describe different sides, such as
    /// `srtp_to_rtp` at a Teams/SRTP edge. Left unset, the transfer inherits the
    /// original call's profile, whose answer half was written for the party that
    /// is being transferred away; the surviving leg is then re-INVITEd with that
    /// party's transport (SRTP toward a plain-RTP carrier) and answers `m=audio
    /// 0`, leaving a connected call with no audio.
    ///
    ///   # both remaining parties are on the carrier side
    ///   call.accept_refer(target=target, next_hop=gw.uri, mode="terminate",
    ///                     profile="rtp_passthrough")
    #[pyo3(signature = (target=None, next_hop=None, mode=None, profile=None))]
    fn accept_refer(
        &mut self,
        target: Option<String>,
        next_hop: Option<String>,
        mode: Option<&str>,
        profile: Option<String>,
    ) -> PyResult<()> {
        let mode = match mode {
            None => None,
            Some("terminate") => Some(ReferMode::Terminate),
            Some("transparent") => Some(ReferMode::Transparent),
            Some(other) => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "accept_refer(mode=…) must be 'terminate' or 'transparent', got {other:?}"
                )));
            }
        };
        self.action = CallAction::AcceptRefer {
            target,
            next_hop,
            mode,
            profile,
        };
        Ok(())
    }

    /// Reject the REFER with a status code and reason.
    fn reject_refer(&mut self, code: u16, reason: &str) {
        self.action = CallAction::RejectRefer {
            code,
            reason: reason.to_string(),
        };
    }

    /// Originate an outbound REFER on this call's connected leg — siphon is the
    /// referrer (UAS-mode / IVR offload). `target` is the Refer-To URI the peer
    /// should contact; `replaces` (a dict with keys `call_id` / `from_tag` /
    /// `to_tag` and optional `early_only`) makes it an attended transfer, or
    /// `None` for a blind transfer.
    ///
    /// Deferred: takes effect when the handler returns (use from
    /// `@b2bua.on_answer`). For event-callback contexts such as
    /// `@rtpengine.on_dtmf` — where deferred call actions are silent no-ops —
    /// use the imperative `b2bua.refer(call_id, target)` instead.
    ///
    /// Usage in Python:
    ///   call.refer("sip:+15550142@example.com")
    ///   call.refer("sip:carol@example.com",
    ///              replaces={"call_id": "abc", "from_tag": "a", "to_tag": "b"})
    #[pyo3(signature = (target, replaces=None))]
    fn refer(
        &mut self,
        target: &str,
        replaces: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<()> {
        let replaces = parse_replaces_dict(replaces)?;
        self.action = CallAction::SendRefer {
            refer_to: crate::sip::headers::refer::ReferTo {
                uri: target.to_string(),
                replaces,
            },
        };
        Ok(())
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

    // -----------------------------------------------------------------------
    // call.flow — RFC 5626 connection reuse
    // -----------------------------------------------------------------------

    fn test_flow(
        transport: &str,
        source: &str,
        local: &str,
        connection_id: u64,
    ) -> super::super::registrar::PyFlow {
        super::super::registrar::PyFlow {
            transport: transport.to_string(),
            source_addr: source.parse().expect("test source addr"),
            local_addr: local.parse().expect("test local addr"),
            connection_id,
        }
    }

    fn call_on(flow: Option<super::super::registrar::PyFlow>) -> PyCall {
        PyCall::new(
            "test-id".to_string(),
            Arc::new(Mutex::new(make_invite())),
            "192.0.2.10".to_string(),
            "tls".to_string(),
        )
        .with_flow(flow)
    }

    #[test]
    fn call_flow_is_none_when_no_transport_binding_was_captured() {
        // An internally-originated call has no inbound flow to describe, and a
        // script must be able to tell that apart from a flow that didn't match.
        assert!(call_on(None).flow().is_none());
    }

    #[test]
    fn call_flow_exposes_the_captured_inbound_flow() {
        let flow = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);
        let call = call_on(Some(flow));

        let exposed = call.flow().expect("flow present");
        assert_eq!(exposed.transport(), "tls");
        assert_eq!(exposed.remote_addr(), "192.0.2.10:41234");
        assert_eq!(exposed.local_addr(), "198.51.100.1:5061");
        assert_eq!(exposed.connection_id(), 0xc0ffee);
    }

    #[test]
    fn a_call_on_the_registered_connection_matches_that_binding_flow() {
        // The authorisation this exists for: the INVITE arrived on the same
        // accepted socket the REGISTER did, so it is the registered UE.
        let registered = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);
        let call = call_on(Some(registered.clone()));

        assert_eq!(call.flow(), Some(registered));
    }

    #[test]
    fn a_call_from_the_same_address_on_a_new_connection_does_not_match() {
        // This is the whole point over a source-address check. Behind carrier
        // NAT every subscriber shares an address, so the address matching says
        // nothing; the accepted connection is what carries the assurance.
        let registered = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);
        let reconnected = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xbeef);

        assert_ne!(call_on(Some(reconnected)).flow(), Some(registered));
    }

    #[test]
    fn a_call_on_a_different_transport_does_not_match() {
        let registered = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);
        let over_tcp = test_flow("tcp", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);

        assert_ne!(call_on(Some(over_tcp)).flow(), Some(registered));
    }

    #[test]
    fn the_match_survives_the_ue_reusing_the_connection_across_calls() {
        // The connection id identifies the socket, not the transaction, so a
        // second and third call over the same connection still match.
        let registered = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);

        for _ in 0..3 {
            assert_eq!(
                call_on(Some(registered.clone())).flow(),
                Some(registered.clone())
            );
        }
    }

    #[test]
    fn call_flow_is_comparable_and_hashable_from_python() {
        // `call.flow == contact.flow` has to work as an expression in a script,
        // and a flow has to be usable as a dict key / set member. pyclass needs
        // `eq` + `hash` for either; a Rust-only PartialEq gives neither.
        Python::initialize();
        Python::attach(|py| {
            let flow = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xc0ffee);
            let other = test_flow("tls", "192.0.2.10:41234", "198.51.100.1:5061", 0xbeef);

            let same_a = Py::new(py, flow.clone()).expect("flow into Python");
            let same_b = Py::new(py, flow).expect("flow into Python");
            let different = Py::new(py, other).expect("flow into Python");

            assert!(same_a
                .bind(py)
                .eq(same_b.bind(py))
                .expect("Flow must support =="));
            assert!(!same_a
                .bind(py)
                .eq(different.bind(py))
                .expect("Flow must support =="));

            // Hashable, and equal flows hash equal, so a set/dict works.
            let hash_a = same_a.bind(py).hash().expect("Flow must be hashable");
            let hash_b = same_b.bind(py).hash().expect("Flow must be hashable");
            assert_eq!(hash_a, hash_b);
        });
    }

    #[test]
    fn call_initial_state() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.id, "test-id");
        assert_eq!(call.state, "calling");
        assert_eq!(call.action(), &CallAction::None);
    }

    #[test]
    fn call_auth_user_starts_unset_and_records_the_verified_username() {
        // The B2BUA twin of request.auth_user, set by
        // auth.require_proxy_digest(call, …) once the caller answers a
        // challenge, and read back by the dispatcher for the call's CDR.
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.get_auth_user(), None);
        assert_eq!(call.auth_user(), None);

        call.set_auth_user("alice".to_string());
        assert_eq!(call.get_auth_user(), Some("alice"));
        assert_eq!(call.auth_user(), Some("alice"));
    }

    #[test]
    fn call_auth_user_can_be_overwritten_and_cleared_from_a_script() {
        // Same mock-versus-runtime parity gap as request.auth_user: the SDK
        // mock exposed a writable property, the binding had only a getter.
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_auth_user("qualifier:alice".to_string());

        call.py_set_auth_user(Some("alice".to_string()));
        assert_eq!(call.auth_user(), Some("alice"));
        // The accessor the dispatcher reads for the call's CDR agrees.
        assert_eq!(call.get_auth_user(), Some("alice"));

        call.py_set_auth_user(None);
        assert_eq!(call.auth_user(), None);
        assert_eq!(call.get_auth_user(), None);
    }

    #[test]
    fn call_auth_user_is_writable_from_python_not_just_from_rust() {
        // Same reasoning as the Request twin: the gap this closes is a
        // mock-versus-runtime one, so the assertion that matters is that the
        // Python attribute accepts an assignment.
        Python::initialize();
        Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            call.set_auth_user("qualifier:alice".to_string());
            let object = Py::new(py, call).expect("PyCall into Python");

            let bound = object.bind(py);
            bound
                .setattr("auth_user", "alice")
                .expect("auth_user must be assignable from Python");

            let read_back: Option<String> = bound
                .getattr("auth_user")
                .and_then(|value| value.extract())
                .expect("auth_user readable");
            assert_eq!(read_back.as_deref(), Some("alice"));

            // The accessor the dispatcher reads for the call's CDR agrees.
            assert_eq!(object.borrow(py).get_auth_user(), Some("alice"));
        });
    }

    #[test]
    fn call_exposes_source_ip_and_transport_to_rust_callers() {
        // The digest helpers read both off the Call for auto-ban bookkeeping
        // (a bad-credentials attempt is only a strong signal over a
        // handshake-validated transport).
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "203.0.113.9".to_string(),
            "tls".to_string(),
        );
        assert_eq!(call.source_ip_str(), "203.0.113.9");
        assert_eq!(call.transport_str(), "tls");
    }

    #[test]
    fn call_reject() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
    fn call_set_reject_sets_reject_action() {
        // The Rust-side setter used by rtpengine.answer_local(auto_reject=True)
        // records the same deferred CallAction::Reject as call.reject().
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_reject(488, "Not Acceptable Here");
        assert_eq!(
            call.action(),
            &CallAction::Reject {
                code: 488,
                reason: "Not Acceptable Here".to_string()
            }
        );
    }

    #[test]
    fn call_handover_sets_handover_action() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let mut vars = std::collections::HashMap::new();
        vars.insert("queue".to_string(), "support".to_string());
        call.handover(
            "ivr-app",
            Some("hangup"),
            Some(3000),
            Some(vars.clone()),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::Handover {
                app: "ivr-app".to_string(),
                on_lost: Some("hangup".to_string()),
                deadline_ms: Some(3000),
                vars,
                answer: false,
                profile: None,
                ws_uri: None,
            }
        );
    }

    #[test]
    fn call_handover_answer_mode_sets_flag_and_media_args() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.handover(
            "ai-app",
            None,
            None,
            None,
            true,
            Some("voice_ai"),
            Some("wss://ai/{call_id}"),
        )
        .unwrap();
        assert!(matches!(
            call.action(),
            CallAction::Handover {
                answer: true,
                profile: Some(ref p),
                ws_uri: Some(ref u),
                ..
            } if p == "voice_ai" && u == "wss://ai/{call_id}"
        ));
    }

    #[test]
    fn call_handover_media_args_require_answer_true() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        // profile/ws_uri without answer=True is a programming error.
        assert!(call
            .handover("app", None, None, None, false, Some("voice_ai"), None)
            .is_err());
        assert!(call
            .handover("app", None, None, None, false, None, Some("wss://ai"))
            .is_err());
    }

    #[test]
    fn call_handover_rejects_empty_app_and_bad_on_lost() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert!(call
            .handover("", None, None, None, false, None, None)
            .is_err());
        assert!(call
            .handover("app", Some("explode"), None, None, false, None, None)
            .is_err());
        // Valid policies are accepted.
        assert!(call
            .handover("app", Some("continue"), None, None, false, None, None)
            .is_ok());
        assert!(call
            .handover("app", Some("fallback"), None, None, false, None, None)
            .is_ok());
    }

    #[test]
    fn call_dial() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:bob@10.0.0.2:5060",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::Dial {
                target: "sip:bob@10.0.0.2:5060".to_string(),
                next_hop: None,
                flow: None,
                route: vec![],
                send_socket: None,
                timeout: 30,
            }
        );
        // No policy kwargs → no input captured (existing scripts pay zero cost)
        assert!(call.header_policy_input().is_none());
    }

    #[test]
    fn call_dial_with_route() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:1000@ims.mnc01.mcc001.3gppnetwork.org",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec!["<sip:scscf.ims.mnc01.mcc001.3gppnetwork.org:6060;lr>".to_string()],
            None,
            false,
            None,
        )
        .unwrap();
        match call.action() {
            CallAction::Dial { route, .. } => {
                assert_eq!(
                    route,
                    &vec!["<sip:scscf.ims.mnc01.mcc001.3gppnetwork.org:6060;lr>".to_string()]
                );
            }
            other => panic!("expected Dial, got {other:?}"),
        }
    }

    #[test]
    fn call_dial_next_hop() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:1000@ims.mnc001.mcc001.3gppnetwork.org",
            30,
            Some("sip:192.0.2.178:4060"),
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::Dial {
                target: "sip:1000@ims.mnc001.mcc001.3gppnetwork.org".to_string(),
                next_hop: Some("sip:192.0.2.178:4060".to_string()),
                flow: None,
                route: vec![],
                send_socket: None,
                timeout: 30,
            }
        );
    }

    #[test]
    fn call_dial_with_header_policy_and_deltas() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
            None,
            false,
            None,
        )
        .unwrap();
        let input = call
            .header_policy_input()
            .expect("policy input must be captured");
        assert_eq!(
            input.policy_name.as_deref(),
            Some("ims-trust-domain-boundary@2026")
        );
        assert_eq!(input.deltas_copy, vec!["X-Operator-Tag".to_string()]);
        assert_eq!(input.deltas_strip, vec!["History-Info".to_string()]);
        assert_eq!(
            input.deltas_translate,
            vec![("Diversion".to_string(), "rfc7044".to_string())]
        );
    }

    #[test]
    fn call_dial_with_send_socket() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:bob@10.0.0.2:5060",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            Some("udp:10.0.0.1:5060".to_string()),
            false,
            None,
        )
        .unwrap();
        match call.action() {
            CallAction::Dial { send_socket, .. } => {
                assert_eq!(send_socket.as_deref(), Some("udp:10.0.0.1:5060"));
            }
            other => panic!("expected Dial, got {other:?}"),
        }
    }

    #[test]
    fn call_dial_rejects_malformed_send_socket() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let result = call.dial(
            "sip:bob@10.0.0.2:5060",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            Some("not-a-socket".to_string()),
            false,
            None,
        );
        assert!(result.is_err());
    }

    /// A registered binding with an RFC 3327 Path vector, as
    /// `registrar.lookup()` hands it to a script.
    fn binding_with_path(uri: &str, path: Vec<String>) -> super::super::registrar::PyContact {
        let contact = crate::registrar::Contact {
            uri: crate::sip::parser::parse_uri_standalone(uri).unwrap(),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: std::time::Duration::from_secs(3600),
            call_id: "reg-call-id".into(),
            cseq: 1,
            source_addr: None,
            source_transport: Some(crate::transport::Transport::Udp),
            sip_instance: None,
            reg_id: None,
            path,
            pending: false,
            instance: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: Vec::new(),
            kind: crate::registrar::ContactKind::Ue,
        };
        super::super::registrar::PyContact::from_rust_contact(&contact)
    }

    #[test]
    fn parallel_fork_carries_each_bindings_own_path() {
        // The B2BUA builds a fresh B-leg INVITE, so a binding registered
        // through an edge proxy is only reachable if that branch carries the
        // binding's own Path as its route set.  A shared one would send every
        // branch through the first binding's proxy chain.
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let contact_a = binding_with_path(
                "sip:bob@10.0.0.2:5060",
                vec!["<sip:TOKEN-A@edge.example.com;lr>".to_string()],
            );
            let contact_b = binding_with_path(
                "sip:bob@10.0.0.3:5060",
                vec!["<sip:TOKEN-B@edge.example.com;lr>".to_string()],
            );
            let targets: Vec<Bound<'_, PyAny>> = vec![
                Py::new(py, contact_a).unwrap().into_bound(py).into_any(),
                Py::new(py, contact_b).unwrap().into_bound(py).into_any(),
                pyo3::types::PyString::new(py, "sip:carol@10.0.0.4").into_any(),
            ];
            call.fork(
                targets,
                "parallel",
                30,
                None,
                vec![],
                vec![],
                vec![],
                None,
                false,
                None,
            )
            .unwrap();

            match call.action() {
                CallAction::Fork {
                    targets, routes, ..
                } => {
                    assert_eq!(targets.len(), 3);
                    assert_eq!(routes.len(), 3, "routes stay parallel to targets");
                    assert_eq!(
                        routes[0],
                        vec!["<sip:TOKEN-A@edge.example.com;lr>".to_string()]
                    );
                    assert_eq!(
                        routes[1],
                        vec!["<sip:TOKEN-B@edge.example.com;lr>".to_string()]
                    );
                    assert!(routes[2].is_empty(), "a bare string target carries no Path");
                }
                other => panic!("expected Fork, got {other:?}"),
            }
        });
    }

    #[test]
    fn sequential_fork_carries_each_bindings_path_as_route_and_next_hop() {
        // The sequential path runs through the LCR route-sequence engine, so
        // the binding's route set has to arrive as an explicit next-hop (where
        // the branch is sent) plus a Route header (the per-registration token
        // that tells the edge proxy which binding the call is for).
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let contact = binding_with_path(
                "sip:bob@10.0.0.2:5060",
                vec!["<sip:TOKEN-A@edge.example.com;lr>".to_string()],
            );
            let targets: Vec<Bound<'_, PyAny>> = vec![
                Py::new(py, contact).unwrap().into_bound(py).into_any(),
                pyo3::types::PyString::new(py, "sip:carol@10.0.0.4").into_any(),
            ];
            call.fork(
                targets,
                "sequential",
                30,
                None,
                vec![],
                vec![],
                vec![],
                None,
                false,
                None,
            )
            .unwrap();

            match call.action() {
                CallAction::RouteSequence { routes, .. } => {
                    assert_eq!(routes.len(), 2);
                    // The binding routes through its edge proxy, R-URI intact.
                    assert_eq!(routes[0].ruri.as_deref(), Some("sip:bob@10.0.0.2:5060"));
                    assert!(routes[0]
                        .next_hop
                        .as_deref()
                        .unwrap()
                        .contains("TOKEN-A@edge.example.com"));
                    assert_eq!(
                        routes[0].headers.get("Route").map(String::as_str),
                        Some("<sip:TOKEN-A@edge.example.com;lr>")
                    );
                    // A bare string keeps pure R-URI routing, exactly as before.
                    assert_eq!(routes[1].ruri.as_deref(), Some("sip:carol@10.0.0.4"));
                    assert!(routes[1].next_hop.is_none());
                    assert!(routes[1].headers.is_empty());
                }
                other => panic!("expected RouteSequence, got {other:?}"),
            }
        });
    }

    #[test]
    fn call_fork() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let targets: Vec<Bound<'_, PyAny>> = vec![
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.2").into_any(),
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.3").into_any(),
            ];
            call.fork(
                targets,
                "parallel",
                30,
                None,
                vec![],
                vec![],
                vec![],
                None,
                false,
                None,
            )
            .unwrap();
            assert_eq!(
                call.action(),
                &CallAction::Fork {
                    targets: vec![
                        "sip:bob@10.0.0.2".to_string(),
                        "sip:bob@10.0.0.3".to_string()
                    ],
                    flows: vec![None, None],
                    routes: vec![vec![], vec![]],
                    strategy: "parallel".to_string(),
                    send_socket: None,
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
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let targets: Vec<Bound<'_, PyAny>> = vec![
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.2").into_any(),
                pyo3::types::PyString::new(py, "sip:bob@10.0.0.3").into_any(),
            ];
            call.fork(
                targets,
                "parallel",
                30,
                Some("sip-trunk-edge@2026"),
                vec![],
                vec!["X-Internal-Tag".to_string()],
                vec![],
                None,
                false,
                None,
            )
            .unwrap();
            let input = call
                .header_policy_input()
                .expect("policy input must be captured");
            assert_eq!(input.policy_name.as_deref(), Some("sip-trunk-edge@2026"));
            assert_eq!(input.deltas_strip, vec!["X-Internal-Tag".to_string()]);
        });
    }

    #[test]
    fn call_dial_auth_passthrough_sets_flag_and_copies_both_auth_headers() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:bob@pbx.example.com:5060",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            true,
            None,
        )
        .unwrap();
        assert!(call.auth_passthrough(), "auth_passthrough flag must be set");
        let input = call
            .header_policy_input()
            .expect("auth_passthrough must capture policy input via the injected copies");
        // The challenge (Proxy-Authenticate, B→A) and credentials (Proxy-Authorization,
        // A→B) must both be copied so device-driven auth crosses the B2BUA (RFC 3261 §22.3).
        assert!(input
            .deltas_copy
            .iter()
            .any(|h| h.eq_ignore_ascii_case("Proxy-Authenticate")));
        assert!(input
            .deltas_copy
            .iter()
            .any(|h| h.eq_ignore_ascii_case("Proxy-Authorization")));
    }

    #[test]
    fn call_dial_auth_passthrough_does_not_duplicate_or_clobber_script_copies() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        // Script already listed Proxy-Authenticate (case-insensitive) plus an unrelated
        // header; auth_passthrough must add only the missing Proxy-Authorization and
        // preserve the script's own copies.
        call.dial(
            "sip:bob@pbx.example.com:5060",
            30,
            None,
            None,
            None,
            vec!["proxy-authenticate".to_string(), "X-Keep".to_string()],
            vec![],
            vec![],
            vec![],
            None,
            true,
            None,
        )
        .unwrap();
        let input = call.header_policy_input().expect("policy input captured");
        let authenticate_count = input
            .deltas_copy
            .iter()
            .filter(|h| h.eq_ignore_ascii_case("Proxy-Authenticate"))
            .count();
        assert_eq!(
            authenticate_count, 1,
            "must not duplicate a script-supplied Proxy-Authenticate"
        );
        assert!(
            input.deltas_copy.iter().any(|h| h == "X-Keep"),
            "script copies preserved"
        );
        assert!(input
            .deltas_copy
            .iter()
            .any(|h| h.eq_ignore_ascii_case("Proxy-Authorization")));
    }

    #[test]
    fn call_dial_auth_passthrough_defaults_false_zero_cost() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.dial(
            "sip:bob@10.0.0.2:5060",
            30,
            None,
            None,
            None,
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            false,
            None,
        )
        .unwrap();
        assert!(!call.auth_passthrough());
        // No auth_passthrough and no policy kwargs → nothing captured (existing scripts pay zero cost).
        assert!(call.header_policy_input().is_none());
    }

    #[test]
    fn call_terminate() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.terminate();
        assert_eq!(call.action(), &CallAction::Terminate);
    }

    #[test]
    fn call_state_transition() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.state, "calling");
        call.set_state("ringing");
        assert_eq!(call.state, "ringing");
        call.set_state("answered");
        assert_eq!(call.state, "answered");
    }

    #[test]
    fn call_header_access() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(
            call.get_header("Call-ID").unwrap(),
            Some("call-test-1".to_string())
        );
        assert!(call.has_header("Via").unwrap());
        assert!(!call.has_header("X-Custom").unwrap());
    }

    #[test]
    fn call_session_timer_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.accept_refer(None, None, None, None).unwrap();
        assert_eq!(
            call.action(),
            &CallAction::AcceptRefer {
                target: None,
                next_hop: None,
                mode: None,
                profile: None,
            }
        );
    }

    #[test]
    fn call_accept_refer_transparent_with_target() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.accept_refer(
            Some("sip:+15550142@example.com".to_string()),
            Some("sip:198.51.100.1:5060".to_string()),
            Some("transparent"),
            None,
        )
        .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::AcceptRefer {
                target: Some("sip:+15550142@example.com".to_string()),
                next_hop: Some("sip:198.51.100.1:5060".to_string()),
                mode: Some(ReferMode::Transparent),
                profile: None,
            }
        );
    }

    #[test]
    fn call_accept_refer_terminate_mode() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.accept_refer(None, None, Some("terminate"), None)
            .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::AcceptRefer {
                target: None,
                next_hop: None,
                mode: Some(ReferMode::Terminate),
                profile: None,
            }
        );
    }

    /// The media profile for the pairing a transfer creates is the script's to
    /// choose; without it the transfer inherits the profile the call was
    /// anchored with, whose answer half was written for the party leaving.
    /// Which leg referred is what tells a script which party survives, and
    /// therefore which media profile the surviving pair needs.
    #[test]
    fn call_refer_side_reports_the_referring_leg() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        // Outside an on_refer handler there is no referring leg.
        assert_eq!(call.refer_side(), None);

        call.set_refer_from_a_leg(true);
        assert_eq!(call.refer_side(), Some("a"));

        call.set_refer_from_a_leg(false);
        assert_eq!(
            call.refer_side(),
            Some("b"),
            "matches the on_bye initiator convention"
        );
    }

    #[test]
    fn call_accept_refer_carries_a_media_profile() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.accept_refer(
            None,
            None,
            Some("terminate"),
            Some("rtp_passthrough".to_string()),
        )
        .unwrap();
        assert_eq!(
            call.action(),
            &CallAction::AcceptRefer {
                target: None,
                next_hop: None,
                mode: Some(ReferMode::Terminate),
                profile: Some("rtp_passthrough".to_string()),
            }
        );
    }

    #[test]
    fn call_accept_refer_rejects_bad_mode() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let result = call.accept_refer(None, None, Some("bridge"), None);
        assert!(result.is_err());
        // The invalid call must not have mutated the action.
        assert_eq!(call.action(), &CallAction::None);
    }

    #[test]
    fn call_reject_refer() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
    fn call_refer_blind() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.refer("sip:+15550142@example.com", None).unwrap();
        match call.action() {
            CallAction::SendRefer { refer_to } => {
                assert_eq!(refer_to.uri, "sip:+15550142@example.com");
                assert!(refer_to.replaces.is_none());
            }
            other => panic!("expected SendRefer, got {other:?}"),
        }
    }

    #[test]
    fn call_refer_attended() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let message = Arc::new(Mutex::new(make_invite()));
            let mut call = PyCall::new(
                "test-id".to_string(),
                message,
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("call_id", "abc@example.com").unwrap();
            dict.set_item("from_tag", "a-tag").unwrap();
            dict.set_item("to_tag", "b-tag").unwrap();
            dict.set_item("early_only", true).unwrap();
            call.refer("sip:carol@example.com", Some(&dict)).unwrap();
            match call.action() {
                CallAction::SendRefer { refer_to } => {
                    assert_eq!(refer_to.uri, "sip:carol@example.com");
                    let replaces = refer_to
                        .replaces
                        .as_ref()
                        .expect("attended → Some(Replaces)");
                    assert_eq!(replaces.call_id, "abc@example.com");
                    assert_eq!(replaces.from_tag, "a-tag");
                    assert_eq!(replaces.to_tag, "b-tag");
                    assert!(replaces.early_only);
                }
                other => panic!("expected SendRefer, got {other:?}"),
            }
        });
    }

    #[test]
    fn parse_replaces_dict_missing_key_errors() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("call_id", "abc@example.com").unwrap();
            // from_tag / to_tag missing → ValueError
            assert!(parse_replaces_dict(Some(&dict)).is_err());
        });
    }

    #[test]
    fn parse_replaces_dict_none_is_none() {
        assert!(parse_replaces_dict(None).unwrap().is_none());
    }

    #[test]
    fn call_refer_to_initially_none() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert!(call.refer_to_uri.is_none());
        assert!(call.refer_replaces_info.is_none());
    }

    #[test]
    fn call_set_refer_to_blind() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_refer_to("sip:carol@example.com".to_string(), None);
        assert_eq!(call.refer_to_uri.as_deref(), Some("sip:carol@example.com"));
        assert!(call.refer_replaces_info.is_none());
    }

    #[test]
    fn call_set_refer_to_attended() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
        let call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
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
        let call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_from_user("+33999888777").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(
            from.contains("+33999888777@atlanta.com"),
            "From should contain new user: {from}"
        );
        assert!(
            from.contains(";tag=abc"),
            "From should preserve tag: {from}"
        );
    }

    #[test]
    fn call_set_to_user() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_to_user("1000").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(
            to.contains("1000@example.com"),
            "To should contain new user: {to}"
        );
        assert!(
            !to.contains(";tag="),
            "Initial INVITE To must not gain a tag: {to}"
        );
    }

    #[test]
    fn call_set_to_user_preserves_tag() {
        let mut invite = make_invite();
        invite
            .headers
            .set("To", "<sip:bob@example.com>;tag=remote-tag".to_string());
        let message = Arc::new(Mutex::new(invite));
        let call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_to_user("1000").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(
            to.contains("1000@example.com"),
            "To should contain new user: {to}"
        );
        assert!(
            to.contains(";tag=remote-tag"),
            "To should preserve existing tag: {to}"
        );
    }

    #[test]
    fn call_set_from_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_from_host("tenant.example.com").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(
            from.contains("alice@tenant.example.com"),
            "From host should change: {from}"
        );
        assert!(
            !from.contains("atlanta.com"),
            "old From host must be gone: {from}"
        );
        assert!(
            from.contains(";tag=abc"),
            "From should preserve tag: {from}"
        );
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
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_from_host("tenant.example.com").unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("\"Alice\""), "display name preserved: {from}");
        assert!(
            from.contains("1001@tenant.example.com:5060"),
            "user+host+port: {from}"
        );
        assert!(from.contains(";tag=xyz"), "tag preserved: {from}");
        assert!(!from.contains("old.example.com"), "old host gone: {from}");
    }

    #[test]
    fn call_set_to_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_to_host("trunk.example.com").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(
            to.contains("bob@trunk.example.com"),
            "To host should change: {to}"
        );
        assert!(
            !to.contains("example.com>") || to.contains("trunk.example.com"),
            "old host replaced: {to}"
        );
        assert!(
            !to.contains(";tag="),
            "initial INVITE To must not gain a tag: {to}"
        );
        drop(msg);
        assert_eq!(call.to_host_override(), Some("trunk.example.com"));
    }

    #[test]
    fn call_set_from_host_none_by_default() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.from_host_override(), None);
        assert_eq!(call.to_host_override(), None);
    }

    #[test]
    fn call_set_from_uri_replaces_uri_and_pins_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_from_uri("sip:1001@tenant.example.com:5070;transport=tcp")
            .unwrap();
        let msg = message.lock().unwrap();
        let from = msg.headers.get("From").unwrap();
        assert!(
            from.contains("1001@tenant.example.com:5070"),
            "user+host+port: {from}"
        );
        assert!(
            from.contains("transport=tcp"),
            "uri params preserved: {from}"
        );
        assert!(from.contains(";tag=abc"), "From tag preserved: {from}");
        assert!(!from.contains("atlanta.com"), "old host gone: {from}");
        drop(msg);
        // Host is pinned so the B-leg builder's topology-hiding rewrite honours it.
        assert_eq!(call.from_host_override(), Some("tenant.example.com"));
    }

    #[test]
    fn call_set_to_uri_replaces_uri_and_pins_host() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_to_uri("sip:1000@ims.example.org").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("1000@ims.example.org"), "user+host: {to}");
        assert!(!to.contains("example.com"), "old host gone: {to}");
        assert!(
            !to.contains(";tag="),
            "initial INVITE To must not gain a tag: {to}"
        );
        drop(msg);
        assert_eq!(call.to_host_override(), Some("ims.example.org"));
    }

    #[test]
    fn call_set_to_uri_preserves_display_and_tag() {
        let mut invite = make_invite();
        invite
            .headers
            .set("To", "\"Bob\" <sip:bob@example.com>;tag=remote".to_string());
        let message = Arc::new(Mutex::new(invite));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message.clone(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_to_uri("sip:1000@ims.example.org").unwrap();
        let msg = message.lock().unwrap();
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("\"Bob\""), "display preserved: {to}");
        assert!(to.contains("1000@ims.example.org"), "uri replaced: {to}");
        assert!(to.contains(";tag=remote"), "tag preserved: {to}");
    }

    #[test]
    fn call_set_contact_user_sets_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.contact_user_override(), None);
        call.set_contact_user("1001").unwrap();
        assert_eq!(call.contact_user_override(), Some("1001"));
    }

    #[test]
    fn call_set_contact_uri_sets_override() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(call.contact_override(), None);
        call.set_contact_uri("sip:gruu-token@edge.example.com:5060")
            .unwrap();
        assert_eq!(
            call.contact_override(),
            Some("sip:gruu-token@edge.example.com:5060")
        );
    }

    #[test]
    fn call_set_contact_uri_rejects_invalid() {
        let message = Arc::new(Mutex::new(make_invite()));
        let mut call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert!(call.set_contact_uri("not-a-uri").is_err());
        assert_eq!(call.contact_override(), None);
    }

    #[test]
    fn call_set_and_remove_header() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        call.set_header("X-Custom", "test-value").unwrap();
        assert_eq!(
            call.get_header("X-Custom").unwrap(),
            Some("test-value".to_string())
        );
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
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let manager = gateway_manager_with_group();
        assert!(call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_for_non_member_source() {
        let message = Arc::new(Mutex::new(make_invite()));
        // RFC 5737 TEST-NET-1 — not a member of the group.
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "192.0.2.7".to_string(),
            "udp".to_string(),
        );
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_for_unknown_group() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("nonexistent", Some(&manager)));
    }

    #[test]
    fn call_from_gateway_false_when_no_manager() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert!(!call.from_gateway_impl("trunks", None));
    }

    #[test]
    fn call_from_gateway_false_for_unparseable_source_ip() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "test-id".to_string(),
            message,
            "not-an-ip".to_string(),
            "udp".to_string(),
        );
        let manager = gateway_manager_with_group();
        assert!(!call.from_gateway_impl("trunks", Some(&manager)));
    }

    #[test]
    fn call_source_ip_in_matches_v4_and_v6_cidrs() {
        let message = Arc::new(Mutex::new(make_invite()));
        // IPv4 source inside a /24; outside another; malformed entries skipped.
        let call = PyCall::new(
            "t".to_string(),
            Arc::clone(&message),
            "203.0.113.9".to_string(),
            "tls".to_string(),
        );
        assert!(call
            .source_ip_in(vec!["203.0.113.0/24".to_string()])
            .unwrap());
        assert!(!call
            .source_ip_in(vec!["198.51.100.0/24".to_string()])
            .unwrap());
        assert!(call
            .source_ip_in(vec!["garbage".to_string(), "203.0.113.0/24".to_string()])
            .unwrap());

        // IPv6 source inside a /32; outside another.
        let call6 = PyCall::new(
            "t".to_string(),
            Arc::clone(&message),
            "2001:db8::5".to_string(),
            "tls".to_string(),
        );
        assert!(call6
            .source_ip_in(vec!["2001:db8::/32".to_string()])
            .unwrap());
        assert!(!call6
            .source_ip_in(vec!["2001:db9::/32".to_string()])
            .unwrap());
    }

    #[test]
    fn call_source_ip_in_raises_on_bad_source_ip() {
        let message = Arc::new(Mutex::new(make_invite()));
        let call = PyCall::new(
            "t".to_string(),
            message,
            "not-an-ip".to_string(),
            "udp".to_string(),
        );
        assert!(call
            .source_ip_in(vec!["203.0.113.0/24".to_string()])
            .is_err());
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
        // A B2BUA Rf record is keyed on the internal call UUID, not on either
        // leg's dialog — offering only the dialog keys is why the Rf stamp
        // never resolved for a B2BUA call.
        assert_eq!(keys.first().map(String::as_str), Some("b2bua:test-id"));
        // make_invite() has Call-ID "call-test-1" and From-tag "abc"; the
        // dialog-keyed candidate must be present so the Rf auto-stamp can hit.
        assert!(
            keys.iter()
                .any(|k| k.contains("call-test-1") && k.contains("abc")),
            "expected a dialog key with Call-ID + From-tag, got {keys:?}"
        );
    }

    /// A B2BUA call's CDR is tracked under the internal call UUID (one record
    /// for two dialogs), which is what `cdr.write(call, extra=…)` has to
    /// resolve to reach it.
    #[test]
    fn call_cdr_session_key_is_the_internal_call_id() {
        let call = PyCall::new(
            "test-id".to_string(),
            Arc::new(Mutex::new(make_invite())),
            "10.0.0.1".to_string(),
            "udp".to_string(),
        );
        assert_eq!(
            call.cdr_session_key_candidates(),
            vec!["test-id".to_string()]
        );
    }
}
