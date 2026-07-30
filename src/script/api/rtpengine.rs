//! PyO3 wrapper for RTPEngine — the `rtpengine` namespace in Python scripts.
//!
//! Scripts interact via:
//!   from siphon import rtpengine
//!   rtpengine.offer(request, profile="srtp_to_rtp")   # proxy script
//!   rtpengine.offer(call, profile="srtp_to_rtp")      # B2BUA script
//!   rtpengine.answer(reply, profile="srtp_to_rtp")
//!   rtpengine.delete(request)
//!   rtpengine.delete(call)
//!   rtpengine.ping()

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::{debug, warn};

use crate::rtpengine::client::PlayMediaSource;
use crate::rtpengine::profile::{NgFlags, ProfileRegistry};
use crate::rtpengine::MediaBackend;
use crate::rtpengine::RtpEngineError;
use crate::rtpengine::session::{MediaSession, MediaSessionStore};
use crate::sip::message::SipMessage;

use super::call::PyCall;
use super::reply::PyReply;
use super::request::PyRequest;

/// Python-visible RTPEngine namespace.
///
/// Injected as `siphon.rtpengine` when media config is present.
#[pyclass(name = "RtpEngineNamespace")]
pub struct PyRtpEngine {
    client: Arc<MediaBackend>,
    sessions: Arc<MediaSessionStore>,
    registry: Arc<ProfileRegistry>,
}

impl PyRtpEngine {
    pub fn new(
        client: Arc<MediaBackend>,
        sessions: Arc<MediaSessionStore>,
        registry: Arc<ProfileRegistry>,
    ) -> Self {
        Self { client, sessions, registry }
    }

    /// Shared body for `silence_media`/`unsilence_media`/`block_media`/`unblock_media`.
    fn simple_media_command<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        method: &'static str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let result = match method {
                "silence_media" => client.silence_media(&call_id, &from_tag).await,
                "unsilence_media" => client.unsilence_media(&call_id, &from_tag).await,
                "block_media" => client.block_media(&call_id, &from_tag).await,
                "unblock_media" => client.unblock_media(&call_id, &from_tag).await,
                other => {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "unknown simple media command: {other}"
                    )))
                }
            };
            result.map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "rtpengine.{method} failed: {error}"
                ))
            })?;
            debug!(call_id = %call_id, method = %method, "rtpengine simple media command");
            Ok(true)
        })
    }
}

/// Validate exactly-one of ``file``/``blob``/``db_id`` and build a [`PlayMediaSource`].
fn resolve_play_media_source(
    file: Option<String>,
    blob: Option<Vec<u8>>,
    db_id: Option<u64>,
) -> PyResult<PlayMediaSource> {
    let count = [file.is_some(), blob.is_some(), db_id.is_some()]
        .iter()
        .filter(|present| **present)
        .count();
    if count != 1 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "play_media requires exactly one of file=, blob=, or db_id="
                .to_string(),
        ));
    }
    if let Some(path) = file {
        return Ok(PlayMediaSource::File(path));
    }
    if let Some(bytes) = blob {
        return Ok(PlayMediaSource::Blob(bytes));
    }
    if let Some(id) = db_id {
        return Ok(PlayMediaSource::DbId(id));
    }
    unreachable!("count == 1 guaranteed one branch above")
}

/// Default profile name when none is specified.
const DEFAULT_PROFILE: &str = "rtp_passthrough";

/// The per-call values a `ws_uri` template can interpolate.
///
/// `pub(crate)` so the dispatcher's answer-first handover path reuses the exact
/// #131 templating (`expand_ws_uri`) instead of duplicating it.
pub(crate) struct WsUriContext<'a> {
    pub(crate) call_id: &'a str,
    pub(crate) from_tag: &'a str,
    pub(crate) from_user: Option<&'a str>,
    pub(crate) to_user: Option<&'a str>,
}

/// The From/To user parts of a message, for `ws_uri` templating.
///
/// Reuses [`NameAddr::parse`] rather than re-parsing name-addrs by hand, so a
/// display-name-with-comma or an angle-bracketed URI is handled the same way the
/// `request.from_uri` / `request.to_uri` getters handle it.
fn ws_uri_user_parts(message: &Arc<Mutex<SipMessage>>) -> (Option<String>, Option<String>) {
    let Ok(message) = message.lock() else {
        return (None, None);
    };
    let user_of = |raw: Option<&String>| -> Option<String> {
        raw.and_then(|value| crate::sip::headers::nameaddr::NameAddr::parse(value).ok())
            .and_then(|nameaddr| nameaddr.uri.user)
    };
    (
        user_of(message.headers.from()),
        user_of(message.headers.to()),
    )
}

/// The source IP of the message a media verb was handed, for `received_from`.
///
/// `SipMessage` does not carry the peer address — it is held by the Python
/// wrapper the dispatcher built (`PyRequest` / `PyCall`), so it has to be read
/// off the object while it is still borrowed, before any async block.
/// A `PyReply` has no source of its own (the address that matters is the
/// offerer's), so it yields `None` and the gate is simply not set.
fn extract_source_ip(object: &Bound<'_, PyAny>) -> Option<String> {
    if let Ok(request) = object.cast::<PyRequest>() {
        return Some(request.borrow().source_ip_str().to_string());
    }
    if let Ok(call) = object.cast::<PyCall>() {
        return Some(call.borrow().cdr_source_ip());
    }
    None
}

/// Expand `{call_id}` / `{from_tag}` / `{from_user}` / `{to_user}` in a `ws_uri`.
///
/// An unrecognised placeholder is an **error**, not a literal: a typo'd
/// `{callid}` passed through verbatim would reach the engine as part of the URI
/// path and the inference server would answer a route nobody meant to call. A
/// placeholder with no value for this call (no From user part, say) is the same
/// error — silently emitting an empty path segment is the same class of bug.
///
/// A URI with no `{` is returned untouched, so the common non-templated case
/// costs one scan and no allocation decisions.
///
/// `pub(crate)` so the dispatcher's answer-first handover path reuses it.
pub(crate) fn expand_ws_uri(template: &str, context: &WsUriContext<'_>) -> PyResult<String> {
    if !template.contains('{') {
        return Ok(template.to_string());
    }

    let mut expanded = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        expanded.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "ws_uri has an unclosed '{{' placeholder: {template:?}"
            )));
        };
        let name = &after_open[..close];
        let value = match name {
            "call_id" => Some(context.call_id),
            "from_tag" => Some(context.from_tag),
            "from_user" => context.from_user,
            "to_user" => context.to_user,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "ws_uri has unknown placeholder {{{other}}}; supported: \
                     {{call_id}}, {{from_tag}}, {{from_user}}, {{to_user}}"
                )))
            }
        };
        let Some(value) = value else {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "ws_uri placeholder {{{name}}} has no value on this call"
            )));
        };
        expanded.push_str(value);
        rest = &after_open[close + 1..];
    }
    expanded.push_str(rest);

    Ok(expanded)
}

/// Resolve which WebSocket bridge URI a call should use, before templating.
///
/// Precedence mirrors [`resolve_answer_profile`], for the same reason: an
/// `answer` following an `offer` should keep the bridge the offer set up without
/// the script having to repeat itself.
///   1. Explicit `ws_uri=` argument from the script (override).
///   2. URI recorded by the matching `offer` (looked up by Call-ID).
///   3. The resolved profile's `ws_uri`.
fn resolve_ws_uri(
    ws_uri: Option<&str>,
    sessions: &MediaSessionStore,
    call_id: &str,
    profile_ws_uri: Option<&str>,
) -> Option<String> {
    if let Some(uri) = ws_uri {
        return Some(uri.to_string());
    }
    if let Some(recorded) = sessions.get(call_id).and_then(|session| session.ws_uri) {
        return Some(recorded);
    }
    profile_ws_uri.map(|uri| uri.to_string())
}

/// Apply the per-call WebSocket URI and `received_from` address to a profile's
/// resolved flags, and reject flags the configured backend cannot honour.
///
/// This is the single place a call's [`NgFlags`] become final, so it is also the
/// only place the backend-capability check has to live. Built-in profiles are
/// registered regardless of backend (config validation only covers
/// operator-declared `media.profiles`), so without this a script naming
/// `voice_ai` on an rtpengine backend would answer the call and bridge it
/// nowhere — silence for the call's whole duration, with nothing logged.
fn finalise_flags(
    mut flags: NgFlags,
    backend: &MediaBackend,
    ws_uri: Option<String>,
    source_ip: Option<&str>,
    profile_name: &str,
) -> PyResult<NgFlags> {
    if let Some(uri) = ws_uri {
        flags.ws_uri = Some(uri);
    }
    if flags.carry_received_from {
        match source_ip.and_then(|ip| ip.parse::<std::net::IpAddr>().ok()) {
            Some(address) => flags.received_from = Some(address),
            None => {
                // Opted in but we have no address to carry. Leaving the gate
                // unset is the safe direction (the engine falls back to the
                // signalled address), but it is silently weaker than asked for,
                // so say it.
                warn!(
                    profile = %profile_name,
                    "media profile sets received_from but no usable source \
                     address is available for this call — media ingress will \
                     not be gated to it"
                );
            }
        }
    }

    let unsupported = backend.unsupported_flags(&flags);
    if !unsupported.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "media profile '{profile_name}' sets {} which the {} backend cannot \
             honour — set media.backend to a backend that supports it",
            unsupported.join(", "),
            backend.kind().as_str(),
        )));
    }

    Ok(flags)
}

/// Resolve which RTP profile to use on the answer side.
///
/// Precedence:
///   1. Explicit `profile` argument from the script (override).
///   2. Profile recorded by the matching `offer` (looked up by Call-ID).
///   3. [`DEFAULT_PROFILE`].
///
/// Step 2 is what makes B2BUA `on_answer` / `on_early_media` "just work" without
/// every script having to re-pass `profile=` — once `rtpengine.offer(call,
/// profile=…)` runs, the answer side mirrors the offer profile automatically,
/// so directional flags (e.g. `direction: ["trunk", "ims"]`) don't get
/// silently dropped on the 200 OK / early-media 18x.
fn resolve_answer_profile(
    profile: Option<&str>,
    sessions: &MediaSessionStore,
    call_id: &str,
) -> String {
    if let Some(name) = profile {
        return name.to_string();
    }
    if let Some(session) = sessions.get(call_id) {
        debug!(
            call_id = %call_id,
            profile = %session.profile,
            "rtpengine.answer: using profile recorded at offer"
        );
        return session.profile;
    }
    debug!(
        call_id = %call_id,
        default = %DEFAULT_PROFILE,
        "rtpengine.answer: no offer-side profile found, falling back to default"
    );
    DEFAULT_PROFILE.to_string()
}

/// The engine's exact `CmdResult::Error` reason when the offer carries no codec
/// this build can encode (RFC 3264 §6.1) — the signal to render a 488.
const NO_ENCODABLE_CODEC: &str = "no-encodable-codec";

/// What `answer_local` should do with the backend's [`answer_local`] result,
/// factored out of the async closure so the mapping is unit-testable without
/// driving the `future_into_py` awaitable.
///
/// [`answer_local`]: MediaBackend::answer_local
#[derive(Debug, PartialEq, Eq)]
enum AnswerLocalOutcome {
    /// Engine synthesised an answer — record the session, resolve to the SDP.
    Answered(String),
    /// No encodable codec and the caller opted into auto-reject on a `Call` —
    /// set a deferred 488 on the call and resolve to `None`.
    Reject488,
    /// No encodable codec but no auto-reject target — raise `ValueError`.
    ValueError,
    /// Transport / protocol / other engine error — raise `RuntimeError`.
    RuntimeError(String),
}

/// Map an `answer_local` backend result to the Python-visible outcome.
///
/// `can_reject` is `true` only when the script asked for `auto_reject` *and*
/// the target was a `Call` (the auto-488 path is defined for the B2BUA call
/// object — a bare `Request` has no deferred-reject channel).
fn classify_answer_local(
    result: Result<String, RtpEngineError>,
    can_reject: bool,
) -> AnswerLocalOutcome {
    match result {
        Ok(answer_sdp) => AnswerLocalOutcome::Answered(answer_sdp),
        Err(RtpEngineError::EngineError(reason)) if reason == NO_ENCODABLE_CODEC => {
            if can_reject {
                AnswerLocalOutcome::Reject488
            } else {
                AnswerLocalOutcome::ValueError
            }
        }
        Err(error) => {
            AnswerLocalOutcome::RuntimeError(format!("rtpengine.answer_local failed: {error}"))
        }
    }
}

/// Extract `Arc<Mutex<SipMessage>>` from a Python object that is either
/// a `Request`, `Reply`, or `Call`.
pub(super) fn extract_message(object: &Bound<'_, PyAny>) -> PyResult<Arc<Mutex<SipMessage>>> {
    // Try PyRequest first.
    if let Ok(request) = object.cast::<PyRequest>() {
        return Ok(request.borrow().message());
    }
    // Try PyReply.
    if let Ok(reply) = object.cast::<PyReply>() {
        return Ok(reply.borrow().message());
    }
    // Try PyCall.
    if let Ok(call) = object.cast::<PyCall>() {
        return Ok(call.borrow().message());
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "expected a Request, Reply, or Call object",
    ))
}

/// Resolve `(call_id, from_tag)` from a media-verb target.
///
/// Accepts three forms so the same verbs work whether the script holds a SIP
/// object or only the identifiers an event delivered:
///   * a `Request` / `Reply` / `Call` → today's `extract_message` +
///     `extract_delete_params` path (behaviour preserved exactly);
///   * a `(call_id, from_tag)` pair of strings;
///   * a bare `call_id` string → best-effort with an empty `from_tag`.
///
/// The pair / bare-string forms are what let an `@rtpengine.on_dtmf` handler —
/// which receives `call_id` / `from_tag` strings, not a SIP message — drive
/// `play_media` / `echo` / `stop_media` / DTMF / gating directly.
fn resolve_call_from_tag(target: &Bound<'_, PyAny>) -> PyResult<(String, String)> {
    // SIP object → the exact path the verbs used before (Call-ID + From-tag off
    // the message), so Request/Reply/Call callers are byte-for-byte unchanged.
    if target.cast::<PyRequest>().is_ok()
        || target.cast::<PyReply>().is_ok()
        || target.cast::<PyCall>().is_ok()
    {
        let message = extract_message(target)?;
        return extract_delete_params(&message);
    }
    // Bare `call_id` string → empty from_tag. Checked before the pair form
    // because a Python `str` is itself a 2-sequence of 1-char strings, so a
    // `(String, String)` extraction would misread a 2-char id as a pair.
    if let Ok(call_id) = target.extract::<String>() {
        return Ok((call_id, String::new()));
    }
    // `(call_id, from_tag)` pair of strings.
    if let Ok((call_id, from_tag)) = target.extract::<(String, String)>() {
        return Ok((call_id, from_tag));
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "rtpengine media verb target must be a Request/Reply/Call, a \
         (call_id, from_tag) tuple, or a call_id string",
    ))
}

#[pymethods]
impl PyRtpEngine {
    /// Send an RTPEngine `offer` command.
    ///
    /// Extracts SDP from the object body, sends it to RTPEngine, and replaces
    /// the body with the rewritten SDP. Returns True on success.
    ///
    /// Args:
    ///     request: A Request or Call object containing the INVITE with SDP.
    ///     profile: RTP profile name (default: "rtp_passthrough").
    ///     ws_uri: Bridge this leg's audio to an external WebSocket media server
    ///             (``siphon-rtp`` backend only), overriding the profile's own
    ///             ``ws_uri`` for this call. Supports ``{call_id}``,
    ///             ``{from_tag}``, ``{from_user}`` and ``{to_user}``
    ///             placeholders. The resolved URI is recorded on the media
    ///             session, so a later ``answer`` reuses it automatically.
    #[pyo3(signature = (request, profile=None, ws_uri=None))]
    fn offer<'py>(
        &self,
        python: Python<'py>,
        request: &Bound<'py, PyAny>,
        profile: Option<&str>,
        ws_uri: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let profile_name = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = self.registry.get(profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.offer.clone();

        let message = extract_message(request)?;
        let (call_id, from_tag, sdp) = extract_offer_params(&message)?;

        // Resolve + template the bridge URI, then finalise the flags. Both run
        // before the async block so a bad template or an unhonourable flag
        // raises to the script instead of failing a call already in flight.
        let source_ip = extract_source_ip(request);
        let resolved_ws_uri = resolve_ws_uri(
            ws_uri,
            &self.sessions,
            &call_id,
            entry.offer.ws_uri.as_deref(),
        );
        let resolved_ws_uri = match resolved_ws_uri {
            Some(template) => {
                let (from_user, to_user) = ws_uri_user_parts(&message);
                Some(expand_ws_uri(
                    &template,
                    &WsUriContext {
                        call_id: &call_id,
                        from_tag: &from_tag,
                        from_user: from_user.as_deref(),
                        to_user: to_user.as_deref(),
                    },
                )?)
            }
            None => None,
        };
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri.clone(),
            source_ip.as_deref(),
            profile_name,
        )?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);
        let profile_str = profile_name.to_string();

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .offer(&call_id, &from_tag, &sdp, &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.offer failed: {error}"
                    ))
                })?;

            debug!(
                call_id = %call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine offer: SDP rewritten"
            );

            replace_body(&message, &rewritten_sdp)?;

            sessions.insert(MediaSession {
                rtpengine_call_id: call_id.clone(),
                call_id,
                from_tag,
                to_tag: None,
                profile: profile_str,
                ws_uri: resolved_ws_uri,
                created_at: std::time::Instant::now(),
            });

            Ok(true)
        })
    }

    /// Send an RTPEngine `answer` command.
    ///
    /// Extracts SDP from the object body, sends it to RTPEngine, and replaces
    /// the body with the rewritten SDP.
    ///
    /// In B2BUA mode the offer was keyed by the A-leg Call-ID/From-tag, but the
    /// reply carries B-leg identifiers. The A-leg identifiers are resolved
    /// automatically when the reply carries an A-leg reference (set by the
    /// dispatcher), or via an explicit `call` parameter.
    ///
    /// Profile precedence:
    ///   1. Explicit ``profile=`` argument (script override).
    ///   2. Profile recorded by the matching ``offer`` (looked up by A-leg
    ///      Call-ID).  This is what most B2BUA scripts want — call
    ///      ``rtpengine.offer(call, profile="…")`` once and the answer side
    ///      mirrors it automatically, including for early-media 18x.
    ///   3. ``DEFAULT_PROFILE`` (``rtp_passthrough``) when no offer was ever
    ///      recorded for this Call-ID.
    ///
    /// Args:
    ///     reply: A Reply or Call object containing the 200 OK with SDP.
    ///     profile: RTP profile name. When omitted, the profile recorded by
    ///              the matching offer is used; falls back to
    ///              ``"rtp_passthrough"`` only if no prior offer exists.
    ///     call: Optional Call object — when provided, Call-ID and From-tag are
    ///           taken from this object (matching the earlier `offer`), while
    ///           To-tag and SDP body still come from `reply`.
    ///     ws_uri: WebSocket bridge URI override for this call (``siphon-rtp``
    ///             backend only). When omitted, the URI recorded by the matching
    ///             ``offer`` is reused, then the resolved profile's own —
    ///             the same precedence as ``profile``.
    #[pyo3(signature = (reply, profile=None, call=None, ws_uri=None))]
    fn answer<'py>(
        &self,
        python: Python<'py>,
        reply: &Bound<'py, PyAny>,
        profile: Option<&str>,
        call: Option<&Bound<'py, PyAny>>,
        ws_uri: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message = extract_message(reply)?;

        // Resolve A-leg identifiers for RTPEngine correlation:
        // 1. Explicit `call` parameter (backward compat / proxy-with-call)
        // 2. Automatic: PyReply carries A-leg INVITE ref set by B2BUA dispatcher
        // 3. Fallback: extract from the reply itself (proxy mode, same Call-ID)
        let a_leg_msg: Option<Arc<Mutex<SipMessage>>> = if let Some(call_obj) = call {
            Some(extract_message(call_obj)?)
        } else if let Ok(py_reply) = reply.cast::<PyReply>() {
            py_reply.borrow().a_leg_message()
        } else {
            None
        };

        let (call_id, from_tag, to_tag, sdp) = if let Some(ref a_msg) = a_leg_msg {
            let (cid, ftag, _sdp) = extract_offer_params(a_msg)?;
            let (_reply_cid, _reply_ftag, ttag, reply_sdp) = extract_answer_params(&message)?;
            (cid, ftag, ttag, reply_sdp)
        } else {
            extract_answer_params(&message)?
        };

        let profile_name = resolve_answer_profile(profile, &self.sessions, &call_id);
        let entry = self.registry.get(&profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.answer.clone();

        // The bridge belongs to the offerer's leg, so template against the A-leg
        // identifiers resolved above — not the reply's own tags.
        let resolved_ws_uri = resolve_ws_uri(
            ws_uri,
            &self.sessions,
            &call_id,
            entry.answer.ws_uri.as_deref(),
        );
        let resolved_ws_uri = match resolved_ws_uri {
            Some(template) => {
                let (from_user, to_user) =
                    ws_uri_user_parts(a_leg_msg.as_ref().unwrap_or(&message));
                Some(expand_ws_uri(
                    &template,
                    &WsUriContext {
                        call_id: &call_id,
                        from_tag: &from_tag,
                        from_user: from_user.as_deref(),
                        to_user: to_user.as_deref(),
                    },
                )?)
            }
            None => None,
        };
        // A reply carries no source address of its own; when the script passed
        // `call=`, that object does.
        let source_ip = call.and_then(|object| extract_source_ip(object));
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri,
            source_ip.as_deref(),
            &profile_name,
        )?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .answer(&call_id, &from_tag, &to_tag, &sdp, &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.answer failed: {error}"
                    ))
                })?;

            debug!(
                call_id = %call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine answer: SDP rewritten"
            );

            replace_body(&message, &rewritten_sdp)?;

            sessions.set_to_tag(&call_id, to_tag);

            Ok(true)
        })
    }

    /// Single-leg UAS answer — synthesise an RFC 3264 answer for the caller's
    /// **own** offer, with the media engine as the far side (IVR / echo /
    /// announcement server).  Unlike :meth:`answer`, this takes the offer
    /// (INVITE) — not a peer's reply — because there is no far leg: the engine
    /// picks one encodable codec from the offer and returns the answer SDP for
    /// the script to put in its own 2xx.
    ///
    /// Profile precedence matches :meth:`answer`:
    ///   1. Explicit ``profile=`` argument (script override).
    ///   2. Profile recorded by a matching ``offer`` (looked up by Call-ID).
    ///   3. ``DEFAULT_PROFILE`` (``rtp_passthrough``).
    ///
    /// When the offer carries no codec this build can encode (RFC 3264 §6.1 —
    /// the answer must select from the offered formats), the engine cannot
    /// answer.  With ``auto_reject=True`` (default) and a ``Call`` target, a
    /// deferred ``488 Not Acceptable Here`` (RFC 3261 §13.3.1.2) is set on the
    /// call and the coroutine resolves to ``None``.  With ``auto_reject=False``
    /// (or a non-``Call`` target) it raises ``ValueError`` instead, leaving the
    /// response to the script.
    ///
    /// Native ``siphon-rtp`` backend only; rtpengine and rtpproxy reject.
    ///
    /// Args:
    ///     call: A ``Call`` (B2BUA) — or ``Request`` — carrying the INVITE offer
    ///           whose Call-ID / From-tag / SDP drive the single-leg answer.
    ///     profile: RTP profile name.  When omitted, the profile recorded by a
    ///              matching offer is used; falls back to ``"rtp_passthrough"``.
    ///     auto_reject: When ``True`` (default) and ``call`` is a ``Call``, a
    ///                  no-encodable-codec engine result sets a deferred
    ///                  ``488 Not Acceptable Here`` on the call and returns
    ///                  ``None``.  When ``False`` it raises ``ValueError``.
    ///     ws_uri: Bridge this leg's audio to an external WebSocket media server
    ///             instead of a far SIP leg — the shape a voice-AI answer takes,
    ///             since the WS server *is* the far side. Overrides the
    ///             profile's own ``ws_uri``; supports the same placeholders as
    ///             :meth:`offer`.
    ///
    /// Returns:
    ///     The answer SDP as ``str`` on success, or ``None`` when the offer had
    ///     no encodable codec and it was auto-rejected with a 488.
    #[pyo3(signature = (call, profile=None, auto_reject=true, ws_uri=None))]
    fn answer_local<'py>(
        &self,
        python: Python<'py>,
        call: &Bound<'py, PyAny>,
        profile: Option<&str>,
        auto_reject: bool,
        ws_uri: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message = extract_message(call)?;
        let (call_id, from_tag, offer_sdp_bytes) = extract_offer_params(&message)?;
        let offer_sdp = String::from_utf8_lossy(&offer_sdp_bytes).into_owned();

        // Resolve the answer-side flags exactly as `answer` does (explicit
        // profile → offer-recorded profile → default).
        let profile_name = resolve_answer_profile(profile, &self.sessions, &call_id);
        let entry = self.registry.get(&profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.answer.clone();

        let source_ip = extract_source_ip(call);
        let resolved_ws_uri = resolve_ws_uri(
            ws_uri,
            &self.sessions,
            &call_id,
            entry.answer.ws_uri.as_deref(),
        );
        let resolved_ws_uri = match resolved_ws_uri {
            Some(template) => {
                let (from_user, to_user) = ws_uri_user_parts(&message);
                Some(expand_ws_uri(
                    &template,
                    &WsUriContext {
                        call_id: &call_id,
                        from_tag: &from_tag,
                        from_user: from_user.as_deref(),
                        to_user: to_user.as_deref(),
                    },
                )?)
            }
            None => None,
        };
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri.clone(),
            source_ip.as_deref(),
            &profile_name,
        )?;

        // Capture an owned handle to the Call for the auto-488 path, cloned
        // while the GIL is held (free-threaded `Py::clone` rule).  `None` when
        // auto_reject is off or the target isn't a `Call` (a bare `Request` has
        // no deferred-reject channel).  `extract_message` above already released
        // its transient borrow of the object, so borrowing this handle later in
        // the async block cannot alias.
        let reject_call: Option<Py<PyCall>> = if auto_reject {
            call.cast::<PyCall>().ok().map(|bound| bound.clone().unbind())
        } else {
            None
        };

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);
        let profile_str = profile_name.clone();

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let result = client
                .answer_local(&call_id, &from_tag, &offer_sdp, &flags)
                .await;
            match classify_answer_local(result, reject_call.is_some()) {
                AnswerLocalOutcome::Answered(answer_sdp) => {
                    debug!(
                        call_id = %call_id,
                        sdp_len = answer_sdp.len(),
                        "rtpengine.answer_local: answer SDP synthesised"
                    );
                    // Record the session exactly as `offer` does, so `delete`,
                    // active-session accounting, and a later `rtpengine.answer`
                    // profile-reuse all work.
                    sessions.insert(MediaSession {
                        rtpengine_call_id: call_id.clone(),
                        call_id,
                        from_tag,
                        to_tag: None,
                        profile: profile_str,
                        ws_uri: resolved_ws_uri,
                        created_at: std::time::Instant::now(),
                    });
                    Ok(Some(answer_sdp))
                }
                AnswerLocalOutcome::Reject488 => {
                    // reject_call is Some here (can_reject implied it).
                    if let Some(reject_call) = reject_call {
                        Python::attach(|py| {
                            let mut call_ref = reject_call.bind(py).borrow_mut();
                            call_ref.set_reject(488, "Not Acceptable Here");
                        });
                    }
                    debug!(
                        call_id = %call_id,
                        "rtpengine.answer_local: no encodable codec, deferred 488 Not Acceptable Here"
                    );
                    Ok(None)
                }
                AnswerLocalOutcome::ValueError => Err(pyo3::exceptions::PyValueError::new_err(
                    "no encodable codec in offer",
                )),
                AnswerLocalOutcome::RuntimeError(message) => {
                    Err(pyo3::exceptions::PyRuntimeError::new_err(message))
                }
            }
        })
    }

    /// Send an RTPEngine `delete` command to tear down the media session.
    ///
    /// Args:
    ///     request: A Request or Call object (used to extract Call-ID/From-tag).
    #[pyo3(signature = (request,))]
    fn delete<'py>(
        &self,
        python: Python<'py>,
        request: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message = extract_message(request)?;
        let (call_id, from_tag) = extract_delete_params(&message)?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match client.delete(&call_id, &from_tag).await {
                Ok(()) => {
                    debug!(call_id = %call_id, "RTPEngine session deleted");
                }
                Err(error) => {
                    // Log but don't fail — the session may already be gone.
                    warn!(call_id = %call_id, error = %error, "RTPEngine delete failed");
                }
            }

            sessions.remove(&call_id);
            Ok(true)
        })
    }

    /// Ping the RTPEngine instance(s). Returns True if healthy.
    fn ping<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match client.ping().await {
                Ok(()) => Ok(true),
                Err(error) => {
                    warn!(error = %error, "RTPEngine ping failed");
                    Ok(false)
                }
            }
        })
    }

    /// Send a `play media` command — inject an audio prompt into the call.
    ///
    /// Exactly one of ``file``, ``blob``, or ``db_id`` must be supplied.
    ///
    /// Per rtpengine semantics, ``from-tag`` selects the monologue whose
    /// outgoing audio is replaced by the prompt — the peer of that monologue
    /// hears it. By default the from-tag is extracted from the SIP object.
    /// Supply ``to_tag`` to scope the prompt to a specific peer when the
    /// monologue has multiple subscribers (MPTY).
    ///
    /// Requires rtpengine built with ``--with-transcoding`` and launched with
    /// ``--audio-player=on-demand``. VoLTE prompts (AMR-NB/WB) need licensed
    /// codec plugins; G.711 and Opus prompts work without them.
    ///
    /// Args:
    ///     target: Request, Reply, or Call object — used to derive Call-ID
    ///             and From-tag.
    ///     file: Absolute path to an audio file on the rtpengine host.
    ///     blob: Raw audio bytes to play (e.g. TTS output).
    ///     db_id: Reference to a prompt stored in rtpengine's prompt DB.
    ///     repeat: Number of times to repeat the prompt (default: 1).
    ///     start_ms: Offset into the file at which to start (milliseconds).
    ///     duration_ms: Cap on playback length (milliseconds).
    ///     to_tag: Optional peer tag for MPTY scoping.
    ///     wait: When ``True`` (default), block until the prompt finishes playing
    ///           (``await`` returns only once it has drained), so a script can
    ///           sequence a following action — e.g. ``echo()`` — after it with no
    ///           overlap. The coroutine parks while it waits (no worker is held).
    ///           ``wait=False`` returns as soon as the engine accepts the prompt
    ///           (fire-and-forget — music-on-hold / background). Native
    ///           ``siphon-rtp`` backend only; the rtpengine / rtpproxy backends
    ///           have no completion signal and always return on accept.
    ///
    /// Returns:
    ///     The played duration in milliseconds if the engine reports one, else
    ///     ``None`` (also ``None`` when the prompt was stopped / superseded before
    ///     it finished, or the fallback timeout elapsed).
    #[pyo3(signature = (target, file=None, blob=None, db_id=None, repeat=None, start_ms=None, duration_ms=None, to_tag=None, wait=true))]
    #[allow(clippy::too_many_arguments)]
    fn play_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        file: Option<String>,
        blob: Option<Vec<u8>>,
        db_id: Option<u64>,
        repeat: Option<u64>,
        start_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<String>,
        wait: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = resolve_play_media_source(file, blob, db_id)?;

        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let duration = client
                .play_media(
                    &call_id,
                    &from_tag,
                    &source,
                    repeat,
                    start_ms,
                    duration_ms,
                    to_tag.as_deref(),
                    wait,
                )
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.play_media failed: {error}"
                    ))
                })?;
            debug!(call_id = %call_id, duration_ms = ?duration, "rtpengine play_media");
            Ok(duration)
        })
    }

    /// Send a `stop media` command — stop any prompt currently playing on the
    /// monologue selected by the SIP object's From-tag.
    #[pyo3(signature = (target,))]
    fn stop_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client.stop_media(&call_id, &from_tag).await.map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "rtpengine.stop_media failed: {error}"
                ))
            })?;
            debug!(call_id = %call_id, "rtpengine stop_media");
            Ok(true)
        })
    }

    /// Send a `play DTMF` command — inject DTMF tone(s) into the call.
    ///
    /// Args:
    ///     target: Request, Reply, or Call object.
    ///     code: A single digit (``"0"``–``"9"``, ``"*"``, ``"#"``, ``"A"``–``"D"``)
    ///           or a string sequence of digits.
    ///     duration_ms: Tone duration per digit (default: 250ms per rtpengine).
    ///     volume_dbm0: Tone volume in dBm0 (typically ``-8``).
    ///     pause_ms: Inter-tone gap when ``code`` is a sequence.
    ///     to_tag: Optional peer tag for MPTY scoping.
    #[pyo3(signature = (target, code, duration_ms=None, volume_dbm0=None, pause_ms=None, to_tag=None))]
    fn play_dtmf<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        code: String,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .play_dtmf(
                    &call_id,
                    &from_tag,
                    &code,
                    duration_ms,
                    volume_dbm0,
                    pause_ms,
                    to_tag.as_deref(),
                )
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.play_dtmf failed: {error}"
                    ))
                })?;
            debug!(call_id = %call_id, code = %code, "rtpengine play_dtmf");
            Ok(true)
        })
    }

    /// Send a `silence media` command — replace outgoing audio on the selected
    /// monologue with silence. Pair with :meth:`unsilence_media` to restore.
    #[pyo3(signature = (target,))]
    fn silence_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.simple_media_command(python, target, "silence_media")
    }

    /// Send an `unsilence media` command — pass the original stream through
    /// again after a prior :meth:`silence_media`.
    #[pyo3(signature = (target,))]
    fn unsilence_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.simple_media_command(python, target, "unsilence_media")
    }

    /// Send a `block media` command — drop outgoing packets on the selected
    /// monologue (peer hears no audio at all, not even comfort silence).
    #[pyo3(signature = (target,))]
    fn block_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.simple_media_command(python, target, "block_media")
    }

    /// Send an `unblock media` command — resume forwarding the selected
    /// monologue's packets after a prior :meth:`block_media`.
    #[pyo3(signature = (target,))]
    fn unblock_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.simple_media_command(python, target, "unblock_media")
    }

    /// Enable/disable echo-test mode on a call — reflect the caller's ingress
    /// audio back to itself (single-leg IVR echo). ``enabled=False`` stops
    /// echoing. Native ``siphon-rtp`` backend only; DTMF and media-timeout
    /// events still fire while echoing.
    ///
    /// Args:
    ///     target: A Request, Reply, or Call whose Call-ID / From-tag select
    ///         the leg to echo (the same message the offer used).
    ///     enabled: True to start echoing (default), False to stop.
    #[pyo3(signature = (target, enabled=true))]
    fn echo<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        enabled: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client.echo(&call_id, &from_tag, enabled).await.map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "rtpengine.echo failed: {error}"
                ))
            })?;
            debug!(call_id = %call_id, enabled, "rtpengine echo");
            Ok(true)
        })
    }

    /// Send a `subscribe request` — create a new subscription to an existing
    /// call's media.
    ///
    /// Low-level primitive for building MPTY / conference topologies (MRF
    /// focus, monitoring, call recording). The caller is responsible for
    /// deciding how to compose pair-wise or N-way subscriptions.
    ///
    /// Args:
    ///     call_id: rtpengine call-id of the source session.
    ///     from_tag: source monologue tag (whose outgoing audio the new
    ///               subscription receives).
    ///     to_tag: subscriber tag to create.
    ///     sdp: Optional inbound SDP for the subscriber. Usually ``None`` —
    ///          rtpengine generates one.
    ///     profile: RTP profile name for flag composition (default
    ///              ``"rtp_passthrough"``).
    ///
    /// Returns:
    ///     The subscriber SDP as ``bytes``.
    #[pyo3(signature = (call_id, from_tag, to_tag, sdp=None, profile=None))]
    fn subscribe_request<'py>(
        &self,
        python: Python<'py>,
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: Option<Vec<u8>>,
        profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let profile_name = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = self.registry.get(profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.offer.clone();
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .subscribe_request(&call_id, &from_tag, &to_tag, sdp.as_deref(), &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.subscribe_request failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                to_tag = %to_tag,
                sdp_len = rewritten_sdp.len(),
                "rtpengine subscribe_request"
            );
            Ok(rewritten_sdp)
        })
    }

    /// Send a `subscribe answer` — complete the SDP negotiation for a
    /// subscription created via :meth:`subscribe_request`.
    ///
    /// Args:
    ///     call_id: rtpengine call-id of the source session.
    ///     from_tag: source monologue tag (same value used in subscribe_request).
    ///     to_tag: subscriber tag (same value used in subscribe_request).
    ///     sdp: Answer SDP for the subscription.
    ///     profile: RTP profile name (default ``"rtp_passthrough"``).
    ///
    /// Returns:
    ///     The rewritten SDP as ``bytes`` (may be empty — rtpengine does
    ///     not always echo SDP on subscribe answer).
    #[pyo3(signature = (call_id, from_tag, to_tag, sdp, profile=None))]
    fn subscribe_answer<'py>(
        &self,
        python: Python<'py>,
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: Vec<u8>,
        profile: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let profile_name = profile.unwrap_or(DEFAULT_PROFILE);
        let entry = self.registry.get(profile_name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown RTP profile '{profile_name}'; valid profiles: {}",
                self.registry.profile_names().join(", ")
            ))
        })?;
        let flags = entry.answer.clone();
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = client
                .subscribe_answer(&call_id, &from_tag, &to_tag, &sdp, &flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.subscribe_answer failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                to_tag = %to_tag,
                sdp_len = rewritten_sdp.len(),
                "rtpengine subscribe_answer"
            );
            Ok(rewritten_sdp)
        })
    }

    /// Send an `unsubscribe` command — tear down a subscription created via
    /// :meth:`subscribe_request`.
    ///
    /// Args:
    ///     call_id: rtpengine call-id of the source session.
    ///     from_tag: source monologue tag.
    ///     to_tag: subscriber tag to remove.
    #[pyo3(signature = (call_id, from_tag, to_tag))]
    fn unsubscribe<'py>(
        &self,
        python: Python<'py>,
        call_id: String,
        from_tag: String,
        to_tag: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .unsubscribe(&call_id, &from_tag, &to_tag)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.unsubscribe failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                to_tag = %to_tag,
                "rtpengine unsubscribe"
            );
            Ok(true)
        })
    }

    /// Register a handler for inbound DTMF events from rtpengine.
    ///
    /// rtpengine must be configured with ``dtmf-log-ng-tcp-uri=tcp://<siphon>``
    /// and siphon must have ``media.events.listen_addr`` set so it accepts
    /// the inbound TCP connection.
    ///
    /// ```python,ignore
    /// @rtpengine.on_dtmf(call_id="abc", from_tag="ftag1")
    /// def handle_digit(call_id, from_tag, digit, duration_ms, volume):
    ///     ...
    ///
    /// # Catch-all - no filters
    /// @rtpengine.on_dtmf
    /// def handle_any(call_id, from_tag, digit, duration_ms, volume):
    ///     ...
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_dtmf``) this
    ///         is the function.  When called with keyword filters the return
    ///         value is a decorator.
    ///     call_id: Optional rtpengine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_dtmf<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Compose a Python-side decorator that registers via _siphon_registry
        // with metadata describing the filters.
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_dtmf", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).unwrap(), Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_dtmf decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_dtmf` (bare) and `@on_dtmf(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for media-timeout events from the media engine.
    ///
    /// The engine reaps a call whose media went dead (no packets past its
    /// inactivity window) and pushes a media-timeout event.  The handler
    /// receives ``(call_id, from_tag)`` and should release the per-call state
    /// no BYE will now clear — Rx/N5 QoS sessions, offline-charging records,
    /// dialog/session-store entries — much like `@proxy.on_cancel` /
    /// `@b2bua.on_cancel` cover the abandoned-call teardown a BYE never sends.
    ///
    /// Delivered by the native **siphon-rtp** backend, which pushes the event
    /// over its control connection.  The rtpengine backend does not emit
    /// media-timeout events (its NG event log carries only DTMF), so this hook
    /// does not fire under rtpengine today.
    ///
    /// ```python,ignore
    /// @rtpengine.on_media_timeout(call_id="abc", from_tag="ftag1")
    /// def handle_timeout(call_id, from_tag):
    ///     ...
    ///
    /// # Catch-all - no filters
    /// @rtpengine.on_media_timeout
    /// def handle_any(call_id, from_tag):
    ///     ...
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_media_timeout``)
    ///         this is the function.  When called with keyword filters the
    ///         return value is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_media_timeout<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Compose a Python-side decorator that registers via _siphon_registry
        // with metadata describing the filters (mirrors `on_dtmf`).
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_media_timeout", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).unwrap(), Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_media_timeout decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_media_timeout` (bare) and
        // `@on_media_timeout(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Number of active media sessions being tracked.
    #[getter]
    fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Number of configured RTPEngine instances.
    #[getter]
    fn instance_count(&self) -> usize {
        self.client.instance_count()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock_message(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
    message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })
}

/// Extract the SDP body from a SIP message, handling multipart/mixed bodies.
///
/// If the Content-Type is `multipart/mixed`, extracts the `application/sdp`
/// part from the multipart body. Otherwise returns the raw body as-is.
pub(super) fn extract_sdp_body(message: &SipMessage) -> PyResult<Vec<u8>> {
    let body = &message.body;
    if body.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "message has no SDP body",
        ));
    }

    let empty_string = String::new();
    let content_type = message.headers.get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .unwrap_or(&empty_string);

    if content_type.to_ascii_lowercase().contains("multipart/mixed") {
        // Parse multipart body and extract the SDP part.
        let parts = crate::siprec::multipart::parse_multipart(content_type, body)
            .map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "failed to parse multipart body: {error}"
                ))
            })?;
        let sdp_part = crate::siprec::multipart::find_part(&parts, "application/sdp")
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "multipart body has no application/sdp part"
                )
            })?;
        Ok(sdp_part.body.clone())
    } else {
        Ok(body.clone())
    }
}

/// Extract call-id, from-tag, and SDP body from a SIP message (offer direction).
fn extract_offer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, Vec<u8>)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    let sdp = extract_sdp_body(&message)?;

    Ok((call_id, from_tag, sdp))
}

/// Extract call-id, from-tag, to-tag, and SDP body from a SIP message (answer direction).
fn extract_answer_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String, String, Vec<u8>)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    let to_raw = message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing To header")
        })?;

    let to_tag = extract_tag(to_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("To header missing tag parameter")
    })?;

    let sdp = extract_sdp_body(&message)?;

    Ok((call_id, from_tag, to_tag, sdp))
}

/// Extract call-id and from-tag from a SIP message (delete direction — no SDP required).
fn extract_delete_params(
    message: &Arc<Mutex<SipMessage>>,
) -> PyResult<(String, String)> {
    let message = lock_message(message)?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing Call-ID header")
        })?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("message missing From header")
        })?;

    let from_tag = extract_tag(from_raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("From header missing tag parameter")
    })?;

    Ok((call_id, from_tag))
}

/// Extract the `tag=` parameter from a From/To header value.
fn extract_tag(header_value: &str) -> Option<String> {
    // Look for ";tag=" (case-insensitive).
    let lower = header_value.to_lowercase();
    let tag_start = lower.find(";tag=")?;
    let value_start = tag_start + 5; // skip ";tag="
    let rest = &header_value[value_start..];
    // Tag ends at next ';', '>', or end of string.
    let end = rest
        .find([';', '>'])
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Replace the SIP message body with new SDP and update Content-Length.
pub(super) fn replace_body(
    message: &Arc<Mutex<SipMessage>>,
    new_body: &[u8],
) -> PyResult<()> {
    let mut message = message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;
    message.body = new_body.to_vec();
    message
        .headers
        .set("Content-Length", new_body.len().to_string());
    message
        .headers
        .set("Content-Type", "application/sdp".to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_resolves_builtins() {
        let registry = ProfileRegistry::new();
        assert!(registry.get(DEFAULT_PROFILE).is_some());
        assert!(registry.get("ws_to_rtp").is_some());
        assert!(registry.get("wss_to_rtp").is_some());
        assert!(registry.get("rtp_passthrough").is_some());
    }

    #[test]
    fn registry_rejects_unknown() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("invalid").is_none());
    }

    #[test]
    fn extract_tag_from_header() {
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>;tag=abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_tag("\"Alice\" <sip:alice@atlanta.com>;tag=xyz;other=val"),
            Some("xyz".to_string())
        );
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>"),
            None,
        );
    }

    #[test]
    fn extract_tag_case_insensitive() {
        assert_eq!(
            extract_tag("<sip:alice@atlanta.com>;Tag=ABC"),
            Some("ABC".to_string())
        );
    }

    /// Helper to build a minimal SIP message for testing.
    fn test_message(content_type: Option<&str>, body: &[u8]) -> SipMessage {
        use crate::sip::message::{RequestLine, StartLine, Version, Method};
        use crate::sip::uri::SipUri;
        use crate::sip::headers::SipHeaders;

        let mut headers = SipHeaders::new();
        if let Some(content_type) = content_type {
            headers.set("Content-Type", content_type.to_string());
        }

        SipMessage {
            start_line: StartLine::Request(RequestLine {
                method: Method::Invite,
                request_uri: SipUri::new("10.0.0.1".to_string()),
                version: Version::sip_2_0(),
            }),
            headers,
            body: body.to_vec(),
        }
    }

    #[test]
    fn extract_sdp_body_plain() {
        let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";
        let message = test_message(Some("application/sdp"), body);

        let sdp = extract_sdp_body(&message).unwrap();
        assert_eq!(sdp, body);
    }

    #[test]
    fn extract_sdp_body_multipart() {
        let multipart_body = concat!(
            "--srec-abc123\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
            "\r\n",
            "--srec-abc123\r\n",
            "Content-Type: application/rs-metadata+xml\r\n",
            "\r\n",
            "<recording xmlns='urn:ietf:params:xml:ns:recording:1'/>\r\n",
            "\r\n",
            "--srec-abc123--\r\n",
        );

        let message = test_message(
            Some("multipart/mixed;boundary=srec-abc123"),
            multipart_body.as_bytes(),
        );

        let sdp = extract_sdp_body(&message).unwrap();
        let sdp_str = String::from_utf8_lossy(&sdp);

        // Should contain only the SDP, not the multipart boundaries or XML.
        assert!(sdp_str.starts_with("v=0"));
        assert!(sdp_str.contains("a=recvonly"));
        assert!(!sdp_str.contains("--srec-abc123"));
        assert!(!sdp_str.contains("recording"));
    }

    #[test]
    fn extract_sdp_body_empty() {
        let message = test_message(None, b"");
        assert!(extract_sdp_body(&message).is_err());
    }

    #[test]
    fn resolve_play_media_source_file() {
        pyo3::Python::initialize();
        let source = resolve_play_media_source(
            Some("/tmp/a.wav".to_string()),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(source, PlayMediaSource::File(ref path) if path == "/tmp/a.wav"));
    }

    #[test]
    fn resolve_play_media_source_blob() {
        pyo3::Python::initialize();
        let source = resolve_play_media_source(
            None,
            Some(vec![0x00, 0xff]),
            None,
        )
        .unwrap();
        assert!(matches!(source, PlayMediaSource::Blob(ref bytes) if bytes == &[0x00, 0xff]));
    }

    #[test]
    fn resolve_play_media_source_db_id() {
        pyo3::Python::initialize();
        let source = resolve_play_media_source(None, None, Some(7)).unwrap();
        assert!(matches!(source, PlayMediaSource::DbId(7)));
    }

    #[test]
    fn resolve_play_media_source_none_rejected() {
        pyo3::Python::initialize();
        let error = resolve_play_media_source(None, None, None).unwrap_err();
        Python::attach(|py| {
            assert!(error.value(py).to_string().contains("exactly one"));
        });
    }

    #[test]
    fn resolve_play_media_source_multiple_rejected() {
        pyo3::Python::initialize();
        let error_file_and_blob = resolve_play_media_source(
            Some("/tmp/a.wav".to_string()),
            Some(vec![0x00]),
            None,
        )
        .unwrap_err();
        let error_file_and_db = resolve_play_media_source(
            Some("/tmp/a.wav".to_string()),
            None,
            Some(1),
        )
        .unwrap_err();
        Python::attach(|py| {
            assert!(error_file_and_blob.value(py).to_string().contains("exactly one"));
            assert!(error_file_and_db.value(py).to_string().contains("exactly one"));
        });
    }

    #[test]
    fn replace_body_always_sets_content_type() {
        let message = test_message(Some("multipart/mixed;boundary=abc"), b"old body");
        let message_arc = Arc::new(Mutex::new(message));
        let new_body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\n";

        replace_body(&message_arc, new_body).unwrap();

        let guard = message_arc.lock().unwrap();
        assert_eq!(
            guard.headers.get("Content-Type"),
            Some(&"application/sdp".to_string())
        );
        assert_eq!(
            guard.headers.get("Content-Length"),
            Some(&new_body.len().to_string())
        );
        assert_eq!(guard.body, new_body);
    }

    fn make_session(call_id: &str, profile: &str) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: call_id.to_string(),
            from_tag: "tag-a".to_string(),
            to_tag: None,
            profile: profile.to_string(),
            ws_uri: None,
            created_at: std::time::Instant::now(),
        }
    }

    fn make_session_with_ws(call_id: &str, ws_uri: &str) -> MediaSession {
        MediaSession {
            ws_uri: Some(ws_uri.to_string()),
            ..make_session(call_id, "voice_ai")
        }
    }

    // -- ws_uri templating ----------------------------------------------------

    fn ws_context<'a>() -> WsUriContext<'a> {
        WsUriContext {
            call_id: "abc123@example.invalid",
            from_tag: "tag-a",
            from_user: Some("1001"),
            to_user: Some("2002"),
        }
    }

    #[test]
    fn expand_ws_uri_without_placeholder_is_untouched() {
        let expanded = expand_ws_uri("wss://ai.invalid/stream", &ws_context()).unwrap();
        assert_eq!(expanded, "wss://ai.invalid/stream");
    }

    #[test]
    fn expand_ws_uri_substitutes_every_placeholder() {
        let expanded = expand_ws_uri(
            "wss://ai.invalid/{call_id}/{from_tag}?from={from_user}&to={to_user}",
            &ws_context(),
        )
        .unwrap();
        assert_eq!(
            expanded,
            "wss://ai.invalid/abc123@example.invalid/tag-a?from=1001&to=2002"
        );
    }

    #[test]
    fn expand_ws_uri_substitutes_repeated_placeholder() {
        let expanded =
            expand_ws_uri("wss://ai.invalid/{call_id}/{call_id}", &ws_context()).unwrap();
        assert_eq!(
            expanded,
            "wss://ai.invalid/abc123@example.invalid/abc123@example.invalid"
        );
    }

    /// A typo'd placeholder must not reach the engine as a literal path segment.
    #[test]
    fn expand_ws_uri_rejects_unknown_placeholder() {
        pyo3::Python::initialize();
        let error = expand_ws_uri("wss://ai.invalid/{callid}", &ws_context()).unwrap_err();
        assert!(
            error.to_string().contains("unknown placeholder {callid}"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn expand_ws_uri_rejects_unclosed_placeholder() {
        pyo3::Python::initialize();
        let error = expand_ws_uri("wss://ai.invalid/{call_id", &ws_context()).unwrap_err();
        assert!(
            error.to_string().contains("unclosed"),
            "unexpected error: {error}"
        );
    }

    /// A placeholder with nothing to substitute is an error too — an empty path
    /// segment is as wrong as a literal one, just harder to spot.
    #[test]
    fn expand_ws_uri_rejects_placeholder_with_no_value() {
        pyo3::Python::initialize();
        let context = WsUriContext {
            from_user: None,
            ..ws_context()
        };
        let error = expand_ws_uri("wss://ai.invalid/{from_user}", &context).unwrap_err();
        assert!(
            error.to_string().contains("has no value"),
            "unexpected error: {error}"
        );
    }

    // -- ws_uri resolution precedence -----------------------------------------

    #[test]
    fn resolve_ws_uri_explicit_arg_wins() {
        let store = MediaSessionStore::new();
        store.insert(make_session_with_ws("call-1", "wss://recorded.invalid"));
        let resolved = resolve_ws_uri(
            Some("wss://explicit.invalid"),
            &store,
            "call-1",
            Some("wss://profile.invalid"),
        );
        assert_eq!(resolved.as_deref(), Some("wss://explicit.invalid"));
    }

    /// The reason this precedence exists: an `answer` after an `offer` keeps the
    /// bridge the offer established, without the script re-passing `ws_uri=`.
    #[test]
    fn resolve_ws_uri_recovers_from_offer() {
        let store = MediaSessionStore::new();
        store.insert(make_session_with_ws("call-1", "wss://recorded.invalid"));
        let resolved = resolve_ws_uri(None, &store, "call-1", Some("wss://profile.invalid"));
        assert_eq!(resolved.as_deref(), Some("wss://recorded.invalid"));
    }

    #[test]
    fn resolve_ws_uri_falls_back_to_profile() {
        let store = MediaSessionStore::new();
        let resolved = resolve_ws_uri(None, &store, "no-such-call", Some("wss://profile.invalid"));
        assert_eq!(resolved.as_deref(), Some("wss://profile.invalid"));
    }

    /// An offer recorded *without* a bridge must not inherit the profile's URI on
    /// the answer — otherwise a script that passed `ws_uri=None` deliberately
    /// gets a bridge attached behind its back at answer time.
    #[test]
    fn resolve_ws_uri_recorded_session_without_bridge_falls_through() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1", "voice_ai"));
        let resolved = resolve_ws_uri(None, &store, "call-1", Some("wss://profile.invalid"));
        assert_eq!(resolved.as_deref(), Some("wss://profile.invalid"));
    }

    #[test]
    fn resolve_ws_uri_none_everywhere_is_none() {
        let store = MediaSessionStore::new();
        assert!(resolve_ws_uri(None, &store, "no-such-call", None).is_none());
    }

    // -- the built-in voice_ai profile ----------------------------------------

    /// The profile has to leave `ws_uri` unset (there is no sensible default
    /// endpoint) but everything else it sets must be live, or naming it would be
    /// a no-op that reads as configured.
    #[test]
    fn builtin_voice_ai_profile_sets_live_flags_but_no_endpoint() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("voice_ai").expect("voice_ai profile missing");
        for flags in [&entry.offer, &entry.answer] {
            assert!(flags.ws_uri.is_none());
            assert!(flags.noise_suppression);
            assert!(flags.echo_cancellation);
            assert!(flags.ws_vad);
            assert!(flags.ws_barge_in);
            assert_eq!(flags.transport_protocol.as_deref(), Some("RTP/AVP"));
        }
    }

    #[test]
    fn resolve_answer_profile_explicit_arg_wins() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1", "srtp_to_rtp"));
        let chosen = resolve_answer_profile(Some("ws_to_rtp"), &store, "call-1");
        assert_eq!(chosen, "ws_to_rtp");
    }

    #[test]
    fn resolve_answer_profile_recovers_from_offer() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1", "srtp_to_rtp"));
        let chosen = resolve_answer_profile(None, &store, "call-1");
        assert_eq!(chosen, "srtp_to_rtp");
    }

    #[test]
    fn resolve_answer_profile_falls_back_when_no_offer() {
        let store = MediaSessionStore::new();
        let chosen = resolve_answer_profile(None, &store, "no-such-call");
        assert_eq!(chosen, DEFAULT_PROFILE);
    }

    #[test]
    fn resolve_answer_profile_explicit_arg_wins_when_no_offer() {
        let store = MediaSessionStore::new();
        let chosen = resolve_answer_profile(Some("rtp_passthrough"), &store, "no-such-call");
        assert_eq!(chosen, "rtp_passthrough");
    }

    // -- answer_local outcome classification ---------------------------------

    #[test]
    fn classify_answer_local_ok_answers() {
        let outcome = classify_answer_local(Ok("v=0\r\nm=audio 40000 RTP/AVP 8\r\n".to_string()), true);
        assert_eq!(
            outcome,
            AnswerLocalOutcome::Answered("v=0\r\nm=audio 40000 RTP/AVP 8\r\n".to_string())
        );
    }

    #[test]
    fn classify_answer_local_no_codec_with_call_rejects() {
        let outcome = classify_answer_local(
            Err(RtpEngineError::EngineError("no-encodable-codec".to_string())),
            true,
        );
        assert_eq!(outcome, AnswerLocalOutcome::Reject488);
    }

    #[test]
    fn classify_answer_local_no_codec_without_call_value_error() {
        let outcome = classify_answer_local(
            Err(RtpEngineError::EngineError("no-encodable-codec".to_string())),
            false,
        );
        assert_eq!(outcome, AnswerLocalOutcome::ValueError);
    }

    #[test]
    fn classify_answer_local_transport_error_is_runtime() {
        let outcome =
            classify_answer_local(Err(RtpEngineError::Timeout { timeout_ms: 2000 }), true);
        match outcome {
            AnswerLocalOutcome::RuntimeError(message) => {
                assert!(message.contains("rtpengine.answer_local failed"));
            }
            other => panic!("expected RuntimeError, got {other:?}"),
        }
    }

    #[test]
    fn classify_answer_local_other_engine_error_is_runtime_not_reject() {
        // A non-"no-encodable-codec" engine error is a runtime error even when a
        // reject target is available — the auto-488 is codec-specific.
        let outcome = classify_answer_local(
            Err(RtpEngineError::EngineError("no such call".to_string())),
            true,
        );
        assert!(matches!(outcome, AnswerLocalOutcome::RuntimeError(_)));
    }

    // -- resolve_call_from_tag: object / tuple / bare-str target forms -------

    #[test]
    fn resolve_call_from_tag_accepts_object_tuple_and_str() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            // (1) SIP object: a Call wrapping an INVITE with Call-ID + From tag.
            let mut message = test_message(Some("application/sdp"), b"v=0\r\n");
            message.headers.set("Call-ID", "call-xyz".to_string());
            message
                .headers
                .set("From", "<sip:alice@atlanta.com>;tag=ftag-1".to_string());
            let call = PyCall::new(
                "id-1".to_string(),
                Arc::new(Mutex::new(message)),
                "10.0.0.1".to_string(),
                "udp".to_string(),
            );
            let py_call = Py::new(py, call).unwrap();
            let bound_call = py_call.bind(py).clone().into_any();
            let (call_id, from_tag) = resolve_call_from_tag(&bound_call).unwrap();
            assert_eq!(call_id, "call-xyz");
            assert_eq!(from_tag, "ftag-1");

            // (2) (call_id, from_tag) pair — the @rtpengine.on_dtmf shape.
            let tuple = pyo3::types::PyTuple::new(py, ["call-xyz", "ftag-1"]).unwrap();
            let (call_id, from_tag) = resolve_call_from_tag(tuple.as_any()).unwrap();
            assert_eq!(call_id, "call-xyz");
            assert_eq!(from_tag, "ftag-1");

            // (3) bare call_id str → empty from_tag (best-effort).
            let string = pyo3::types::PyString::new(py, "call-xyz");
            let (call_id, from_tag) = resolve_call_from_tag(string.as_any()).unwrap();
            assert_eq!(call_id, "call-xyz");
            assert_eq!(from_tag, "");

            // (4) unsupported type → TypeError.
            let number = 42i64.into_pyobject(py).unwrap();
            let error = resolve_call_from_tag(number.as_any()).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(py));
        });
    }
}
