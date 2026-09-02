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
use crate::rtpengine::profile::{
    validate_ws_sample_rate, NgFlags, ProfileRegistry, WsTeeDirection, WsVadEngine,
};
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

/// Validate exactly-one of ``file``/``blob``/``db_id``/``tone``/``url`` and
/// build a [`PlayMediaSource`].
fn resolve_play_media_source(
    file: Option<String>,
    blob: Option<Vec<u8>>,
    db_id: Option<u64>,
    tone: Option<String>,
    url: Option<String>,
) -> PyResult<PlayMediaSource> {
    let count = [
        file.is_some(),
        blob.is_some(),
        db_id.is_some(),
        tone.is_some(),
        url.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if count != 1 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "play_media requires exactly one of file=, blob=, db_id=, tone=, or url="
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
    if let Some(spec) = tone {
        return Ok(PlayMediaSource::Tone(validate_tone(spec)?));
    }
    if let Some(location) = url {
        return Ok(PlayMediaSource::Http(validate_http_url(location)?));
    }
    unreachable!("count == 1 guaranteed one branch above")
}

/// Reject an empty tone spec before it reaches the engine.
///
/// The engine tells a **preset name** from a **cadence spec** by the `/` (a
/// preset never contains one; a cadence spec is never valid without one), so
/// both forms are accepted verbatim — siphon deliberately does not keep its own
/// copy of the preset table, which would go stale against the engine's the first
/// time a preset is added.  Only the one thing that is wrong under either
/// reading is caught here.
fn validate_tone(spec: String) -> PyResult<String> {
    if spec.trim().is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "play_media tone= must be a preset name (e.g. \"ringback_eu\") or a \
             cadence spec (e.g. \"425/1000,0/4000*inf\"), not an empty string"
                .to_string(),
        ));
    }
    Ok(spec)
}

/// Reject a URL scheme the engine will not fetch.
///
/// The **engine** performs this fetch from its own network position, bounded by
/// its own connect / first-byte / deadline / size / redirect caps and run off
/// the media path, so a URL that never answers ends the *playback* (a
/// play-finished `error`) and never stalls the leg.  siphon deliberately does
/// not fetch it here: doing so would put an unbounded third-party HTTP
/// round-trip on the call-setup path, which is the failure mode this design
/// avoids.  What is checked here is only the part the engine would reject
/// outright.
fn validate_http_url(url: String) -> PyResult<String> {
    let lowered = url.trim().to_ascii_lowercase();
    if !(lowered.starts_with("http://") || lowered.starts_with("https://")) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "play_media url= must be an http:// or https:// URL, got {url:?}"
        )));
    }
    Ok(url)
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

/// The 0.3.0 media knobs a script can override for **one call**, on top of
/// whatever its `media.profiles` entry set.
///
/// Same model as the existing per-call `ws_uri=`: `None` means "leave the
/// profile's value alone", so passing nothing emits exactly the command a
/// pre-override build did.  These are the knobs whose right value genuinely
/// varies per call rather than per deployment — arming beep detection only on
/// the leg being transferred, or matching the wire rate to the model a
/// particular AI backend expects.
#[derive(Debug, Clone, Copy, Default)]
struct MediaOverrides {
    beep_detection: Option<bool>,
    beep_cadence_guard_ms: Option<u32>,
    ws_sample_rate: Option<u32>,
    ws_tee_sample_rate: Option<u32>,
    ws_vad_min_speech_ms: Option<u32>,
    ws_vad_engine: Option<WsVadEngine>,
}

impl MediaOverrides {
    /// Parse the raw keyword values, rejecting anything the engine would refuse.
    ///
    /// The two sample rates are validated here rather than at the engine: the
    /// engine *fails the offer* on a bad rate instead of clamping, so a script
    /// that passed one would get a call that answers and never carries media.
    fn parse(
        beep_detection: Option<bool>,
        beep_cadence_guard_ms: Option<u32>,
        ws_sample_rate: Option<u32>,
        ws_tee_sample_rate: Option<u32>,
        ws_vad_min_speech_ms: Option<u32>,
        ws_vad_engine: Option<&str>,
    ) -> PyResult<Self> {
        for (field, rate) in [
            ("ws_sample_rate", ws_sample_rate),
            ("ws_tee_sample_rate", ws_tee_sample_rate),
        ] {
            if let Some(rate) = rate {
                validate_ws_sample_rate(rate).map_err(|reason| {
                    pyo3::exceptions::PyValueError::new_err(format!("{field} {reason}"))
                })?;
            }
        }

        let ws_vad_engine = match ws_vad_engine {
            None => None,
            Some(value) => Some(WsVadEngine::parse(value).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "ws_vad_engine must be one of {}, got {value:?}",
                    WsVadEngine::VALUES.join(" / ")
                ))
            })?),
        };

        Ok(Self {
            beep_detection,
            beep_cadence_guard_ms,
            ws_sample_rate,
            ws_tee_sample_rate,
            ws_vad_min_speech_ms,
            ws_vad_engine,
        })
    }

    /// Overlay the set values onto the profile's flags.
    fn apply(self, flags: &mut NgFlags) -> PyResult<()> {
        if let Some(value) = self.beep_detection {
            flags.beep_detection = value;
        }
        if let Some(value) = self.beep_cadence_guard_ms {
            flags.beep_cadence_guard_ms = Some(value);
        }
        if let Some(value) = self.ws_sample_rate {
            flags.ws_sample_rate = Some(value);
        }
        if let Some(value) = self.ws_tee_sample_rate {
            flags.ws_tee_sample_rate = Some(value);
        }
        if let Some(value) = self.ws_vad_min_speech_ms {
            flags.ws_vad_min_speech_ms = Some(value);
        }
        if let Some(value) = self.ws_vad_engine {
            flags.ws_vad_engine = Some(value);
        }
        Ok(())
    }
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
    overrides: MediaOverrides,
    source_ip: Option<&str>,
    profile_name: &str,
) -> PyResult<NgFlags> {
    if let Some(uri) = ws_uri {
        flags.ws_uri = Some(uri);
    }
    overrides.apply(&mut flags)?;
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
    ///     beep_detection: Arm the record-tone ("voicemail beep") detector on this
    ///             leg for this call, overriding the profile. Arming it on the leg
    ///             toward the callee is what watches the party that might be a
    ///             machine; the tone arrives as ``@rtpengine.on_beep``, once per
    ///             leg per call. ``siphon-rtp`` backend only.
    ///     beep_cadence_guard_ms: How long the detector waits after a candidate
    ///             tone to rule out a cadenced ringback/busy tone. **Also the
    ///             detection latency** — the event trails the tone by this long.
    ///             Unset uses the engine default (4500 ms).
    ///     ws_sample_rate: L16 wire rate in Hz for the ``ws_uri`` bridge,
    ///             independent of the leg's codec rate and applied both ways.
    ///             Must be a multiple of 1000 within 8000-48000 (the engine fails
    ///             the offer rather than clamping, so it is checked here).
    ///     ws_tee_sample_rate: L16 wire rate in Hz for the ``ws_tee`` copy. Same
    ///             range rule; send-only, so it never changes what the call hears.
    ///     ws_vad_engine: Which uplink VAD to run — ``"energy"`` (cheap; any loud
    ///             sound reads as speech) or ``"neural"`` (answers "is this
    ///             speech", so it does not turn-start on noise).
    ///     ws_vad_min_speech_ms: **Leading** minimum continuous-speech run before
    ///             the speech-start edge (and barge-in) fires — distinct from the
    ///             trailing hangover. Rounded up to whole ptime frames and added
    ///             to turn-start latency, so 60-120 ms is the useful range.
    #[pyo3(signature = (request, profile=None, ws_uri=None, beep_detection=None, beep_cadence_guard_ms=None, ws_sample_rate=None, ws_tee_sample_rate=None, ws_vad_engine=None, ws_vad_min_speech_ms=None))]
    #[allow(clippy::too_many_arguments)]
    fn offer<'py>(
        &self,
        python: Python<'py>,
        request: &Bound<'py, PyAny>,
        profile: Option<&str>,
        ws_uri: Option<&str>,
        beep_detection: Option<bool>,
        beep_cadence_guard_ms: Option<u32>,
        ws_sample_rate: Option<u32>,
        ws_tee_sample_rate: Option<u32>,
        ws_vad_engine: Option<&str>,
        ws_vad_min_speech_ms: Option<u32>,
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
        let overrides = MediaOverrides::parse(
            beep_detection,
            beep_cadence_guard_ms,
            ws_sample_rate,
            ws_tee_sample_rate,
            ws_vad_min_speech_ms,
            ws_vad_engine,
        )?;
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri.clone(),
            overrides,
            source_ip.as_deref(),
            profile_name,
        )?;

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);
        let profile_str = profile_name.to_string();

        // A call this process has already anchored is a *re*-offer — a re-INVITE
        // or an UPDATE, the shape hold/unhold and an ICE restart arrive in. It
        // has to keep the ports it already holds, so it goes out as `reoffer`;
        // a plain `offer` on a live call-id replaces it on the siphon-rtp
        // backend, taking its WebSocket bridge, tee and SIPREC subscription with
        // it. Address the engine by the session's own id, not the SIP Call-ID:
        // a siphon-terminated transfer re-anchors the surviving pair on a fresh
        // engine call-id while the store key stays the SIP one.
        let existing = sessions.get(&call_id);
        let engine_call_id = existing
            .as_ref()
            .map(|session| session.rtpengine_id().to_string())
            .unwrap_or_else(|| call_id.clone());
        let is_reoffer = existing.is_some();

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let rewritten_sdp = if is_reoffer {
                client
                    .reoffer(&engine_call_id, &from_tag, &sdp, &flags)
                    .await
                    .map_err(|error| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "rtpengine.offer failed (re-offer): {error}"
                        ))
                    })?
            } else {
                client
                    .offer(&engine_call_id, &from_tag, &sdp, &flags)
                    .await
                    .map_err(|error| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "rtpengine.offer failed: {error}"
                        ))
                    })?
            };

            debug!(
                call_id = %call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine offer: SDP rewritten"
            );

            replace_body(&message, &rewritten_sdp)?;

            // Only an *initial* offer creates the session. Re-inserting on a
            // re-offer would reset `rtpengine_call_id` to the SIP Call-ID —
            // stranding a transfer-re-anchored call, whose engine id is
            // deliberately different — and clear the `to_tag` the answer set,
            // which is what every later `answer`/`delete` addresses the leg by.
            if !is_reoffer {
                sessions.insert(MediaSession {
                    rtpengine_call_id: call_id.clone(),
                    call_id,
                    from_tag,
                    to_tag: None,
                    profile: profile_str,
                    ws_uri: resolved_ws_uri,
                    ws_tee: flags.ws_tee.clone(),
                    ws_bridge_attached: false,
                    created_at: std::time::Instant::now(),
                });
            }

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
    ///     beep_detection: Arm the record-tone ("voicemail beep") detector on this
    ///             leg for this call, overriding the profile. Delivered as
    ///             ``@rtpengine.on_beep``, once per leg per call. ``siphon-rtp``
    ///             backend only.
    ///     beep_cadence_guard_ms: Cadence guard for the beep detector, and also
    ///             its detection latency. Unset uses the engine default (4500 ms).
    ///     ws_sample_rate: L16 wire rate in Hz for the ``ws_uri`` bridge. Must be
    ///             a multiple of 1000 within 8000-48000.
    ///     ws_tee_sample_rate: L16 wire rate in Hz for the ``ws_tee`` copy. Same
    ///             range rule; send-only.
    ///     ws_vad_engine: ``"energy"`` or ``"neural"`` uplink VAD.
    ///     ws_vad_min_speech_ms: Leading minimum continuous-speech run before the
    ///             speech-start edge fires (60-120 ms is the useful range).
    #[pyo3(signature = (reply, profile=None, call=None, ws_uri=None, beep_detection=None, beep_cadence_guard_ms=None, ws_sample_rate=None, ws_tee_sample_rate=None, ws_vad_engine=None, ws_vad_min_speech_ms=None))]
    #[allow(clippy::too_many_arguments)]
    fn answer<'py>(
        &self,
        python: Python<'py>,
        reply: &Bound<'py, PyAny>,
        profile: Option<&str>,
        call: Option<&Bound<'py, PyAny>>,
        ws_uri: Option<&str>,
        beep_detection: Option<bool>,
        beep_cadence_guard_ms: Option<u32>,
        ws_sample_rate: Option<u32>,
        ws_tee_sample_rate: Option<u32>,
        ws_vad_engine: Option<&str>,
        ws_vad_min_speech_ms: Option<u32>,
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
        let overrides = MediaOverrides::parse(
            beep_detection,
            beep_cadence_guard_ms,
            ws_sample_rate,
            ws_tee_sample_rate,
            ws_vad_min_speech_ms,
            ws_vad_engine,
        )?;
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri,
            overrides,
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
    ///     beep_detection: Arm the record-tone ("voicemail beep") detector on this
    ///             leg for this call, overriding the profile. Delivered as
    ///             ``@rtpengine.on_beep``, once per leg per call. ``siphon-rtp``
    ///             backend only.
    ///     beep_cadence_guard_ms: Cadence guard for the beep detector, and also
    ///             its detection latency. Unset uses the engine default (4500 ms).
    ///     ws_sample_rate: L16 wire rate in Hz for the ``ws_uri`` bridge. Must be
    ///             a multiple of 1000 within 8000-48000.
    ///     ws_tee_sample_rate: L16 wire rate in Hz for the ``ws_tee`` copy. Same
    ///             range rule; send-only.
    ///     ws_vad_engine: ``"energy"`` or ``"neural"`` uplink VAD.
    ///     ws_vad_min_speech_ms: Leading minimum continuous-speech run before the
    ///             speech-start edge fires (60-120 ms is the useful range).
    #[pyo3(signature = (call, profile=None, auto_reject=true, ws_uri=None, beep_detection=None, beep_cadence_guard_ms=None, ws_sample_rate=None, ws_tee_sample_rate=None, ws_vad_engine=None, ws_vad_min_speech_ms=None))]
    #[allow(clippy::too_many_arguments)]
    fn answer_local<'py>(
        &self,
        python: Python<'py>,
        call: &Bound<'py, PyAny>,
        profile: Option<&str>,
        auto_reject: bool,
        ws_uri: Option<&str>,
        beep_detection: Option<bool>,
        beep_cadence_guard_ms: Option<u32>,
        ws_sample_rate: Option<u32>,
        ws_tee_sample_rate: Option<u32>,
        ws_vad_engine: Option<&str>,
        ws_vad_min_speech_ms: Option<u32>,
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
        let overrides = MediaOverrides::parse(
            beep_detection,
            beep_cadence_guard_ms,
            ws_sample_rate,
            ws_tee_sample_rate,
            ws_vad_min_speech_ms,
            ws_vad_engine,
        )?;
        let flags = finalise_flags(
            flags,
            &self.client,
            resolved_ws_uri.clone(),
            overrides,
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
                        ws_tee: flags.ws_tee.clone(),
                        ws_bridge_attached: false,
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
    /// Exactly one of ``file``, ``blob``, ``db_id``, ``tone`` or ``url`` must be
    /// supplied.
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
    ///     tone: A synthesised call-progress tone — no audio file to provision.
    ///           Either a preset name (``"ringback_eu"``, ``"busy_na"``,
    ///           ``"dial_uk"``, …) or an explicit cadence spec in the engine's
    ///           tone grammar (``"425/1000,0/4000*inf"`` = 425 Hz one second on,
    ///           four seconds off, forever). The two are told apart by the
    ///           ``/``. Rendered at the leg's codec rate, so never resampled.
    ///           Native **siphon-rtp** backend only.
    ///     url: An ``http://`` / ``https://`` WAV the **engine** fetches from its
    ///          own network position. The fetch is bounded engine-side (connect,
    ///          first-byte, overall deadline, size cap, redirect cap) and runs
    ///          off the media path, so a URL that never answers ends the
    ///          *playback*, never the leg — it comes back as a play that
    ///          produced no audio rather than a stalled call. The accept carries
    ///          no duration (the length is unknown until the body arrives).
    ///          Native **siphon-rtp** backend only.
    ///     gain_decibels: Playout gain in whole decibels relative to the
    ///           source's own level, clamped engine-side to −60..=+12. Native
    ///           **siphon-rtp** backend only.
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
    #[pyo3(signature = (target, file=None, blob=None, db_id=None, tone=None, url=None, repeat=None, start_ms=None, duration_ms=None, gain_decibels=None, to_tag=None, wait=true))]
    #[allow(clippy::too_many_arguments)]
    fn play_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        file: Option<String>,
        blob: Option<Vec<u8>>,
        db_id: Option<u64>,
        tone: Option<String>,
        url: Option<String>,
        repeat: Option<u64>,
        start_ms: Option<u64>,
        duration_ms: Option<u64>,
        gain_decibels: Option<i32>,
        to_tag: Option<String>,
        wait: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = resolve_play_media_source(file, blob, db_id, tone, url)?;

        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let outcome = client
                .play_media(
                    &call_id,
                    &from_tag,
                    &source,
                    repeat,
                    start_ms,
                    duration_ms,
                    to_tag.as_deref(),
                    // Superseding playback — `play_overlay` is the additive twin.
                    false,
                    gain_decibels,
                    wait,
                )
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.play_media failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                duration_ms = ?outcome.duration_ms,
                "rtpengine play_media"
            );
            Ok(outcome.duration_ms)
        })
    }

    /// Start an **overlay** playback — mix audio *under* the party's live egress
    /// instead of replacing it, and return its ``play_id`` handle.
    ///
    /// The additive twin of :meth:`play_media`. Where ``play_media`` answers
    /// "how long did it play", this answers "which playback is it", because that
    /// is what an overlay is for: a music bed you will duck with
    /// :meth:`set_play_gain` and stop individually with
    /// ``stop_media(target, play_id=...)``.
    ///
    /// Up to **four** overlays run concurrently per direction, each with its own
    /// ``play_id`` and its own completion. Starting a fifth is rejected rather
    /// than displacing one — a script that lost a playback it believes is
    /// running has no way to notice. An overlay never supersedes anything,
    /// including another overlay.
    ///
    /// Returns immediately on the engine's accept (an overlay is background
    /// audio; there is no ``wait``). Native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// bed = await rtpengine.play_overlay(call, file="/prompts/hold.wav", repeat=0)
    /// await rtpengine.play_media(call, file="/prompts/agent.wav")
    /// await rtpengine.set_play_gain(call, bed, -18)   # duck the bed
    /// await rtpengine.stop_media(call, play_id=bed)
    /// ```
    ///
    /// Args:
    ///     target: Request, Reply, or Call object.
    ///     file / blob / db_id / tone / url: exactly one, as for
    ///         :meth:`play_media`.
    ///     repeat: Number of times to repeat.
    ///     start_ms: Offset into the source at which to start.
    ///     duration_ms: Hard playout cap — the only bound, short of a stop, on
    ///         an endless (``*inf``) tone.
    ///     gain_decibels: Playout gain relative to the source's own level,
    ///         clamped engine-side to −60..=+12.
    ///     to_tag: Optional peer tag for MPTY scoping.
    ///
    /// Returns:
    ///     The ``play_id`` of the started overlay, or ``None`` if the engine
    ///     assigned none.
    #[pyo3(signature = (target, file=None, blob=None, db_id=None, tone=None, url=None, repeat=None, start_ms=None, duration_ms=None, gain_decibels=None, to_tag=None))]
    #[allow(clippy::too_many_arguments)]
    fn play_overlay<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        file: Option<String>,
        blob: Option<Vec<u8>>,
        db_id: Option<u64>,
        tone: Option<String>,
        url: Option<String>,
        repeat: Option<u64>,
        start_ms: Option<u64>,
        duration_ms: Option<u64>,
        gain_decibels: Option<i32>,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = resolve_play_media_source(file, blob, db_id, tone, url)?;

        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            let outcome = client
                .play_media(
                    &call_id,
                    &from_tag,
                    &source,
                    repeat,
                    start_ms,
                    duration_ms,
                    to_tag.as_deref(),
                    true,
                    gain_decibels,
                    // An overlay is background audio: blocking until it drains
                    // would defeat the point (and an endless tone never drains).
                    false,
                )
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.play_overlay failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                play_id = ?outcome.play_id,
                "rtpengine play_overlay"
            );
            Ok(outcome.play_id)
        })
    }

    /// Send a `stop media` command — stop prompt playback on the monologue
    /// selected by the SIP object's From-tag.
    ///
    /// ``play_id`` stops one specific playback (an individual overlay slot, from
    /// :meth:`play_overlay`); omitting it stops everything playing on the leg.
    /// A ``play_id`` is native **siphon-rtp** only — the other backends have no
    /// handle on an individual playback, and are refused rather than widened
    /// into "stop everything", which would kill playbacks the script meant to
    /// keep running.
    #[pyo3(signature = (target, play_id=None))]
    fn stop_media<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        play_id: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client.stop_media(&call_id, &from_tag, play_id).await.map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "rtpengine.stop_media failed: {error}"
                ))
            })?;
            debug!(call_id = %call_id, play_id = ?play_id, "rtpengine stop_media");
            Ok(true)
        })
    }

    /// Retune the playout gain of a playback that is already running — how a
    /// script ducks a music bed under a prompt and lifts it again afterwards.
    ///
    /// A separate verb rather than a field on :meth:`play_media` because
    /// ``play_media`` is a *start*: reusing it would mean "start another
    /// playback", not "change this one".
    ///
    /// The engine answers an error when no playback on the call holds that
    /// ``play_id``, so a stale handle raises rather than silently doing nothing.
    /// Native **siphon-rtp** backend only.
    ///
    /// Args:
    ///     target: Request, Reply, or Call object.
    ///     play_id: The running playback to retune, from :meth:`play_overlay`.
    ///     gain_decibels: New gain in whole decibels, clamped engine-side to
    ///         −60..=+12.
    ///     to_tag: Optional peer tag for MPTY scoping.
    #[pyo3(signature = (target, play_id, gain_decibels, to_tag=None))]
    fn set_play_gain<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        play_id: u64,
        gain_decibels: i32,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let client = Arc::clone(&self.client);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .set_play_gain(&call_id, &from_tag, play_id, gain_decibels, to_tag.as_deref())
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.set_play_gain failed: {error}"
                    ))
                })?;
            debug!(
                call_id = %call_id,
                play_id,
                gain_decibels,
                "rtpengine set_play_gain"
            );
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

    /// Attach a **WebSocket tee** to a live call — stream a copy of its decoded
    /// audio to a WebSocket media server while the call keeps relaying.
    ///
    /// The distinction from the ``ws_uri`` media-profile flag matters:
    ///
    /// * ``ws_uri`` is a **takeover** — the WebSocket server *becomes* leg A's
    ///   far side and the A↔B relay is not wired.  That is the voice-AI
    ///   answer-the-call shape.
    /// * A tee is **send-only and additive** — the call relays (or transcodes)
    ///   normally *and* streams a copy of its audio out.  Any SIPREC
    ///   subscription and recording on the same leg keep running untouched.
    ///
    /// Use a tee for live transcription, agent-assist, sentiment or compliance
    /// monitoring on a call that is otherwise a normal two-party call.
    ///
    /// A tee never affects the call: the engine drops frames rather than
    /// stalling the media path if the consumer cannot keep up, and a failure
    /// here raises rather than tearing anything down — catch it and carry on.
    ///
    /// Requires ``media.backend: siphon-rtp``; the rtpengine and rtpproxy
    /// backends raise rather than silently doing nothing.
    ///
    /// ```python,ignore
    /// @b2bua.on_answer
    /// async def on_answer(call, reply):
    ///     await rtpengine.answer(reply)
    ///     try:
    ///         await rtpengine.attach_ws_tee(call, f"wss://asr.internal/{call.call_id}")
    ///     except RuntimeError as error:
    ///         log.warn(f"transcription tee unavailable: {error}")
    /// ```
    ///
    /// Args:
    ///     target: Request, Reply or Call identifying the media session.
    ///     ws_uri: ``ws://`` or ``wss://`` URI the engine dials as a client.
    ///     direction: Which leg(s) to stream — ``"both"`` (default),
    ///         ``"caller"`` (the offerer) or ``"callee"`` (the answerer).
    ///     channels: Wire channel count — ``2`` interleaves caller/callee as
    ///         stereo, ``1`` mixes them to mono.  Only meaningful with
    ///         ``direction="both"``; a single-leg tee is always mono.  ``None``
    ///         (default) leaves the engine's choice: 2 for both legs, 1 for one.
    ///     sample_rate: L16 wire sample rate in Hz, independent of the legs'
    ///         codec rates — the engine resamples the teed copy into it. Must be
    ///         a multiple of 1000 within 8000–48000; the engine *fails* the
    ///         attach on anything else rather than clamping, so it is checked
    ///         here first. ``None`` (default) leaves the engine's choice.
    #[pyo3(signature = (target, ws_uri, direction="both", channels=None, sample_rate=None))]
    fn attach_ws_tee<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        ws_uri: String,
        direction: &str,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;

        let direction = WsTeeDirection::parse(direction).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "rtpengine.attach_ws_tee direction must be one of {}, got {direction:?}",
                WsTeeDirection::VALUES.join(" / ")
            ))
        })?;

        // Caught here rather than at the engine so the script gets a precise
        // error instead of a generic engine rejection.
        if let Some(channels) = channels {
            if channels != 1 && channels != 2 {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "rtpengine.attach_ws_tee channels must be 1 or 2, got {channels}"
                )));
            }
        }

        // Same reason as `channels`: the engine fails the attach on a bad rate
        // rather than clamping, so catching it here gives the script the precise
        // rule instead of a generic engine rejection.
        if let Some(rate) = sample_rate {
            validate_ws_sample_rate(rate).map_err(|reason| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "rtpengine.attach_ws_tee sample_rate {reason}"
                ))
            })?;
        }

        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .attach_ws_tee(&call_id, &from_tag, &ws_uri, direction, channels, sample_rate)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.attach_ws_tee failed: {error}"
                    ))
                })?;
            // Recorded only after the engine accepted, so a failed attach never
            // leaves a bridge plan detaching a tee that was never there.
            sessions.set_ws_tee(&call_id, Some(ws_uri.clone()));
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                ws_uri = %ws_uri,
                direction = %direction.as_str(),
                ?channels,
                ?sample_rate,
                "rtpengine attach_ws_tee"
            );
            Ok(true)
        })
    }

    /// Detach a call's **WebSocket tee**, closing its stream.
    ///
    /// Idempotent — detaching a call with no tee is not an error.  A tee is
    /// also torn down automatically when the call ends, so an explicit detach
    /// is only needed to stop streaming mid-call.
    ///
    /// Requires ``media.backend: siphon-rtp``.
    ///
    /// ```python,ignore
    /// await rtpengine.detach_ws_tee(call)
    /// ```
    ///
    /// Args:
    ///     target: Request, Reply or Call identifying the media session.
    #[pyo3(signature = (target))]
    fn detach_ws_tee<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;
        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .detach_ws_tee(&call_id, &from_tag)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.detach_ws_tee failed: {error}"
                    ))
                })?;
            sessions.set_ws_tee(&call_id, None);
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                "rtpengine detach_ws_tee"
            );
            Ok(true)
        })
    }

    /// Attach a **WebSocket takeover bridge** to a live call, or re-point an
    /// existing one at a different server.
    ///
    /// The opposite of :meth:`attach_ws_tee` in what it does to the call.  A
    /// tee is *additive* — the call keeps relaying and a copy is streamed out.
    /// A bridge is a *takeover*: the WebSocket server becomes this leg's far
    /// side and A↔B is unwired for as long as the bridge lives.
    ///
    /// Calling it on a call that already has a bridge **re-points** it rather
    /// than failing, and the media path never drops in between — which is what
    /// lets one party be moved from one media server to another without the
    /// other party hearing a gap.
    ///
    /// Requires ``media.backend: siphon-rtp``.
    ///
    /// ```python,ignore
    /// await rtpengine.attach_ws_bridge(call, "wss://ai.internal/session-1")
    /// # ... later, hand the same caller to a different model session:
    /// await rtpengine.attach_ws_bridge(call, "wss://ai.internal/session-2")
    /// ```
    ///
    /// Args:
    ///     target: Request, Reply or Call identifying the media session.
    ///     ws_uri: ``ws://`` or ``wss://`` URI the engine dials as a client.
    #[pyo3(signature = (target, ws_uri))]
    fn attach_ws_bridge<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
        ws_uri: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;
        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .attach_ws_bridge(&call_id, &from_tag, &ws_uri)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.attach_ws_bridge failed: {error}"
                    ))
                })?;
            // A re-point stays attached — the flag tracks "a detachable bridge
            // is on this leg", not how many times it has been pointed.
            sessions.set_ws_bridge_attached(&call_id, true);
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                ws_uri = %ws_uri,
                "rtpengine attach_ws_bridge"
            );
            Ok(true)
        })
    }

    /// Detach a call's **WebSocket takeover bridge**, putting its media path
    /// back the way it was.
    ///
    /// Not idempotent, unlike :meth:`detach_ws_tee`.  The engine refuses a
    /// detach when there is no relay to return the call to — a bridge
    /// negotiated through ``ws_uri`` on the media profile *is* the call's media
    /// path, and a single-leg (``answer_local``) takeover has no second party
    /// that could ever be relayed to.  Both raise rather than answering
    /// success, because the alternative is a live call with no audio path at
    /// all.  Re-point those with :meth:`attach_ws_bridge`, or end the call.
    ///
    /// Requires ``media.backend: siphon-rtp``.
    ///
    /// ```python,ignore
    /// await rtpengine.detach_ws_bridge(call)   # back to relaying A<->B
    /// ```
    ///
    /// Args:
    ///     target: Request, Reply or Call identifying the media session.
    #[pyo3(signature = (target))]
    fn detach_ws_bridge<'py>(
        &self,
        python: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (call_id, from_tag) = resolve_call_from_tag(target)?;
        let client = Arc::clone(&self.client);
        let sessions = Arc::clone(&self.sessions);

        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            client
                .detach_ws_bridge(&call_id, &from_tag)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.detach_ws_bridge failed: {error}"
                    ))
                })?;
            sessions.set_ws_bridge_attached(&call_id, false);
            debug!(
                call_id = %call_id,
                from_tag = %from_tag,
                "rtpengine detach_ws_bridge"
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

    /// Register a handler for **RFC 4103 real-time text** (T.140) increments.
    ///
    /// Fires once per increment the engine's text processor recovers on the
    /// call's ``m=text`` stream, carrying the UTF-8 text that packet newly
    /// delivered.  Only non-empty increments are reported — a duplicate, a
    /// reordered packet or an idle keepalive produces no event — so the handler
    /// firing always means new characters arrived.  A ``\ufffd`` in the text is
    /// a gap RED redundancy could not repair (RFC 4103 §5.3), left in place so a
    /// consumer sees where loss occurred rather than silently reading a shorter
    /// message.
    ///
    /// Requires the call's media profile to set ``text_events``, and a call that
    /// actually negotiated a plaintext text stream.  Delivered by the native
    /// **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_text
    /// def transcript(call_id, from_tag, to_tag, text, direction):
    ///     log.info(f"[{call_id}] {direction}: {text}")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_text``) this is
    ///         the function.  When called with keyword filters the return value
    ///         is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter — the leg that *sent* the text.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_text<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_text", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("on_text decorator source: {error}"))
        })?, Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_text decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_text` (bare) and `@on_text(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for **WebSocket tee started** events.
    ///
    /// Fires once the engine has dialled the tee's WebSocket server, sent its
    /// ``start`` envelope, and begun streaming.  The handler receives the
    /// negotiated wire shape, so it can decode the binary frames without
    /// guessing — ``stream_id`` is the correlator between this control event
    /// and the media stream on the socket.
    ///
    /// Delivered by the native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_ws_tee_started
    /// def tee_up(call_id, from_tag, stream_id, ws_uri, direction, channels, sample_rate):
    ///     log.info(f"tee {stream_id}: {channels}ch @ {sample_rate}Hz -> {ws_uri}")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_ws_tee_started``)
    ///         this is the function.  When called with keyword filters the
    ///         return value is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_ws_tee_started<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_ws_tee_started", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).unwrap(), Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_ws_tee_started decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_ws_tee_started` (bare) and
        // `@on_ws_tee_started(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for **WebSocket takeover bridge started** events.
    ///
    /// Fires once the engine has dialled the bridge's WebSocket server and the
    /// leg's far side *is* that server — A↔B is unwired for the bridge's
    /// lifetime.  ``stream_id`` is the correlator between this control event
    /// and the media stream on the socket.
    ///
    /// A re-point (``attach_ws_bridge`` on a call that already had one) ends
    /// the old bridge and starts a new one, so it delivers an ``ended`` with
    /// reason ``detached`` followed by a fresh ``started`` carrying the new
    /// ``stream_id``.
    ///
    /// Delivered by the native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_ws_bridge_started
    /// def bridge_up(call_id, from_tag, stream_id, ws_uri, sample_rate):
    ///     log.info(f"bridge {stream_id} @ {sample_rate}Hz -> {ws_uri}")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_ws_bridge_started``) this is
    ///         the function.  When called with keyword filters the return value
    ///         is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_ws_bridge_started<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_ws_bridge_started", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let code = std::ffi::CString::new(code).map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to build on_ws_bridge_started decorator source: {error}"
            ))
        })?;
        let globals = PyDict::new(python);
        python.run(&code, Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_ws_bridge_started decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_ws_bridge_started` (bare) and
        // `@on_ws_bridge_started(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for **WebSocket takeover bridge ended** events.
    ///
    /// Fires exactly once per started bridge, including when the *server* ends
    /// it.  ``reason`` is one of ``detached``, ``server_closed``,
    /// ``server_stopped``, ``call_ended`` or ``transport_error``.
    ///
    /// Only ``detached`` is orderly.  Every other reason leaves a **live call
    /// with no media far side** — both parties are up and hearing nothing — so
    /// unlike the tee's equivalent this handler usually has to act: re-point
    /// with ``attach_ws_bridge``, fall back with ``detach_ws_bridge``, or tear
    /// the call down.  siphon logs an unexpected end at WARN even when no
    /// handler is registered.
    ///
    /// Delivered by the native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_ws_bridge_ended
    /// async def bridge_down(call_id, from_tag, stream_id, reason):
    ///     if reason != "detached":
    ///         log.warn(f"{call_id}: bridge died ({reason}), falling back to relay")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_ws_bridge_ended``) this is
    ///         the function.  When called with keyword filters the return value
    ///         is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_ws_bridge_ended<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_ws_bridge_ended", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let code = std::ffi::CString::new(code).map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to build on_ws_bridge_ended decorator source: {error}"
            ))
        })?;
        let globals = PyDict::new(python);
        python.run(&code, Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_ws_bridge_ended decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_ws_bridge_ended` (bare) and
        // `@on_ws_bridge_ended(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for **record-tone (voicemail beep)** events.
    ///
    /// Fires when the engine hears the short single tone an answering machine
    /// plays before it starts recording, on a leg whose media profile set
    /// ``beep_detection``.  This is the *media* half of answering-machine
    /// detection: a script can abort an attended transfer here instead of
    /// bridging the caller into a voicemail box.
    ///
    /// Arm it **per leg** — the profile used toward the callee is what watches
    /// the party that might be a machine.  It fires **once per leg per call**
    /// (the engine drops the detector after the first tone, so a handler never
    /// has to de-duplicate, and there is no mid-call re-arm).
    ///
    /// ``offset_ms`` is how much decoded audio was seen on the leg before the
    /// tone **started** — the offset of the tone itself, *not* of this event.
    /// The event trails it by roughly the profile's ``beep_cadence_guard_ms``
    /// (4500 ms by default), which is the detector's cadence guard *and* its
    /// detection latency.
    ///
    /// Delivered by the native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_beep
    /// def machine(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    ///     log.info(f"{call_id}: answering machine ({frequency_hz:.0f} Hz)")
    ///     b2bua.terminate(call_id, "Answering machine detected")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_beep``) this is
    ///         the function.  When called with keyword filters the return value
    ///         is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_beep<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_beep", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code)?, Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_beep decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_beep` (bare) and `@on_beep(call_id=...)` forms.
        match func_or_none {
            Some(func) => decorator.call1((func.bind(python),)),
            None => Ok(decorator),
        }
    }

    /// Register a handler for **WebSocket tee ended** events.
    ///
    /// Fires exactly once per started tee, **including when the server ends
    /// it**.  That is the point of the hook: any ``reason`` other than
    /// ``"detached"`` means the audio stream died while the call is still up,
    /// which is otherwise invisible — the call carries on and nothing reaches
    /// the consumer.  Re-attach, fail over, or alert from here.
    ///
    /// ``reason`` is one of ``"detached"`` (the script or the call teardown
    /// asked for it — the only orderly end), ``"server_closed"``,
    /// ``"server_stopped"``, ``"call_ended"`` or ``"transport_error"``.
    ///
    /// ``frames_dropped`` non-zero means the consumer could not keep up; the
    /// call itself was never affected.
    ///
    /// Delivered by the native **siphon-rtp** backend only.
    ///
    /// ```python,ignore
    /// @rtpengine.on_ws_tee_ended
    /// async def tee_down(call_id, from_tag, stream_id, reason, frames_sent, frames_dropped):
    ///     if reason != "detached":
    ///         log.warn(f"tee {stream_id} died: {reason}")
    /// ```
    ///
    /// Args:
    ///     func_or_none: When applied directly (``@rtpengine.on_ws_tee_ended``)
    ///         this is the function.  When called with keyword filters the
    ///         return value is a decorator.
    ///     call_id: Optional engine call-id filter.
    ///     from_tag: Optional from-tag filter.
    #[pyo3(signature = (func_or_none=None, *, call_id=None, from_tag=None))]
    fn on_ws_tee_ended<'py>(
        &self,
        python: Python<'py>,
        func_or_none: Option<Py<PyAny>>,
        call_id: Option<String>,
        from_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = r#"
def make_decorator(call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"call_id": call_id, "from_tag": from_tag}
        _siphon_registry.register("rtpengine.on_ws_tee_ended", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).unwrap(), Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build on_ws_tee_ended decorator")
        })?;
        let decorator = make_decorator.call1((call_id, from_tag))?;

        // Support both `@on_ws_tee_ended` (bare) and
        // `@on_ws_tee_ended(call_id=...)` forms.
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
            None,
            None,
        )
        .unwrap();
        assert!(matches!(source, PlayMediaSource::Blob(ref bytes) if bytes == &[0x00, 0xff]));
    }

    #[test]
    fn resolve_play_media_source_db_id() {
        pyo3::Python::initialize();
        let source = resolve_play_media_source(None, None, Some(7), None, None).unwrap();
        assert!(matches!(source, PlayMediaSource::DbId(7)));
    }

    #[test]
    fn resolve_play_media_source_tone_preset_and_cadence() {
        pyo3::Python::initialize();
        // Both forms are accepted verbatim — the engine tells them apart by the
        // `/`, and siphon deliberately keeps no copy of the preset table, which
        // would go stale the first time the engine adds a preset.
        let preset =
            resolve_play_media_source(None, None, None, Some("ringback_eu".to_string()), None)
                .unwrap();
        assert!(matches!(preset, PlayMediaSource::Tone(ref t) if t == "ringback_eu"));

        let cadence = resolve_play_media_source(
            None,
            None,
            None,
            Some("425/1000,0/4000*inf".to_string()),
            None,
        )
        .unwrap();
        assert!(matches!(cadence, PlayMediaSource::Tone(ref t) if t == "425/1000,0/4000*inf"));
    }

    #[test]
    fn resolve_play_media_source_empty_tone_rejected() {
        pyo3::Python::initialize();
        let error =
            resolve_play_media_source(None, None, None, Some("   ".to_string()), None).unwrap_err();
        Python::attach(|py| {
            assert!(error.value(py).to_string().contains("tone="));
        });
    }

    #[test]
    fn resolve_play_media_source_http_url() {
        pyo3::Python::initialize();
        for url in [
            "http://prompts.invalid/a.wav",
            "https://prompts.invalid/a.wav",
            // Scheme match is case-insensitive, but the URL is passed through
            // unchanged — the engine, not siphon, is what fetches it.
            "HTTPS://prompts.invalid/a.wav",
        ] {
            let source =
                resolve_play_media_source(None, None, None, None, Some(url.to_string())).unwrap();
            assert!(matches!(source, PlayMediaSource::Http(ref got) if got == url));
        }
    }

    #[test]
    fn resolve_play_media_source_non_http_url_rejected() {
        pyo3::Python::initialize();
        for url in ["file:///etc/passwd", "ftp://host/a.wav", "prompts/a.wav"] {
            let error =
                resolve_play_media_source(None, None, None, None, Some(url.to_string()))
                    .unwrap_err();
            Python::attach(|py| {
                assert!(
                    error.value(py).to_string().contains("http://"),
                    "error must state the accepted schemes for {url}"
                );
            });
        }
    }

    /// The new sources join the same exactly-one rule as the old ones, so a
    /// script cannot send an ambiguous command.
    #[test]
    fn resolve_play_media_source_tone_and_url_are_mutually_exclusive() {
        pyo3::Python::initialize();
        let error = resolve_play_media_source(
            None,
            None,
            None,
            Some("ringback_eu".to_string()),
            Some("https://prompts.invalid/a.wav".to_string()),
        )
        .unwrap_err();
        Python::attach(|py| {
            assert!(error.value(py).to_string().contains("exactly one"));
        });

        let with_file = resolve_play_media_source(
            Some("/tmp/a.wav".to_string()),
            None,
            None,
            Some("ringback_eu".to_string()),
            None,
        )
        .unwrap_err();
        Python::attach(|py| {
            assert!(with_file.value(py).to_string().contains("exactly one"));
        });
    }

    /// A per-call override must reach the flags, and a bad one must raise rather
    /// than reach an engine that would fail the whole offer.
    #[test]
    fn media_overrides_apply_and_validate() {
        pyo3::Python::initialize();

        let overrides = MediaOverrides::parse(
            Some(true),
            Some(3_000),
            Some(16_000),
            Some(48_000),
            Some(80),
            Some("neural"),
        )
        .unwrap();
        let mut flags = NgFlags::default();
        overrides.apply(&mut flags).unwrap();
        assert!(flags.beep_detection);
        assert_eq!(flags.beep_cadence_guard_ms, Some(3_000));
        assert_eq!(flags.ws_sample_rate, Some(16_000));
        assert_eq!(flags.ws_tee_sample_rate, Some(48_000));
        assert_eq!(flags.ws_vad_min_speech_ms, Some(80));
        assert_eq!(flags.ws_vad_engine, Some(WsVadEngine::Neural));

        // Nothing set → the profile is left exactly as it was.
        let mut untouched = NgFlags {
            beep_detection: true,
            ws_sample_rate: Some(24_000),
            ..NgFlags::default()
        };
        MediaOverrides::default().apply(&mut untouched).unwrap();
        assert!(untouched.beep_detection);
        assert_eq!(untouched.ws_sample_rate, Some(24_000));

        // An explicit `beep_detection=False` must be able to turn OFF a profile
        // that had it on — the reason the field is `Option<bool>` and not `bool`.
        let mut disarmed = NgFlags {
            beep_detection: true,
            ..NgFlags::default()
        };
        MediaOverrides::parse(Some(false), None, None, None, None, None)
            .unwrap()
            .apply(&mut disarmed)
            .unwrap();
        assert!(!disarmed.beep_detection);
    }

    #[test]
    fn media_overrides_reject_bad_values() {
        pyo3::Python::initialize();

        let bad_rate =
            MediaOverrides::parse(None, None, Some(44_100), None, None, None).unwrap_err();
        let bad_tee_rate =
            MediaOverrides::parse(None, None, None, Some(96_000), None, None).unwrap_err();
        let bad_engine =
            MediaOverrides::parse(None, None, None, None, None, Some("telepathy")).unwrap_err();

        Python::attach(|py| {
            assert!(bad_rate.value(py).to_string().contains("ws_sample_rate"));
            assert!(bad_tee_rate.value(py).to_string().contains("ws_tee_sample_rate"));
            assert!(bad_engine.value(py).to_string().contains("ws_vad_engine"));
        });
    }

    #[test]
    fn resolve_play_media_source_none_rejected() {
        pyo3::Python::initialize();
        let error = resolve_play_media_source(None, None, None, None, None).unwrap_err();
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
            None,
            None,
        )
        .unwrap_err();
        let error_file_and_db = resolve_play_media_source(
            Some("/tmp/a.wav".to_string()),
            None,
            Some(1),
            None,
            None,
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
            ws_tee: None,
            ws_bridge_attached: false,
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
