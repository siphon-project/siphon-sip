//! Proxy namespace utility methods — rate limiting, sanity checking, ENUM lookup.
//!
//! These are injected onto the Python `proxy` namespace alongside the
//! decorator methods defined in `siphon_package.py`.

use std::ffi::CString;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::route::RouteEntry;
use crate::sip::message::{Method, StartLine};
use crate::sip::parser::parse_uri_standalone;
use crate::sip::uri::SipUri;
use crate::transport::Transport;
use crate::uac::UacSender;

use std::net::SocketAddr;

use super::reply::PyReply;
use super::request::PyRequest;

/// Global UacSender — set once from main.rs after transport channels are ready.
static UAC_SENDER: OnceLock<Arc<UacSender>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Deferred message queue — ensures NOTIFY is sent after the reply (RFC 3265)
// ---------------------------------------------------------------------------

use crate::sip::message::SipMessage;

/// A message waiting to be sent after the current reply is dispatched.
pub struct DeferredMessage {
    pub message: SipMessage,
    pub destination: std::net::SocketAddr,
    pub transport: Transport,
}

thread_local! {
    /// When a request handler is active, deferred messages are queued here
    /// and flushed by the dispatcher after the reply is sent.
    static DEFERRED_SENDS: std::cell::RefCell<Option<Vec<DeferredMessage>>> =
        const { std::cell::RefCell::new(None) };
}

/// Enable deferred sending mode for the current thread.
/// Call before invoking Python handlers.
pub fn enable_deferred_sends() {
    DEFERRED_SENDS.with(|cell| {
        *cell.borrow_mut() = Some(Vec::new());
    });
}

/// Drain and return all deferred messages, disabling deferred mode.
/// Call after the reply has been sent to wire.
pub fn drain_deferred_sends() -> Vec<DeferredMessage> {
    DEFERRED_SENDS.with(|cell| {
        cell.borrow_mut().take().unwrap_or_default()
    })
}

/// Try to queue a message for deferred sending.  Returns `true` if deferred
/// mode is active and the message was queued; `false` if no request handler
/// is active (caller should send immediately).
pub(crate) fn try_defer_send(message: SipMessage, destination: std::net::SocketAddr, transport: Transport) -> bool {
    DEFERRED_SENDS.with(|cell| {
        let mut guard = cell.borrow_mut();
        if let Some(ref mut queue) = *guard {
            queue.push(DeferredMessage { message, destination, transport });
            true
        } else {
            false
        }
    })
}

/// Global DNS resolver for send_request — set alongside the UAC sender.
static SEND_RESOLVER: OnceLock<Arc<SipResolver>> = OnceLock::new();

/// Wire the UacSender + DNS resolver so `proxy.send_request()` can originate
/// outbound SIP requests. Called once from main.rs.
pub fn set_uac_sender(sender: Arc<UacSender>, resolver: Arc<SipResolver>) {
    let _ = UAC_SENDER.set(sender);
    let _ = SEND_RESOLVER.set(resolver);
}

/// Get the global UAC sender (for use by other script API modules like presence).
pub(crate) fn uac_sender() -> Option<&'static Arc<UacSender>> {
    UAC_SENDER.get()
}

/// Get the global SIP resolver (for use by other script API modules like presence).
pub(crate) fn send_resolver() -> Option<&'static Arc<SipResolver>> {
    SEND_RESOLVER.get()
}

/// Rate limiter using a sliding window counter per source IP.
pub struct RateLimiter {
    /// Map of source IP → list of request timestamps.
    windows: DashMap<String, Vec<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            windows: DashMap::new(),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Proxy utility methods exposed to Python.
#[pyclass(name = "ProxyUtils")]
pub struct PyProxyUtils {
    rate_limiter: Arc<RateLimiter>,
    dns_resolver: Arc<SipResolver>,
}

impl PyProxyUtils {
    pub fn new(dns_resolver: Arc<SipResolver>) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new()),
            dns_resolver,
        }
    }
}

#[pymethods]
impl PyProxyUtils {
    /// Check if a request exceeds the rate limit for its source IP.
    ///
    /// Returns `True` if the request is within the limit (allowed),
    /// `False` if it exceeds the limit (should be blocked/dropped).
    fn rate_limit(&self, request: &PyRequest, window_secs: f64, max_requests: usize) -> bool {
        let source_ip = request.source_ip_str().to_string();
        let now = Instant::now();
        let window = std::time::Duration::from_secs_f64(window_secs);

        let mut entry = self.rate_limiter.windows.entry(source_ip).or_default();
        // Prune expired entries
        entry.retain(|timestamp| now.duration_since(*timestamp) < window);
        if entry.len() >= max_requests {
            return false;
        }
        entry.push(now);
        true
    }

    /// Perform basic RFC 3261 sanity checks on a request.
    ///
    /// Returns `True` if the request passes all checks, `False` otherwise.
    /// Checks: mandatory headers present, Max-Forwards > 0, CSeq method
    /// matches request method, Content-Length matches body length.
    fn sanity_check(&self, request: &PyRequest) -> PyResult<bool> {
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // Must be a request
        let request_line = match &message.start_line {
            StartLine::Request(request_line) => request_line,
            _ => return Ok(false),
        };

        // Mandatory headers
        for header_name in &["Via", "From", "To", "Call-ID", "CSeq"] {
            if !message.headers.has(header_name) {
                return Ok(false);
            }
        }

        // Max-Forwards > 0
        if let Some(max_forwards) = message.headers.max_forwards() {
            if max_forwards == 0 {
                return Ok(false);
            }
        }

        // CSeq method must match request method
        if let Some(raw_cseq) = message.headers.cseq() {
            if let Ok(cseq) = CSeq::parse(raw_cseq) {
                if cseq.method.as_str() != request_line.method.as_str() {
                    return Ok(false);
                }
            } else {
                return Ok(false); // Unparseable CSeq
            }
        }

        // Content-Length must match body length (if present)
        if let Some(content_length) = message.headers.content_length() {
            if content_length != message.body.len() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Look up a phone number via ENUM (DNS NAPTR) query.
    ///
    /// Converts a number like "+12125551234" to a DNS query against
    /// `4.3.2.1.5.5.5.2.1.2.1.e164.arpa` and returns the SIP URI
    /// from the first matching NAPTR record, or `None`.
    #[pyo3(signature = (number, suffix="e164.arpa.", service="E2U+sip"))]
    fn enum_lookup<'py>(
        &self,
        py: Python<'py>,
        number: String,
        suffix: &str,
        service: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let resolver = Arc::clone(&self.dns_resolver);
        let suffix = suffix.to_string();
        let service = service.to_string();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let enum_result = enum_naptr_lookup(&resolver, &number, &suffix, &service).await;
            Ok(enum_result)
        })
    }

    /// Originate an outbound SIP request.
    ///
    /// Always returns a Python awaitable — scripts must ``await`` it.
    /// Fire-and-forget by default; pass ``wait_for_response=True`` to wait
    /// for the peer's response (or ``timeout_ms`` elapses).
    ///
    /// Args:
    ///     method: SIP method name (e.g. "NOTIFY", "OPTIONS", "MESSAGE").
    ///     ruri: Request-URI string (e.g. "sip:alice@10.0.0.1:5060").
    ///     headers: Optional dict of header name → value to add.
    ///     body: Optional body — ``str`` or ``bytes``.
    ///     next_hop: Optional next-hop URI (e.g. Path from registrar).  The
    ///               R-URI stays in the Request-Line; the message is routed
    ///               to next_hop.  Outranks a `Route` header for next-hop
    ///               selection (see "Pre-loaded route set" below).
    ///     wait_for_response: When ``True``, the awaitable resolves to a
    ///               :class:`Reply` once the peer responds (or ``None`` after
    ///               ``timeout_ms``).  When ``False`` (default), the
    ///               awaitable resolves to ``None`` as soon as the request
    ///               is on the wire.  Either way the UAC registers a pending
    ///               entry so the dispatcher silently consumes the matching
    ///               response (no "unknown branch" log noise on every reply).
    ///     timeout_ms: Response timeout in milliseconds (default 2000).
    ///               Ignored when ``wait_for_response=False``.
    ///
    /// Returns:
    ///     A Python awaitable. ``await`` it to get ``None`` (fire-and-forget
    ///     or timeout) or a :class:`Reply` (when ``wait_for_response=True``
    ///     and the peer responded in time).
    ///
    /// Pre-loaded route set: when `next_hop` is omitted but `headers` carries a
    /// `Route` (a pre-loaded route set), the request is sent to the URI of the
    /// first `Route` entry (its `;lr` loose-route target) per RFC 3261 §8.1.2 /
    /// §16.4 — the R-URI stays in the Request-Line and the `Route` rides along.
    /// Only when neither is present is the R-URI itself resolved (RFC 3263).
    ///
    /// Example (Python script):
    ///
    /// ```text
    /// # Fire-and-forget -- still must be awaited.
    /// await proxy.send_request("MESSAGE", "sip:alice@10.0.0.1", body=text)
    ///
    /// # Wait for the response.
    /// reply = await proxy.send_request(
    ///     "OPTIONS", target_uri,
    ///     wait_for_response=True, timeout_ms=5000,
    /// )
    /// ```
    #[pyo3(signature = (method, ruri, headers=None, body=None, next_hop=None, wait_for_response=false, timeout_ms=2000))]
    fn send_request<'py>(
        &self,
        python: Python<'py>,
        method: &str,
        ruri: &str,
        headers: Option<&Bound<'_, PyDict>>,
        body: Option<&Bound<'_, PyAny>>,
        next_hop: Option<&str>,
        wait_for_response: bool,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let uac_sender = UAC_SENDER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "proxy.send_request() unavailable: UAC sender not initialized",
            )
        })?;
        let resolver = SEND_RESOLVER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "proxy.send_request() unavailable: DNS resolver not initialized",
            )
        })?;

        // Parse the request URI (used in the Request-Line)
        let uri = parse_uri_standalone(ruri).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid request URI '{ruri}': {error}"))
        })?;

        // Resolve the transport destination per RFC 3261 §8.1.2 (a UAC's
        // next-hop rules):
        //   1. An explicit `next_hop` override wins (local policy — e.g. a
        //      Path learned from the registrar). The R-URI stays in the
        //      Request-Line but the message is sent to next_hop.
        //   2. Otherwise, if the script pre-loaded a route set (a `Route`
        //      header), the destination is the URI of the *first* Route entry
        //      (its `;lr` loose-route target). The R-URI stays in the
        //      Request-Line and the Route header(s) ride along untouched —
        //      RFC 3261 §16.4 / §12.2.1.1. This is what lets a script steer a
        //      UAC-originated request straight to a known next hop (e.g. an
        //      AS addressing a served IMPU with the serving S-CSCF pre-loaded)
        //      instead of resolving the R-URI's home domain and taking the
        //      long way round.
        //   3. Otherwise, resolve the R-URI (RFC 3263).
        let resolve_uri = resolve_send_target(&uri, next_hop, headers)?;

        let transport_hint = resolve_uri.get_param("transport").map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(resolver);
        let host = resolve_uri.host.clone();
        let port = resolve_uri.port;
        let scheme = resolve_uri.scheme.clone();

        // Resolver is async, but cheap for numeric IPs (short-circuits).
        // Doing this synchronously up-front lets the wire send happen before
        // we hand a coroutine back to Python — scripts that don't `await`
        // still get the message out.  The only awaitable work is the
        // optional response wait.
        let destination = crate::script::detach_block_on(resolver_clone.resolve(
            &host,
            port,
            &scheme,
            transport_hint.as_deref(),
        ));

        let target = destination.into_iter().next().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_uri}'"
            ))
        })?;

        // Determine transport
        let transport = match target
            .transport
            .as_deref()
            .or(transport_hint.as_deref())
        {
            Some(hint) => match hint.to_lowercase().as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                "sctp" => Transport::Sctp,
                _ => Transport::Udp,
            },
            None => if scheme == "sips" { Transport::Tls } else { Transport::Udp },
        };

        let (message, branch) = build_send_request_message(
            method,
            uri,
            transport,
            target.address,
            headers,
            body,
        )?;

        // Always register a pending entry. For fire-and-forget the entry
        // exists only so the dispatcher's `UacSender::match_response` silently
        // consumes the matching response — without it, every legitimate
        // response logs "response for unknown branch (not ours)".
        let receiver = uac_sender.send_request_with_response(
            message,
            target.address,
            transport,
        );

        if !wait_for_response {
            // Fire-and-forget: clean up the pending entry after RFC 3261
            // §17.1.2.2 Timer F (32 s = 64 × T1) — no peer can sensibly
            // respond after that, and the slot must self-evict.  On a
            // matched response, the receiver fires before the timeout and
            // the entry has already been removed by `match_response`.
            let uac_for_cleanup = Arc::clone(uac_sender);
            let branch_for_cleanup = branch;
            tokio::spawn(async move {
                if tokio::time::timeout(
                    std::time::Duration::from_secs(32),
                    receiver,
                )
                .await
                .is_err()
                {
                    uac_for_cleanup.expire_branch(&branch_for_cleanup);
                }
            });
            return immediate_none_coroutine(python);
        }

        // wait_for_response: hand a coroutine back that resolves to the
        // Reply (or None on timeout).  The caller is necessarily inside an
        // async context — `await proxy.send_request(..., wait_for_response=True)`
        // — so `future_into_py` finds a running event loop.
        let timeout = std::time::Duration::from_millis(timeout_ms);
        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match tokio::time::timeout(timeout, receiver).await {
                Ok(Ok(crate::uac::UacResult::Response(message))) => {
                    Python::attach(|py| {
                        let py_reply = PyReply::new(Arc::new(std::sync::Mutex::new(*message)));
                        Py::new(py, py_reply).map(Some)
                    })
                }
                // Timeout, channel closed, or explicit UacResult::Timeout
                _ => Ok(None),
            }
        })
    }

    /// Return approximate RSS memory usage as a percentage (0-100).
    ///
    /// Reads `/proc/self/status` on Linux. Returns 0 on non-Linux platforms.
    fn memory_used_pct(&self) -> u32 {
        #[cfg(target_os = "linux")]
        {
            memory_pct_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}

/// Decide which URI the outbound request's next hop resolves to, per
/// RFC 3261 §8.1.2 (a UAC's next-hop selection):
///
///   1. An explicit `next_hop` override wins (local policy).
///   2. Else the URI of the first `Route` header entry, when the script
///      pre-loaded a route set (loose routing — §16.4 / §12.2.1.1).
///   3. Else the Request-URI.
///
/// In every case the Request-URI stays in the Request-Line; only the
/// *destination* (the address RFC 3263 resolution runs against) changes.
fn resolve_send_target(
    ruri: &SipUri,
    next_hop: Option<&str>,
    headers: Option<&Bound<'_, PyDict>>,
) -> PyResult<SipUri> {
    if let Some(hop) = next_hop {
        return parse_uri_standalone(hop).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid next_hop URI '{hop}': {error}"
            ))
        });
    }
    if let Some(route_uri) = route_next_hop(headers) {
        return Ok(route_uri);
    }
    Ok(ruri.clone())
}

/// Extract the next-hop URI from a script-supplied `Route` header.
///
/// Scans the outgoing `headers` dict for a `Route` (case-insensitive) and
/// returns the URI of its first entry — the loose-route target the request
/// should be sent to (RFC 3261 §8.1.2).  Returns `None` when no `Route`
/// header is present (or its value can't be parsed), so the caller falls
/// back to resolving the Request-URI.  Non-string keys/values are skipped
/// here; `build_send_request_message` surfaces the canonical type error.
fn route_next_hop(headers: Option<&Bound<'_, PyDict>>) -> Option<SipUri> {
    let header_dict = headers?;
    for (key, value) in header_dict.iter() {
        let Ok(name) = key.extract::<String>() else {
            continue;
        };
        if !name.eq_ignore_ascii_case("Route") {
            continue;
        }
        let Ok(raw) = value.extract::<String>() else {
            continue;
        };
        return parse_first_route_uri(&raw);
    }
    None
}

/// Parse the URI of the first entry of a `Route` header value.
///
/// Handles a comma-separated route set (`<sip:a;lr>, <sip:b;lr>` → the `a`
/// URI) via the angle-bracket-aware [`RouteEntry`] parser, with a lenient
/// fallback for a bare addr-spec that omits the angle brackets.
fn parse_first_route_uri(raw: &str) -> Option<SipUri> {
    if let Ok(mut entries) = RouteEntry::parse_multi(raw) {
        if !entries.is_empty() {
            return Some(entries.remove(0).uri);
        }
    }
    // Lenient fallback: a bare addr-spec (`sip:host;lr`) without angle
    // brackets — strip an opening `<` up to `>` if present, then take the
    // first comma-separated chunk.
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
        .unwrap_or(trimmed);
    let first = inner.split(',').next().unwrap_or(inner).trim();
    parse_uri_standalone(first).ok()
}

/// Build the SIP message originated by `proxy.send_request()`.
///
/// Returns the built message paired with its top-Via branch — the caller
/// needs the branch to register / expire the matching pending UAC entry.
///
/// Pulled out as a free function so it can be unit-tested without a UAC
/// sender / DNS resolver — the bug that motivated the extraction was the
/// body argument silently dropping on REGISTER 3PR (TS 24.229 §5.4.1.7).
fn build_send_request_message(
    method: &str,
    uri: SipUri,
    transport: Transport,
    destination: SocketAddr,
    headers: Option<&Bound<'_, PyDict>>,
    body: Option<&Bound<'_, PyAny>>,
) -> PyResult<(SipMessage, String)> {
    let sip_method = Method::from_str(method);

    // Pre-extract user headers so that single-value auto-set headers
    // (Call-ID, CSeq, Max-Forwards, Via — RFC 3261 §7.3.1) get *replaced*
    // when the script supplies them, not duplicated.  Without this split,
    // builder.header() appends every user value on top of our auto-set
    // one and the resulting message has two Call-IDs / CSeqs / etc.;
    // strict UAS implementations pick the first (auto-generated) header
    // and discard the script-intended value.  Same root cause as the
    // set_reply_header dual-To bug fixed in b1b2d55.
    let mut user_call_id: Option<String> = None;
    let mut user_cseq: Option<String> = None;
    let mut user_max_forwards: Option<String> = None;
    let mut user_via: Option<String> = None;
    let mut other_headers: Vec<(String, String)> = Vec::new();

    if let Some(header_dict) = headers {
        for (key, value) in header_dict.iter() {
            let name: String = key.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "header name must be str: {error}"
                ))
            })?;
            let val: String = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "header value must be str: {error}"
                ))
            })?;
            // Case-insensitive match — RFC 3261 §7.3 makes header names
            // case-insensitive, and Call-ID has the compact form "i".
            if name.eq_ignore_ascii_case("Call-ID") || name.eq_ignore_ascii_case("i") {
                user_call_id = Some(val);
            } else if name.eq_ignore_ascii_case("CSeq") {
                user_cseq = Some(val);
            } else if name.eq_ignore_ascii_case("Max-Forwards") {
                user_max_forwards = Some(val);
            } else if name.eq_ignore_ascii_case("Via") || name.eq_ignore_ascii_case("v") {
                user_via = Some(val);
            } else {
                other_headers.push((name, val));
            }
        }
    }

    // Branch returned to the caller so it can register / expire the
    // pending UAC entry.  When the script supplies its own Via, prefer
    // the branch parsed from that value so response correlation still
    // works — falling back to a fresh UAC-shaped branch if the parse
    // fails or the supplied Via has no branch param.
    let auto_branch = format!("z9hG4bK-uac-py-{}", uuid::Uuid::new_v4());
    let via_value = match user_via {
        Some(via_str) => via_str,
        None => format!("SIP/2.0/{} {};branch={}", transport, destination, auto_branch),
    };
    let branch = crate::sip::headers::via::Via::parse(&via_value)
        .ok()
        .and_then(|v| v.branch)
        .unwrap_or_else(|| auto_branch.clone());

    let call_id = user_call_id.unwrap_or_else(|| format!("py-{}", uuid::Uuid::new_v4()));
    let cseq_str = user_cseq.unwrap_or_else(|| format!("1 {}", sip_method.as_str()));

    let mut builder = SipMessageBuilder::new()
        .request(sip_method, uri)
        .via(via_value)
        .call_id(call_id)
        .cseq(cseq_str);

    // Max-Forwards is u8 in the builder; if the script supplied a
    // non-numeric value, fall through to the default rather than
    // erroring — header() preserves the raw string for parsers that
    // accept extension forms.
    builder = match user_max_forwards
        .as_deref()
        .map(str::trim)
        .and_then(|s| s.parse::<u8>().ok())
    {
        Some(max) => builder.max_forwards(max),
        None => match user_max_forwards {
            Some(raw) => builder.set_header("Max-Forwards", raw),
            None => builder.max_forwards(70),
        },
    };

    for (name, val) in other_headers {
        builder = builder.header(&name, val);
    }

    // Set body if provided — accept str or bytes.  body_str() / body() each
    // refresh Content-Length so any caller-provided value is corrected.
    if let Some(body_obj) = body {
        let bytes = super::request::extract_body_bytes(body_obj)?;
        builder = builder.body(bytes);
    } else {
        builder = builder.content_length(0);
    }

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to build SIP message: {error}"
        ))
    })?;
    Ok((message, branch))
}

/// Return a Python coroutine that resolves to ``None`` immediately.
///
/// Used by ``proxy.send_request(wait_for_response=False)`` so the function
/// always hands back an awaitable, even when no event loop is "running"
/// at the call site (e.g. when invoked from a sync handler context).
/// `future_into_py` requires a running asyncio loop at construction time;
/// a plain Python ``async def`` coroutine does not, so this works in any
/// caller context — including unit tests with no asyncio loop.
fn immediate_none_coroutine<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    static HELPER: OnceLock<Py<PyAny>> = OnceLock::new();
    if let Some(handle) = HELPER.get() {
        return handle.bind(py).call0();
    }

    let source = CString::new("async def _none():\n    return None\n").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("helper source CString: {error}"))
    })?;
    let file_name = CString::new("_proxy_send_request_helper.py").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("helper file CString: {error}"))
    })?;
    let module_name = CString::new("_proxy_send_request_helper").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("helper module CString: {error}"))
    })?;
    let module = PyModule::from_code(py, &source, &file_name, &module_name)?;
    let func = module.getattr("_none")?;
    let _ = HELPER.set(func.clone().unbind());
    func.call0()
}

/// Perform ENUM NAPTR lookup for a phone number.
async fn enum_naptr_lookup(
    resolver: &SipResolver,
    number: &str,
    suffix: &str,
    _service: &str,
) -> Option<String> {
    // Strip leading '+' and non-digit characters
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }

    // Reverse digits and join with dots: +12125551234 → 4.3.2.1.5.5.5.2.1.2.1
    let reversed: String = digits
        .chars()
        .rev()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(".");

    let query_name = format!("{reversed}.{suffix}");

    // Use the resolver's inner hickory resolver for NAPTR
    match resolver.naptr_lookup(&query_name).await {
        Some(uri) => Some(uri),
        None => {
            tracing::debug!(query = %query_name, "ENUM NAPTR lookup returned no results");
            None
        }
    }
}

/// Read RSS and total memory from /proc on Linux.
#[cfg(target_os = "linux")]
fn memory_pct_linux() -> u32 {
    use std::fs;

    let rss_kb = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .unwrap_or(0);

    let total_kb = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo
                .lines()
                .find(|line| line.starts_with("MemTotal:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .unwrap_or(1); // Avoid divide by zero

    if total_kb == 0 {
        return 0;
    }
    ((rss_kb * 100) / total_kb) as u32
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
    use std::sync::Mutex;

    fn make_request() -> PyRequest {
        let message = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("\"Alice\" <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33".to_string())
            .cseq("314159 INVITE".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap();
        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    fn make_proxy_utils() -> PyProxyUtils {
        let resolver = Arc::new(SipResolver::from_system().unwrap());
        PyProxyUtils::new(resolver)
    }

    #[test]
    fn rate_limit_allows_under_limit() {
        let utils = make_proxy_utils();
        let request = make_request();
        assert!(utils.rate_limit(&request, 10.0, 5));
        assert!(utils.rate_limit(&request, 10.0, 5));
    }

    #[test]
    fn rate_limit_blocks_over_limit() {
        let utils = make_proxy_utils();
        let request = make_request();
        for _ in 0..3 {
            assert!(utils.rate_limit(&request, 60.0, 3));
        }
        // 4th request should be blocked
        assert!(!utils.rate_limit(&request, 60.0, 3));
    }

    #[test]
    fn sanity_check_valid_invite() {
        let utils = make_proxy_utils();
        let request = make_request();
        assert!(utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_missing_via() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_cseq_method_mismatch() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 REGISTER".to_string()) // Mismatch: request is INVITE
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[test]
    fn sanity_check_max_forwards_zero() {
        let utils = make_proxy_utils();
        let message = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("biloxi.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=123".to_string())
            .call_id("test-call".to_string())
            .cseq("1 INVITE".to_string())
            .max_forwards(0)
            .content_length(0)
            .build()
            .unwrap();
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        );
        assert!(!utils.sanity_check(&request).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_used_pct_returns_reasonable_value() {
        let utils = make_proxy_utils();
        let pct = utils.memory_used_pct();
        // Should be between 0 and 100 for any running process
        assert!(pct <= 100, "memory_used_pct returned {pct}");
    }

    fn destination() -> SocketAddr {
        "10.0.0.1:5060".parse().unwrap()
    }

    fn target_uri() -> SipUri {
        SipUri::new("mmtel.ims.example.org".to_string())
    }

    /// 3PR (TS 24.229 §5.4.1.7): S-CSCF sends a REGISTER body containing
    /// the original REGISTER as `message/sip` to the AS.  Both the body
    /// and the script-supplied `Content-Type` MUST appear on the wire.
    #[test]
    fn send_request_preserves_str_body_and_content_type() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Content-Type", "message/sip").unwrap();
            headers.set_item("Event", "registration").unwrap();
            headers.set_item("Expires", "0").unwrap();

            let body = "REGISTER sip:bob@biloxi.com SIP/2.0\r\n\
                        Content-Length: 0\r\n\
                        \r\n";
            let body_obj = body.into_pyobject(py).unwrap();
            let body_any = body_obj.as_any();

            let (message, branch) = build_send_request_message(
                "REGISTER",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                Some(body_any),
            )
            .expect("build_send_request_message");

            assert!(
                branch.starts_with("z9hG4bK-uac-py-"),
                "branch must use the UAC-py prefix, got {branch}"
            );
            assert_eq!(
                message.body, body.as_bytes(),
                "body must round-trip through the builder"
            );
            assert_eq!(
                message.headers.content_length(),
                Some(body.len()),
                "Content-Length must reflect the body length, not 0"
            );
            assert_eq!(
                message.headers.get("Content-Type").map(String::as_str),
                Some("message/sip"),
                "Content-Type from headers dict must propagate"
            );

            // Wire bytes carry the body verbatim after the blank line.
            let wire = message.to_bytes();
            let wire_str = String::from_utf8_lossy(&wire);
            assert!(
                wire_str.contains("Content-Type: message/sip"),
                "wire output must include Content-Type, got:\n{wire_str}"
            );
            assert!(
                wire_str.ends_with(body),
                "wire output must end with the body, got:\n{wire_str}"
            );
        });
    }

    #[test]
    fn send_request_accepts_bytes_body() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Content-Type", "application/sdp").unwrap();

            let body_bytes: &[u8] = b"v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\n";
            let body_obj = pyo3::types::PyBytes::new(py, body_bytes);

            let (message, _branch) = build_send_request_message(
                "MESSAGE",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                Some(body_obj.as_any()),
            )
            .expect("build_send_request_message");

            assert_eq!(message.body, body_bytes);
            assert_eq!(message.headers.content_length(), Some(body_bytes.len()));
        });
    }

    #[test]
    fn send_request_without_body_sets_content_length_zero() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Event", "reg").unwrap();

            let (message, _branch) = build_send_request_message(
                "OPTIONS",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                None,
            )
            .expect("build_send_request_message");

            assert!(message.body.is_empty());
            assert_eq!(message.headers.content_length(), Some(0));
        });
    }

    #[test]
    fn send_request_caller_content_length_is_overridden_by_body() {
        // A caller that sets `Content-Length: 0` in the headers dict (e.g.
        // because they copied headers from another message) must not end up
        // with a stale Content-Length on the wire — body() refreshes it.
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Content-Length", "0").unwrap();
            headers.set_item("Content-Type", "message/sip").unwrap();

            let body = "REGISTER sip:bob@biloxi.com SIP/2.0\r\n\r\n";
            let body_obj = body.into_pyobject(py).unwrap();

            let (message, _branch) = build_send_request_message(
                "REGISTER",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                Some(body_obj.as_any()),
            )
            .expect("build_send_request_message");

            assert_eq!(message.headers.content_length(), Some(body.len()));
            assert_eq!(message.body, body.as_bytes());
        });
    }

    /// USSD-AS / TS 24.390 §5.3 reuses the original SUBSCRIBE Call-ID on
    /// the response NOTIFY so the UE can correlate.  When the script
    /// supplies `headers={"Call-ID": "<original>"}`, the wire output must
    /// carry exactly one Call-ID — duplicate Call-IDs cause SIPp / strict
    /// UAS impls to keep the first (auto-generated `py-…`) and discard
    /// the script value, breaking dialog correlation.
    #[test]
    fn send_request_user_call_id_replaces_auto_value() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Call-ID", "ussd-original-call-id").unwrap();

            let (message, _branch) = build_send_request_message(
                "MESSAGE",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                None,
            )
            .expect("build_send_request_message");

            let call_ids = message
                .headers
                .get_all("Call-ID")
                .expect("Call-ID must be present");
            assert_eq!(
                call_ids.len(),
                1,
                "user-supplied Call-ID must replace auto-generated, got {call_ids:?}"
            );
            assert_eq!(call_ids[0], "ussd-original-call-id");
            // No stale auto-generated Call-ID anywhere on the wire.
            let wire = String::from_utf8_lossy(&message.to_bytes()).into_owned();
            assert!(
                !wire.contains("Call-ID: py-"),
                "wire output must not carry auto-generated py- Call-ID alongside user value:\n{wire}"
            );
        });
    }

    /// CSeq is single-value (RFC 3261 §7.3.1).  A script-supplied CSeq
    /// must replace the auto-generated `1 <method>` value, not stack on
    /// top of it.
    #[test]
    fn send_request_user_cseq_replaces_auto_value() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("CSeq", "42 MESSAGE").unwrap();

            let (message, _branch) = build_send_request_message(
                "MESSAGE",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                None,
            )
            .expect("build_send_request_message");

            let cseqs = message.headers.get_all("CSeq").expect("CSeq must be present");
            assert_eq!(cseqs.len(), 1, "CSeq must be unique, got {cseqs:?}");
            assert_eq!(cseqs[0], "42 MESSAGE");
        });
    }

    /// Max-Forwards is single-value.  Script override must replace, not
    /// duplicate, the default 70.
    #[test]
    fn send_request_user_max_forwards_replaces_auto_value() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("Max-Forwards", "5").unwrap();

            let (message, _branch) = build_send_request_message(
                "OPTIONS",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                None,
            )
            .expect("build_send_request_message");

            let mf = message
                .headers
                .get_all("Max-Forwards")
                .expect("Max-Forwards must be present");
            assert_eq!(mf.len(), 1, "Max-Forwards must be unique, got {mf:?}");
            assert_eq!(mf[0], "5");
        });
    }

    /// Script-supplied Via must replace the auto-generated UAC Via, and
    /// the branch returned to the caller must be parsed from the user
    /// value so response correlation can still be wired up by the UAC.
    #[test]
    fn send_request_user_via_replaces_auto_and_branch_is_extracted() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers
                .set_item(
                    "Via",
                    "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-uac-script-supplied",
                )
                .unwrap();

            let (message, branch) = build_send_request_message(
                "MESSAGE",
                target_uri(),
                Transport::Udp,
                destination(),
                Some(&headers),
                None,
            )
            .expect("build_send_request_message");

            let vias = message.headers.get_all("Via").expect("Via must be present");
            assert_eq!(vias.len(), 1, "Via must be a single value, got {vias:?}");
            assert!(
                vias[0].contains("branch=z9hG4bK-uac-script-supplied"),
                "Via must carry script-supplied branch, got {vias:?}"
            );
            assert_eq!(
                branch, "z9hG4bK-uac-script-supplied",
                "returned branch must come from the user-supplied Via"
            );
        });
    }

    /// End-to-end PyO3 dispatch test: call `proxy_utils.send_request(...)`
    /// from Python with `body=` and `headers=` kwargs, then read the wire
    /// bytes off a flume channel.  This is what `build_send_request_message`
    /// tests *can't* catch — it exercises the kwarg-binding path that the
    /// 3PR bug report says is dropping the body.
    ///
    /// Runs four scenarios back-to-back (UAC_SENDER is a OnceLock — only
    /// one test per process can install it, so we cover everything here):
    /// 1. The reporter's 3PR shape: 9 headers including Content-Type,
    ///    1809-byte str body.
    /// 2. body=bytes (binary SDP-style).
    /// 3. headers dict containing `Content-Length: 0` plus a non-empty
    ///    body — the builder must override the stale CL.
    /// 4. Fire-and-forget registers a pending UAC entry (so dispatcher
    ///    silently consumes the response — no "unknown branch" log) and
    ///    `match_response` removes it on the matching reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_request_python_kwargs_preserve_body_and_content_type() {
        use crate::transport::OutboundRouter;
        use crate::uac::UacSender;
        use std::collections::HashMap;
        use pyo3::types::PyTuple;

        pyo3::Python::initialize();

        // Wire up a UAC sender whose UDP egress lands on a flume channel
        // so the test can read back the bytes that would have hit the wire.
        let (udp_tx, udp_rx) = flume::unbounded();
        let (tcp_tx, _tcp_rx) = flume::unbounded();
        let (tls_tx, _tls_rx) = flume::unbounded();
        let (ws_tx, _ws_rx) = flume::unbounded();
        let (wss_tx, _wss_rx) = flume::unbounded();
        let (sctp_tx, _sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            udp_by_local: HashMap::new(),
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });
        let sender = Arc::new(UacSender::new(
            router,
            "127.0.0.1:5060".parse().unwrap(),
            HashMap::new(),
            HashMap::new(),
            None,
            None,
            None,
        ));
        let resolver = Arc::new(SipResolver::from_system().unwrap());

        // OnceLock — first test to set wins.  Ignore the result; subsequent
        // tests on the same process just reuse whatever is installed.
        let _ = UAC_SENDER.set(sender);
        let _ = SEND_RESOLVER.set(Arc::clone(&resolver));

        let utils = PyProxyUtils::new(resolver);
        let utils_py = Python::attach(|py| Py::new(py, utils).unwrap());

        // ---------------------------------------------------------------
        // Scenario 1 — exact 3PR shape from the bug report:
        // 9 headers (incl. Content-Type), 1809-byte str body.
        // ---------------------------------------------------------------
        let mut body_1 = String::with_capacity(1809);
        body_1.push_str(
            "REGISTER sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n",
        );
        body_1.push_str(
            "Via: SIP/2.0/UDP 172.30.0.50:5060;branch=z9hG4bK-ue-1\r\n",
        );
        body_1.push_str("From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-1\r\n");
        body_1.push_str("To: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>\r\n");
        body_1.push_str("Call-ID: orig-call-id\r\n");
        body_1.push_str("CSeq: 2 REGISTER\r\n");
        body_1.push_str(
            "Contact: <sip:001010000000001@172.30.0.50:5060>;expires=600000;+sip.instance=\"<urn:gsma:imei:35-209900-176148-1>\"\r\n",
        );
        body_1.push_str("Authorization: Digest username=\"001010000000001\", realm=\"ims.mnc001.mcc001.3gppnetwork.org\", uri=\"sip:ims.mnc001.mcc001.3gppnetwork.org\", response=\"deadbeef\", nonce=\"feedface\", algorithm=AKAv1-MD5, opaque=\"000000\"\r\n");
        body_1.push_str("P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00101D0F\r\n");
        body_1.push_str("P-Visited-Network-ID: ims.mnc001.mcc001.3gppnetwork.org\r\n");
        // pad to 1809 bytes total to mirror the diagnostic body_len.
        while body_1.len() < 1809 - 4 {
            body_1.push('.');
        }
        body_1.push_str("\r\n\r\n");
        let body_1: &str = &body_1;

        Python::attach(|py| {
            let bound = utils_py.bind(py);

            let headers = PyDict::new(py);
            headers.set_item("Contact", "<sip:scscf-0.ims.mnc001.mcc001.3gppnetwork.org:6060>").unwrap();
            headers.set_item("Content-Type", "message/sip").unwrap();
            headers.set_item("Event", "registration").unwrap();
            headers.set_item("Expires", "0").unwrap();
            headers.set_item("From", "<sip:scscf-0.ims.mnc001.mcc001.3gppnetwork.org:6060>;tag=scscf-3preg").unwrap();
            headers.set_item("P-Associated-URI", "<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>").unwrap();
            headers.set_item("P-Visited-Network-ID", "ims.mnc001.mcc001.3gppnetwork.org").unwrap();
            headers.set_item("Path", "<sip:term@pcscf.ims.mnc001.mcc001.3gppnetwork.org:5060;lr>").unwrap();
            headers.set_item("To", "<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>").unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("headers", headers).unwrap();
            kwargs.set_item("body", body_1).unwrap();

            // Numeric IP — the resolver short-circuits without DNS.
            let args = PyTuple::new(py, ["REGISTER", "sip:127.0.0.1:5060"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 1: kwarg dispatch");
            // send_request returns an awaitable; the wire send already
            // happened synchronously.  Close the coroutine to suppress
            // Python's "coroutine was never awaited" warning.
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 1: no UDP egress — dispatch dropped the message");
        let wire = String::from_utf8(outbound.data.to_vec()).unwrap();
        assert!(
            wire.contains("Content-Type: message/sip"),
            "scenario 1: missing Content-Type:\n{wire}"
        );
        assert!(
            wire.contains(&format!("Content-Length: {}", body_1.len())),
            "scenario 1: wrong Content-Length (expected {}, body {} bytes):\n{wire}",
            body_1.len(),
            body_1.len()
        );
        assert!(
            wire.ends_with(body_1),
            "scenario 1: body not verbatim on wire — kwarg dispatch dropped body="
        );

        // ---------------------------------------------------------------
        // Scenario 2 — body=bytes through the same dispatch path.
        // ---------------------------------------------------------------
        let body_2: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\n";
        Python::attach(|py| {
            let bound = utils_py.bind(py);

            let headers = PyDict::new(py);
            headers.set_item("Content-Type", "application/sdp").unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("headers", headers).unwrap();
            kwargs
                .set_item("body", pyo3::types::PyBytes::new(py, body_2))
                .unwrap();

            let args = PyTuple::new(py, ["MESSAGE", "sip:127.0.0.1:5060"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 2: bytes-body dispatch");
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 2: no UDP egress for bytes body");
        assert!(
            outbound.data.windows(body_2.len()).any(|w| w == body_2),
            "scenario 2: bytes body lost"
        );
        let wire = String::from_utf8(outbound.data.to_vec()).unwrap();
        assert!(
            wire.contains(&format!("Content-Length: {}", body_2.len())),
            "scenario 2: wrong Content-Length:\n{wire}"
        );

        // ---------------------------------------------------------------
        // Scenario 3 — caller passes Content-Length: 0 in the headers
        // dict but supplies a non-empty body.  build_send_request_message
        // must override the stale Content-Length from the dict.
        // ---------------------------------------------------------------
        let body_3 = "abc\r\nhello\r\n";
        Python::attach(|py| {
            let bound = utils_py.bind(py);

            let headers = PyDict::new(py);
            headers.set_item("Content-Length", "0").unwrap();
            headers.set_item("Content-Type", "text/plain").unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("headers", headers).unwrap();
            kwargs.set_item("body", body_3).unwrap();

            let args = PyTuple::new(py, ["MESSAGE", "sip:127.0.0.1:5060"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 3: stale-CL dispatch");
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 3: no UDP egress for stale-CL test");
        let wire = String::from_utf8(outbound.data.to_vec()).unwrap();
        assert!(
            wire.contains(&format!("Content-Length: {}", body_3.len())),
            "scenario 3: stale Content-Length: 0 leaked from headers dict:\n{wire}"
        );
        assert!(
            !wire.contains("Content-Length: 0\r\n"),
            "scenario 3: Content-Length: 0 still present in wire output:\n{wire}"
        );
        assert!(
            wire.ends_with(body_3),
            "scenario 3: body not verbatim on wire:\n{wire}"
        );

        // ---------------------------------------------------------------
        // Scenario 4 — fire-and-forget registers a pending UAC entry so
        // the dispatcher silently consumes the matching response.  Without
        // this the dispatcher logs "response for unknown branch (not ours)"
        // on every legitimate reply (the second half of the bug report).
        // ---------------------------------------------------------------
        let installed_sender = UAC_SENDER
            .get()
            .expect("scenario 4: UAC_SENDER must be installed");
        let pending_before = installed_sender.pending_count();

        Python::attach(|py| {
            let bound = utils_py.bind(py);
            let kwargs = PyDict::new(py);
            let args = PyTuple::new(py, ["OPTIONS", "sip:127.0.0.1:5060"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 4: fire-and-forget dispatch");
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 4: no UDP egress — dispatch dropped the message");
        let wire = String::from_utf8(outbound.data.to_vec()).unwrap();
        assert_eq!(
            installed_sender.pending_count(),
            pending_before + 1,
            "scenario 4: fire-and-forget must register a pending UAC entry \
             so the dispatcher can silently consume the eventual response"
        );

        // Reflect a 200 OK back with the same Via branch and verify
        // match_response consumes it (the silent-consumption path the
        // dispatcher's `handle_response` short-circuit relies on).
        let branch = wire
            .lines()
            .find(|line| line.starts_with("Via:"))
            .and_then(|via| via.split(";branch=").nth(1))
            .and_then(|rest| rest.split(|c: char| c == ';' || c.is_ascii_whitespace()).next())
            .expect("scenario 4: outbound Via must carry branch");
        assert!(
            branch.starts_with("z9hG4bK-uac-py-"),
            "scenario 4: branch must be UAC-shaped, got {branch}"
        );

        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via(format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"))
            .to("<sip:127.0.0.1>".to_string())
            .from("<sip:siphon@127.0.0.1>;tag=py-1".to_string())
            .call_id("scenario4-call".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .expect("scenario 4: build response");

        assert!(
            installed_sender.match_response(&response),
            "scenario 4: match_response must consume the reply for the registered branch"
        );
        assert_eq!(
            installed_sender.pending_count(),
            pending_before,
            "scenario 4: matched response must remove the pending entry"
        );

        // ---------------------------------------------------------------
        // Scenario 5 — a pre-loaded `Route` header drives the next hop
        // (RFC 3261 §8.1.2 / §16.4).  The R-URI resolves to host-B
        // (127.0.0.9), but the route set names host-A (127.0.0.5), so the
        // message MUST be sent to host-A with the R-URI unchanged and the
        // Route header riding along.  This is the reg-event-SUBSCRIBE bug:
        // pre-loading the serving S-CSCF as a loose route should bypass the
        // I-CSCF the R-URI's home domain would otherwise resolve to.
        // ---------------------------------------------------------------
        Python::attach(|py| {
            let bound = utils_py.bind(py);

            let headers = PyDict::new(py);
            headers
                .set_item("Route", "<sip:127.0.0.5:5055;lr>")
                .unwrap();
            headers.set_item("Event", "reg").unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("headers", headers).unwrap();

            // R-URI is host-B; Route is host-A.
            let args = PyTuple::new(py, ["SUBSCRIBE", "sip:127.0.0.9:5099"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 5: route-driven dispatch");
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 5: no UDP egress for route-driven request");
        assert_eq!(
            outbound.destination,
            "127.0.0.5:5055".parse().unwrap(),
            "scenario 5: a pre-loaded Route must drive the next hop (host-A), \
             not the R-URI (host-B)"
        );
        let wire = String::from_utf8(outbound.data.to_vec()).unwrap();
        assert!(
            wire.starts_with("SUBSCRIBE sip:127.0.0.9:5099 SIP/2.0\r\n"),
            "scenario 5: R-URI must stay in the Request-Line unchanged:\n{wire}"
        );
        assert!(
            wire.contains("Route: <sip:127.0.0.5:5055;lr>"),
            "scenario 5: the Route header must ride along untouched:\n{wire}"
        );

        // ---------------------------------------------------------------
        // Scenario 6 — an explicit `next_hop` outranks a `Route` header
        // (local policy wins, RFC 3261 §8.1.2 step 1).  R-URI = host-B,
        // Route = host-A, next_hop = host-C (127.0.0.7) → host-C wins.
        // ---------------------------------------------------------------
        Python::attach(|py| {
            let bound = utils_py.bind(py);

            let headers = PyDict::new(py);
            headers
                .set_item("Route", "<sip:127.0.0.5:5055;lr>")
                .unwrap();

            let kwargs = PyDict::new(py);
            kwargs.set_item("headers", headers).unwrap();
            kwargs.set_item("next_hop", "sip:127.0.0.7:5077").unwrap();

            let args = PyTuple::new(py, ["SUBSCRIBE", "sip:127.0.0.9:5099"]).unwrap();
            let coroutine = bound
                .call_method("send_request", args, Some(&kwargs))
                .expect("scenario 6: next_hop-override dispatch");
            let _ = coroutine.call_method0("close");
        });

        let outbound = udp_rx
            .try_recv()
            .expect("scenario 6: no UDP egress for next_hop-override request");
        assert_eq!(
            outbound.destination,
            "127.0.0.7:5077".parse().unwrap(),
            "scenario 6: an explicit next_hop must outrank a Route header"
        );
    }

    #[test]
    fn parse_first_route_uri_single_loose_route() {
        let uri = parse_first_route_uri("<sip:scscf-0.ims.example.org:6060;lr>")
            .expect("loose route must parse");
        assert_eq!(uri.host, "scscf-0.ims.example.org");
        assert_eq!(uri.port, Some(6060));
        assert!(uri.params.iter().any(|(n, _)| n == "lr"));
    }

    #[test]
    fn parse_first_route_uri_picks_first_of_route_set() {
        // A comma-separated route set must yield the FIRST hop only.
        let uri = parse_first_route_uri("<sip:host-a.example.org;lr>, <sip:host-b.example.org;lr>")
            .expect("multi route must parse");
        assert_eq!(uri.host, "host-a.example.org");
    }

    #[test]
    fn parse_first_route_uri_with_transport_param() {
        let uri = parse_first_route_uri("<sip:proxy.example.org:5060;transport=tcp;lr>")
            .expect("route with transport must parse");
        assert_eq!(uri.get_param("transport"), Some("tcp"));
        assert_eq!(uri.port, Some(5060));
    }

    #[test]
    fn parse_first_route_uri_bare_addr_spec_fallback() {
        // A bare addr-spec without angle brackets is tolerated.
        let uri = parse_first_route_uri("sip:proxy.example.org:5060").expect("bare uri must parse");
        assert_eq!(uri.host, "proxy.example.org");
        assert_eq!(uri.port, Some(5060));
    }

    #[test]
    fn parse_first_route_uri_rejects_garbage() {
        assert!(parse_first_route_uri("not a uri at all").is_none());
    }

    #[test]
    fn route_next_hop_reads_route_header() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("To", "<sip:bob@example.org>").unwrap();
            headers.set_item("Route", "<sip:scscf-0.example.org:6060;lr>").unwrap();

            let uri = route_next_hop(Some(&headers)).expect("Route must produce a next hop");
            assert_eq!(uri.host, "scscf-0.example.org");
            assert_eq!(uri.port, Some(6060));
        });
    }

    #[test]
    fn route_next_hop_is_case_insensitive() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("rOuTe", "<sip:scscf-0.example.org:6060;lr>").unwrap();

            let uri = route_next_hop(Some(&headers)).expect("Route is case-insensitive");
            assert_eq!(uri.host, "scscf-0.example.org");
        });
    }

    #[test]
    fn route_next_hop_none_without_route_header() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let headers = PyDict::new(py);
            headers.set_item("To", "<sip:bob@example.org>").unwrap();
            headers.set_item("Event", "reg").unwrap();

            assert!(route_next_hop(Some(&headers)).is_none());
        });
    }

    #[test]
    fn route_next_hop_none_for_empty_headers() {
        assert!(route_next_hop(None).is_none());
    }

    #[test]
    fn resolve_send_target_prefers_explicit_next_hop() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let ruri = SipUri::new("host-b.example.org".to_string());
            let headers = PyDict::new(py);
            headers.set_item("Route", "<sip:host-a.example.org;lr>").unwrap();

            // next_hop (host-c) outranks both the Route (host-a) and R-URI (host-b).
            let target = resolve_send_target(&ruri, Some("sip:host-c.example.org"), Some(&headers))
                .expect("explicit next_hop must parse");
            assert_eq!(target.host, "host-c.example.org");
        });
    }

    #[test]
    fn resolve_send_target_uses_route_over_ruri() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let ruri = SipUri::new("host-b.example.org".to_string());
            let headers = PyDict::new(py);
            headers.set_item("Route", "<sip:host-a.example.org;lr>").unwrap();

            let target = resolve_send_target(&ruri, None, Some(&headers))
                .expect("route must produce a target");
            assert_eq!(
                target.host, "host-a.example.org",
                "a Route set must outrank the R-URI for next-hop selection"
            );
        });
    }

    #[test]
    fn resolve_send_target_falls_back_to_ruri() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let ruri = SipUri::new("host-b.example.org".to_string());
            let headers = PyDict::new(py);
            headers.set_item("Event", "reg").unwrap();

            let target = resolve_send_target(&ruri, None, Some(&headers))
                .expect("R-URI fallback must parse");
            assert_eq!(target.host, "host-b.example.org");
        });
    }
}
