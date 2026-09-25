//! PyO3 wrapper for the generic SUBSCRIBE dialog manager.
//!
//! Exposed to scripts as ``proxy.subscribe_state``.  See
//! [`crate::subscribe_state`] for the underlying store + persistence
//! semantics.

use std::sync::{Arc, OnceLock};

use pyo3::prelude::*;
use tracing::debug;
use uuid::Uuid;

use crate::dns::SipResolver;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::subscribe_state::{SubscribeDialog, SubscribeStore};
use crate::transport::Transport;
use crate::uac::UacSender;

use super::reply::PyReply;
use super::request::PyRequest;

static UAC_SENDER: OnceLock<Arc<UacSender>> = OnceLock::new();
static SEND_RESOLVER: OnceLock<Arc<SipResolver>> = OnceLock::new();

/// One-time wire-up from ``server.rs`` — the UAC and resolver are shared
/// with [`super::proxy_utils`].
pub fn set_uac_sender(sender: Arc<UacSender>) {
    let _ = UAC_SENDER.set(sender);
}

pub fn set_resolver(resolver: Arc<SipResolver>) {
    let _ = SEND_RESOLVER.set(resolver);
}

/// Python-visible namespace — injected as ``proxy.subscribe_state``.
#[pyclass(name = "SubscribeStateNamespace")]
pub struct PySubscribeState {
    store: Arc<SubscribeStore>,
}

impl PySubscribeState {
    pub fn new(store: Arc<SubscribeStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PySubscribeState {
    /// Accept an authenticated, authorized incoming SUBSCRIBE. Returns the
    /// existing handle on refresh, or None after replying 481 to an unknown
    /// in-dialog request. The script must immediately notify (or terminate for
    /// Expires:0); package bodies and access policy remain script-owned.
    #[pyo3(signature = (request, expires=None))]
    fn accept(
        &self,
        request: &Bound<'_, PyRequest>,
        expires: Option<u64>,
    ) -> PyResult<Option<PySubscribeHandle>> {
        let candidate = capture_incoming(request, expires)?;
        let mut borrowed = request.borrow_mut();
        let message_arc = borrowed.message();
        let message = message_arc
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        let to = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"))
            .cloned()
            .unwrap_or_default();
        let tagged = extract_tag(&to).is_some();
        let dialog = if tagged {
            match self.store.find_by_tags(
                &candidate.call_id,
                &candidate.local_tag,
                &candidate.remote_tag,
            ) {
                Some(existing)
                    if !existing.is_outbound
                        && existing.event == candidate.event
                        && existing.remaining_secs() > 0
                        && existing.local_uri == candidate.local_uri
                        && existing.remote_uri == candidate.remote_uri =>
                {
                    existing
                }
                _ => {
                    drop(message);
                    borrowed.set_reply(481, "Subscription Does Not Exist".into());
                    return Ok(None);
                }
            }
        } else {
            candidate.clone()
        };
        drop(message);
        let mut dialog = dialog;
        dialog.remote_target = candidate.remote_target;
        // A notifier's route set is the request's order, unlike a UAC's reversed
        // response route set (RFC 3261 section 12.1.1).
        if !tagged {
            dialog.route_set = candidate.route_set.into_iter().rev().collect();
        }
        dialog.received_address = borrowed.source_socket_addr();
        dialog.received_transport = Some(borrowed.transport_name().to_ascii_lowercase());
        dialog.received_connection_id = borrowed.inbound_connection_id_u64();
        dialog.refresh(candidate.expires_secs);
        borrowed.push_reply_header_replace("To", ensure_tag(&to, &dialog.local_tag));
        borrowed.push_reply_header_replace("Expires", candidate.expires_secs.to_string());
        let transport = received_transport(dialog.received_transport.as_deref().unwrap_or("udp"));
        let contact = UAC_SENDER
            .get()
            .map(|sender| {
                format_default_contact(
                    &sender.via_host_for(&transport),
                    sender.addr_for(&transport).port(),
                    transport,
                )
            })
            .unwrap_or_else(|| format!("<{}>", dialog.local_uri));
        borrowed.push_reply_header_replace("Contact", contact);
        borrowed.set_reply(200, "OK".into());
        let id = dialog.id.clone();
        if tagged {
            // Preserve counters bumped concurrently by change notifications.
            let refreshed = self.store.update(&id, |existing| {
                existing.remote_target = dialog.remote_target;
                existing.received_address = dialog.received_address;
                existing.received_transport = dialog.received_transport;
                existing.received_connection_id = dialog.received_connection_id;
                existing.refresh(dialog.expires_secs);
            });
            if refreshed.is_none() {
                borrowed.set_reply(481, "Subscription Does Not Exist".into());
                return Ok(None);
            }
        } else {
            self.store.put(dialog);
        }
        Ok(Some(PySubscribeHandle {
            store: Arc::clone(&self.store),
            id,
        }))
    }

    /// Capture the dialog from an incoming SUBSCRIBE request and return a
    /// handle for later NOTIFY/terminate operations.
    ///
    /// The handle id is durable — when ``media.cache``/``cache:`` Redis
    /// is configured for ``subscribe_state.cache``, the dialog survives
    /// restarts and is visible to other siphon replicas.  Store the id
    /// via :attr:`SubscribeHandle.id` and pass it to :meth:`get` later.
    #[pyo3(signature = (request, expires=None))]
    fn create(
        &self,
        request: &Bound<'_, PyRequest>,
        expires: Option<u64>,
    ) -> PyResult<PySubscribeHandle> {
        let dialog = capture_incoming(request, expires)?;
        let id = dialog.id.clone();
        self.store.put(dialog);
        debug!(id, "subscribe_state: dialog created");

        Ok(PySubscribeHandle {
            store: Arc::clone(&self.store),
            id,
        })
    }

    /// Look up a previously-created handle by id.  Returns ``None`` if
    /// the dialog is unknown, expired, or terminated.
    #[pyo3(signature = (id))]
    fn get<'py>(&self, python: Python<'py>, id: &str) -> PyResult<Bound<'py, PyAny>> {
        let store = Arc::clone(&self.store);
        let id_owned = id.to_string();
        crate::script::awaitable(python, async move {
            let found = store.get(&id_owned).await;
            Ok(found.map(|dialog| PySubscribeHandle {
                store: Arc::clone(&store),
                id: dialog.id,
            }))
        })
    }

    /// Number of subscribe dialogs currently held in the in-process
    /// cache (excludes cache-only entries on other replicas).
    #[getter]
    fn local_count(&self) -> usize {
        self.store.local_count()
    }

    /// Originate an outbound SUBSCRIBE and capture the resulting dialog.
    ///
    /// Sends a SUBSCRIBE to ``ruri`` (or to ``target_uri`` if given as a
    /// pre-loaded Route — see RFC 3261 §16.4) and blocks until the
    /// notifier responds. On a 2xx response the dialog state is captured
    /// from the From/To/Contact/Record-Route headers and a
    /// :class:`SubscribeHandle` is returned for later
    /// :meth:`SubscribeHandle.refresh` / :meth:`SubscribeHandle.terminate`
    /// or in-dialog NOTIFY correlation via :meth:`find`.
    ///
    /// Args:
    ///     ruri: SUBSCRIBE Request-URI (the watched resource).
    ///     event: Event package name written to the ``Event`` header
    ///            (e.g. ``"reg"`` for RFC 3680, ``"presence"`` for RFC 3856).
    ///     expires: Subscription duration in seconds (Expires header).
    ///     accept: Optional ``Accept`` header value (e.g.
    ///             ``"application/reginfo+xml"``).
    ///     target_uri: Optional pre-loaded Route — when set, the SUBSCRIBE
    ///                 is routed to this URI but ``ruri`` stays as the
    ///                 Request-URI. Useful for IMS where the watcher knows
    ///                 the next-hop S-CSCF.
    ///     headers: Optional dict of extra header name → value pairs to add
    ///              (e.g. ``P-Asserted-Identity``).
    ///     timeout_ms: Response timeout in milliseconds (default 2000).
    ///
    /// Raises ``RuntimeError`` on non-2xx response, timeout, malformed
    /// 200 OK (missing tag/Contact), or transport failure.
    #[pyo3(signature = (
        ruri,
        event,
        expires,
        accept=None,
        target_uri=None,
        headers=None,
        timeout_ms=2000,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn send<'py>(
        &self,
        python: Python<'py>,
        ruri: &str,
        event: &str,
        expires: u64,
        accept: Option<&str>,
        target_uri: Option<&str>,
        headers: Option<&Bound<'_, pyo3::types::PyDict>>,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Read the header dict here: a `Bound` cannot cross into the future.
        let extra_headers: Vec<(String, String)> = match headers {
            Some(dict) => dict
                .iter()
                .map(|(key, value)| Ok((key.extract::<String>()?, value.extract::<String>()?)))
                .collect::<PyResult<_>>()?,
            None => Vec::new(),
        };
        let store = Arc::clone(&self.store);
        let (ruri, event) = (ruri.to_string(), event.to_string());
        let accept = accept.map(str::to_string);
        let target_uri = target_uri.map(str::to_string);

        crate::script::awaitable(python, async move {
            Self::send_inner(
                store,
                &ruri,
                &event,
                expires,
                accept.as_deref(),
                target_uri.as_deref(),
                extra_headers,
                timeout_ms,
            )
            .await
        })
    }

    /// Look up a live dialog by its three identity tags. Used to
    /// correlate an in-dialog NOTIFY (received via
    /// ``@proxy.on_request("NOTIFY")``) to the outbound SUBSCRIBE that
    /// established the dialog.
    ///
    /// On NOTIFY, the From-tag is the notifier's tag (our remote_tag)
    /// and the To-tag is ours (our local_tag). Returns ``None`` if the
    /// dialog is unknown or terminated.
    #[pyo3(signature = (call_id, local_tag, remote_tag))]
    fn find(&self, call_id: &str, local_tag: &str, remote_tag: &str) -> Option<PySubscribeHandle> {
        self.store
            .find_by_tags(call_id, local_tag, remote_tag)
            .map(|dialog| PySubscribeHandle {
                store: Arc::clone(&self.store),
                id: dialog.id,
            })
    }
}

/// Handle returned by :meth:`PySubscribeState.create` / ``get``.
#[pyclass(name = "SubscribeHandle")]
pub struct PySubscribeHandle {
    store: Arc<SubscribeStore>,
    id: String,
}

#[pymethods]
impl PySubscribeHandle {
    /// The durable id — pass to ``proxy.subscribe_state.get()`` to
    /// retrieve this handle from another worker or after restart.
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Notifier tag shared by the SUBSCRIBE response and every NOTIFY.
    #[getter]
    fn local_tag(&self) -> PyResult<String> {
        Ok(self.load_local()?.local_tag)
    }

    /// The SIP Event package (copied from the SUBSCRIBE).
    #[getter]
    fn event(&self) -> PyResult<String> {
        let dialog = self.load_local()?;
        Ok(dialog.event)
    }

    /// Seconds remaining until the dialog expires.
    #[getter]
    fn expires(&self) -> PyResult<u64> {
        let dialog = self.load_local()?;
        Ok(dialog.remaining_secs())
    }

    /// Current event-package body version (monotonic NOTIFY body counter).
    ///
    /// Used for RFC 3680 reginfo, RFC 4235 dialog-info, RFC 4575 conference,
    /// etc.  Persisted alongside the dialog so it survives restart when an
    /// L2 cache is configured.  Read-only — call
    /// :meth:`next_event_version` to advance it.
    #[getter]
    fn event_version(&self) -> PyResult<u32> {
        let dialog = self.load_local()?;
        Ok(dialog.event_version)
    }

    /// Atomically increment and return the next event-package body version.
    ///
    /// Call before building a NOTIFY body that requires monotonicity (e.g.
    /// the `version=` attribute on RFC 3680 reginfo).  Python usage:
    ///
    /// ```python
    /// version = handle.next_event_version()
    /// body = registrar.reginfo_xml(aor, state="full", version=version)
    /// await handle.notify(body=body, content_type="application/reginfo+xml")
    /// ```
    fn next_event_version(&self) -> PyResult<u32> {
        // Raise rather than no-op when the dialog is gone; the update below is
        // local-only, so this is the whole liveness check.
        let _ = self.load_local()?;
        let updated = self.store.update(&self.id, |dialog| {
            dialog.next_event_version();
        });
        match updated {
            Some(dialog) => Ok(dialog.event_version),
            None => Err(pyo3::exceptions::PyLookupError::new_err(format!(
                "subscribe_state dialog '{}' not found",
                self.id
            ))),
        }
    }

    fn __repr__(&self) -> String {
        format!("SubscribeHandle(id={:?})", self.id)
    }

    /// Re-read the dialog through the configured L2 cache, refreshing this
    /// instance's local view of it.  Returns ``True`` when a live dialog is in
    /// hand afterwards, ``False`` when it is unknown or terminated.
    ///
    /// Every property and every send on a handle reads local state only, so
    /// none of them can block.  This is the awaited counterpart for the one
    /// case that needs the cache: a dialog another replica owns, whose local
    /// entry has since been reaped, where a property would otherwise raise
    /// ``LookupError``.
    ///
    /// ```python
    /// if not await handle.reload():
    ///     return              # the subscription is gone
    /// log.info(f"{handle.expires}s left")
    /// ```
    ///
    /// Without an L2 cache configured (``subscribe_state.cache``) this is just
    /// a liveness check against local state.
    fn reload<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let store = Arc::clone(&self.store);
        let id = self.id.clone();
        crate::script::awaitable(python, async move { Ok(store.get(&id).await.is_some()) })
    }

    /// Send an in-dialog NOTIFY with ``body``/``content_type``.
    ///
    /// ``state`` is the full ``Subscription-State`` header value.  When
    /// omitted, siphon emits ``active;expires=<remaining>``.  Set it
    /// explicitly for ``pending``, ``active;expires=N;reason=...``, or
    /// to override the expiry.
    ///
    /// Returns ``True`` on success, ``False`` if the dialog has been
    /// terminated or is unknown.
    #[pyo3(signature = (body=None, content_type=None, state=None))]
    fn notify<'py>(
        &self,
        python: Python<'py>,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
        state: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Read the body here: a `Bound` cannot cross into the future. The CSeq
        // bump stays here too, so two NOTIFYs a script sends in order keep
        // their order.
        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };
        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return crate::script::ready(python, false),
        };
        let subscription_state = state
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("active;expires={}", dialog.remaining_secs()));
        let content_type = content_type.map(str::to_string);

        crate::script::awaitable(python, async move {
            send_notify(
                &dialog,
                &subscription_state,
                content_type.as_deref(),
                body_bytes.as_deref(),
            )
            .await?;
            Ok(true)
        })
    }

    /// Terminate the subscription dialog.
    ///
    /// For dialogs we received as the notifier (the original
    /// ``create()`` flow), this sends a final NOTIFY with
    /// ``Subscription-State: terminated;reason=<reason>`` (RFC 6665
    /// §4.2.2). For dialogs we originated as the watcher (the
    /// :meth:`SubscribeStateNamespace.send` flow), this sends a
    /// SUBSCRIBE Expires:0 instead — the notifier owes us the final
    /// terminating NOTIFY, which arrives via ``@proxy.on_request("NOTIFY")``.
    ///
    /// In both cases the dialog is marked terminated and removed from
    /// the store. ``reason`` defaults to ``"noresource"`` and is only
    /// used for the notifier path.
    #[pyo3(signature = (reason=None, body=None, content_type=None))]
    fn terminate<'py>(
        &self,
        python: Python<'py>,
        reason: Option<&str>,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };
        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return crate::script::ready(python, false),
        };
        let subscription_state = format!("terminated;reason={}", reason.unwrap_or("noresource"));
        let content_type = content_type.map(str::to_string);
        let store = Arc::clone(&self.store);
        let id = self.id.clone();

        crate::script::awaitable(python, async move {
            if dialog.is_outbound {
                // Watcher role — terminate by sending SUBSCRIBE Expires:0.
                send_in_dialog_subscribe(&dialog, 0).await?;
            } else {
                // Notifier role — send the final NOTIFY.
                send_notify(
                    &dialog,
                    &subscription_state,
                    content_type.as_deref(),
                    body_bytes.as_deref(),
                )
                .await?;
            }

            // Mark terminated + remove.  Mark-then-remove gives a brief
            // window where get() returns None even if the cache still has
            // the entry (race-safe for cross-instance lookups).
            store.update(&id, |dialog| dialog.terminated = true);
            store.remove(&id);
            Ok(true)
        })
    }

    /// Re-SUBSCRIBE to refresh the dialog. Only valid on dialogs
    /// originated via :meth:`SubscribeStateNamespace.send` (watcher
    /// role) — refreshing a notifier-side dialog is a no-op since the
    /// peer drives refresh by sending us another SUBSCRIBE.
    ///
    /// ``expires`` defaults to the original Expires value the dialog
    /// was created with. Increments CSeq, updates the dialog's expiry
    /// anchor on success, and persists to L2 if configured. Raises on
    /// non-2xx, timeout, or transport failure (existing dialog is
    /// kept; the script can decide to retry or terminate).
    #[pyo3(signature = (expires=None, timeout_ms=2000))]
    fn refresh<'py>(
        &self,
        python: Python<'py>,
        expires: Option<u64>,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let dialog = self.load_local()?;
        if !dialog.is_outbound {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "refresh() is only valid on outbound dialogs (created via send())",
            ));
        }
        let new_expires = expires.unwrap_or(dialog.expires_secs);

        // Bump CSeq before sending so retransmits (handled by transport
        // layer) carry the same value we'll commit on success.
        let bumped = self
            .store
            .update(&self.id, |dialog| {
                dialog.next_cseq();
            })
            .ok_or_else(|| {
                pyo3::exceptions::PyLookupError::new_err(format!(
                    "subscribe_state dialog '{}' not found",
                    self.id
                ))
            })?;

        let store = Arc::clone(&self.store);
        let id = self.id.clone();
        crate::script::awaitable(python, async move {
            send_in_dialog_subscribe_with_timeout(&bumped, new_expires, timeout_ms).await?;

            // Commit the new expiry anchor.
            store.update(&id, |dialog| {
                dialog.refresh(new_expires);
            });
            Ok(true)
        })
    }

    /// Send a final NOTIFY using an already-built
    /// ``Subscription-State`` value built elsewhere (advanced).
    ///
    /// Wraps :meth:`notify` but without the automatic
    /// ``active;expires=...`` default.
    #[pyo3(signature = (reply))]
    #[allow(dead_code)]
    fn mirror_reply(&self, reply: &Bound<'_, PyReply>) -> PyResult<bool> {
        // Kept as a placeholder for a later convenience that builds a
        // NOTIFY body from an existing :class:`Reply`.  For now just
        // no-ops so the attribute exists; scripts should use notify().
        let _ = reply;
        Ok(false)
    }
}

impl PySubscribeHandle {
    /// Load the dialog out of the local store. Synchronous and non-blocking:
    /// no network, nothing an asyncio driver can be held for.
    ///
    /// This backs the Python **properties** (`event`, `expires`, `local_tag`,
    /// …), which cannot be awaited, so the loader they read through must not be
    /// able to wait on anything. It reads L1 only, and that costs nothing here:
    /// a `SubscribeHandle` only ever comes from a call that has already put its
    /// dialog in L1 — `accept`/`create`/`send` via `put`, `find` off an L1 scan,
    /// and the awaitable `get`, which hydrates L1 from the cache before it
    /// builds the handle. A handle is a Python object, so it cannot arrive from
    /// another process either. L1 therefore holds whatever a live handle refers
    /// to, and it is still a *live* read — the same entry a SUBSCRIBE refresh
    /// mutates, not a snapshot taken at construction.
    ///
    /// What it gives up is the implicit revival: once the sweeper reaps the
    /// local entry (expired or terminated) this raises instead of fetching a
    /// copy the cache may still hold on its own TTL — a copy the sweeper has
    /// already sent the terminating NOTIFY for. Scripts that genuinely want the
    /// cache re-read ask for it with `await handle.reload()`.
    fn load_local(&self) -> PyResult<SubscribeDialog> {
        self.store.get_local(&self.id).ok_or_else(|| {
            pyo3::exceptions::PyLookupError::new_err(format!(
                "subscribe_state dialog '{}' not found",
                self.id
            ))
        })
    }

    /// Increment CSeq and return the updated dialog snapshot, or
    /// ``None`` if the dialog has disappeared.
    fn bump_cseq(&self) -> PyResult<Option<SubscribeDialog>> {
        // Liveness check first, so a reaped dialog raises rather than silently
        // no-opping. Stays synchronous: `update` must not be reordered against
        // a sibling NOTIFY, so the CSeq it takes cannot be decided inside a
        // future (RFC 6665 §4.4.1 — NOTIFY CSeq is monotonic per dialog).
        let _ = self.load_local()?;
        let updated = self.store.update(&self.id, |dialog| {
            dialog.next_cseq();
        });
        Ok(updated)
    }
}

fn capture_incoming(
    request: &Bound<'_, PyRequest>,
    expires: Option<u64>,
) -> PyResult<SubscribeDialog> {
    let borrowed = request.borrow();
    let message_arc = borrowed.message();
    let message = message_arc.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })?;

    let call_id = message
        .headers
        .get("Call-ID")
        .or_else(|| message.headers.get("i"))
        .cloned()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Call-ID"))?;

    let from_raw = message
        .headers
        .get("From")
        .or_else(|| message.headers.get("f"))
        .cloned()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing From"))?;
    let to_raw = message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .cloned()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing To"))?;

    let contact_raw = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .cloned()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Contact"))?;

    let event = message
        .headers
        .get("Event")
        .or_else(|| message.headers.get("o"))
        .cloned()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Event header"))?;

    let remote_tag = extract_tag(&from_raw)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("SUBSCRIBE From has no tag"))?;

    // The SUBSCRIBE's To-tag is the notifier's (our) tag.  If the
    // SUBSCRIBE had no To-tag (first-in-dialog), we mint one now so
    // our NOTIFYs carry a stable tag.
    let local_tag = extract_tag(&to_raw).unwrap_or_else(short_uuid);

    let local_uri = strip_nameaddr(&to_raw);
    let remote_uri = strip_nameaddr(&from_raw);
    let remote_target = strip_nameaddr(&contact_raw);

    // Record-Route values are copied left-to-right; NOTIFY Route
    // headers are the reverse (RFC 3261 §12.1).
    let route_set: Vec<String> = message
        .headers
        .get_all("Record-Route")
        .map(|entries| entries.iter().rev().cloned().collect())
        .unwrap_or_default();

    let expires_secs = expires
        .or_else(|| {
            message
                .headers
                .get("Expires")
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .unwrap_or(3600);

    let id = short_uuid();
    let dialog = SubscribeDialog {
        id: id.clone(),
        call_id,
        local_tag,
        remote_tag,
        local_uri,
        remote_uri,
        remote_target,
        received_address: None,
        received_transport: None,
        received_connection_id: None,
        route_set,
        event,
        expires_secs,
        created_at_unix: now_unix(),
        cseq: 0,
        event_version: 0,
        terminated: false,
        is_outbound: false,
    };

    drop(message);
    Ok(dialog)
}

// ---------------------------------------------------------------------------
// Wire helpers — borrowed from proxy_utils / presence patterns
// ---------------------------------------------------------------------------

/// Finish expired notifier dialogs outside the dispatcher task: DNS resolution
/// must not stall SIP dispatch. State has already been removed by the sweep.
pub(crate) async fn notify_expired(mut dialog: SubscribeDialog) {
    if dialog.terminated || dialog.is_outbound {
        return;
    }
    dialog.next_cseq();
    if let Err(error) = send_notify(&dialog, "terminated;reason=timeout", None, None).await {
        tracing::error!(id = %dialog.id, %error, "failed to notify subscription expiry");
    }
}

fn received_transport(name: &str) -> Transport {
    match name {
        "tls" => Transport::Tls,
        "tcp" => Transport::Tcp,
        "ws" => Transport::WebSocket,
        "wss" => Transport::WebSocketSecure,
        "sctp" => Transport::Sctp,
        _ => Transport::Udp,
    }
}

async fn send_notify(
    dialog: &SubscribeDialog,
    subscription_state: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> PyResult<()> {
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: UAC sender not initialized",
        )
    })?;
    let resolver = SEND_RESOLVER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state.notify() unavailable: DNS resolver not initialized",
        )
    })?;

    // Determine transport destination: first Route URI or remote_target.
    let ruri = parse_uri_standalone(&dialog.remote_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid remote target: {error}"))
    })?;
    let (destination, transport) = if let (true, Some(address), Some(transport)) = (
        dialog.route_set.is_empty(),
        dialog.received_address,
        dialog.received_transport.as_deref(),
    ) {
        let transport = received_transport(transport);
        (address, transport)
    } else {
        let resolve_target: String = dialog
            .route_set
            .first()
            .map(|route| {
                route
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
            .unwrap_or_else(|| dialog.remote_target.clone());

        let resolve_uri = parse_uri_standalone(&resolve_target).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid route/target URI '{resolve_target}': {error}"
            ))
        })?;

        let transport_hint = resolve_uri
            .get_param("transport")
            .map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(resolver);
        let host = resolve_uri.host.clone();
        let port = resolve_uri.port;
        let scheme = resolve_uri.scheme.clone();

        let destination = resolver_clone
            .resolve(&host, port, scheme.as_str(), transport_hint.as_deref())
            .await;

        let target = destination.into_iter().next().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_target}'"
            ))
        })?;

        let transport = match target.transport.as_deref().or(transport_hint.as_deref()) {
            Some(hint) => match hint.to_lowercase().as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                "sctp" => Transport::Sctp,
                _ => Transport::Udp,
            },
            None => {
                if scheme == "sips" {
                    Transport::Tls
                } else {
                    Transport::Udp
                }
            }
        };

        (target.address, transport)
    };

    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport,
        uac_sender.via_host_for(&transport),
        uac_sender.addr_for(&transport).port(),
        branch
    );
    let cseq_str = format!("{} NOTIFY", dialog.cseq);

    // NOTIFY tag orientation (RFC 6665 §4.4.1): From = notifier (us),
    // To = subscriber (peer).
    let from_header = format!("<{}>;tag={}", dialog.local_uri, dialog.local_tag);
    let to_header = format!("<{}>;tag={}", dialog.remote_uri, dialog.remote_tag);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Notify, ruri)
        .via(via)
        .call_id(dialog.call_id.clone())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header)
        .to(to_header)
        .header(
            "Contact",
            format_default_contact(
                &uac_sender.via_host_for(&transport),
                uac_sender.addr_for(&transport).port(),
                transport,
            ),
        )
        .header("Event", dialog.event.clone())
        .header("Subscription-State", subscription_state.to_string());

    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }

    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct.to_string());
    }

    if let Some(body_bytes) = body {
        builder = builder.body(body_bytes.to_vec());
    } else {
        builder = builder.content_length(0);
    }

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build NOTIFY: {error}"))
    })?;

    // If called from inside a request handler, the dispatcher may defer
    // until after the SUBSCRIBE reply is sent (RFC 6665 §4.1).
    if !super::proxy_utils::try_defer_send(message.clone(), destination, transport) {
        if dialog.route_set.is_empty()
            && dialog.received_address.is_some()
            && transport != Transport::Udp
        {
            // Exact match only: IP-only reuse can select another subscriber's
            // connection when several phones share one front proxy.
            let connection_id = super::stream_connections()
                .and_then(|registry| registry.get(&destination))
                .filter(|(registered_transport, _)| *registered_transport == transport)
                .filter(|(_, connection_id)| {
                    dialog
                        .received_connection_id
                        .map_or(true, |expected| connection_id.0 == expected)
                })
                .map(|(_, connection_id)| connection_id)
                .ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "SUBSCRIBE transport flow is no longer connected",
                    )
                })?;
            uac_sender.send_request_on_connection(message, destination, transport, connection_id);
        } else {
            uac_sender.send_request(message, destination, transport);
        }
    }
    debug!(id = %dialog.id, "subscribe_state: NOTIFY sent");
    Ok(())
}

/// Send an in-dialog SUBSCRIBE (refresh or Expires:0 termination)
/// without waiting for a response. Used by `terminate()` on outbound
/// dialogs — the response carries no information we need.
async fn send_in_dialog_subscribe(dialog: &SubscribeDialog, expires_secs: u64) -> PyResult<()> {
    let (message, target_addr, transport) = build_in_dialog_subscribe(dialog, expires_secs).await?;
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state outbound unavailable: UAC sender not initialized",
        )
    })?;
    uac_sender.send_request(message, target_addr, transport);
    Ok(())
}

/// Send an in-dialog SUBSCRIBE and block until the peer responds.
/// Used by `refresh()` so the script learns about a non-2xx refresh
/// failure synchronously.
async fn send_in_dialog_subscribe_with_timeout(
    dialog: &SubscribeDialog,
    expires_secs: u64,
    timeout_ms: u64,
) -> PyResult<()> {
    let (message, target_addr, transport) = build_in_dialog_subscribe(dialog, expires_secs).await?;
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state refresh unavailable: UAC sender not initialized",
        )
    })?;
    let receiver = uac_sender.send_request_with_response(message, target_addr, transport);
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let result = tokio::time::timeout(timeout, receiver).await;
    match result {
        Ok(Ok(crate::uac::UacResult::Response(message))) => {
            let status = message.status_code().unwrap_or(0);
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "subscribe refresh got non-2xx response: {status}"
                )))
            }
        }
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe refresh timed out waiting for 2xx",
        )),
    }
}

/// Build a SUBSCRIBE message inside an established dialog. Used for
/// both refresh (`Expires: <new>`) and termination (`Expires: 0`).
async fn build_in_dialog_subscribe(
    dialog: &SubscribeDialog,
    expires_secs: u64,
) -> PyResult<(
    crate::sip::message::SipMessage,
    std::net::SocketAddr,
    Transport,
)> {
    let resolver = SEND_RESOLVER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state outbound unavailable: DNS resolver not initialized",
        )
    })?;

    // Same routing rules as send_notify() — first Route URI if present,
    // otherwise the remote target.
    let resolve_target: String = dialog
        .route_set
        .first()
        .map(|route| {
            route
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string()
        })
        .unwrap_or_else(|| dialog.remote_target.clone());

    let resolve_uri = parse_uri_standalone(&resolve_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid route/target URI '{resolve_target}': {error}"
        ))
    })?;
    let ruri = parse_uri_standalone(&dialog.remote_target).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "invalid remote_target URI '{}': {error}",
            dialog.remote_target
        ))
    })?;

    let transport_hint = resolve_uri
        .get_param("transport")
        .map(|s: &str| s.to_string());
    let resolver_clone = Arc::clone(resolver);
    let host = resolve_uri.host.clone();
    let port = resolve_uri.port;
    let scheme = resolve_uri.scheme.clone();

    let destination = resolver_clone
        .resolve(&host, port, scheme.as_str(), transport_hint.as_deref())
        .await;
    let target = destination.into_iter().next().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cannot resolve destination for '{resolve_target}'"
        ))
    })?;

    let transport = match target.transport.as_deref().or(transport_hint.as_deref()) {
        Some(hint) => match hint.to_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "ws" => Transport::WebSocket,
            "wss" => Transport::WebSocketSecure,
            "sctp" => Transport::Sctp,
            _ => Transport::Udp,
        },
        None => {
            if scheme == "sips" {
                Transport::Tls
            } else {
                Transport::Udp
            }
        }
    };

    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!("SIP/2.0/{} {};branch={}", transport, target.address, branch);
    let cseq_str = format!("{} SUBSCRIBE", dialog.cseq);

    // Outbound watcher orientation: From = us (subscriber), To = peer.
    let from_header = format!("<{}>;tag={}", dialog.local_uri, dialog.local_tag);
    let to_header = format!("<{}>;tag={}", dialog.remote_uri, dialog.remote_tag);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Subscribe, ruri)
        .via(via)
        .call_id(dialog.call_id.clone())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header)
        .to(to_header)
        .header("Event", dialog.event.clone())
        .header("Expires", expires_secs.to_string());

    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }
    builder = builder.content_length(0);

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build SUBSCRIBE: {error}"))
    })?;

    Ok((message, target.address, transport))
}

/// Build the outbound SUBSCRIBE message originated by
/// `proxy.subscribe_state.send()`.
///
/// Returns the built message, the CSeq value used, and the optional
/// caller-supplied From override (so the caller can record `local_uri`
/// from the override rather than the default R-URI).
///
/// Pulled out as a free function so it can be unit-tested without a UAC
/// sender / DNS resolver — the bug that motivated the extraction was the
/// missing default Contact (RFC 6665 §4.1.2.1) which left notifiers
/// without a dialog remote target and silently dropped every NOTIFY.
fn build_outbound_subscribe(
    ruri: &str,
    ruri_parsed: crate::sip::uri::SipUri,
    event: &str,
    expires: u64,
    accept: Option<&str>,
    target_uri: Option<&str>,
    transport: Transport,
    local_host: &str,
    local_port: u16,
    call_id: &str,
    local_tag: &str,
    extra_headers: &[(String, String)],
) -> PyResult<(crate::sip::message::SipMessage, u32, Option<String>)> {
    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    // Via sent-by is *our* advertised host:port so the notifier routes the
    // response back to us (RFC 3261 §18.2.1 / §20.42 — the sent-by may be an
    // FQDN), not to the destination or a loopback fallback.
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport, local_host, local_port, branch
    );
    let cseq_value: u32 = 1;
    let cseq_str = format!("{cseq_value} SUBSCRIBE");

    // From/To URIs:
    //   From = us (subscriber). We use the R-URI as a stand-in identity
    //          unless the script overrides via headers={"From": ...}.
    //   To   = the watched resource (R-URI bareform).
    let local_uri_default = strip_uri_params(ruri);
    let remote_uri_default = strip_uri_params(ruri);
    let from_header_default = format!("<{}>;tag={}", local_uri_default, local_tag);
    let to_header_default = format!("<{}>", remote_uri_default);

    // RFC 6665 §4.1.2.1: every SUBSCRIBE MUST contain a Contact.  Without
    // it, the notifier has no dialog remote target (RFC 3261 §12.1.1) and
    // any in-dialog NOTIFY it tries to send has nowhere to go.  Derive
    // the default from siphon's listen address for the chosen transport;
    // a caller-supplied ``headers={"Contact": ...}`` replaces this below.
    let contact_default = format_default_contact(local_host, local_port, transport);

    let mut builder = SipMessageBuilder::new()
        .request(Method::Subscribe, ruri_parsed)
        .via(via)
        .call_id(call_id.to_string())
        .cseq(cseq_str)
        .max_forwards(70)
        .from(from_header_default)
        .to(to_header_default)
        .header("Contact", contact_default)
        .header("Event", event.to_string())
        .header("Expires", expires.to_string());

    if let Some(accept_val) = accept {
        builder = builder.header("Accept", accept_val.to_string());
    }
    if let Some(loose_route) = target_uri {
        builder = builder.header("Route", format!("<{loose_route}>"));
    }

    // Apply caller-supplied extra headers.  Single-value headers (RFC 3261
    // §7.3.1) are *replaced* — without this, a script-supplied Contact
    // would stack on top of the default we just added, producing a dual-
    // Contact SUBSCRIBE that strict UAS impls truncate to the first
    // (auto-generated) value.  Same root cause as the dual-To bug fixed
    // in b1b2d55 / dual-Call-ID bug fixed in proxy_utils.
    let mut from_override: Option<String> = None;
    for (name, val) in extra_headers {
        if name.eq_ignore_ascii_case("from") {
            from_override = Some(val.clone());
            continue;
        }
        if is_single_value_header(name) {
            builder = builder.set_header(name, val.clone());
        } else {
            builder = builder.header(name, val.clone());
        }
    }
    if let Some(custom_from) = from_override.as_ref() {
        // From is single-value (RFC 3261 §7.3.1) — replace the default
        // we already wrote rather than appending alongside it.
        builder = builder.set_header("From", ensure_tag(custom_from, local_tag));
    }
    builder = builder.content_length(0);

    let message = builder.build().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build SUBSCRIBE: {error}"))
    })?;

    Ok((message, cseq_value, from_override))
}

/// Format a default Contact URI from a local socket address + transport.
///
/// Mirrors the `Via` host-port siphon already emits, with a transport
/// param appended for non-UDP (UDP is the default per RFC 3261 §19.1.1).
/// Used so the SUBSCRIBE we originate carries a routable Contact, which
/// becomes the dialog's remote target for the notifier (RFC 3261 §12.1.1
/// / RFC 6665 §4.1.2.1).
fn format_default_contact(host: &str, port: u16, transport: Transport) -> String {
    let transport_param = match transport {
        Transport::Udp => "",
        Transport::Tcp => ";transport=tcp",
        Transport::Tls => ";transport=tls",
        Transport::WebSocket => ";transport=ws",
        Transport::WebSocketSecure => ";transport=wss",
        Transport::Sctp => ";transport=sctp",
    };
    format!("<sip:{}:{}{}>", host, port, transport_param)
}

/// Return true for SIP headers that must appear at most once per RFC 3261
/// §7.3.1 — script-supplied values for these headers should *replace* the
/// builder's default rather than appending alongside it.  Multi-value
/// headers (Via, Route, Record-Route, P-Associated-URI, P-Asserted-Identity,
/// etc.) deliberately stay out of this list so callers can append.
fn is_single_value_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "contact"
            | "m"
            | "event"
            | "o"
            | "expires"
            | "accept"
            | "call-id"
            | "i"
            | "cseq"
            | "max-forwards"
            | "content-type"
            | "c"
            | "content-length"
            | "l"
            | "to"
            | "t"
            | "subject"
            | "s"
            | "user-agent"
            | "server"
            | "subscription-state"
    )
}

/// Strip parameters (`;param=val`) from a SIP URI string, returning
/// only the bare `scheme:user@host[:port]` portion. Used to derive a
/// stable identity URI for the From/To lines on an originated
/// SUBSCRIBE — refresh / terminate must use the *same* URI string the
/// peer's 200 OK echoed back.
fn strip_uri_params(uri: &str) -> String {
    let trimmed = uri.trim();
    match trimmed.find(';') {
        Some(idx) => trimmed[..idx].to_string(),
        None => trimmed.to_string(),
    }
}

/// Append `;tag=<tag>` to a name-addr value if it does not already
/// carry one. Used when the script supplies a `From` override that
/// already specifies a custom URI but should still carry our minted
/// dialog tag.
fn ensure_tag(value: &str, tag: &str) -> String {
    if extract_tag(value).is_some() {
        value.to_string()
    } else {
        format!("{};tag={}", value.trim(), tag)
    }
}

fn short_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pull ``tag=...`` from a From/To header value.
fn extract_tag(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let tag_start = lower.find(";tag=")?;
    let rest = &value[tag_start + 5..];
    let end = rest.find([';', '>']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Strip display-name and angle-brackets from a name-addr header value,
/// returning only the URI portion.  Falls back to the whole trimmed
/// value on parse failure.
pub(crate) fn strip_nameaddr(value: &str) -> String {
    let trimmed = value.trim();
    if let (Some(l), Some(r)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if l < r {
            return trimmed[l + 1..r].to_string();
        }
    }
    // No angle brackets — strip any trailing ;tag=… or other params.
    trimmed
        .split(';')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

impl PySubscribeState {
    /// The outbound SUBSCRIBE itself: resolve, send, await the 2xx, record the
    /// dialog. Awaitable because both the DNS lookup and the response wait are
    /// network waits an asyncio driver must not be held for.
    #[allow(clippy::too_many_arguments)]
    async fn send_inner(
        store: Arc<SubscribeStore>,
        ruri: &str,
        event: &str,
        expires: u64,
        accept: Option<&str>,
        target_uri: Option<&str>,
        extra_headers: Vec<(String, String)>,
        timeout_ms: u64,
    ) -> PyResult<PySubscribeHandle> {
        let uac_sender = UAC_SENDER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "subscribe_state.send() unavailable: UAC sender not initialized",
            )
        })?;
        let resolver = SEND_RESOLVER.get().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "subscribe_state.send() unavailable: DNS resolver not initialized",
            )
        })?;

        let ruri_parsed = parse_uri_standalone(ruri).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid request URI '{ruri}': {error}"
            ))
        })?;

        // Resolve the next-hop: explicit target_uri (pre-loaded Route)
        // wins, else the Request-URI.
        let resolve_target = target_uri.unwrap_or(ruri);
        let resolve_uri = parse_uri_standalone(resolve_target).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid target URI '{resolve_target}': {error}"
            ))
        })?;

        let transport_hint = resolve_uri
            .get_param("transport")
            .map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(resolver);
        let host = resolve_uri.host.clone();
        let port = resolve_uri.port;
        let scheme = resolve_uri.scheme.clone();

        let destination = resolver_clone
            .resolve(&host, port, scheme.as_str(), transport_hint.as_deref())
            .await;
        let target = destination.into_iter().next().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_target}'"
            ))
        })?;

        let transport = match target.transport.as_deref().or(transport_hint.as_deref()) {
            Some(hint) => match hint.to_lowercase().as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                "sctp" => Transport::Sctp,
                _ => Transport::Udp,
            },
            None => {
                if scheme == "sips" {
                    Transport::Tls
                } else {
                    Transport::Udp
                }
            }
        };

        // Mint dialog identity on our side.
        let call_id = format!("py-sub-{}", Uuid::new_v4());
        let local_tag = short_uuid();
        // Advertise our own reachable host (FQDN-aware) + listen port in the
        // Via/Contact so the notifier can route the response and any in-dialog
        // NOTIFY back to us; addr_for only supplies the port here.
        let local_host = uac_sender.via_host_for(&transport);
        let local_port = uac_sender.addr_for(&transport).port();
        let local_uri_default = strip_uri_params(ruri);

        // Pre-extract the script-supplied header dict into a Vec so the
        // builder can be assembled inside a non-Python helper that is unit
        // testable. The header pairs were read from Python by the caller.

        let (message, cseq_value, from_override) = build_outbound_subscribe(
            ruri,
            ruri_parsed,
            event,
            expires,
            accept,
            target_uri,
            transport,
            &local_host,
            local_port,
            &call_id,
            &local_tag,
            &extra_headers,
        )?;

        let receiver = uac_sender.send_request_with_response(message, target.address, transport);

        let timeout = std::time::Duration::from_millis(timeout_ms);
        let result = tokio::time::timeout(timeout, receiver).await;

        let response = match result {
            Ok(Ok(crate::uac::UacResult::Response(message))) => *message,
            Ok(Ok(crate::uac::UacResult::Timeout)) | Ok(Err(_)) | Err(_) => {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "subscribe_state.send() timed out waiting for 2xx",
                ));
            }
        };

        let status = response.status_code().unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "subscribe_state.send() got non-2xx response: {status}"
            )));
        }

        // Extract dialog state from the 2xx.
        let to_raw = response
            .headers
            .get("To")
            .or_else(|| response.headers.get("t"))
            .cloned()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("2xx missing To header"))?;
        let remote_tag = extract_tag(&to_raw).ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "2xx response To header missing tag — peer did not establish dialog",
            )
        })?;
        let remote_uri = strip_nameaddr(&to_raw);

        // Contact in 2xx is the notifier's remote target. Per RFC 3265,
        // it's mandatory for SUBSCRIBE 2xx; tolerate absence by falling
        // back to the original R-URI (some buggy peers omit it for
        // already-established dialogs).
        let remote_target = response
            .headers
            .get("Contact")
            .or_else(|| response.headers.get("m"))
            .map(|c| strip_nameaddr(c))
            .unwrap_or_else(|| local_uri_default.clone());

        // Reverse Record-Route per RFC 3261 §12.1.2 — we reverse here
        // because the same field on inbound dialogs is reversed at
        // create() time, so all storage holds Route in the order needed
        // for outgoing in-dialog traffic.
        let route_set: Vec<String> = response
            .headers
            .get_all("Record-Route")
            .map(|entries| entries.iter().rev().cloned().collect())
            .unwrap_or_default();

        let local_uri = match from_override.as_ref() {
            Some(val) => strip_nameaddr(val),
            None => local_uri_default,
        };

        let id = short_uuid();
        let dialog = SubscribeDialog {
            id: id.clone(),
            call_id,
            local_tag,
            remote_tag,
            local_uri,
            remote_uri,
            remote_target,
            received_address: None,
            received_transport: None,
            received_connection_id: None,
            route_set,
            event: event.to_string(),
            expires_secs: expires,
            created_at_unix: now_unix(),
            cseq: cseq_value,
            event_version: 0,
            terminated: false,
            is_outbound: true,
        };
        store.put(dialog);
        debug!(id, "subscribe_state: outbound dialog established");

        Ok(PySubscribeHandle { store, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn incoming<'py>(python: Python<'py>, tag: &str, expires: u64) -> Bound<'py, PyRequest> {
        let message = SipMessageBuilder::new()
            .request(
                Method::Subscribe,
                parse_uri_standalone("sip:201@example.com").unwrap(),
            )
            .via("SIP/2.0/TLS 192.0.2.20:5061;branch=z9hG4bK-test".into())
            .from("<sip:201@example.com>;tag=watcher".into())
            .to(format!("<sip:201@example.com>{tag}"))
            .call_id("subscription-test".into())
            .cseq("1 SUBSCRIBE".into())
            .header("Contact", "<sip:201@192.0.2.20:5061;transport=tls>".into())
            .header("Event", "message-summary".into())
            .header("Expires", expires.to_string())
            .content_length(0)
            .build()
            .unwrap();
        let mut request = PyRequest::new(
            Arc::new(std::sync::Mutex::new(message)),
            "tls".into(),
            "198.51.100.20".into(),
            43210,
        );
        request.set_inbound_flow("198.51.100.10:5061".parse().unwrap(), 42);
        Bound::new(python, request).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_refresh_keeps_dialog_identity_and_received_tls_destination() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(Arc::clone(&store));
            let request = incoming(python, "", 300);
            let handle = namespace.accept(&request, Some(300)).unwrap().unwrap();
            let initial = handle.load_local().unwrap();
            assert_eq!(
                initial.received_address.unwrap().to_string(),
                "198.51.100.20:43210"
            );
            assert_eq!(initial.received_transport.as_deref(), Some("tls"));
            assert_eq!(initial.received_connection_id, Some(42));
            assert!(initial.remote_target.contains("192.0.2.20"));
            let headers = request.borrow_mut().take_reply_headers();
            assert!(headers.iter().any(|(_, name, value)| name == "To"
                && value.ends_with(&format!(";tag={}", initial.local_tag))));
            store.update(&handle.id, |dialog| {
                dialog.cseq = 7;
                dialog.event_version = 4;
            });
            let refresh = incoming(python, &format!(";tag={}", initial.local_tag), 600);
            let refreshed = namespace.accept(&refresh, Some(600)).unwrap().unwrap();
            assert_eq!(refreshed.id, handle.id);
            let updated = refreshed.load_local().unwrap();
            assert_eq!(
                (updated.cseq, updated.event_version, updated.expires_secs),
                (7, 4, 600)
            );
            assert_eq!(store.local_count(), 1);
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_unknown_dialog_returns_481_without_allocating() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(Arc::clone(&store));
            let request = incoming(python, ";tag=unknown", 300);
            assert!(namespace.accept(&request, Some(300)).unwrap().is_none());
            assert!(matches!(
                request.borrow().action(),
                super::super::request::RequestAction::Reply { code: 481, .. }
            ));
            assert_eq!(store.local_count(), 0);
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_initial_zero_expiry_returns_handle_for_final_notify() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(store);
            let request = incoming(python, "", 0);
            let handle = namespace.accept(&request, Some(0)).unwrap().unwrap();
            assert_eq!(handle.load_local().unwrap().expires_secs, 0);
            assert!(request
                .borrow_mut()
                .take_reply_headers()
                .iter()
                .any(|(_, name, value)| name == "Expires" && value == "0"));
        });
    }

    /// The regression guard for the driver-pinning bug, and it works precisely
    /// because it is a plain `#[test]`: reading a property used to go through
    /// `detach_block_on`, whose `block_in_place` + `Handle::current()` panics
    /// with no tokio runtime in scope. So this test could not have been written
    /// before, and it fails the moment a property starts waiting on anything.
    #[test]
    fn handle_properties_read_without_a_tokio_runtime() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(Arc::clone(&store));
            let handle = namespace
                .create(&incoming(python, "", 300), Some(300))
                .unwrap();

            assert_eq!(handle.event().unwrap(), "message-summary");
            assert_eq!(handle.expires().unwrap(), 300);
            assert!(!handle.local_tag().unwrap().is_empty());
            assert_eq!(handle.event_version().unwrap(), 0);
            assert_eq!(handle.next_event_version().unwrap(), 1);
            assert_eq!(handle.event_version().unwrap(), 1);

            // Still a live read, not a snapshot taken at construction: a
            // refresh landing on the store is visible through the same handle.
            store.update(&handle.id, |dialog| dialog.refresh(600));
            assert_eq!(handle.expires().unwrap(), 600);
        });
    }

    /// Once the sweeper has reaped the dialog, every property raises
    /// `LookupError` rather than reaching the cache for a copy the sweeper has
    /// already sent the terminating NOTIFY for.
    #[test]
    fn handle_properties_raise_lookup_error_once_the_dialog_is_reaped() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(Arc::clone(&store));
            let handle = namespace
                .create(&incoming(python, "", 300), Some(300))
                .unwrap();

            store.update(&handle.id, |dialog| dialog.expires_secs = 0);
            assert_eq!(store.take_stale().len(), 1);

            for error in [
                handle.event().unwrap_err(),
                handle.expires().unwrap_err(),
                handle.local_tag().unwrap_err(),
                handle.event_version().unwrap_err(),
                handle.next_event_version().unwrap_err(),
            ] {
                assert!(
                    error.is_instance_of::<pyo3::exceptions::PyLookupError>(python),
                    "a reaped dialog must raise LookupError, got {error}"
                );
                assert!(error.to_string().contains(&handle.id));
            }
            // `id` is the handle's own state and keeps answering, which is what
            // lets a script log or re-`get()` the dialog it just lost.
            assert!(!handle.id().is_empty());
        });
    }

    /// `refresh` reads the dialog before it builds its coroutine, so it must
    /// raise the same way — and, like the properties, without a runtime.
    #[test]
    fn refresh_raises_lookup_error_for_a_reaped_dialog() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(Arc::clone(&store));
            let handle = namespace
                .create(&incoming(python, "", 300), Some(300))
                .unwrap();
            store.update(&handle.id, |dialog| dialog.is_outbound = true);

            // Live: the outbound check passes and it gets as far as needing a
            // loop, which is the awaitable contract every 1.10 API has.
            let error = handle.refresh(python, None, 2000).unwrap_err();
            assert!(error.to_string().contains("await"), "got {error}");

            store.remove(&handle.id);
            let error = handle.refresh(python, None, 2000).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyLookupError>(python));
        });
    }

    /// The L2-miss path: a dialog only the cache holds is invisible to the
    /// properties — no implicit fetch, so nothing to block on — and the
    /// documented recovery (`reload`, whose body is this `get`) restores them.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cache_only_dialog_raises_until_reload_hydrates_it() {
        Python::initialize();
        let cache_name = "subscribe_dialogs";
        let manager = Arc::new(crate::cache::CacheManager::new(&[
            crate::config::NamedCacheConfig {
                name: cache_name.to_string(),
                // Unreachable on purpose: the local LRU alone stands in for
                // the shared cache, the way `cache_tests.rs` does it.
                url: "redis://127.0.0.1:1".to_string(),
                local_ttl_secs: Some(60),
                local_max_entries: Some(16),
            },
        ]));

        // A dialog written by "another replica": it reaches the cache without
        // ever passing through this process's local store.
        let mut dialog = SubscribeDialog {
            id: "cache-only".to_string(),
            call_id: "c1".to_string(),
            local_tag: "ltag".to_string(),
            remote_tag: "rtag".to_string(),
            local_uri: "sip:mailbox@example.com".to_string(),
            remote_uri: "sip:201@example.com".to_string(),
            remote_target: "sip:201@192.0.2.20:5061".to_string(),
            received_address: None,
            received_transport: None,
            received_connection_id: None,
            route_set: Vec::new(),
            event: "message-summary".to_string(),
            expires_secs: 900,
            created_at_unix: now_unix(),
            cseq: 4,
            event_version: 2,
            terminated: false,
            is_outbound: false,
        };
        dialog.event_version = 2;
        let json = serde_json::to_string(&dialog).expect("serialize dialog");
        assert!(
            manager
                .store(cache_name, "subscribe_dialog:cache-only", &json, Some(900))
                .await
        );

        let store = Arc::new(
            SubscribeStore::new().with_cache(Arc::clone(&manager), cache_name.to_string()),
        );
        let handle = PySubscribeHandle {
            store: Arc::clone(&store),
            id: "cache-only".to_string(),
        };

        Python::attach(|python| {
            let error = handle.event().unwrap_err();
            assert!(
                error.is_instance_of::<pyo3::exceptions::PyLookupError>(python),
                "a cache-only dialog must not be fetched implicitly, got {error}"
            );
        });

        // What `reload()` awaits.
        assert!(store.get("cache-only").await.is_some());

        Python::attach(|_| {
            assert_eq!(handle.event().unwrap(), "message-summary");
            assert_eq!(handle.event_version().unwrap(), 2);
            assert!(handle.expires().unwrap() > 0);
        });
    }

    /// `reload` is awaitable, so from a synchronous handler it raises the error
    /// that names the fix rather than quietly returning a value.
    #[test]
    fn reload_without_a_running_loop_explains_the_await() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(store);
            let handle = namespace
                .create(&incoming(python, "", 300), Some(300))
                .unwrap();

            let error = handle.reload(python).unwrap_err();
            assert!(
                error.to_string().contains("await") && error.to_string().contains("async def"),
                "got {error}"
            );
        });
    }

    #[test]
    fn extract_tag_basic() {
        assert_eq!(
            extract_tag("<sip:alice@ex>;tag=abc;foo=1"),
            Some("abc".to_string())
        );
        assert_eq!(extract_tag("<sip:alice@ex>"), None);
    }

    #[test]
    fn strip_nameaddr_removes_brackets_and_display_name() {
        assert_eq!(
            strip_nameaddr("\"Alice\" <sip:alice@ex>;tag=abc"),
            "sip:alice@ex"
        );
        assert_eq!(strip_nameaddr("sip:alice@ex;tag=abc"), "sip:alice@ex");
    }

    /// Singleton-injection regression: with the singleton registered before
    /// `install_siphon_module()` runs, the resulting `siphon` module must
    /// expose a Rust-backed `proxy.subscribe_state` carrying the full method
    /// surface (`send`, `find`, `create`, `get`, `local_count`).
    ///
    /// This guards the startup-ordering bug where `_SubscribeStateStub` stayed
    /// bound to `proxy.subscribe_state` for embedded-bytecode apps because the
    /// singleton was being set *after* the script engine loaded.
    #[test]
    fn rust_namespace_replaces_stub_when_singleton_set_first() {
        Python::initialize();
        Python::attach(|python| {
            let store = Arc::new(SubscribeStore::new());
            let namespace = PySubscribeState::new(store);
            // Idempotent: if another test already populated the OnceLock
            // we still want to verify install_siphon_module's behaviour.
            let _ = crate::script::api::set_subscribe_state_singleton(python, namespace);

            crate::script::api::ensure_registry(python).expect("ensure registry");
            crate::script::api::install_siphon_module(python).expect("install siphon module");

            let script = r#"
import siphon
ns = siphon.proxy.subscribe_state
assert type(ns).__name__ != '_SubscribeStateStub', type(ns).__name__
for m in ('accept', 'create', 'get', 'send', 'find'):
    assert hasattr(ns, m), m
assert hasattr(ns, 'local_count'), 'local_count'
"#;
            let assertions = std::ffi::CString::new(script).expect("CString");
            python
                .run(assertions.as_c_str(), None, None)
                .expect("Rust subscribe_state namespace must replace the stub");
        });
    }

    /// Stub-API surface regression: without the Rust namespace, the
    /// `_SubscribeStateStub` must mirror the real method surface and raise a
    /// self-describing `NotImplementedError` for every method, not opaque
    /// `AttributeError`. Catches stub drift when methods are added to the
    /// Rust side without updating siphon_package.py.
    #[test]
    fn stub_methods_raise_self_describing_error() {
        Python::initialize();
        Python::attach(|python| {
            // Reach _SubscribeStateStub directly out of the package source —
            // independent of whether the OnceLock has been populated by other
            // tests (it likely has, in the parallel cargo test process).
            let source = include_str!("siphon_package.py");
            let module_globals = PyDict::new(python);
            python
                .run(
                    &std::ffi::CString::new(source).expect("CString"),
                    Some(&module_globals),
                    Some(&module_globals),
                )
                .expect("evaluate siphon_package.py");

            let script = r#"
stub = _SubscribeStateStub()
for m in ('create', 'get', 'send', 'find'):
    assert hasattr(stub, m), m
# local_count is a @property whose getter raises — check its presence on the class.
assert 'local_count' in dir(_SubscribeStateStub), 'local_count missing from stub'
try:
    stub.local_count
except NotImplementedError:
    pass
else:
    raise AssertionError('stub.local_count did not raise')
try:
    stub.send('sip:x', 'reg', 60)
except NotImplementedError as e:
    msg = str(e)
    assert 'subscribe_state' in msg and 'singleton' in msg, msg
except AttributeError as e:
    raise AssertionError('stub raised AttributeError instead of NotImplementedError: ' + str(e))
else:
    raise AssertionError('stub.send() did not raise')
try:
    stub.find('cid', 'lt', 'rt')
except NotImplementedError:
    pass
else:
    raise AssertionError('stub.find() did not raise')
"#;
            let assertions = std::ffi::CString::new(script).expect("CString");
            python
                .run(
                    assertions.as_c_str(),
                    Some(&module_globals),
                    Some(&module_globals),
                )
                .expect("stub surface assertions");
        });
    }

    fn parse_ruri(ruri: &str) -> crate::sip::uri::SipUri {
        parse_uri_standalone(ruri).expect("parse ruri")
    }

    fn local_host() -> &'static str {
        "172.30.0.46"
    }

    fn local_port() -> u16 {
        5070
    }

    fn collect_header<'a>(
        message: &'a crate::sip::message::SipMessage,
        name: &str,
    ) -> Vec<&'a str> {
        message
            .headers
            .get_all(name)
            .map(|values| values.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// RFC 6665 §4.1.2.1 regression: every SUBSCRIBE built by
    /// `subscribe_state.send()` MUST carry exactly one Contact, derived from
    /// siphon's own listen address. Without it, the notifier has no dialog
    /// remote target (RFC 3261 §12.1.1) and every NOTIFY is silently dropped.
    #[test]
    fn outbound_subscribe_carries_default_contact() {
        let ruri = "sip:alice@ims.example.org";
        let (message, _cseq, _from) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "reg",
            7200,
            Some("application/reginfo+xml"),
            None,
            Transport::Udp,
            local_host(),
            local_port(),
            "py-sub-test",
            "local-tag-1",
            &[],
        )
        .expect("build SUBSCRIBE");

        let contacts = collect_header(&message, "Contact");
        assert_eq!(
            contacts.len(),
            1,
            "default Contact must be present exactly once, got {contacts:?}"
        );
        assert_eq!(
            contacts[0], "<sip:172.30.0.46:5070>",
            "default Contact must carry siphon's listen address (transport-param omitted for UDP)"
        );

        // Wire-level sanity: the Contact line is on the wire.
        let wire = String::from_utf8(message.to_bytes()).unwrap();
        assert!(
            wire.contains("Contact: <sip:172.30.0.46:5070>"),
            "wire output must include the default Contact line:\n{wire}"
        );
    }

    /// Non-UDP transports must surface `;transport=<proto>` in the Contact so
    /// the notifier can route in-dialog NOTIFYs back over the same transport
    /// (RFC 3261 §19.1.1 — UDP is the default, others must be explicit).
    #[test]
    fn outbound_subscribe_contact_has_transport_param_for_tcp() {
        let ruri = "sip:bob@example.com";
        let (message, _, _) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "presence",
            3600,
            None,
            None,
            Transport::Tcp,
            local_host(),
            local_port(),
            "py-sub-tcp",
            "local-tag-tcp",
            &[],
        )
        .expect("build SUBSCRIBE");

        let contacts = collect_header(&message, "Contact");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0], "<sip:172.30.0.46:5070;transport=tcp>");
    }

    /// Caller-supplied `headers={"Contact": "..."}` MUST replace the default,
    /// not append.  Two Contacts is a dual-Contact bug — strict UAS impls
    /// truncate to the first (auto-generated) value, breaking the override.
    #[test]
    fn outbound_subscribe_user_contact_replaces_default() {
        let ruri = "sip:alice@ims.example.org";
        let extra = vec![(
            "Contact".to_string(),
            "<sip:ipsmgw@ipsmgw.example.com:6060>".to_string(),
        )];
        let (message, _, _) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "reg",
            3600,
            None,
            None,
            Transport::Udp,
            local_host(),
            local_port(),
            "py-sub-override",
            "local-tag-2",
            &extra,
        )
        .expect("build SUBSCRIBE");

        let contacts = collect_header(&message, "Contact");
        assert_eq!(
            contacts.len(),
            1,
            "user Contact must replace the default, got {contacts:?}"
        );
        assert_eq!(contacts[0], "<sip:ipsmgw@ipsmgw.example.com:6060>");

        // No stale default Contact leaks onto the wire. Match the Contact
        // form specifically (`<sip:host:port>`), not the bare host:port —
        // the latter now legitimately appears in the Via sent-by (our own
        // advertised address), which is a different header.
        let wire = String::from_utf8(message.to_bytes()).unwrap();
        assert!(
            !wire.contains("<sip:172.30.0.46:5070"),
            "default Contact leaked alongside user override:\n{wire}"
        );
    }

    /// The other single-value SUBSCRIBE headers (Event, Expires, Accept) MUST
    /// also use replace semantics when the script supplies them — otherwise
    /// the kwarg dict stacks on top of the builder defaults and produces
    /// duplicates that strict UAS impls reject.
    #[test]
    fn outbound_subscribe_user_event_and_expires_replace_default() {
        let ruri = "sip:alice@ims.example.org";
        let extra = vec![
            ("Event".to_string(), "presence".to_string()),
            ("Expires".to_string(), "1800".to_string()),
            ("Accept".to_string(), "application/pidf+xml".to_string()),
        ];
        let (message, _, _) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            // Built-in defaults — should be overridden by extra_headers.
            "reg",
            7200,
            Some("application/reginfo+xml"),
            None,
            Transport::Udp,
            local_host(),
            local_port(),
            "py-sub-event",
            "local-tag-3",
            &extra,
        )
        .expect("build SUBSCRIBE");

        let events = collect_header(&message, "Event");
        assert_eq!(events, vec!["presence"], "Event must be replaced");
        let expires = collect_header(&message, "Expires");
        assert_eq!(expires, vec!["1800"], "Expires must be replaced");
        let accepts = collect_header(&message, "Accept");
        assert_eq!(
            accepts,
            vec!["application/pidf+xml"],
            "Accept must be replaced"
        );
    }

    /// Multi-value headers (Route, Record-Route, Via, P-Associated-URI, etc.)
    /// must NOT be collapsed to set-semantics — the kwarg loop appends them.
    /// Verified here for `Route`, since IMS scripts often add an additional
    /// Route alongside the `target_uri=` pre-loaded route.
    #[test]
    fn outbound_subscribe_multivalue_headers_append() {
        let ruri = "sip:alice@ims.example.org";
        let extra = vec![
            (
                "Route".to_string(),
                "<sip:second-route@bgcf.example.org;lr>".to_string(),
            ),
            (
                "P-Associated-URI".to_string(),
                "<sip:alice2@ims.example.org>".to_string(),
            ),
            (
                "P-Associated-URI".to_string(),
                "<tel:+15551234>".to_string(),
            ),
        ];
        let (message, _, _) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "reg",
            3600,
            None,
            Some("sip:scscf.example.org;lr"),
            Transport::Udp,
            local_host(),
            local_port(),
            "py-sub-multi",
            "local-tag-4",
            &extra,
        )
        .expect("build SUBSCRIBE");

        let routes = collect_header(&message, "Route");
        assert_eq!(
            routes.len(),
            2,
            "Route must be multi-value (target_uri + script-supplied), got {routes:?}"
        );
        assert_eq!(routes[0], "<sip:scscf.example.org;lr>");
        assert_eq!(routes[1], "<sip:second-route@bgcf.example.org;lr>");
    }

    /// Caller-supplied `From` overrides the R-URI-based default and the
    /// returned `from_override` reflects it (used by the caller to record
    /// `local_uri` correctly on the dialog).
    #[test]
    fn outbound_subscribe_from_override_returned() {
        let ruri = "sip:alice@ims.example.org";
        let extra = vec![(
            "From".to_string(),
            "<sip:scscf-0.example.org:6060>".to_string(),
        )];
        let (message, _, from_override) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "reg",
            3600,
            None,
            None,
            Transport::Udp,
            local_host(),
            local_port(),
            "py-sub-from",
            "local-tag-5",
            &extra,
        )
        .expect("build SUBSCRIBE");

        assert_eq!(
            from_override.as_deref(),
            Some("<sip:scscf-0.example.org:6060>")
        );
        let froms = collect_header(&message, "From");
        assert_eq!(froms.len(), 1, "From must be unique, got {froms:?}");
        assert!(
            froms[0].contains(";tag=local-tag-5"),
            "user From must carry the dialog tag, got {}",
            froms[0]
        );
    }

    /// `format_default_contact` produces the correct shape for every
    /// supported transport — the transport param is omitted only for UDP.
    #[test]
    fn format_default_contact_per_transport() {
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::Udp),
            "<sip:192.0.2.10:5070>"
        );
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::Tcp),
            "<sip:192.0.2.10:5070;transport=tcp>"
        );
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::Tls),
            "<sip:192.0.2.10:5070;transport=tls>"
        );
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::WebSocket),
            "<sip:192.0.2.10:5070;transport=ws>"
        );
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::WebSocketSecure),
            "<sip:192.0.2.10:5070;transport=wss>"
        );
        assert_eq!(
            format_default_contact("192.0.2.10", 5070, Transport::Sctp),
            "<sip:192.0.2.10:5070;transport=sctp>"
        );
    }

    /// An FQDN `advertised_address` is carried verbatim into the SUBSCRIBE
    /// Via sent-by and default Contact — the notifier must be able to reach
    /// us for the response and any in-dialog NOTIFY (RFC 6665 §4.1.2.1).
    #[test]
    fn build_outbound_subscribe_advertises_fqdn_host() {
        let ruri = "sip:alice@ims.example.org";
        let (message, _cseq, _from) = build_outbound_subscribe(
            ruri,
            parse_ruri(ruri),
            "reg",
            3600,
            None,
            None,
            Transport::Udp,
            "sbc.example.org",
            5060,
            "py-sub-fqdn",
            "local-tag-fqdn",
            &[],
        )
        .expect("build SUBSCRIBE");

        let vias = collect_header(&message, "Via");
        assert_eq!(vias.len(), 1, "one Via expected, got {vias:?}");
        assert!(
            vias[0].contains("sbc.example.org:5060"),
            "Via sent-by must be our advertised FQDN:port, got {}",
            vias[0]
        );
        let contacts = collect_header(&message, "Contact");
        assert_eq!(contacts.len(), 1, "one Contact expected, got {contacts:?}");
        assert_eq!(contacts[0], "<sip:sbc.example.org:5060>");
    }
}
