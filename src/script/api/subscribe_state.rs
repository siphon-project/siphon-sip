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
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Call-ID")
            })?;

        let from_raw = message
            .headers
            .get("From")
            .or_else(|| message.headers.get("f"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing From")
            })?;
        let to_raw = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing To")
            })?;

        let contact_raw = message
            .headers
            .get("Contact")
            .or_else(|| message.headers.get("m"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("SUBSCRIBE missing Contact")
            })?;

        let event = message
            .headers
            .get("Event")
            .or_else(|| message.headers.get("o"))
            .cloned()
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "SUBSCRIBE missing Event header",
                )
            })?;

        let remote_tag = extract_tag(&from_raw).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("SUBSCRIBE From has no tag")
        })?;

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
    fn get(&self, id: &str) -> PyResult<Option<PySubscribeHandle>> {
        let store = Arc::clone(&self.store);
        let id_owned = id.to_string();
        let found = crate::script::detach_block_on(store.get(&id_owned));
        Ok(found.map(|dialog| PySubscribeHandle {
            store: Arc::clone(&self.store),
            id: dialog.id,
        }))
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
    fn send(
        &self,
        ruri: &str,
        event: &str,
        expires: u64,
        accept: Option<&str>,
        target_uri: Option<&str>,
        headers: Option<&Bound<'_, pyo3::types::PyDict>>,
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

        let transport_hint = resolve_uri.get_param("transport").map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(resolver);
        let host = resolve_uri.host.clone();
        let port = resolve_uri.port;
        let scheme = resolve_uri.scheme.clone();

        let destination = crate::script::detach_block_on(resolver_clone.resolve(
            &host,
            port,
            &scheme,
            transport_hint.as_deref(),
        ));
        let target = destination.into_iter().next().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cannot resolve destination for '{resolve_target}'"
            ))
        })?;

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
        // testable.
        let mut extra_headers: Vec<(String, String)> = Vec::new();
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
                extra_headers.push((name, val));
            }
        }

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

        let receiver = uac_sender.send_request_with_response(
            message,
            target.address,
            transport,
        );

        let timeout = std::time::Duration::from_millis(timeout_ms);
        let result = crate::script::detach_block_on(async {
            tokio::time::timeout(timeout, receiver).await
        });

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
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("2xx missing To header")
            })?;
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
            route_set,
            event: event.to_string(),
            expires_secs: expires,
            created_at_unix: now_unix(),
            cseq: cseq_value,
            event_version: 0,
            terminated: false,
            is_outbound: true,
        };
        self.store.put(dialog);
        debug!(id, "subscribe_state: outbound dialog established");

        Ok(PySubscribeHandle {
            store: Arc::clone(&self.store),
            id,
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
    fn find(
        &self,
        call_id: &str,
        local_tag: &str,
        remote_tag: &str,
    ) -> Option<PySubscribeHandle> {
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

    /// The SIP Event package (copied from the SUBSCRIBE).
    #[getter]
    fn event(&self) -> PyResult<String> {
        let dialog = self.load_sync()?;
        Ok(dialog.event)
    }

    /// Seconds remaining until the dialog expires.
    #[getter]
    fn expires(&self) -> PyResult<u64> {
        let dialog = self.load_sync()?;
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
        let dialog = self.load_sync()?;
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
    /// handle.notify(body=body, content_type="application/reginfo+xml")
    /// ```
    fn next_event_version(&self) -> PyResult<u32> {
        // Hydrate L1 in case we're on a different worker than the creator.
        let _ = self.load_sync()?;
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
    fn notify(
        &self,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
        state: Option<&str>,
    ) -> PyResult<bool> {
        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return Ok(false),
        };

        let body_bytes = match body {
            Some(obj) => Some(super::request::extract_body_bytes(obj)?),
            None => None,
        };

        let subscription_state = state
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("active;expires={}", dialog.remaining_secs()));

        send_notify(&dialog, &subscription_state, content_type, body_bytes.as_deref())?;
        Ok(true)
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
    fn terminate(
        &self,
        reason: Option<&str>,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
    ) -> PyResult<bool> {
        let dialog = match self.bump_cseq()? {
            Some(dialog) => dialog,
            None => return Ok(false),
        };

        if dialog.is_outbound {
            // Watcher role — terminate by sending SUBSCRIBE Expires:0.
            send_in_dialog_subscribe(&dialog, 0)?;
        } else {
            // Notifier role — send the final NOTIFY.
            let reason_str = reason.unwrap_or("noresource");
            let subscription_state = format!("terminated;reason={reason_str}");
            let body_bytes = match body {
                Some(obj) => Some(super::request::extract_body_bytes(obj)?),
                None => None,
            };
            send_notify(&dialog, &subscription_state, content_type, body_bytes.as_deref())?;
        }

        // Mark terminated + remove.  Mark-then-remove gives a brief
        // window where get() returns None even if the cache still has
        // the entry (race-safe for cross-instance lookups).
        self.store.update(&self.id, |dialog| dialog.terminated = true);
        self.store.remove(&self.id);
        Ok(true)
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
    fn refresh(&self, expires: Option<u64>, timeout_ms: u64) -> PyResult<bool> {
        let dialog = self.load_sync()?;
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

        send_in_dialog_subscribe_with_timeout(&bumped, new_expires, timeout_ms)?;

        // Commit the new expiry anchor.
        self.store.update(&self.id, |dialog| {
            dialog.refresh(new_expires);
        });
        Ok(true)
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
    fn load_sync(&self) -> PyResult<SubscribeDialog> {
        let store = Arc::clone(&self.store);
        let id = self.id.clone();
        let found = crate::script::detach_block_on(store.get(&id));
        found.ok_or_else(|| {
            pyo3::exceptions::PyLookupError::new_err(format!(
                "subscribe_state dialog '{}' not found",
                self.id
            ))
        })
    }

    /// Increment CSeq and return the updated dialog snapshot, or
    /// ``None`` if the dialog has disappeared.
    fn bump_cseq(&self) -> PyResult<Option<SubscribeDialog>> {
        // Ensure L1 is hydrated (cross-replica case).
        let _ = self.load_sync()?;
        let updated = self.store.update(&self.id, |dialog| {
            dialog.next_cseq();
        });
        Ok(updated)
    }
}

// ---------------------------------------------------------------------------
// Wire helpers — borrowed from proxy_utils / presence patterns
// ---------------------------------------------------------------------------

fn send_notify(
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
    let resolve_target: String = dialog
        .route_set
        .first()
        .map(|route| route.trim().trim_start_matches('<').trim_end_matches('>').to_string())
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

    let transport_hint = resolve_uri.get_param("transport").map(|s: &str| s.to_string());
    let resolver_clone = Arc::clone(resolver);
    let host = resolve_uri.host.clone();
    let port = resolve_uri.port;
    let scheme = resolve_uri.scheme.clone();

    let destination = crate::script::detach_block_on(resolver_clone.resolve(
        &host,
        port,
        &scheme,
        transport_hint.as_deref(),
    ));

    let target = destination.into_iter().next().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cannot resolve destination for '{resolve_target}'"
        ))
    })?;

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

    let branch = format!("z9hG4bK-uac-py-{}", Uuid::new_v4());
    let via = format!("SIP/2.0/{} {};branch={}", transport, target.address, branch);
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
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to build NOTIFY: {error}"
        ))
    })?;

    // If called from inside a request handler, the dispatcher may defer
    // until after the SUBSCRIBE reply is sent (RFC 6665 §4.1).
    if !super::proxy_utils::try_defer_send(message.clone(), target.address, transport) {
        uac_sender.send_request(message, target.address, transport);
    }
    debug!(id = %dialog.id, "subscribe_state: NOTIFY sent");
    Ok(())
}

/// Send an in-dialog SUBSCRIBE (refresh or Expires:0 termination)
/// without waiting for a response. Used by `terminate()` on outbound
/// dialogs — the response carries no information we need.
fn send_in_dialog_subscribe(dialog: &SubscribeDialog, expires_secs: u64) -> PyResult<()> {
    let (message, target_addr, transport) = build_in_dialog_subscribe(dialog, expires_secs)?;
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
fn send_in_dialog_subscribe_with_timeout(
    dialog: &SubscribeDialog,
    expires_secs: u64,
    timeout_ms: u64,
) -> PyResult<()> {
    let (message, target_addr, transport) = build_in_dialog_subscribe(dialog, expires_secs)?;
    let uac_sender = UAC_SENDER.get().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "subscribe_state refresh unavailable: UAC sender not initialized",
        )
    })?;
    let receiver = uac_sender.send_request_with_response(message, target_addr, transport);
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let result = crate::script::detach_block_on(async {
        tokio::time::timeout(timeout, receiver).await
    });
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
fn build_in_dialog_subscribe(
    dialog: &SubscribeDialog,
    expires_secs: u64,
) -> PyResult<(crate::sip::message::SipMessage, std::net::SocketAddr, Transport)> {
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
        .map(|route| route.trim().trim_start_matches('<').trim_end_matches('>').to_string())
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

    let transport_hint = resolve_uri.get_param("transport").map(|s: &str| s.to_string());
    let resolver_clone = Arc::clone(resolver);
    let host = resolve_uri.host.clone();
    let port = resolve_uri.port;
    let scheme = resolve_uri.scheme.clone();

    let destination = crate::script::detach_block_on(resolver_clone.resolve(
        &host,
        port,
        &scheme,
        transport_hint.as_deref(),
    ));
    let target = destination.into_iter().next().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cannot resolve destination for '{resolve_target}'"
        ))
    })?;

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
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to build SUBSCRIBE: {error}"
        ))
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
    let via = format!("SIP/2.0/{} {}:{};branch={}", transport, local_host, local_port, branch);
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
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to build SUBSCRIBE: {error}"
        ))
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
fn strip_nameaddr(value: &str) -> String {
    let trimmed = value.trim();
    if let (Some(l), Some(r)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if l < r {
            return trimmed[l + 1..r].to_string();
        }
    }
    // No angle brackets — strip any trailing ;tag=… or other params.
    trimmed.split(';').next().unwrap_or(trimmed).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

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
for m in ('create', 'get', 'send', 'find'):
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
                .run(assertions.as_c_str(), Some(&module_globals), Some(&module_globals))
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

    fn collect_header<'a>(message: &'a crate::sip::message::SipMessage, name: &str) -> Vec<&'a str> {
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
