//! Python API for the SIP Presence subsystem.
//!
//! Scripts use:
//! ```python
//! from siphon import presence
//!
//! presence.publish("sip:alice@example.com", pidf_xml, expires=3600)
//! doc = presence.lookup("sip:alice@example.com")
//!
//! sub_id = presence.subscribe("sip:bob@example.com", "sip:alice@example.com",
//!                              event="presence", expires=3600)
//! presence.unsubscribe(sub_id)
//!
//! for watcher in presence.subscribers("sip:alice@example.com"):
//!     log.info(f"watcher: {watcher['subscriber']}")
//!
//! presence.notify("sip:bob@example.com", body=xml, content_type="application/reginfo+xml",
//!                 subscription_state="active", event="reg")
//!
//! # Close out a subscription (final NOTIFY + remove from store) per RFC 6665 §4.4.1:
//! presence.terminate(sub_id, reason="timeout")
//! ```

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::dns::SipResolver;
use crate::presence::{notify_failure, NotifyDialogState, PresenceStore, Subscription};
use crate::script::api::subscribe_state::strip_nameaddr;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::transport::{ConnectionId, Transport};
use crate::uac::{UacResult, UacSender};

/// Returns true if the given Subscription-State header value indicates a
/// terminated subscription per RFC 6665 §4.1.3.  Matches both the bare
/// ``terminated`` token and ``terminated;reason=...`` forms; tolerates
/// leading whitespace.
fn is_terminated_subscription_state(subscription_state: &str) -> bool {
    let trimmed = subscription_state.trim_start();
    if let Some(rest) = trimmed.strip_prefix("terminated") {
        rest.is_empty() || rest.starts_with(';') || rest.starts_with(char::is_whitespace)
    } else {
        false
    }
}

/// Python-visible presence namespace.
#[pyclass(name = "PresenceNamespace", skip_from_py_object)]
pub struct PyPresence {
    store: Arc<PresenceStore>,
}

impl PyPresence {
    pub fn new(store: Arc<PresenceStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PyPresence {
    /// Publish a presence document for a presentity.
    ///
    /// Creates a new PIDF document (application/pidf+xml) for the given entity.
    /// Returns the etag assigned to the document, which can be used for
    /// conditional updates.
    ///
    /// Args:
    ///     entity: Presentity URI (e.g. "sip:alice@example.com").
    ///     pidf_xml: PIDF XML body string.
    ///     expires: Document expiry in seconds (default: 3600).
    ///
    /// Returns:
    ///     The etag string assigned to the published document.
    #[pyo3(signature = (entity, pidf_xml, expires=3600))]
    fn publish(&self, entity: &str, pidf_xml: &str, expires: u64) -> String {
        self.store.publish(
            entity,
            "application/pidf+xml".to_string(),
            pidf_xml.to_string(),
            None,
            Duration::from_secs(expires),
        )
    }

    /// Look up the current presence document for a URI.
    ///
    /// Returns the PIDF XML body of the latest non-expired document,
    /// or None if no document exists for the entity.
    ///
    /// Args:
    ///     entity: Presentity URI to look up.
    ///
    /// Returns:
    ///     PIDF XML string, or None if not found.
    fn lookup(&self, entity: &str) -> Option<String> {
        self.store
            .get_presence(entity)
            .map(|document| document.body)
    }

    /// Subscribe to presence for a resource.
    ///
    /// Creates a new subscription in the presence store and returns the
    /// subscription ID. The subscription starts in Init state.
    ///
    /// Args:
    ///     subscriber: Watcher URI (e.g. "sip:bob@example.com").
    ///     resource: Presentity URI to watch (e.g. "sip:alice@example.com").
    ///     event: Event package name (default: "presence").
    ///     expires: Subscription duration in seconds (default: 3600).
    ///
    /// Returns:
    ///     Subscription ID string.
    #[pyo3(signature = (subscriber, resource, event="presence", expires=3600))]
    fn subscribe(&self, subscriber: &str, resource: &str, event: &str, expires: u64) -> String {
        let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
        let subscription = Subscription::new(
            subscription_id.clone(),
            subscriber.to_string(),
            resource.to_string(),
            event.to_string(),
            Duration::from_secs(expires),
            None,
            vec!["application/pidf+xml".to_string()],
        );
        self.store.add_subscription(subscription);
        subscription_id
    }

    /// Create a subscription with full dialog state from a SUBSCRIBE request.
    ///
    /// Stores the dialog's Call-ID, From/To tags, and Route set so that
    /// ``notify()`` can send in-dialog NOTIFYs per RFC 3265 §3.2.2.
    ///
    /// Args:
    ///     subscriber: Watcher **Contact** URI from the SUBSCRIBE — the dialog's
    ///         remote target.  Used for the NOTIFY's Request-URI and to resolve
    ///         where to send it; it is *not* what goes in ``To`` (see
    ///         ``remote_uri``).
    ///     resource: Presentity URI being watched.
    ///     event: Event package name (e.g. ``"reg"``).
    ///     expires: Subscription duration in seconds.
    ///     call_id: Call-ID from the SUBSCRIBE dialog.
    ///     from_tag: From-tag from the SUBSCRIBE (subscriber's tag).
    ///     to_tag: To-tag from the SUBSCRIBE (notifier's tag, set by S-CSCF).
    ///     route_set: Route headers from Record-Route of the SUBSCRIBE dialog.
    ///     local_uri: The SUBSCRIBE's **To URI** — the dialog's local URI, which
    ///         RFC 3261 §12.2.1.1 requires in the ``From`` of every in-dialog
    ///         NOTIFY.  Pass ``str(request.to_uri)``.
    ///     remote_uri: The SUBSCRIBE's **From URI** — the dialog's remote URI,
    ///         required in the ``To``.  Pass ``str(request.from_uri)``.
    ///     local_cseq: The CSeq number the dialog's last NOTIFY had; the next
    ///         one carries one more.  ``0`` (the default) for a new dialog.
    ///         A dialog rebuilt from stored state (IMS restoration, TS 23.380
    ///         §4.6.3, which keeps no CSeq) starts high enough for the
    ///         subscriber to accept its next NOTIFY (RFC 3261 §12.2.2).
    ///     version: The version the dialog's next event-state document
    ///         carries (RFC 3680 §5.2), handed out by :meth:`next_version`.
    ///         ``0`` (the default) for a new subscription.  Restoration keeps
    ///         no version either (TS 29.229 Subscription-Info holds the
    ///         Call-ID, From, To, Record-Route and Contact only), so a rebuilt
    ///         dialog passes one above any it could have sent, as it does for
    ///         ``local_cseq``: a subscriber that sees a version more than one
    ///         higher than its own takes it, processes the document, and
    ///         SHOULD refresh for full state.
    ///
    /// Both URI arguments default to ``resource`` when omitted, which is
    /// correct for any package where the subscriber watches an AoR directly
    /// (the reg event package, TS 24.341 §5.3.2.4).  Supply them explicitly for
    /// a watcher subscribed to somebody else's resource, where the remote URI
    /// is the watcher's own AoR and cannot be derived here.
    ///
    /// Returns:
    ///     Subscription ID string.
    #[pyo3(signature = (subscriber, resource, event, expires, call_id, from_tag, to_tag, route_set=None, local_uri=None, remote_uri=None, local_cseq=0, version=0))]
    #[allow(clippy::too_many_arguments)]
    fn subscribe_dialog(
        &self,
        subscriber: &str,
        resource: &str,
        event: &str,
        expires: u64,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        route_set: Option<Vec<String>>,
        local_uri: Option<String>,
        remote_uri: Option<String>,
        local_cseq: u32,
        version: u32,
    ) -> PyResult<String> {
        // Each NOTIFY carries these as its `Route`, which takes `name-addr`
        // values (RFC 3261 §20.34): one per entry, whatever form it came in.
        let route_set = super::route_entries::route_set_from(&route_set.unwrap_or_default())?;
        let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
        let mut subscription = Subscription::with_dialog(
            subscription_id.clone(),
            subscriber.to_string(),
            resource.to_string(),
            event.to_string(),
            Duration::from_secs(expires),
            vec![],
            call_id.to_string(),
            from_tag.to_string(),
            to_tag.to_string(),
            route_set,
            local_uri.map(|uri| strip_nameaddr(&uri)),
            remote_uri.map(|uri| strip_nameaddr(&uri)),
        );
        subscription.local_cseq = local_cseq;
        subscription.next_version = version;
        self.store.add_subscription(subscription);
        Ok(subscription_id)
    }

    /// Unsubscribe by subscription ID.
    ///
    /// Removes the subscription from the store entirely.
    ///
    /// Args:
    ///     subscription_id: The subscription ID returned by subscribe().
    ///
    /// Returns:
    ///     True if the subscription was found and removed, False otherwise.
    fn unsubscribe(&self, subscription_id: &str) -> bool {
        let exists = self.store.get_subscription(subscription_id).is_some();
        if exists {
            self.store.remove_subscription(subscription_id);
        }
        exists
    }

    /// Refresh a subscription's expiry (RFC 6665 §4.4.1 in-dialog re-SUBSCRIBE).
    ///
    /// Resets the subscription's timer to `expires` seconds from now, keeping the
    /// same dialog. Pair with [`find_by_dialog`] to resolve the id from an
    /// in-dialog SUBSCRIBE before refreshing.
    ///
    /// Args:
    ///     subscription_id: The subscription ID (from ``subscribe*`` or
    ///         ``find_by_dialog``).
    ///     expires: New subscription duration in seconds.
    ///
    /// Returns:
    ///     True if the subscription was found and refreshed, False otherwise
    ///     (unknown id, or the subscription is already terminated).
    fn refresh(&self, subscription_id: &str, expires: u64) -> bool {
        self.store
            .refresh_subscription(subscription_id, Duration::from_secs(expires))
    }

    /// Resolve a subscription id from its dialog `(Call-ID, From-tag)`.
    ///
    /// An in-dialog SUBSCRIBE — a refresh, or an un-SUBSCRIBE with ``Expires: 0`` —
    /// arrives with the dialog's Call-ID and the subscriber's From-tag but not the
    /// original subscription id. This maps that pair back to the id so a notifier
    /// (e.g. an S-CSCF handling reg-event) can ``refresh()`` or ``unsubscribe()``
    /// the right dialog. Only a subscription created with dialog state
    /// (``subscribe_dialog``) is findable; terminated ones are skipped.
    ///
    /// Args:
    ///     call_id: Call-ID of the in-dialog SUBSCRIBE.
    ///     from_tag: From-tag of the in-dialog SUBSCRIBE (subscriber's tag).
    ///
    /// Returns:
    ///     The subscription ID string, or None if no live dialog matches.
    fn find_by_dialog(&self, call_id: &str, from_tag: &str) -> Option<String> {
        self.store.find_subscription_by_dialog(call_id, from_tag)
    }

    /// The version for the next event-state document sent on a subscription,
    /// advancing its count (RFC 3680 §5.2: "Versions start at 0, and
    /// increment by one for each new document sent to a subscriber.  Versions
    /// are scoped within a subscription.").
    ///
    /// The store owns one count per subscription, so every NOTIFY a script
    /// builds a reginfo body for takes the next one:
    ///
    /// ```python
    /// body = registrar.reginfo_xml(aor, state="partial",
    ///                              version=presence.next_version(sub_id))
    /// await presence.notify(sub_id, body=body,
    ///                       content_type="application/reginfo+xml")
    /// ```
    ///
    /// Take the version only for a document that is sent: each call advances
    /// the count, and a version the subscriber never sees reads to it as a
    /// gap (it then asks for full state).
    ///
    /// Args:
    ///     subscription_id: The subscription ID.
    ///
    /// Returns:
    ///     The version (``int``, 0 for the first document), or ``None`` for an
    ///     unknown subscription.  A removed subscription's count goes with it.
    fn next_version(&self, subscription_id: &str) -> Option<u32> {
        self.store.next_version(subscription_id)
    }

    /// List subscribers (watchers) for a resource.
    ///
    /// Returns active, non-expired subscriptions for the given resource URI.
    ///
    /// Args:
    ///     resource: Presentity URI to query.
    ///
    /// Returns:
    ///     List of dicts with keys: id, subscriber, event, state, remaining.
    fn subscribers<'py>(
        &self,
        python: Python<'py>,
        resource: &str,
    ) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let subscriptions = self.store.subscriptions_for(resource);
        let mut result = Vec::with_capacity(subscriptions.len());
        for subscription in subscriptions {
            let dict = PyDict::new(python);
            dict.set_item("id", &subscription.id)?;
            dict.set_item("subscriber", &subscription.subscriber)?;
            dict.set_item("event", &subscription.event)?;
            dict.set_item("state", subscription.state.to_string())?;
            dict.set_item("remaining", subscription.remaining_seconds())?;
            result.push(dict);
        }
        Ok(result)
    }

    /// Get the total number of subscriptions in the store.
    fn subscription_count(&self) -> usize {
        self.store.subscription_count()
    }

    /// Get the total number of entities with published documents.
    fn document_count(&self) -> usize {
        self.store.document_count()
    }

    /// Remove expired subscriptions and documents.
    fn expire_stale(&self) {
        self.store.expire_stale();
    }

    /// Parse an RFC 3680 ``application/reginfo+xml`` body.
    ///
    /// Used on the watcher side: a NOTIFY arrives via
    /// ``@proxy.on_request("NOTIFY")``, the script extracts the body, and
    /// calls this to walk the registration data without rolling its own
    /// XML parser.
    ///
    /// Args:
    ///     xml: The reginfo XML body (str).
    ///
    /// Returns:
    ///     Dict ``{"version": int, "state": "full"|"partial",
    ///             "registrations": [{"aor": str, "id": str,
    ///                                "state": "active"|"terminated"|"init",
    ///                                "contacts": [{"uri": str,
    ///                                              "state": "active"|"terminated",
    ///                                              "event": str,
    ///                                              "expires": int|None,
    ///                                              "q": float|None}]}]}``.
    ///
    /// Raises ``ValueError`` on malformed XML or unknown attribute values.
    fn parse_reginfo<'py>(&self, python: Python<'py>, xml: &str) -> PyResult<Bound<'py, PyDict>> {
        let body = crate::registrar::reginfo::parse_reginfo(xml).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid reginfo: {error}"))
        })?;
        reginfo_to_pydict(python, &body)
    }

    /// Send an in-dialog NOTIFY for a subscription (RFC 3265 §3.2.2).
    ///
    /// Uses the stored dialog state (Call-ID, From/To tags, Route set, CSeq)
    /// from the SUBSCRIBE to construct a proper in-dialog NOTIFY.  The message
    /// is routed through the dialog's Route set (typically via the P-CSCF).
    ///
    /// The NOTIFY's final response is always observed, whether or not the
    /// script waits for it: a 404, 405, 410, 416, 480-485, 489, 501 or 604, a
    /// 408, or no final response before Timer F removes the subscription (RFC
    /// 6665 §4.2.2), counted in ``siphon_presence_subscriptions_removed_total``.
    ///
    /// Args:
    ///     subscription_id: The subscription ID returned by ``subscribe()``.
    ///     body: Optional body string (reginfo XML, PIDF XML, etc.).
    ///     content_type: Content-Type of the body (e.g. ``"application/reginfo+xml"``).
    ///     subscription_state: Subscription-State header value (default ``"active"``).
    ///     wait_for_response: ``False`` (the default) resolves once the NOTIFY
    ///         is handed to the transport; ``True`` resolves to the final
    ///         status code instead.  The initial NOTIFY sent from the
    ///         SUBSCRIBE handler is held until the handler's 200 OK is out, so
    ///         waiting on it there only ends at ``timeout_ms``.
    ///     timeout_ms: How long ``wait_for_response=True`` waits before
    ///         resolving to ``None``.
    ///
    /// Returns:
    ///     ``None``, or with ``wait_for_response=True`` the final status
    ///     (``int``), or ``None`` when no final response arrived in time.
    #[pyo3(signature = (subscription_id, body=None, content_type=None, subscription_state="active", wait_for_response=false, timeout_ms=2000))]
    #[allow(clippy::too_many_arguments)]
    fn notify<'py>(
        &self,
        python: Python<'py>,
        subscription_id: &str,
        body: Option<&str>,
        content_type: Option<&str>,
        subscription_state: &str,
        wait_for_response: bool,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let store = Arc::clone(&self.store);
        let subscription_id = subscription_id.to_string();
        let body = body.map(str::to_string);
        let content_type = content_type.map(str::to_string);
        let subscription_state = subscription_state.to_string();
        let (uac_sender, resolver) = notify_senders()?;

        crate::script::awaitable(python, async move {
            let outcome = Self::notify_inner(
                store,
                uac_sender,
                resolver,
                &subscription_id,
                body.as_deref(),
                content_type.as_deref(),
                &subscription_state,
            )
            .await?;
            if !wait_for_response {
                return Ok(None);
            }
            Ok(await_notify_status(outcome, Duration::from_millis(timeout_ms)).await)
        })
    }

    /// Send a terminating NOTIFY for a subscription and remove it from the
    /// store (RFC 6665 §4.4.1).
    ///
    /// Sends an in-dialog NOTIFY with ``Subscription-State:
    /// terminated;reason=<reason>``, then removes the subscription's dialog
    /// state.  Without this, scripts that respond to ``SUBSCRIBE Expires=0``
    /// (or any other termination trigger) leak dialog state on every
    /// short-lived subscription, and subsequent reg-event refreshes for the
    /// resource fan out NOTIFYs to long-departed watchers.
    ///
    /// Args:
    ///     subscription_id: ID returned by :meth:`subscribe_dialog`.
    ///     reason: Termination reason per RFC 6665 §4.2.2 — one of
    ///         ``"deactivated"``, ``"probation"``, ``"rejected"``,
    ///         ``"timeout"``, ``"giveup"``, ``"noresource"``, ``"invariant"``.
    ///         Defaults to ``"noresource"``.
    ///     body: Optional final body (e.g. terminal reginfo XML).
    ///     content_type: Content-Type of the body.
    ///
    /// Returns:
    ///     ``True`` if the subscription existed and the NOTIFY was sent;
    ///     ``False`` if the ``subscription_id`` was unknown (idempotent — safe
    ///     to call repeatedly).
    #[pyo3(signature = (subscription_id, reason=None, body=None, content_type=None))]
    fn terminate<'py>(
        &self,
        python: Python<'py>,
        subscription_id: &str,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // The unknown-subscription answer needs no NOTIFY, but it still has to
        // be a coroutine: the caller writes one `await` for every path.
        if self.store.get_subscription(subscription_id).is_none() {
            return crate::script::ready(python, false);
        }
        let store = Arc::clone(&self.store);
        let subscription_id = subscription_id.to_string();
        let body = body.map(str::to_string);
        let content_type = content_type.map(str::to_string);
        let subscription_state = format!("terminated;reason={}", reason.unwrap_or("noresource"));
        let (uac_sender, resolver) = notify_senders()?;

        crate::script::awaitable(python, async move {
            // notify() auto-removes the subscription when the state is
            // terminated; we rely on that path so terminate() and
            // notify(state="terminated;…") are observably equivalent.
            Self::notify_inner(
                store,
                uac_sender,
                resolver,
                &subscription_id,
                body.as_deref(),
                content_type.as_deref(),
                &subscription_state,
            )
            .await?;
            Ok(true)
        })
    }
}

/// Convert a parsed [`crate::registrar::reginfo::ReginfoBody`] to a Python
/// dict shaped for script consumption (snake-case keys, all-string enum
/// values, optional fields surfaced as `None` when absent).
fn reginfo_to_pydict<'py>(
    python: Python<'py>,
    body: &crate::registrar::reginfo::ReginfoBody,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item("version", body.version)?;
    dict.set_item("state", body.state.to_string())?;

    let registrations = pyo3::types::PyList::empty(python);
    for reg in &body.registrations {
        let reg_dict = PyDict::new(python);
        reg_dict.set_item("aor", &reg.aor)?;
        reg_dict.set_item("id", &reg.id)?;
        reg_dict.set_item("state", reg.state.to_string())?;

        let contacts = pyo3::types::PyList::empty(python);
        for contact in &reg.contacts {
            let contact_dict = PyDict::new(python);
            contact_dict.set_item("uri", &contact.uri)?;
            contact_dict.set_item("state", contact.state.to_string())?;
            contact_dict.set_item("event", contact.event.to_string())?;
            match contact.expires {
                Some(secs) => contact_dict.set_item("expires", secs)?,
                None => contact_dict.set_item("expires", python.None())?,
            }
            match contact.q {
                Some(q) => contact_dict.set_item("q", q)?,
                None => contact_dict.set_item("q", python.None())?,
            }
            contacts.append(contact_dict)?;
        }
        reg_dict.set_item("contacts", contacts)?;
        registrations.append(reg_dict)?;
    }
    dict.set_item("registrations", registrations)?;
    Ok(dict)
}

impl PyPresence {
    /// The NOTIFY itself.
    ///
    /// Awaitable because the destination is resolved through DNS (RFC 3263),
    /// which for an `async def` handler would otherwise block the asyncio
    /// driver every coroutine on that loop shares. The deferral below still
    /// works: the script awaits this before its handler returns, so the send is
    /// registered in time for the dispatcher to order it after the 200 OK.
    ///
    /// Resolves once the NOTIFY is handed on, to the receiver of its outcome:
    /// the final status, or `None` when there was none before Timer F.  The
    /// outcome is acted on in the background whether or not anyone reads it
    /// ([`watch_notify_outcome`]).
    async fn notify_inner(
        store: Arc<PresenceStore>,
        uac_sender: Arc<UacSender>,
        resolver: Arc<SipResolver>,
        subscription_id: &str,
        body: Option<&str>,
        content_type: Option<&str>,
        subscription_state: &str,
    ) -> PyResult<tokio::sync::oneshot::Receiver<Option<u16>>> {
        // Look up subscription and extract + increment CSeq atomically
        let dialog = store.prepare_notify(subscription_id).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "subscription '{subscription_id}' not found or has no dialog state \
                 — use subscribe_dialog() to create subscriptions with dialog fields"
            ))
        })?;
        let NotifyDialogState {
            subscriber,
            local_uri,
            remote_uri,
            event,
            call_id,
            from_tag,
            to_tag,
            route_set,
            cseq,
            generation,
        } = dialog;
        let call_id_for_gate = call_id.clone();

        // Determine transport destination: first Route header, or subscriber URI
        let resolve_target: String = route_set
            .first()
            .map(|route: &String| {
                // Strip angle brackets from Route value: <sip:pcscf:5060;lr> → sip:pcscf:5060;lr
                route
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
            .unwrap_or_else(|| subscriber.clone());

        let resolve_uri = parse_uri_standalone(&resolve_target).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid route/subscriber URI '{resolve_target}': {error}"
            ))
        })?;

        // R-URI: subscriber URI (the watcher's Contact from SUBSCRIBE)
        let ruri = parse_uri_standalone(&subscriber).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "invalid subscriber URI '{subscriber}': {error}"
            ))
        })?;

        let transport_hint = resolve_uri
            .get_param("transport")
            .map(|s: &str| s.to_string());
        let resolver_clone = Arc::clone(&resolver);
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

        // Build in-dialog NOTIFY: same Call-ID, swapped From/To tags, Route set.
        // The branch is a UAC one, so the dispatcher hands its responses to
        // the UAC sender (`UacSender::match_response`), and the Via names our
        // own sent-by, where the response is sent back (RFC 3261 §18.2.2).
        let branch = format!("z9hG4bK-uac-notify-{}", uuid::Uuid::new_v4());
        let (sent_by_host, sent_by_port) =
            uac_sender.sent_by_for(transport, Some(target.address), ConnectionId::default());
        let via = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport, sent_by_host, sent_by_port, branch
        );
        let cseq_str = format!("{} NOTIFY", cseq);
        // RFC 3261 §12.2.1.1 — a request sent within a dialog carries the
        // dialog's *URIs*, not its remote target:
        //   From = the local URI  (the SUBSCRIBE's To URI)  + our tag  (to_tag)
        //   To   = the remote URI (the SUBSCRIBE's From URI) + their tag (from_tag)
        // The remote target (the subscriber's Contact) is the Request-URI only,
        // set below.  Putting the Contact in From/To instead produced a NOTIFY
        // that matched by tags — so a permissive UA answered 200 — but that a
        // baseband validating the URIs (as RFC 6665 §4.4.1 entitles it to)
        // treats as invalid, after which it de-registers.
        let from_header = if to_tag.is_empty() {
            format!("<{}>;tag={}", local_uri, uuid::Uuid::new_v4())
        } else {
            format!("<{}>;tag={}", local_uri, to_tag)
        };
        let to_header = if from_tag.is_empty() {
            format!("<{}>", remote_uri)
        } else {
            format!("<{}>;tag={}", remote_uri, from_tag)
        };

        let mut builder = SipMessageBuilder::new()
            .request(Method::Notify, ruri)
            .via(via)
            .call_id(call_id)
            .cseq(cseq_str)
            .max_forwards(70)
            .from(from_header)
            .to(to_header)
            .header("Event", event)
            .header("Subscription-State", subscription_state.to_string());

        // Add Route headers from the dialog's route set
        for route in &route_set {
            builder = builder.header("Route", route.clone());
        }

        if let Some(content_type_value) = content_type {
            builder = builder.header("Content-Type", content_type_value.to_string());
        }

        if let Some(body_str) = body {
            builder = builder.body_str(body_str);
        } else {
            builder = builder.content_length(0);
        }

        let message = builder.build().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to build NOTIFY message: {error}"
            ))
        })?;

        // Registered before the NOTIFY can leave, so an answer that overtakes
        // the rest of this function still finds its transaction.
        let answered = uac_sender.expect_final_response(&branch);
        let (outcome_sender, outcome) = tokio::sync::oneshot::channel();
        tokio::spawn(watch_notify_outcome(
            Arc::clone(&store),
            subscription_id.to_string(),
            generation,
            answered,
            outcome_sender,
        ));

        // Called while the SUBSCRIBE that created the dialog is still being
        // handled: hold it until that 200 OK is out (RFC 6665 §4.1.2.3, the
        // initial NOTIFY follows the 2xx). This future runs on a tokio worker,
        // so the request's gate is found by the dialog's Call-ID rather than
        // the handler thread's queue, which it cannot see.
        super::proxy_utils::hold_or_send(
            &call_id_for_gate,
            message,
            target.address,
            transport,
            |message, destination, transport| {
                uac_sender.send_request(message, destination, transport)
            },
        );

        // RFC 6665 §4.4.1: after the terminating NOTIFY, the subscription is
        // gone — drop the dialog state so subsequent state-change events for
        // this resource don't keep emitting NOTIFYs to a watcher that is no
        // longer subscribed.
        if is_terminated_subscription_state(subscription_state) {
            store.remove_subscription(subscription_id);
        }
        Ok(outcome)
    }
}

/// The UAC sender and resolver a NOTIFY is sent with.
fn notify_senders() -> PyResult<(Arc<UacSender>, Arc<SipResolver>)> {
    let uac_sender = super::proxy_utils::uac_sender().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "presence.notify() unavailable: UAC sender not initialized",
        )
    })?;
    let resolver = super::proxy_utils::send_resolver().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "presence.notify() unavailable: DNS resolver not initialized",
        )
    })?;
    Ok((Arc::clone(uac_sender), Arc::clone(resolver)))
}

/// Wait for the final response to the NOTIFY sent under `generation`, end
/// the subscription when RFC 6665 §4.2.2 says it ends, and pass the outcome
/// on to whoever still listens.
///
/// Pure Rust on a tokio worker: nothing here attaches to Python.  It ends
/// when the transaction does, on its final response or when the UAC sweep
/// expires it at Timer F, so it holds nothing past the transaction.
async fn watch_notify_outcome(
    store: Arc<PresenceStore>,
    subscription_id: String,
    generation: u64,
    answered: tokio::sync::oneshot::Receiver<UacResult>,
    outcome_sender: tokio::sync::oneshot::Sender<Option<u16>>,
) {
    let outcome = match answered.await {
        Ok(UacResult::Response(response)) => response.status_code(),
        // Timer F, or the transaction was dropped without an answer.
        Ok(UacResult::Timeout) | Err(_) => None,
    };
    if let Some(failure) = notify_failure(outcome) {
        // A late failure must not end an incarnation the NOTIFY was not sent
        // under: a refresh meanwhile moved the subscription on, and an id
        // already removed (terminate(), an un-SUBSCRIBE) stays a no-op.
        if store.remove_subscription_if_current(&subscription_id, generation) {
            tracing::debug!(
                subscription_id = %subscription_id,
                status = ?outcome,
                reason = failure.label(),
                "presence: NOTIFY failed, subscription removed (RFC 6665 §4.2.2)"
            );
            crate::presence::metrics::record_removed(failure);
        }
    }
    let _ = outcome_sender.send(outcome);
}

/// What `notify(wait_for_response=True)` resolves to: the final status, or
/// `None` without one inside `timeout`.
async fn await_notify_status(
    outcome: tokio::sync::oneshot::Receiver<Option<u16>>,
    timeout: Duration,
) -> Option<u16> {
    match tokio::time::timeout(timeout, outcome).await {
        Ok(Ok(status)) => status,
        _ => None,
    }
}

#[cfg(test)]
#[path = "presence_notify_tests.rs"]
mod notify_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<PresenceStore> {
        Arc::new(PresenceStore::new())
    }

    #[test]
    fn publish_and_lookup() {
        let store = make_store();
        let presence = PyPresence::new(store);

        let etag = presence.publish("sip:alice@example.com", "<presence/>", 3600);
        assert!(!etag.is_empty());

        let body = presence.lookup("sip:alice@example.com");
        assert_eq!(body.as_deref(), Some("<presence/>"));
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert!(presence.lookup("sip:nobody@example.com").is_none());
    }

    #[test]
    fn subscribe_and_unsubscribe() {
        let store = make_store();
        let presence = PyPresence::new(store);

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "presence",
            3600,
        );
        assert!(subscription_id.starts_with("sub-"));
        assert_eq!(presence.subscription_count(), 1);

        let removed = presence.unsubscribe(&subscription_id);
        assert!(removed);
        assert_eq!(presence.subscription_count(), 0);
    }

    #[test]
    fn unsubscribe_nonexistent_returns_false() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert!(!presence.unsubscribe("sub-nonexistent"));
    }

    /// RFC 3261 §12.2.1.1: an in-dialog NOTIFY carries the dialog's URIs in
    /// From/To.  The subscriber's Contact is the *remote target* and belongs in
    /// the Request-URI only.
    ///
    /// The bug this guards: both From and To carried the Contact, so a NOTIFY
    /// matched by tags (permissive UAs answered 200) but was rejected by a
    /// baseband that validates the URIs, which then de-registered.
    #[test]
    fn notify_dialog_uris_come_from_the_dialog_not_the_contact() {
        let store = make_store();
        let presence = PyPresence::new(Arc::clone(&store));

        // What a P-CSCF/S-CSCF sees on a reg-event SUBSCRIBE: the Contact is a
        // UUID@ip:port, both dialog URIs are the AoR.
        let contact = "sip:f81d4fae-7dec-11d0-a765-00a0c91e6bf6@198.51.100.7:43080";
        let aor = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
        let sub_id = presence
            .subscribe_dialog(
                contact,
                aor,
                "reg",
                7200,
                "call-1",
                "ftag-ue",
                "scscf-notifier",
                None,
                Some(format!("<{aor}>")),
                Some(format!("<{aor}>;tag=ftag-ue")),
                0,
                0,
            )
            .expect("a subscription");

        let dialog = store.prepare_notify(&sub_id).expect("dialog state");
        assert_eq!(
            dialog.subscriber, contact,
            "R-URI still targets the Contact"
        );
        assert_eq!(dialog.local_uri, aor, "From must be the dialog's local URI");
        assert_eq!(dialog.remote_uri, aor, "To must be the dialog's remote URI");
        // Display names / tags supplied by a script are stripped — a From URI
        // carrying a second tag would be malformed.
        assert!(!dialog.remote_uri.contains("tag="));
        assert!(!dialog.local_uri.contains('<'));
    }

    /// A dialog rebuilt from stored state (IMS restoration keeps no CSeq)
    /// continues from the CSeq it is given: the next NOTIFY carries one more.
    #[test]
    fn a_rebuilt_dialog_notifies_above_the_cseq_it_is_given() {
        let store = make_store();
        let presence = PyPresence::new(Arc::clone(&store));
        let sub_id = presence
            .subscribe_dialog(
                "sip:uuid@192.0.2.7:43080",
                "sip:001010000000001@ims.example.com",
                "reg",
                600,
                "call-restored",
                "ftag",
                "notif",
                None,
                None,
                None,
                1_792_310_400,
                0,
            )
            .expect("a subscription");
        let dialog = store.prepare_notify(&sub_id).expect("dialog state");
        assert_eq!(dialog.cseq, 1_792_310_401);
    }

    /// A subscription created before the dialog URIs were captured must not
    /// fall back to the Contact — the resource AoR is the notifier's URI for
    /// every package where the subscriber watches an AoR directly.
    #[test]
    fn notify_dialog_uris_fall_back_to_the_resource_not_the_contact() {
        let store = make_store();
        let presence = PyPresence::new(Arc::clone(&store));

        let contact = "sip:uuid@198.51.100.7:43080";
        let aor = "sip:001010000000001@ims.example.com";
        let sub_id = presence
            .subscribe_dialog(
                contact, aor, "reg", 7200, "call-2", "ftag", "notif", None, None, None, 0, 0,
            )
            .expect("a subscription");

        let dialog = store.prepare_notify(&sub_id).expect("dialog state");
        assert_eq!(dialog.local_uri, aor);
        assert_eq!(dialog.remote_uri, aor);
        assert_ne!(dialog.local_uri, contact);
        assert_ne!(dialog.remote_uri, contact);
    }

    /// A presence watcher subscribed to somebody else's resource: the remote
    /// URI is the watcher's own AoR and differs from both the resource and the
    /// Contact, so it has to be supplied.
    #[test]
    fn notify_dialog_uris_differ_for_a_third_party_watcher() {
        let store = make_store();
        let presence = PyPresence::new(Arc::clone(&store));

        let sub_id = presence
            .subscribe_dialog(
                "sip:bob@10.0.0.9:5060",
                "sip:alice@example.com",
                "presence",
                3600,
                "call-3",
                "ftag-bob",
                "notif",
                None,
                Some("<sip:alice@example.com>".to_string()),
                Some("<sip:bob@example.com>".to_string()),
                0,
                0,
            )
            .expect("a subscription");

        let dialog = store.prepare_notify(&sub_id).expect("dialog state");
        assert_eq!(dialog.local_uri, "sip:alice@example.com");
        assert_eq!(dialog.remote_uri, "sip:bob@example.com");
        assert_eq!(dialog.subscriber, "sip:bob@10.0.0.9:5060");
    }

    /// The route set a NOTIFY carries is one name-addr per entry (RFC 3261
    /// §20.34), whatever form the script handed it over in, and an entry that
    /// is not a SIP URI is refused where the script made the call.
    #[test]
    fn a_dialog_route_set_is_kept_as_name_addrs() {
        let store = make_store();
        let presence = PyPresence::new(Arc::clone(&store));
        let subscribe = |route_set: Vec<&str>| {
            presence.subscribe_dialog(
                "sip:watcher@198.51.100.7:5060",
                "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
                "reg",
                3600,
                "call-route-set",
                "ftag-watcher",
                "notifier-tag",
                Some(route_set.into_iter().map(str::to_string).collect()),
                None,
                None,
                0,
                0,
            )
        };

        let sub_id = subscribe(vec![
            "sip:edge.example.com:5060;lr",
            "<sip:core.example.com;lr>, Core <sip:core2.example.com;lr>;x=1",
        ])
        .expect("a subscription");
        let dialog = store.prepare_notify(&sub_id).expect("dialog state");
        assert_eq!(
            dialog.route_set,
            vec![
                "<sip:edge.example.com:5060;lr>".to_string(),
                "<sip:core.example.com;lr>".to_string(),
                "Core <sip:core2.example.com;lr>;x=1".to_string(),
            ]
        );

        pyo3::Python::initialize();
        let error = subscribe(vec!["edge.example.com;lr"]).expect_err("no URI");
        Python::attach(|python| {
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let text = error.value(python).to_string();
            assert!(text.contains("\"edge.example.com;lr\""), "{text}");
        });
    }

    #[test]
    fn find_by_dialog_then_refresh_and_unsubscribe() {
        // Models the S-CSCF reg-event flow: an initial subscribe_dialog, then an
        // in-dialog SUBSCRIBE that resolves the id by (Call-ID, From-tag) and
        // refreshes it, then an un-SUBSCRIBE that removes it.
        let store = make_store();
        let presence = PyPresence::new(store);

        let sub_id = presence
            .subscribe_dialog(
                "sip:alice@ims.example.com",
                "sip:alice@ims.example.com",
                "reg",
                3600,
                "call-abc",
                "ftag-alice",
                "scscf-notif",
                None,
                None,
                None,
                0,
                0,
            )
            .expect("a subscription");

        // In-dialog refresh path: resolve by dialog, then refresh.
        assert_eq!(
            presence.find_by_dialog("call-abc", "ftag-alice").as_deref(),
            Some(sub_id.as_str())
        );
        assert!(presence.refresh(&sub_id, 7200));
        // Unknown dialog / unknown id return None / false.
        assert!(presence.find_by_dialog("call-xyz", "ftag-alice").is_none());
        assert!(!presence.refresh("sub-nope", 7200));

        // Un-SUBSCRIBE path: resolve then remove.
        let resolved = presence.find_by_dialog("call-abc", "ftag-alice").unwrap();
        assert!(presence.unsubscribe(&resolved));
        assert!(presence.find_by_dialog("call-abc", "ftag-alice").is_none());
        assert_eq!(presence.subscription_count(), 0);
    }

    fn reg_subscription(presence: &PyPresence, call_id: &str, version: u32) -> String {
        presence
            .subscribe_dialog(
                "sip:watcher@192.0.2.7:5060",
                "sip:001010000000001@ims.example.com",
                "reg",
                600,
                call_id,
                "ftag",
                "notif",
                None,
                None,
                None,
                0,
                version,
            )
            .expect("a subscription")
    }

    /// RFC 3680 §5.2: versions start at 0 and go up by one per document, per
    /// subscription.
    #[test]
    fn next_version_counts_per_subscription() {
        let presence = PyPresence::new(make_store());
        let first = reg_subscription(&presence, "call-v1", 0);
        let second = reg_subscription(&presence, "call-v2", 0);
        assert_eq!(presence.next_version(&first), Some(0));
        assert_eq!(presence.next_version(&first), Some(1));
        assert_eq!(presence.next_version(&second), Some(0));
        assert_eq!(presence.next_version(&first), Some(2));
        assert!(presence.unsubscribe(&first));
        assert_eq!(presence.next_version(&first), None);
        assert_eq!(presence.next_version(&second), Some(1));
    }

    /// A dialog rebuilt from stored state, which keeps no version, continues
    /// from the version it is given.
    #[test]
    fn a_rebuilt_dialog_continues_from_the_version_it_is_given() {
        let presence = PyPresence::new(make_store());
        let restored = reg_subscription(&presence, "call-restored-v", 1_792_310_400);
        assert_eq!(presence.next_version(&restored), Some(1_792_310_400));
        assert_eq!(presence.next_version(&restored), Some(1_792_310_401));
    }

    /// `presence.next_version` from Python on several threads while another
    /// keeps forcing garbage collections: the call takes the store's entry lock
    /// only, never waits attached, and every version is handed out once. Runs
    /// in a child process with a budget, so a regression fails instead of
    /// hanging.
    #[test]
    fn next_version_from_scripts_survives_forced_collections() {
        use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};
        use std::sync::atomic::{AtomicBool, Ordering};

        if !in_child(
            concat!(
                module_path!(),
                "::next_version_from_scripts_survives_forced_collections"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }

        pyo3::Python::initialize();
        let presence = PyPresence::new(make_store());
        let subscription_id = reg_subscription(&presence, "call-gc", 0);
        let presence = Python::attach(|python| Py::new(python, presence).expect("namespace"));

        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let takers: Vec<_> = (0..4)
            .map(|_| {
                let presence = Python::attach(|python| presence.clone_ref(python));
                let subscription_id = subscription_id.clone();
                std::thread::spawn(move || {
                    Python::attach(|python| {
                        (0..500)
                            .map(|_| {
                                presence
                                    .bind(python)
                                    .call_method1("next_version", (subscription_id.as_str(),))
                                    .and_then(|version| version.extract::<u32>())
                                    .expect("a version")
                            })
                            .collect::<Vec<u32>>()
                    })
                })
            })
            .collect();
        let mut versions: Vec<u32> = takers
            .into_iter()
            .flat_map(|taker| taker.join().expect("the taker ran"))
            .collect();
        stop.store(true, Ordering::SeqCst);
        collector.join().expect("the collector ran");
        versions.sort_unstable();
        assert_eq!(versions, (0..2000).collect::<Vec<u32>>());
    }

    #[test]
    fn document_count() {
        let store = make_store();
        let presence = PyPresence::new(store);

        assert_eq!(presence.document_count(), 0);
        presence.publish("sip:alice@example.com", "<presence/>", 3600);
        assert_eq!(presence.document_count(), 1);
    }

    #[test]
    fn subscribe_default_event_and_expires() {
        let store = make_store();
        let presence = PyPresence::new(store.clone());

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "presence",
            3600,
        );

        let subscription = store.get_subscription(&subscription_id).unwrap();
        assert_eq!(subscription.event, "presence");
        assert_eq!(subscription.expires, Duration::from_secs(3600));
    }

    #[test]
    fn subscribe_custom_event() {
        let store = make_store();
        let presence = PyPresence::new(store.clone());

        let subscription_id = presence.subscribe(
            "sip:bob@example.com",
            "sip:alice@example.com",
            "dialog",
            1800,
        );

        let subscription = store.get_subscription(&subscription_id).unwrap();
        assert_eq!(subscription.event, "dialog");
        assert_eq!(subscription.expires, Duration::from_secs(1800));
    }

    /// Unknown subscription: still an awaitable, still `False`. The caller
    /// writes one `await` for every path, so this arm has to be a coroutine
    /// too — a plain `False` here could not be awaited.
    #[test]
    fn terminate_nonexistent_returns_false() {
        pyo3::Python::initialize();
        let store = make_store();
        let presence = PyPresence::new(store);

        pyo3::Python::attach(|python| {
            let coroutine = presence
                .terminate(python, "sub-nonexistent", None, None, None)
                .expect("terminate builds a coroutine");
            let resolved: bool = python
                .import("asyncio")
                .expect("asyncio")
                .call_method1("run", (coroutine,))
                .expect("coroutine resolves")
                .extract()
                .expect("bool");
            assert!(!resolved);
        });
    }

    #[test]
    fn is_terminated_subscription_state_recognizes_terminated_forms() {
        // RFC 6665 §4.1.3 forms:
        assert!(is_terminated_subscription_state("terminated"));
        assert!(is_terminated_subscription_state(
            "terminated;reason=timeout"
        ));
        assert!(is_terminated_subscription_state(
            "terminated;reason=noresource"
        ));
        assert!(is_terminated_subscription_state(
            "terminated;reason=deactivated;retry-after=60"
        ));
        // Tolerate leading whitespace and the SP separator some impls use:
        assert!(is_terminated_subscription_state(" terminated;reason=foo"));
        assert!(is_terminated_subscription_state("terminated reason=foo"));

        // Non-terminated states must NOT match:
        assert!(!is_terminated_subscription_state("active"));
        assert!(!is_terminated_subscription_state("active;expires=3600"));
        assert!(!is_terminated_subscription_state("pending"));
        assert!(!is_terminated_subscription_state(""));
        // Don't match prefix-but-not-token (defensive — no real header would say this):
        assert!(!is_terminated_subscription_state("terminatedsoon"));
    }

    #[test]
    fn expire_stale_cleans_up() {
        let store = make_store();
        let presence = PyPresence::new(store);

        // Publish with zero expiry (immediately expired)
        presence.publish("sip:alice@example.com", "<presence/>", 0);
        assert_eq!(presence.document_count(), 1);

        presence.expire_stale();
        assert_eq!(presence.document_count(), 0);
    }
}
