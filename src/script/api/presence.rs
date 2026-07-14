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

use crate::presence::{PresenceStore, Subscription};
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_uri_standalone;
use crate::transport::Transport;

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
    fn subscribe(
        &self,
        subscriber: &str,
        resource: &str,
        event: &str,
        expires: u64,
    ) -> String {
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
    ///     subscriber: Watcher URI (Contact from the SUBSCRIBE).
    ///     resource: Presentity URI being watched.
    ///     event: Event package name (e.g. ``"reg"``).
    ///     expires: Subscription duration in seconds.
    ///     call_id: Call-ID from the SUBSCRIBE dialog.
    ///     from_tag: From-tag from the SUBSCRIBE (subscriber's tag).
    ///     to_tag: To-tag from the SUBSCRIBE (notifier's tag, set by S-CSCF).
    ///     route_set: Route headers from Record-Route of the SUBSCRIBE dialog.
    ///
    /// Returns:
    ///     Subscription ID string.
    #[pyo3(signature = (subscriber, resource, event, expires, call_id, from_tag, to_tag, route_set=None))]
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
    ) -> String {
        let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
        let subscription = Subscription::with_dialog(
            subscription_id.clone(),
            subscriber.to_string(),
            resource.to_string(),
            event.to_string(),
            Duration::from_secs(expires),
            vec![],
            call_id.to_string(),
            from_tag.to_string(),
            to_tag.to_string(),
            route_set.unwrap_or_default(),
        );
        self.store.add_subscription(subscription);
        subscription_id
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
    fn parse_reginfo<'py>(
        &self,
        python: Python<'py>,
        xml: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
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
    /// Args:
    ///     subscription_id: The subscription ID returned by ``subscribe()``.
    ///     body: Optional body string (reginfo XML, PIDF XML, etc.).
    ///     content_type: Content-Type of the body (e.g. ``"application/reginfo+xml"``).
    ///     subscription_state: Subscription-State header value (default ``"active"``).
    #[pyo3(signature = (subscription_id, body=None, content_type=None, subscription_state="active"))]
    fn notify(
        &self,
        subscription_id: &str,
        body: Option<&str>,
        content_type: Option<&str>,
        subscription_state: &str,
    ) -> PyResult<()> {
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

        // Look up subscription and extract + increment CSeq atomically
        let (subscriber, event, call_id, from_tag, to_tag, route_set, cseq) =
            self.store.prepare_notify(subscription_id).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "subscription '{subscription_id}' not found or has no dialog state \
                     — use subscribe_dialog() to create subscriptions with dialog fields"
                ))
            })?;

        // Determine transport destination: first Route header, or subscriber URI
        let resolve_target: String = route_set.first()
            .map(|route: &String| {
                // Strip angle brackets from Route value: <sip:pcscf:5060;lr> → sip:pcscf:5060;lr
                route.trim().trim_start_matches('<').trim_end_matches('>').to_string()
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

        // Build in-dialog NOTIFY: same Call-ID, swapped From/To tags, Route set
        let branch = format!("z9hG4bK-py-{}", uuid::Uuid::new_v4());
        let via = format!("SIP/2.0/{} {};branch={}", transport, target.address, branch);
        let cseq_str = format!("{} NOTIFY", cseq);
        // In NOTIFY: From = notifier (our tag = to_tag from SUBSCRIBE),
        //            To = subscriber (their tag = from_tag from SUBSCRIBE)
        let from_header = if to_tag.is_empty() {
            format!("<{}>;tag={}", ruri, uuid::Uuid::new_v4())
        } else {
            format!("<{}>;tag={}", ruri, to_tag)
        };
        let to_header = if from_tag.is_empty() {
            format!("<{}>", subscriber)
        } else {
            format!("<{}>;tag={}", subscriber, from_tag)
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

        // If called within a request handler, defer until after the reply is
        // sent (RFC 3265 §3.1.6.2: 200 OK to SUBSCRIBE before initial NOTIFY).
        if !super::proxy_utils::try_defer_send(message.clone(), target.address, transport) {
            uac_sender.send_request(message, target.address, transport);
        }

        // RFC 6665 §4.4.1: after the terminating NOTIFY, the subscription is
        // gone — drop the dialog state so subsequent state-change events for
        // this resource don't keep emitting NOTIFYs to a watcher that is no
        // longer subscribed.
        if is_terminated_subscription_state(subscription_state) {
            self.store.remove_subscription(subscription_id);
        }
        Ok(())
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
    fn terminate(
        &self,
        subscription_id: &str,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> PyResult<bool> {
        if self.store.get_subscription(subscription_id).is_none() {
            return Ok(false);
        }
        let reason_str = reason.unwrap_or("noresource");
        let subscription_state = format!("terminated;reason={reason_str}");
        // notify() auto-removes the subscription when the state is terminated;
        // we rely on that path so terminate() and notify(state="terminated;…")
        // are observably equivalent.
        self.notify(subscription_id, body, content_type, &subscription_state)?;
        Ok(true)
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

    #[test]
    fn find_by_dialog_then_refresh_and_unsubscribe() {
        // Models the S-CSCF reg-event flow: an initial subscribe_dialog, then an
        // in-dialog SUBSCRIBE that resolves the id by (Call-ID, From-tag) and
        // refreshes it, then an un-SUBSCRIBE that removes it.
        let store = make_store();
        let presence = PyPresence::new(store);

        let sub_id = presence.subscribe_dialog(
            "sip:alice@ims.example.com",
            "sip:alice@ims.example.com",
            "reg",
            3600,
            "call-abc",
            "ftag-alice",
            "scscf-notif",
            None,
        );

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

    #[test]
    fn terminate_nonexistent_returns_false() {
        let store = make_store();
        let presence = PyPresence::new(store);

        let result = presence.terminate("sub-nonexistent", None, None, None).unwrap();
        assert!(!result);
    }

    #[test]
    fn is_terminated_subscription_state_recognizes_terminated_forms() {
        // RFC 6665 §4.1.3 forms:
        assert!(is_terminated_subscription_state("terminated"));
        assert!(is_terminated_subscription_state("terminated;reason=timeout"));
        assert!(is_terminated_subscription_state("terminated;reason=noresource"));
        assert!(is_terminated_subscription_state("terminated;reason=deactivated;retry-after=60"));
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
