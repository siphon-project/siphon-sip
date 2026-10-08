//! The subscriber's side of a subscription, from the SUBSCRIBE leaving.
//!
//! RFC 6665 §4.1.2.4 has a subscriber "prepared to receive NOTIFY requests
//! before the SUBSCRIBE transaction has completed", and §4.4.1 matches such a
//! NOTIFY on Call-ID, the tag the subscriber put in From, and the Event
//! header.  So a subscription is registered here before its SUBSCRIBE is sent
//! and tracked by Call-ID from then on, through the states of §4.1.2:
//!
//! - *pending* is `notify_wait`: nothing has established a dialog yet.
//! - *established*: the first NOTIFY did, or the 2xx when it came first.  One
//!   `send()` tracks one dialog, which §5.4.9 words as "the first potential
//!   dialog-establishing message will create a dialog".  A NOTIFY for the
//!   same SUBSCRIBE from another notifier tag "would be rejected with a 481
//!   response", and a 2xx that does not correlate to the dialog is ignored.
//! - *terminated*: a NOTIFY said so.  §4.4.1 creates no dialog usage for it
//!   and destroys the one there is.  The script still gets that NOTIFY as its
//!   subscription's; the dialog is gone once its handlers have returned.
//!
//! The SUBSCRIBE transaction decides only what is left when no NOTIFY
//! established anything: Timer N of §4.1.2.4 bounds the wait for a NOTIFY, not
//! for a response.  A subscription a NOTIFY established stands when the
//! SUBSCRIBE is never answered.  A non-2xx withdraws it: §4.1.2.1 has such a
//! response "indicate that no subscription or new dialog usage has been
//! created, and no subsequent NOTIFY request will be sent".
//!
//! The caller of `send()` holds a [`PendingSubscription`].  Dropping it
//! without an outcome that keeps the subscription withdraws whatever the
//! attempt put in the store, so a failed attempt leaves nothing behind.

use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use thiserror::Error;
use tracing::debug;

use super::{extract_tag, strip_nameaddr, unix_now, SubscribeDialog, SubscribeStore};
use crate::sip::headers::SipHeaders;
use crate::sip::message::SipMessage;

/// What the notifier contributes to a subscription dialog: its tag, its URI,
/// where in-dialog requests go and the route they take.
#[derive(Debug)]
pub struct RemoteParty {
    tag: String,
    uri: String,
    /// The Contact, when the message carried one.
    target: Option<String>,
    route_set: Vec<String>,
}

impl RemoteParty {
    /// The notifier as a NOTIFY presents it.  We are the UAS of that request,
    /// so the peer is in From and the route set is its Record-Route taken in
    /// order (RFC 3261 §12.1.1).  `None` when From carries no tag.
    fn from_notify(notify: &SipMessage) -> Option<Self> {
        let from = header(&notify.headers, "From", "f")?;
        Some(Self {
            tag: extract_tag(from)?,
            uri: strip_nameaddr(from),
            target: contact(&notify.headers),
            route_set: record_route(&notify.headers).cloned().unwrap_or_default(),
        })
    }

    /// The notifier as the 2xx to our SUBSCRIBE presents it.  We are the UAC
    /// of that transaction, so the peer is in To and the route set is its
    /// Record-Route reversed (RFC 3261 §12.1.2).
    pub fn from_subscribe_response(response: &SipMessage) -> Result<Self, &'static str> {
        let to = header(&response.headers, "To", "t").ok_or("2xx missing To header")?;
        let tag = extract_tag(to)
            .ok_or("2xx response To header missing tag — peer did not establish dialog")?;
        Ok(Self {
            tag,
            uri: strip_nameaddr(to),
            target: contact(&response.headers),
            route_set: record_route(&response.headers)
                .map(|entries| entries.iter().rev().cloned().collect())
                .unwrap_or_default(),
        })
    }

    /// Write this peer into `dialog`.  A missing Contact leaves the target the
    /// dialog was registered with, which is the SUBSCRIBE's Request-URI.
    fn apply_to(&self, dialog: &mut SubscribeDialog) {
        dialog.remote_tag.clone_from(&self.tag);
        dialog.remote_uri.clone_from(&self.uri);
        if let Some(target) = &self.target {
            dialog.remote_target.clone_from(target);
        }
        dialog.route_set.clone_from(&self.route_set);
    }
}

/// A header by its name or its compact form.
fn header<'a>(headers: &'a SipHeaders, name: &str, compact: &str) -> Option<&'a String> {
    headers.get(name).or_else(|| headers.get(compact))
}

fn contact(headers: &SipHeaders) -> Option<String> {
    header(headers, "Contact", "m").map(|value| strip_nameaddr(value))
}

fn record_route(headers: &SipHeaders) -> Option<&Vec<String>> {
    headers.get_all("Record-Route")
}

/// The event-type and the `id` parameter of an Event header value.
fn event_identity(value: &str) -> (&str, Option<&str>) {
    let mut parts = value.split(';');
    let event_type = parts.next().unwrap_or_default().trim();
    let id = parts.find_map(|parameter| {
        let (name, id) = parameter.split_once('=')?;
        name.trim().eq_ignore_ascii_case("id").then(|| id.trim())
    });
    (event_type, id)
}

/// RFC 6665 §8.2.1: the event-type and the `id` parameter are compared byte by
/// byte, a value with an `id` never matches one without, and no other
/// parameter is considered.
fn event_matches(subscribed: &str, notified: &str) -> bool {
    event_identity(subscribed) == event_identity(notified)
}

/// `Subscription-State: terminated`, with whatever parameters follow.
fn terminated_state(notify: &SipMessage) -> Option<&String> {
    let value = notify.headers.get("Subscription-State")?;
    let state = value.split(';').next().unwrap_or_default().trim();
    state.eq_ignore_ascii_case("terminated").then_some(value)
}

/// One outbound subscription, as the store tracks it by Call-ID.
pub(super) struct OutboundSubscription {
    id: String,
    local_tag: String,
    event: String,
    /// The `send()` that made it has not learned its outcome yet.
    awaiting_response: bool,
    state: OutboundState,
}

enum OutboundState {
    /// The subscriber's half of the dialog, waiting for the notifier's.
    Pending(Box<SubscribeDialog>),
    /// The dialog is among the store's live dialogs, with this notifier tag.
    Established { remote_tag: String },
    /// Over before its `send()` returned.  Kept until that `send()` reads it.
    Ended { cause: String },
}

/// What the dispatcher does with an inbound NOTIFY.
pub enum NotifyDisposition {
    /// Run the script's handlers: it is the subscription's NOTIFY, or it
    /// belongs to no outbound subscription this store tracks and the script
    /// decides, as it always has.
    Deliver,
    /// Run the script's handlers, then drop the guard: the NOTIFY terminates
    /// the subscription, which exists until they have returned.
    DeliverThenEnd(EndedSubscription),
    /// Answer 481 without asking the script: the NOTIFY is for a SUBSCRIBE of
    /// ours but not for the dialog that SUBSCRIBE has (RFC 6665 §5.4.9).
    Reject,
}

/// A subscription its notifier terminated.  Dropping this destroys it.
pub struct EndedSubscription {
    store: Arc<SubscribeStore>,
    id: String,
}

impl Drop for EndedSubscription {
    fn drop(&mut self) {
        self.store.discard(&self.id);
        debug!(id = %self.id, "subscribe_state: outbound dialog terminated by NOTIFY");
    }
}

/// Why a `send()` has no subscription to return.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttemptFailure {
    /// Neither a NOTIFY nor a final response arrived in time.
    #[error("subscribe_state.send() timed out waiting for 2xx")]
    Unanswered,
    /// The 2xx would have had to establish the dialog and cannot.
    #[error("{0}")]
    Malformed(&'static str),
    /// The subscription ended while the SUBSCRIBE was in flight: `cause` is
    /// the Subscription-State of the NOTIFY that terminated it.
    #[error(
        "subscribe_state.send(): the subscription ended before the SUBSCRIBE completed ({cause})"
    )]
    Ended { cause: String },
}

/// The registration of one outbound SUBSCRIBE, held while its response is
/// awaited.  Dropped without a kept outcome, it withdraws the subscription.
pub struct PendingSubscription {
    store: Arc<SubscribeStore>,
    call_id: String,
    id: String,
    kept: bool,
}

impl PendingSubscription {
    /// The 2xx to the SUBSCRIBE arrived.  Returns the subscription's id.
    ///
    /// With no NOTIFY ahead of it the 2xx establishes the dialog, and
    /// `notifier` must be a dialog-forming 2xx.  After a NOTIFY the dialog is
    /// the NOTIFY's, route set included (RFC 6665 §4.4.1), and the 2xx only
    /// completes the transaction, whatever tag it carries (§5.4.9).
    pub fn accepted(
        self,
        notifier: Result<RemoteParty, &'static str>,
    ) -> Result<String, AttemptFailure> {
        self.settle(Some(notifier))
    }

    /// No final response arrived.  The subscription stands if a NOTIFY
    /// established it (RFC 6665 §4.1.2), and its id is returned.
    pub fn unanswered(self) -> Result<String, AttemptFailure> {
        self.settle(None)
    }

    fn settle(
        mut self,
        response: Option<Result<RemoteParty, &'static str>>,
    ) -> Result<String, AttemptFailure> {
        let store = Arc::clone(&self.store);
        let Entry::Occupied(mut entry) = store.outbound.entry(self.call_id.clone()) else {
            return Err(AttemptFailure::Unanswered);
        };
        let subscription = entry.get_mut();
        let dialog = match &subscription.state {
            OutboundState::Ended { cause } => {
                return Err(AttemptFailure::Ended {
                    cause: cause.clone(),
                });
            }
            OutboundState::Established { .. } => store.get_local(&self.id),
            OutboundState::Pending(pending) => {
                let notifier = response
                    .ok_or(AttemptFailure::Unanswered)?
                    .map_err(AttemptFailure::Malformed)?;
                let dialog = notifier.establish(pending);
                store.dialogs.insert(dialog.id.clone(), dialog.clone());
                subscription.state = OutboundState::Established {
                    remote_tag: notifier.tag,
                };
                Some(dialog)
            }
        };
        subscription.awaiting_response = false;
        drop(entry);
        self.kept = true;
        // L2 learns of the subscription here and not from an early NOTIFY, so
        // that an attempt which fails afterwards has nothing to take back out.
        if let Some(dialog) = &dialog {
            store.persist(dialog);
        }
        Ok(self.id.clone())
    }
}

impl Drop for PendingSubscription {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        let withdrawn = self
            .store
            .outbound
            .remove_if(&self.call_id, |_, subscription| subscription.id == self.id);
        if let Some((_, subscription)) = withdrawn {
            if matches!(subscription.state, OutboundState::Established { .. }) {
                self.store.discard(&self.id);
                debug!(id = %self.id, "subscribe_state: unconfirmed outbound dialog withdrawn");
            }
        }
    }
}

impl RemoteParty {
    /// The dialog `pending` becomes with this notifier.
    fn establish(&self, pending: &SubscribeDialog) -> SubscribeDialog {
        let mut dialog = pending.clone();
        self.apply_to(&mut dialog);
        dialog.created_at_unix = unix_now();
        dialog
    }
}

impl SubscribeStore {
    /// Register an outbound subscription before its SUBSCRIBE is sent, so a
    /// NOTIFY that overtakes the 2xx has something to match.  `dialog` is the
    /// subscriber's half: Call-ID, local tag, event, and the Request-URI as
    /// the remote target until a Contact replaces it.
    pub fn register_pending(self: &Arc<Self>, dialog: SubscribeDialog) -> PendingSubscription {
        let registration = PendingSubscription {
            store: Arc::clone(self),
            call_id: dialog.call_id.clone(),
            id: dialog.id.clone(),
            kept: false,
        };
        self.outbound.insert(
            dialog.call_id.clone(),
            OutboundSubscription {
                id: dialog.id.clone(),
                local_tag: dialog.local_tag.clone(),
                event: dialog.event.clone(),
                awaiting_response: true,
                state: OutboundState::Pending(Box::new(dialog)),
            },
        );
        registration
    }

    /// Number of outbound subscriptions whose `send()` has yet to settle
    /// them: nothing established, or terminated and not yet read.
    pub fn pending_count(&self) -> usize {
        self.outbound
            .iter()
            .filter(|subscription| !matches!(subscription.state, OutboundState::Established { .. }))
            .count()
    }

    /// Number of outbound subscriptions tracked by Call-ID, in any state.
    pub fn outbound_count(&self) -> usize {
        self.outbound.len()
    }

    /// Place an inbound NOTIFY against the outbound subscriptions.
    ///
    /// It corresponds to one of our SUBSCRIBEs when it has that Call-ID, a To
    /// tag equal to the tag the SUBSCRIBE carried in From, and a matching
    /// Event (RFC 6665 §4.4.1, §8.2.1).  The first such NOTIFY establishes
    /// the dialog unless the 2xx already has.  One from the dialog's notifier
    /// is the subscription's.  One from any other tag is refused (§5.4.9).
    /// One that says `terminated` ends the subscription once delivered.
    pub fn notify_received(self: &Arc<Self>, notify: &SipMessage) -> NotifyDisposition {
        let Some(call_id) = notify.headers.call_id() else {
            return NotifyDisposition::Deliver;
        };
        {
            // A read that costs one lookup for the NOTIFY that is not ours.
            let Some(subscription) = self.outbound.get(call_id.as_str()) else {
                return NotifyDisposition::Deliver;
            };
            let to_tag = header(&notify.headers, "To", "t").and_then(|to| extract_tag(to));
            let event = header(&notify.headers, "Event", "o");
            if to_tag.as_deref() != Some(subscription.local_tag.as_str())
                || !event.is_some_and(|event| event_matches(&subscription.event, event))
            {
                return NotifyDisposition::Deliver;
            }
        }
        let Some(notifier) = RemoteParty::from_notify(notify) else {
            return NotifyDisposition::Deliver;
        };
        // The entry stays locked while the dialog goes in, so the NOTIFY and
        // the end of the SUBSCRIBE transaction never both find it pending.
        let Entry::Occupied(mut entry) = self.outbound.entry(call_id.clone()) else {
            return NotifyDisposition::Deliver;
        };
        let subscription = entry.get_mut();
        let terminated = terminated_state(notify);
        match &subscription.state {
            OutboundState::Pending(pending) => {
                // Also for a terminating NOTIFY, for as long as its handlers
                // run: the script's lookup is how it knows whose NOTIFY it is.
                let dialog = notifier.establish(pending);
                self.dialogs.insert(dialog.id.clone(), dialog);
                debug!(id = %subscription.id, "subscribe_state: outbound dialog established by NOTIFY");
                subscription.state = OutboundState::Established {
                    remote_tag: notifier.tag,
                };
            }
            OutboundState::Established { remote_tag } if *remote_tag == notifier.tag => {}
            OutboundState::Established { .. } | OutboundState::Ended { .. } => {
                return NotifyDisposition::Reject;
            }
        }
        let Some(subscription_state) = terminated else {
            return NotifyDisposition::Deliver;
        };
        let id = subscription.id.clone();
        if subscription.awaiting_response {
            subscription.state = OutboundState::Ended {
                cause: subscription_state.clone(),
            };
        }
        drop(entry);
        NotifyDisposition::DeliverThenEnd(EndedSubscription {
            store: Arc::clone(self),
            id,
        })
    }

    /// A dialog left the live dialogs: stop tracking it as an outbound
    /// subscription.  While its `send()` is still waiting, the entry stays as
    /// ended for that `send()` to read.
    pub(super) fn forget_outbound(&self, dialog: &SubscribeDialog) {
        if !dialog.is_outbound {
            return;
        }
        let Entry::Occupied(mut entry) = self.outbound.entry(dialog.call_id.clone()) else {
            return;
        };
        let subscription = entry.get_mut();
        if subscription.id != dialog.id
            || !matches!(subscription.state, OutboundState::Established { .. })
        {
            return;
        }
        if subscription.awaiting_response {
            subscription.state = OutboundState::Ended {
                cause: "ended by the script".to_string(),
            };
        } else {
            entry.remove();
        }
    }

    /// Take a dialog out of the store from a path that may have no runtime to
    /// run the L2 delete on: a caller torn down along with its runtime.  That
    /// copy then ages out on its TTL.
    fn discard(&self, id: &str) {
        if self.cache.is_some() && tokio::runtime::Handle::try_current().is_err() {
            if let Some((_, dialog)) = self.dialogs.remove(id) {
                self.forget_outbound(&dialog);
            }
        } else {
            self.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message_bytes;

    const NOTIFIER_TAG: &str = "notifier";

    fn subscription(id: &str) -> SubscribeDialog {
        SubscribeDialog {
            id: id.to_string(),
            call_id: format!("call-{id}"),
            local_tag: format!("local-{id}"),
            remote_tag: String::new(),
            local_uri: "sip:watcher@example.com".to_string(),
            remote_uri: "sip:001010123456789@example.com".to_string(),
            remote_target: "sip:001010123456789@example.com".to_string(),
            received_address: None,
            received_transport: None,
            received_connection_id: None,
            route_set: Vec::new(),
            event: "reg".to_string(),
            expires_secs: 600,
            created_at_unix: unix_now(),
            cseq: 1,
            event_version: 0,
            terminated: false,
            is_outbound: true,
        }
    }

    /// A NOTIFY for `subscription(id)` from `tag`, through two proxies.
    fn notify(id: &str, tag: &str, event: &str, subscription_state: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "NOTIFY sip:watcher@192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-notify\r\n",
                "From: <sip:001010123456789@example.com>;tag={tag}\r\n",
                "To: <sip:watcher@example.com>;tag=local-{id}\r\n",
                "Call-ID: call-{id}\r\n",
                "CSeq: 1 NOTIFY\r\n",
                "Contact: <sip:notifier@192.0.2.30:5060>\r\n",
                "Record-Route: <sip:near.example.com;lr>\r\n",
                "Record-Route: <sip:far.example.com;lr>\r\n",
                "Event: {event}\r\n",
                "Subscription-State: {subscription_state}\r\n",
                "Max-Forwards: 70\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            tag = tag,
            id = id,
            event = event,
            subscription_state = subscription_state,
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the NOTIFY parses")
    }

    /// The 2xx to the SUBSCRIBE of `subscription(id)`, from `tag`, back along
    /// the path the NOTIFY of [`notify`] took.
    fn accepted(id: &str, tag: &str) -> RemoteParty {
        let raw = format!(
            concat!(
                "SIP/2.0 200 OK\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uac-py-1\r\n",
                "From: <sip:watcher@example.com>;tag=local-{id}\r\n",
                "To: <sip:001010123456789@example.com>;tag={tag}\r\n",
                "Call-ID: call-{id}\r\n",
                "CSeq: 1 SUBSCRIBE\r\n",
                "Contact: <sip:accepted@192.0.2.30:5060>\r\n",
                "Record-Route: <sip:far.example.com;lr>\r\n",
                "Record-Route: <sip:near.example.com;lr>\r\n",
                "Expires: 600\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            id = id,
            tag = tag,
        );
        let response = parse_sip_message_bytes(raw.as_bytes()).expect("the 2xx parses");
        RemoteParty::from_subscribe_response(&response).expect("a dialog-forming 2xx")
    }

    fn active(id: &str) -> SipMessage {
        notify(id, NOTIFIER_TAG, "reg", "active;expires=600")
    }

    fn two_hundred(id: &str, tag: &str) -> Result<RemoteParty, &'static str> {
        Ok(accepted(id, tag))
    }

    fn delivered(disposition: &NotifyDisposition) -> bool {
        matches!(disposition, NotifyDisposition::Deliver)
    }

    const ROUTE_OF_THE_NOTIFY: [&str; 2] =
        ["<sip:near.example.com;lr>", "<sip:far.example.com;lr>"];

    #[test]
    fn a_registered_subscription_is_pending_and_not_yet_a_dialog() {
        let store = Arc::new(SubscribeStore::new());
        let _registration = store.register_pending(subscription("a"));
        assert_eq!(store.pending_count(), 1);
        assert_eq!(store.local_count(), 0);
        assert!(store.get_local("a").is_none());
        assert!(store.find_by_tags("call-a", "local-a", "").is_none());
    }

    #[test]
    fn a_notify_ahead_of_the_2xx_establishes_the_dialog_from_the_notify() {
        let store = Arc::new(SubscribeStore::new());
        let _registration = store.register_pending(subscription("a"));

        assert!(delivered(&store.notify_received(&active("a"))));

        assert_eq!(store.pending_count(), 0);
        let dialog = store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .expect("the lookup a NOTIFY handler makes finds it");
        assert_eq!(dialog.id, "a");
        assert_eq!(dialog.remote_uri, "sip:001010123456789@example.com");
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        // A UAS takes Record-Route in the order of the request.
        assert_eq!(dialog.route_set, ROUTE_OF_THE_NOTIFY);
        assert!(dialog.is_outbound);
    }

    #[test]
    fn the_2xx_after_a_notify_keeps_the_dialog_the_notify_made() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));

        let id = registration.accepted(two_hundred("a", NOTIFIER_TAG));

        assert_eq!(id.as_deref(), Ok("a"));
        assert_eq!(store.local_count(), 1);
        let dialog = store.get_local("a").expect("still there");
        // RFC 6665 §4.4.1: the route set is the NOTIFY's, not the 2xx's.
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        assert_eq!(dialog.route_set, ROUTE_OF_THE_NOTIFY);
    }

    #[test]
    fn the_2xx_alone_establishes_the_dialog_as_before() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));

        let id = registration.accepted(two_hundred("a", NOTIFIER_TAG));

        assert_eq!(id.as_deref(), Ok("a"));
        assert_eq!(store.pending_count(), 0);
        let dialog = store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .expect("established");
        assert_eq!(dialog.remote_target, "sip:accepted@192.0.2.30:5060");
        // A UAC reverses the Record-Route of the response.
        assert_eq!(dialog.route_set, ROUTE_OF_THE_NOTIFY);
        // The NOTIFY that follows is the subscription's and changes nothing.
        assert!(delivered(&store.notify_received(&active("a"))));
        assert_eq!(store.local_count(), 1);
        assert_eq!(
            store.get_local("a").map(|dialog| dialog.remote_target),
            Some("sip:accepted@192.0.2.30:5060".to_string())
        );
    }

    #[test]
    fn a_2xx_without_contact_keeps_the_request_uri_as_target() {
        let raw = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uac-py-1\r\n",
            "From: <sip:watcher@example.com>;tag=local-a\r\n",
            "To: <sip:001010123456789@example.com>;tag=notifier\r\n",
            "Call-ID: call-a\r\n",
            "CSeq: 1 SUBSCRIBE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let response = parse_sip_message_bytes(raw.as_bytes()).expect("the 2xx parses");
        let store = Arc::new(SubscribeStore::new());
        let id = store
            .register_pending(subscription("a"))
            .accepted(RemoteParty::from_subscribe_response(&response));
        assert_eq!(id.as_deref(), Ok("a"));
        let dialog = store.get_local("a").expect("established");
        assert_eq!(dialog.remote_target, "sip:001010123456789@example.com");
        assert!(dialog.route_set.is_empty());
    }

    fn untagged_2xx() -> Result<RemoteParty, &'static str> {
        let raw = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uac-py-1\r\n",
            "From: <sip:watcher@example.com>;tag=local-a\r\n",
            "To: <sip:001010123456789@example.com>\r\n",
            "Call-ID: call-a\r\n",
            "CSeq: 1 SUBSCRIBE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let response = parse_sip_message_bytes(raw.as_bytes()).expect("the 2xx parses");
        RemoteParty::from_subscribe_response(&response)
    }

    #[test]
    fn a_2xx_without_a_to_tag_establishes_nothing_and_leaves_nothing() {
        let store = Arc::new(SubscribeStore::new());
        let outcome = store
            .register_pending(subscription("a"))
            .accepted(untagged_2xx());
        assert!(matches!(outcome, Err(AttemptFailure::Malformed(_))));
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    /// RFC 6665 §5.4.9: a 2xx that does not correlate to the dialog the
    /// NOTIFY established is ignored, so what it lacks does not matter.
    #[test]
    fn a_2xx_is_not_examined_once_a_notify_established_the_dialog() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        assert_eq!(registration.accepted(untagged_2xx()).as_deref(), Ok("a"));
        assert_eq!(store.local_count(), 1);
    }

    #[test]
    fn a_2xx_from_another_fork_does_not_replace_the_dialog_of_the_notify() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&notify("a", "fork-one", "reg", "active"));

        let id = registration.accepted(two_hundred("a", "fork-two"));

        assert_eq!(id.as_deref(), Ok("a"));
        assert_eq!(store.local_count(), 1, "one send() tracks one dialog");
        let dialog = store
            .find_by_tags("call-a", "local-a", "fork-one")
            .expect("the dialog of the first NOTIFY");
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        assert!(store
            .find_by_tags("call-a", "local-a", "fork-two")
            .is_none());
        // The other fork's NOTIFYs stay refused after the 2xx, too.
        assert!(matches!(
            store.notify_received(&notify("a", "fork-two", "reg", "active")),
            NotifyDisposition::Reject
        ));
    }

    #[test]
    fn a_notify_from_another_fork_is_refused_in_either_order() {
        let store = Arc::new(SubscribeStore::new());
        // The first NOTIFY established the dialog.
        let _registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&notify("a", "fork-one", "reg", "active"));
        assert!(matches!(
            store.notify_received(&notify("a", "fork-two", "reg", "active")),
            NotifyDisposition::Reject
        ));
        // The 2xx established the dialog.
        let accepted = store.register_pending(subscription("b"));
        assert_eq!(
            accepted.accepted(two_hundred("b", "fork-one")).as_deref(),
            Ok("b")
        );
        assert!(matches!(
            store.notify_received(&notify("b", "fork-two", "reg", "active")),
            NotifyDisposition::Reject
        ));
        assert!(delivered(
            &store.notify_received(&notify("b", "fork-one", "reg", "active"))
        ));

        assert_eq!(store.local_count(), 2);
        assert!(store
            .find_by_tags("call-a", "local-a", "fork-two")
            .is_none());
        assert!(store
            .find_by_tags("call-b", "local-b", "fork-two")
            .is_none());
    }

    #[test]
    fn a_notify_that_is_not_the_subscriptions_leaves_it_pending() {
        let store = Arc::new(SubscribeStore::new());
        let _registration = store.register_pending(subscription("a"));

        // Another Call-ID, another To tag, another event package, an `id` the
        // SUBSCRIBE did not carry, and no From tag to form a dialog with.
        assert!(delivered(&store.notify_received(&active("b"))));
        let mut other_tag = active("a");
        other_tag.headers.set(
            "To",
            "<sip:watcher@example.com>;tag=someone-else".to_string(),
        );
        assert!(delivered(&store.notify_received(&other_tag)));
        assert!(delivered(&store.notify_received(&notify(
            "a",
            NOTIFIER_TAG,
            "presence",
            "active"
        ))));
        assert!(delivered(&store.notify_received(&notify(
            "a",
            NOTIFIER_TAG,
            "reg;id=7",
            "active"
        ))));
        let mut untagged = active("a");
        untagged
            .headers
            .set("From", "<sip:001010123456789@example.com>".to_string());
        assert!(delivered(&store.notify_received(&untagged)));

        assert_eq!(store.pending_count(), 1);
        assert_eq!(store.local_count(), 0);
    }

    #[test]
    fn event_headers_compare_on_type_and_id_only() {
        assert!(event_matches("reg", "reg"));
        assert!(event_matches("reg", " reg ;foo=bar"));
        assert!(event_matches("foo;id=1234", "foo;param=abcd;id=1234"));
        assert!(!event_matches("foo;id=1234", "foo"));
        assert!(!event_matches("foo", "foo;id=1234"));
        assert!(!event_matches("foo;id=1234", "foo;id=4321"));
        assert!(!event_matches("foo;id=1234", "Foo;id=1234"));
        assert!(!event_matches("reg", "presence"));
    }

    /// RFC 6665 §4.1.2: no final response is not an event in the state a
    /// NOTIFY put the subscription in.
    #[test]
    fn a_notified_subscription_stands_when_the_subscribe_goes_unanswered() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));

        assert_eq!(registration.unanswered().as_deref(), Ok("a"));

        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), 1);
        assert!(delivered(&store.notify_received(&active("a"))));
    }

    /// RFC 6665 §4.1.2.4: without a NOTIFY the attempt failed, and its state
    /// is cleaned up.
    #[test]
    fn an_unanswered_subscribe_without_a_notify_leaves_nothing() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        assert_eq!(registration.unanswered(), Err(AttemptFailure::Unanswered));
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
        assert!(delivered(&store.notify_received(&active("a"))));
        assert_eq!(store.local_count(), 0);
    }

    /// RFC 6665 §4.1.2: `notify_wait` to `terminated` on "NOTIFY,
    /// state=terminated"; §4.4.1: no dialog usage is created by it.
    #[test]
    fn a_terminated_notify_ahead_of_the_2xx_ends_the_attempt() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));

        let terminated = notify("a", NOTIFIER_TAG, "reg", "Terminated;reason=rejected");
        let disposition = store.notify_received(&terminated);
        assert!(matches!(disposition, NotifyDisposition::DeliverThenEnd(_)));
        assert!(
            store
                .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
                .is_some(),
            "found while the NOTIFY is being handled"
        );
        drop(disposition);
        assert_eq!(store.local_count(), 0, "and gone once it has been");

        // Nothing revives it: not a later NOTIFY, not the 2xx.
        assert!(matches!(
            store.notify_received(&active("a")),
            NotifyDisposition::Reject
        ));
        assert_eq!(
            registration.accepted(two_hundred("a", NOTIFIER_TAG)),
            Err(AttemptFailure::Ended {
                cause: "Terminated;reason=rejected".to_string()
            })
        );
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    #[test]
    fn a_terminated_notify_after_an_active_one_also_ends_the_attempt() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        drop(store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "terminated")));

        assert!(matches!(
            registration.unanswered(),
            Err(AttemptFailure::Ended { .. })
        ));
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    /// RFC 6665 §4.4.1: "A subscription is destroyed after a notifier sends a
    /// NOTIFY request with a Subscription-State of terminated".
    #[test]
    fn a_terminated_notify_destroys_an_established_subscription() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        assert!(registration
            .accepted(two_hundred("a", NOTIFIER_TAG))
            .is_ok());

        let disposition = store.notify_received(&notify(
            "a",
            NOTIFIER_TAG,
            "reg",
            "terminated;reason=timeout",
        ));
        assert!(matches!(disposition, NotifyDisposition::DeliverThenEnd(_)));
        assert_eq!(store.local_count(), 1);
        drop(disposition);

        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);
        // What comes after belongs to no subscription the store tracks.
        assert!(delivered(&store.notify_received(&active("a"))));
        assert_eq!(store.local_count(), 0);
    }

    #[test]
    fn dropping_an_unsettled_registration_leaves_nothing_pending() {
        let store = Arc::new(SubscribeStore::new());
        drop(store.register_pending(subscription("a")));
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    /// RFC 6665 §4.1.2.1: a non-2xx final response says no subscription was
    /// created, so the caller drops the registration.
    #[test]
    fn dropping_an_unsettled_registration_withdraws_an_established_dialog() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        assert_eq!(store.local_count(), 1);

        drop(registration);

        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
        assert!(store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .is_none());
    }

    #[test]
    fn a_dialog_the_script_ended_is_not_revived_by_the_2xx() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        store.remove("a");

        assert!(matches!(
            registration.accepted(two_hundred("a", NOTIFIER_TAG)),
            Err(AttemptFailure::Ended { .. })
        ));
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);
    }

    #[test]
    fn removing_or_expiring_a_dialog_stops_tracking_it() {
        let store = Arc::new(SubscribeStore::new());
        assert!(store
            .register_pending(subscription("a"))
            .accepted(two_hundred("a", NOTIFIER_TAG))
            .is_ok());
        let mut short = subscription("b");
        short.expires_secs = 0;
        assert!(store
            .register_pending(short)
            .accepted(two_hundred("b", NOTIFIER_TAG))
            .is_ok());
        assert_eq!(store.outbound_count(), 2);

        store.remove("a");
        assert_eq!(store.take_stale().len(), 1);

        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    /// The per-structure gate: a batch of attempts with every outcome, the
    /// NOTIFY on either side of the response, returns the Call-ID map to
    /// empty once the subscriptions that stood have ended.
    #[test]
    fn the_outbound_map_drains_to_empty_over_a_batch_of_attempts() {
        let store = Arc::new(SubscribeStore::new());
        const ROUNDS: usize = 2_400;
        let mut standing = Vec::new();
        for round in 0..ROUNDS {
            let id = round.to_string();
            let registration = store.register_pending(subscription(&id));
            let notified = round % 2 == 0;
            if notified {
                let _ = store.notify_received(&active(&id));
            }
            let stands = match round % 6 {
                0 | 1 => registration
                    .accepted(two_hundred(&id, NOTIFIER_TAG))
                    .is_ok(),
                2 | 3 => registration.unanswered().is_ok(),
                _ => {
                    drop(registration);
                    false
                }
            };
            assert_eq!(stands, round % 6 < 2 || (round % 6 < 4 && notified));
            if stands {
                standing.push(id);
            }
        }
        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), standing.len());
        assert_eq!(store.outbound_count(), standing.len());

        for (index, id) in standing.iter().enumerate() {
            if index % 2 == 0 {
                store.remove(id);
            } else {
                drop(store.notify_received(&notify(id, NOTIFIER_TAG, "reg", "terminated")));
            }
        }
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
    }

    /// The NOTIFY and the end of the SUBSCRIBE transaction arrive on different
    /// threads.  Whatever the interleaving, a subscription that stands is one
    /// dialog under its id and one that does not is gone.
    #[test]
    fn a_notify_racing_the_end_of_the_subscribe_never_loses_or_leaks() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 600;
        let store = Arc::new(SubscribeStore::new());
        let standing = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let store = Arc::clone(&store);
                let standing = &standing;
                scope.spawn(move || {
                    for round in 0..ROUNDS {
                        let id = format!("{thread}-{round}");
                        let registration = store.register_pending(subscription(&id));
                        let gate = std::sync::Barrier::new(2);
                        let stands = std::thread::scope(|race| {
                            race.spawn(|| {
                                gate.wait();
                                let _ = store.notify_received(&active(&id));
                            });
                            gate.wait();
                            match round % 3 {
                                0 => registration
                                    .accepted(two_hundred(&id, NOTIFIER_TAG))
                                    .is_ok(),
                                // Stands only if the NOTIFY won the race.
                                1 => registration.unanswered().is_ok(),
                                _ => {
                                    drop(registration);
                                    false
                                }
                            }
                        });
                        let found = store.find_by_tags(
                            &format!("call-{id}"),
                            &format!("local-{id}"),
                            NOTIFIER_TAG,
                        );
                        assert_eq!(found.map(|dialog| dialog.id), stands.then_some(id));
                        if round % 3 == 0 {
                            assert!(stands, "a 2xx always leaves a subscription");
                        }
                        standing
                            .fetch_add(usize::from(stands), std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
        });
        let standing = standing.into_inner();
        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), standing);
        assert_eq!(store.outbound_count(), standing);
    }
}
