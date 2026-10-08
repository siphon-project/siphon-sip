//! Outbound subscriptions between the SUBSCRIBE leaving and a dialog existing.
//!
//! RFC 6665 §4.1.2.4 has a subscriber "prepared to receive NOTIFY requests
//! before the SUBSCRIBE transaction has completed", and §4.4.1 has the dialog
//! created by that NOTIFY, matched on Call-ID, the tag the subscriber put in
//! From, and the Event header.  So the subscription is registered here before
//! the SUBSCRIBE is sent, and whichever arrives first, the NOTIFY or the 2xx,
//! moves it into the store's live dialogs under the id it was registered with.
//! The other one then finds it already there.
//!
//! A registration is owned by the [`PendingSubscription`] its caller holds.
//! Dropping that without confirming it (a non-2xx, a timeout, a cancelled
//! caller) takes the subscription out again, established or not, so a failed
//! attempt leaves nothing behind.

use std::sync::Arc;

use dashmap::mapref::entry::Entry;
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

/// The registration of one outbound SUBSCRIBE.  [`confirm`](Self::confirm) it
/// when the 2xx arrives; dropping it otherwise withdraws the subscription.
pub struct PendingSubscription {
    store: Arc<SubscribeStore>,
    call_id: String,
    id: String,
    confirmed: bool,
}

impl PendingSubscription {
    /// The 2xx to the SUBSCRIBE arrived: the subscription stays.  Returns its
    /// handle id.
    ///
    /// With no NOTIFY ahead of it, the 2xx establishes the dialog.  After one,
    /// the dialog stands as the NOTIFY made it, route set included (RFC 6665
    /// §4.4.1), unless the 2xx names another notifier tag, which a forked
    /// SUBSCRIBE can produce.  One `send()` tracks one dialog, and that has
    /// always been the 2xx's, so the 2xx's dialog replaces the NOTIFY's.
    pub fn confirm(mut self, notifier: &RemoteParty) -> String {
        self.confirmed = true;
        let store = &self.store;
        let dialog = store.establish(&self.call_id, notifier).or_else(|| {
            let mut established = store.dialogs.get_mut(&self.id)?;
            if established.terminated {
                return None;
            }
            if established.remote_tag != notifier.tag {
                notifier.apply_to(&mut established);
            }
            Some(established.clone())
        });
        // L2 learns of the subscription here and not from an early NOTIFY, so
        // that an attempt which fails afterwards has nothing to take back out.
        if let Some(dialog) = &dialog {
            store.persist(dialog);
        }
        self.id.clone()
    }
}

impl Drop for PendingSubscription {
    fn drop(&mut self) {
        if !self.confirmed {
            self.store.abandon(&self.call_id, &self.id);
        }
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
            confirmed: false,
        };
        self.pending.insert(dialog.call_id.clone(), dialog);
        registration
    }

    /// Number of outbound subscriptions no NOTIFY or 2xx has established yet.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Establish the pending subscription `notify` belongs to, if there is
    /// one: same Call-ID, a To tag equal to the tag our SUBSCRIBE carried in
    /// From, and a matching Event (RFC 6665 §4.4.1).  Returns its handle id.
    ///
    /// A NOTIFY with `Subscription-State: terminated` is matched like any
    /// other.  §4.4.1 creates no dialog usage for it, but the script still has
    /// to see it as its subscription's to learn that it ended, and what a
    /// script does with a terminated subscription is the same in either order.
    pub fn establish_from_notify(&self, notify: &SipMessage) -> Option<String> {
        let call_id = notify.headers.call_id()?;
        {
            // A read that costs one lookup for the NOTIFY that is not ours.
            let candidate = self.pending.get(call_id.as_str())?;
            let to = header(&notify.headers, "To", "t")?;
            if extract_tag(to).as_deref() != Some(candidate.local_tag.as_str()) {
                return None;
            }
            let event = header(&notify.headers, "Event", "o")?;
            if !event_matches(&candidate.event, event) {
                return None;
            }
        }
        let notifier = RemoteParty::from_notify(notify)?;
        let dialog = self.establish(call_id, &notifier)?;
        debug!(id = %dialog.id, "subscribe_state: outbound dialog established by NOTIFY");
        Some(dialog.id)
    }

    /// Move the subscription pending under `call_id` into the live dialogs,
    /// completed with `notifier`.  `None` when it is no longer pending.
    ///
    /// The pending entry stays locked until the dialog is in place, so the
    /// NOTIFY and the 2xx racing for it never both find it missing.
    fn establish(&self, call_id: &str, notifier: &RemoteParty) -> Option<SubscribeDialog> {
        let Entry::Occupied(entry) = self.pending.entry(call_id.to_string()) else {
            return None;
        };
        let mut dialog = entry.get().clone();
        notifier.apply_to(&mut dialog);
        dialog.created_at_unix = unix_now();
        self.dialogs.insert(dialog.id.clone(), dialog.clone());
        entry.remove();
        Some(dialog)
    }

    /// Withdraw a subscription whose SUBSCRIBE did not get its 2xx, whether it
    /// is still pending or an early NOTIFY had established it.
    fn abandon(&self, call_id: &str, id: &str) {
        self.pending.remove(call_id);
        if !self.dialogs.contains_key(id) {
            return;
        }
        if self.cache.is_some() && tokio::runtime::Handle::try_current().is_err() {
            // The caller is being torn down along with its runtime, so there
            // is nothing to run the L2 delete on; that copy ages out on its TTL.
            self.dialogs.remove(id);
        } else {
            self.remove(id);
        }
        debug!(id, "subscribe_state: unconfirmed outbound dialog withdrawn");
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

        assert_eq!(
            store.establish_from_notify(&active("a")).as_deref(),
            Some("a")
        );

        assert_eq!(store.pending_count(), 0);
        let dialog = store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .expect("the lookup a NOTIFY handler makes finds it");
        assert_eq!(dialog.id, "a");
        assert_eq!(dialog.remote_uri, "sip:001010123456789@example.com");
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        // A UAS takes Record-Route in the order of the request.
        assert_eq!(
            dialog.route_set,
            ["<sip:near.example.com;lr>", "<sip:far.example.com;lr>"]
        );
        assert!(dialog.is_outbound);
    }

    #[test]
    fn the_2xx_after_a_notify_confirms_the_dialog_the_notify_made() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        store.establish_from_notify(&active("a"));

        let id = registration.confirm(&accepted("a", NOTIFIER_TAG));

        assert_eq!(id, "a");
        assert_eq!(store.local_count(), 1);
        let dialog = store.get_local("a").expect("still there");
        // RFC 6665 §4.4.1: the route set is the NOTIFY's, not the 2xx's.
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        assert_eq!(
            dialog.route_set,
            ["<sip:near.example.com;lr>", "<sip:far.example.com;lr>"]
        );
    }

    #[test]
    fn the_2xx_alone_establishes_the_dialog_as_before() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));

        let id = registration.confirm(&accepted("a", NOTIFIER_TAG));

        assert_eq!(id, "a");
        assert_eq!(store.pending_count(), 0);
        let dialog = store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .expect("established");
        assert_eq!(dialog.remote_target, "sip:accepted@192.0.2.30:5060");
        // A UAC reverses the Record-Route of the response.
        assert_eq!(
            dialog.route_set,
            ["<sip:near.example.com;lr>", "<sip:far.example.com;lr>"]
        );
        // The NOTIFY that follows has nothing left to establish.
        assert!(store.establish_from_notify(&active("a")).is_none());
        assert_eq!(store.local_count(), 1);
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
        let notifier = RemoteParty::from_subscribe_response(&response).expect("dialog-forming");
        let store = Arc::new(SubscribeStore::new());
        store.register_pending(subscription("a")).confirm(&notifier);
        let dialog = store.get_local("a").expect("established");
        assert_eq!(dialog.remote_target, "sip:001010123456789@example.com");
        assert!(dialog.route_set.is_empty());
    }

    #[test]
    fn a_2xx_without_a_to_tag_forms_no_dialog() {
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
        assert!(RemoteParty::from_subscribe_response(&response).is_err());
    }

    #[test]
    fn a_2xx_from_another_fork_replaces_the_dialog_of_the_early_notify() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        store.establish_from_notify(&notify("a", "fork-one", "reg", "active"));

        let id = registration.confirm(&accepted("a", "fork-two"));

        assert_eq!(id, "a", "the handle keeps its identity");
        assert_eq!(store.local_count(), 1, "one send() tracks one dialog");
        let dialog = store
            .find_by_tags("call-a", "local-a", "fork-two")
            .expect("the dialog of the 2xx, as send() has always returned");
        assert_eq!(dialog.remote_target, "sip:accepted@192.0.2.30:5060");
        assert!(store
            .find_by_tags("call-a", "local-a", "fork-one")
            .is_none());
    }

    #[test]
    fn a_second_notify_from_another_fork_establishes_nothing() {
        let store = Arc::new(SubscribeStore::new());
        let _registration = store.register_pending(subscription("a"));
        store.establish_from_notify(&notify("a", "fork-one", "reg", "active"));

        assert!(store
            .establish_from_notify(&notify("a", "fork-two", "reg", "active"))
            .is_none());
        assert_eq!(store.local_count(), 1);
        assert!(store
            .find_by_tags("call-a", "local-a", "fork-two")
            .is_none());
    }

    #[test]
    fn a_notify_that_is_not_the_subscriptions_leaves_it_pending() {
        let store = Arc::new(SubscribeStore::new());
        let _registration = store.register_pending(subscription("a"));

        // Another Call-ID, another To tag, another event package, an `id` the
        // SUBSCRIBE did not carry, and no From tag to form a dialog with.
        assert!(store.establish_from_notify(&active("b")).is_none());
        let mut other_tag = active("a");
        other_tag.headers.set(
            "To",
            "<sip:watcher@example.com>;tag=someone-else".to_string(),
        );
        assert!(store.establish_from_notify(&other_tag).is_none());
        assert!(store
            .establish_from_notify(&notify("a", NOTIFIER_TAG, "presence", "active"))
            .is_none());
        assert!(store
            .establish_from_notify(&notify("a", NOTIFIER_TAG, "reg;id=7", "active"))
            .is_none());
        let mut untagged = active("a");
        untagged
            .headers
            .set("From", "<sip:001010123456789@example.com>".to_string());
        assert!(store.establish_from_notify(&untagged).is_none());

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

    #[test]
    fn a_terminated_notify_is_matched_like_any_other() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));

        let terminated = notify("a", NOTIFIER_TAG, "reg", "terminated;reason=rejected");
        assert_eq!(
            store.establish_from_notify(&terminated).as_deref(),
            Some("a")
        );
        assert!(store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .is_some());

        // The 2xx that follows returns the same subscription, as it would
        // have with the two the other way round.
        assert_eq!(registration.confirm(&accepted("a", NOTIFIER_TAG)), "a");
        assert_eq!(store.local_count(), 1);
    }

    #[test]
    fn dropping_an_unconfirmed_registration_leaves_nothing_pending() {
        let store = Arc::new(SubscribeStore::new());
        drop(store.register_pending(subscription("a")));
        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), 0);
        assert!(store.establish_from_notify(&active("a")).is_none());
    }

    #[test]
    fn dropping_an_unconfirmed_registration_withdraws_an_established_dialog() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        store.establish_from_notify(&active("a"));
        assert_eq!(store.local_count(), 1);

        drop(registration);

        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), 0);
        assert!(store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .is_none());
    }

    #[test]
    fn confirming_does_not_revive_a_dialog_the_script_ended() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        store.establish_from_notify(&active("a"));
        store.remove("a");

        assert_eq!(registration.confirm(&accepted("a", NOTIFIER_TAG)), "a");
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.pending_count(), 0);
    }

    /// The per-structure gate: a batch of attempts, complete and failed, with
    /// the NOTIFY on either side of the 2xx, returns the pending map to empty
    /// and keeps exactly the subscriptions that were confirmed.
    #[test]
    fn the_pending_map_drains_to_empty_over_a_batch_of_attempts() {
        let store = Arc::new(SubscribeStore::new());
        const ROUNDS: usize = 2_000;
        for round in 0..ROUNDS {
            let id = round.to_string();
            let registration = store.register_pending(subscription(&id));
            if round % 2 == 0 {
                store.establish_from_notify(&active(&id));
            }
            if round % 4 < 2 {
                registration.confirm(&accepted(&id, NOTIFIER_TAG));
                store.establish_from_notify(&active(&id));
            } else {
                drop(registration);
            }
        }
        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), ROUNDS / 2);
    }

    /// The NOTIFY and the end of the SUBSCRIBE transaction arrive on different
    /// threads.  Whatever the interleaving, a confirmed subscription is one
    /// dialog under its id and an unconfirmed one is gone.
    #[test]
    fn a_notify_racing_the_end_of_the_subscribe_never_loses_or_leaks() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 500;
        let store = Arc::new(SubscribeStore::new());
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let store = Arc::clone(&store);
                scope.spawn(move || {
                    for round in 0..ROUNDS {
                        let id = format!("{thread}-{round}");
                        let confirms = round % 2 == 0;
                        let registration = store.register_pending(subscription(&id));
                        let gate = std::sync::Barrier::new(2);
                        std::thread::scope(|race| {
                            race.spawn(|| {
                                gate.wait();
                                store.establish_from_notify(&active(&id));
                            });
                            gate.wait();
                            if confirms {
                                assert_eq!(registration.confirm(&accepted(&id, NOTIFIER_TAG)), id);
                            } else {
                                drop(registration);
                            }
                        });
                        let found = store.find_by_tags(
                            &format!("call-{id}"),
                            &format!("local-{id}"),
                            NOTIFIER_TAG,
                        );
                        assert_eq!(found.map(|dialog| dialog.id), confirms.then_some(id));
                    }
                });
            }
        });
        assert_eq!(store.pending_count(), 0);
        assert_eq!(store.local_count(), THREADS * ROUNDS / 2);
    }
}
