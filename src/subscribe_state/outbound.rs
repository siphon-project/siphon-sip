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
//! What `send()` gives its caller follows from which of these happened, never
//! from the order they happened in.  The 2xx and the NOTIFYs travel
//! separately and race, so an outcome that depended on the winner would hand
//! the same exchange to a script two different ways.  Concretely: a NOTIFY
//! that terminates the subscription is reported to the NOTIFY handler and
//! nowhere else.  `send()` returns the subscription's id whether that NOTIFY
//! came before its 2xx or after, and in both cases nothing is left in the
//! store once the handler has returned.  Repeating an event changes nothing
//! either: a second 2xx, or a NOTIFY for a subscription already terminated,
//! finds no state to alter.
//!
//! The caller of `send()` holds a [`PendingSubscription`].  Dropping it
//! without an outcome that keeps the subscription withdraws whatever the
//! attempt put in the store, so a failed attempt leaves nothing behind.
//!
//! The same holds for what the dialog ends up holding.  Its remote target is
//! the Contact of the latest NOTIFY, since a NOTIFY is a target refresh
//! request (RFC 6665 §4.4.1, RFC 3261 §12.2.2); the 2xx supplies it only
//! until a NOTIFY has.  Its duration is the shortest the notifier has stated,
//! in the Expires of the 2xx (§4.1.2.1) or the `expires` of a
//! Subscription-State (§4.1.2.2), and only a refresh the script sends makes
//! it longer.  Neither depends on the order the two arrived in.  The route
//! set is the one thing fixed by whichever established the dialog (RFC 3261
//! §12.1); a 2xx that would have given another is logged.
//!
//! Three things end a subscription without the script asking:
//!
//! - Timer N (§4.1.2.4): a 2xx that no NOTIFY follows within 64*T1 is a
//!   failed attempt, and its state is removed.
//! - A non-2xx that arrives after `send()` gave up waiting and returned the
//!   subscription a NOTIFY had established (§4.1.2.1).
//! - The notifier's terminating NOTIFY, including the one that answers the
//!   script's own unsubscribe: `handle.terminate()` sends SUBSCRIBE with
//!   Expires 0 and the subscription stays until that NOTIFY, or Timer N.
//!
//! A subscription read back from the L2 cache, after a restart or on another
//! replica, is tracked again from the moment it is loaded, and a terminating
//! NOTIFY for one this map does not know removes it all the same.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use thiserror::Error;
use tracing::{debug, warn};

use super::{extract_tag, strip_nameaddr, unix_now, SubscribeDialog, SubscribeStore};
use crate::sip::headers::SipHeaders;
use crate::sip::message::SipMessage;

/// Timer N of RFC 6665 §4.1.2.4, 64*T1 with T1 at its 500 ms default: how long
/// a subscriber waits for the NOTIFY a SUBSCRIBE must be followed by.
pub const TIMER_N: Duration = Duration::from_secs(32);

/// What the notifier contributes to a subscription dialog: its tag, its URI,
/// where in-dialog requests go, the route they take and how long it grants.
#[derive(Debug)]
pub struct RemoteParty {
    tag: String,
    uri: String,
    /// The Contact, when the message carried one.
    target: Option<String>,
    route_set: Vec<String>,
    /// The duration the message states: the Expires of a 2xx, or the
    /// `expires` of a NOTIFY's Subscription-State.
    expires: Option<u64>,
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
            expires: notify
                .headers
                .get("Subscription-State")
                .and_then(|value| subscription_state_expires(value)),
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
            expires: response
                .headers
                .get("Expires")
                .and_then(|value| value.trim().parse().ok()),
        })
    }

    /// The dialog `pending` becomes with this notifier.  A missing Contact
    /// leaves the target the dialog was registered with, which is the
    /// SUBSCRIBE's Request-URI.  The duration is the notifier's when it
    /// states a shorter one than was asked for; it cannot grant a longer one
    /// (RFC 6665 §4.1.2.1).
    fn establish(&self, pending: &SubscribeDialog) -> SubscribeDialog {
        let mut dialog = pending.clone();
        dialog.remote_tag.clone_from(&self.tag);
        dialog.remote_uri.clone_from(&self.uri);
        if let Some(target) = &self.target {
            dialog.remote_target.clone_from(target);
        }
        dialog.route_set.clone_from(&self.route_set);
        if let Some(granted) = self.expires {
            dialog.expires_secs = dialog.expires_secs.min(granted);
        }
        dialog.created_at_unix = unix_now();
        dialog
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
fn is_terminated(notify: &SipMessage) -> bool {
    notify
        .headers
        .get("Subscription-State")
        .is_some_and(|value| {
            let state = value.split(';').next().unwrap_or_default().trim();
            state.eq_ignore_ascii_case("terminated")
        })
}

/// The `expires` parameter of a Subscription-State value (RFC 6665 §4.1.2.2).
fn subscription_state_expires(value: &str) -> Option<u64> {
    value.split(';').skip(1).find_map(|parameter| {
        let (name, seconds) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("expires")
            .then(|| seconds.trim().parse().ok())?
    })
}

/// One outbound subscription, as the store tracks it by Call-ID.
pub(super) struct OutboundSubscription {
    id: String,
    local_tag: String,
    event: String,
    /// The `send()` that made it has not learned its outcome yet.
    awaiting_response: bool,
    state: OutboundState,
    /// When its SUBSCRIBE left, which is when Timer N started.
    subscribed_at: Instant,
    /// A NOTIFY has arrived for it, which stops Timer N.
    notified: bool,
    /// A NOTIFY supplied the remote target.  Until one has, the 2xx may.
    target_from_notify: bool,
}

enum OutboundState {
    /// The subscriber's half of the dialog, waiting for the notifier's.
    Pending(Box<SubscribeDialog>),
    /// The dialog is among the store's live dialogs, with this notifier tag.
    Established { remote_tag: String },
    /// Established and then over, by a terminating NOTIFY or by the script,
    /// before its `send()` returned.  Kept until that `send()` settles, so
    /// that nothing arriving meanwhile revives it.
    Ended,
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
    subscription: Ended,
}

/// Which subscription a terminating NOTIFY ends.
enum Ended {
    /// One this store tracks.
    Tracked { id: String },
    /// One this store does not track: a NOTIFY for a subscription made by
    /// another process, which a handler may load from the L2 cache while it
    /// runs.  Looked up by its dialog once the handlers have returned.
    ByDialog {
        call_id: String,
        local_tag: String,
        remote_tag: String,
    },
}

impl Drop for EndedSubscription {
    fn drop(&mut self) {
        let id = match &self.subscription {
            Ended::Tracked { id } => id.clone(),
            Ended::ByDialog {
                call_id,
                local_tag,
                remote_tag,
            } => {
                match self
                    .store
                    .find_by_tags(call_id, local_tag, remote_tag)
                    .filter(|dialog| dialog.is_outbound)
                {
                    Some(dialog) => dialog.id,
                    None => return,
                }
            }
        };
        self.store.discard(&id);
        debug!(%id, "subscribe_state: outbound dialog terminated by NOTIFY");
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
    /// The Call-ID of the SUBSCRIBE, which is what a response that arrives
    /// after this registration settled is placed by.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The 2xx to the SUBSCRIBE arrived.  Returns the subscription's id.
    ///
    /// With no NOTIFY ahead of it the 2xx establishes the dialog, and
    /// `notifier` must be a dialog-forming 2xx.  After a NOTIFY the dialog is
    /// the NOTIFY's, route set included (RFC 6665 §4.4.1), and the 2xx only
    /// completes the transaction, whatever tag it carries (§5.4.9).
    ///
    /// The id is returned as well when a NOTIFY has already terminated the
    /// subscription.  That is the same exchange as a 2xx followed by the
    /// terminating NOTIFY, where the id was handed out before anything could
    /// say it would end, so it has the same result: the id of a subscription
    /// that no longer exists.
    pub fn accepted(
        self,
        notifier: Result<RemoteParty, &'static str>,
    ) -> Result<String, AttemptFailure> {
        self.settle(Some(notifier))
    }

    /// No final response arrived.  The subscription stands if a NOTIFY
    /// established it (RFC 6665 §4.1.2), and its id is returned, also when a
    /// later NOTIFY has terminated it since.
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
        if matches!(entry.get().state, OutboundState::Ended) {
            // Nothing is left to track, and nothing is brought back.
            entry.remove();
            self.kept = true;
            return Ok(self.id.clone());
        }
        let subscription = entry.get_mut();
        match &subscription.state {
            // Settled just above.
            OutboundState::Ended => {}
            OutboundState::Established { .. } => {
                if let Some(Ok(notifier)) = &response {
                    store.reconcile_with_response(subscription, notifier);
                }
            }
            OutboundState::Pending(pending) => {
                let notifier = response
                    .ok_or(AttemptFailure::Unanswered)?
                    .map_err(AttemptFailure::Malformed)?;
                let dialog = notifier.establish(pending);
                store.dialogs.insert(dialog.id.clone(), dialog);
                subscription.state = OutboundState::Established {
                    remote_tag: notifier.tag,
                };
            }
        }
        subscription.awaiting_response = false;
        drop(entry);
        self.kept = true;
        // L2 learns of the subscription here and not from an early NOTIFY, so
        // that an attempt which fails afterwards has nothing to take back out.
        if let Some(dialog) = store.get_local(&self.id) {
            store.persist(&dialog);
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
                subscribed_at: Instant::now(),
                notified: false,
                target_from_notify: false,
                state: OutboundState::Pending(Box::new(dialog)),
            },
        );
        registration
    }

    /// Track an outbound subscription that was read back from the L2 cache:
    /// one made before a restart, or by another replica.  It is past the
    /// stage Timer N guards, and its target is whatever was stored.
    pub(super) fn track_restored(&self, dialog: &SubscribeDialog) {
        if !dialog.is_outbound || dialog.terminated {
            return;
        }
        self.outbound
            .entry(dialog.call_id.clone())
            .or_insert_with(|| OutboundSubscription {
                id: dialog.id.clone(),
                local_tag: dialog.local_tag.clone(),
                event: dialog.event.clone(),
                awaiting_response: false,
                subscribed_at: Instant::now(),
                notified: true,
                target_from_notify: true,
                state: OutboundState::Established {
                    remote_tag: dialog.remote_tag.clone(),
                },
            });
    }

    /// Number of outbound subscriptions whose `send()` has yet to settle
    /// them: nothing established, or ended while it waits.
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
    /// is the subscription's, and refreshes its target and its duration.  One
    /// from any other tag is refused (§5.4.9).  One that says `terminated`
    /// ends the subscription once delivered.
    pub fn notify_received(self: &Arc<Self>, notify: &SipMessage) -> NotifyDisposition {
        let Some(call_id) = notify.headers.call_id() else {
            return NotifyDisposition::Deliver;
        };
        let to_tag = header(&notify.headers, "To", "t").and_then(|to| extract_tag(to));
        {
            // A read that costs one lookup for the NOTIFY that is not ours.
            let Some(subscription) = self.outbound.get(call_id.as_str()) else {
                return self.untracked_notify(notify, call_id, to_tag);
            };
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
        let terminated = is_terminated(notify);
        match &subscription.state {
            OutboundState::Pending(pending) => {
                // Also for a terminating NOTIFY, for as long as its handlers
                // run: the script's lookup is how it knows whose NOTIFY it is.
                let dialog = notifier.establish(pending);
                self.dialogs.insert(dialog.id.clone(), dialog);
                debug!(id = %subscription.id, "subscribe_state: outbound dialog established by NOTIFY");
                subscription.state = OutboundState::Established {
                    remote_tag: notifier.tag.clone(),
                };
            }
            OutboundState::Established { remote_tag } if *remote_tag == notifier.tag => {
                if !terminated {
                    self.refresh_from_notify(&subscription.id, &notifier);
                }
            }
            OutboundState::Established { .. } | OutboundState::Ended => {
                return NotifyDisposition::Reject;
            }
        }
        subscription.notified = true;
        subscription.target_from_notify |= notifier.target.is_some();
        if !terminated {
            return NotifyDisposition::Deliver;
        }
        let id = subscription.id.clone();
        if subscription.awaiting_response {
            subscription.state = OutboundState::Ended;
        }
        drop(entry);
        NotifyDisposition::DeliverThenEnd(EndedSubscription {
            store: Arc::clone(self),
            subscription: Ended::Tracked { id },
        })
    }

    /// A NOTIFY whose Call-ID this map does not know.  It is not a
    /// subscription this process is tracking, and the script decides what it
    /// is.  One that terminates a subscription may still be ending one the
    /// script reads from the L2 cache while it handles it, so that is looked
    /// for once the handlers have returned.
    fn untracked_notify(
        self: &Arc<Self>,
        notify: &SipMessage,
        call_id: &str,
        to_tag: Option<String>,
    ) -> NotifyDisposition {
        if !is_terminated(notify) {
            return NotifyDisposition::Deliver;
        }
        let from_tag = header(&notify.headers, "From", "f").and_then(|from| extract_tag(from));
        match (to_tag, from_tag) {
            (Some(local_tag), Some(remote_tag)) => {
                NotifyDisposition::DeliverThenEnd(EndedSubscription {
                    store: Arc::clone(self),
                    subscription: Ended::ByDialog {
                        call_id: call_id.to_string(),
                        local_tag,
                        remote_tag,
                    },
                })
            }
            _ => NotifyDisposition::Deliver,
        }
    }

    /// Apply what a NOTIFY from the dialog's notifier says about the dialog.
    ///
    /// A NOTIFY is a target refresh request, so its Contact replaces the
    /// remote target (RFC 6665 §4.4.1, RFC 3261 §12.2.2).  The `expires` of
    /// its Subscription-State is how long the notifier will keep the
    /// subscription, and shortens ours when it is less than we assumed
    /// (§4.1.2.2); it never lengthens it, which only a refresh does.
    fn refresh_from_notify(&self, id: &str, notifier: &RemoteParty) {
        let Some(dialog) = self.get_local(id) else {
            return;
        };
        let target = notifier
            .target
            .as_ref()
            .filter(|target| **target != dialog.remote_target);
        let duration = notifier
            .expires
            .filter(|granted| shortens(&dialog, *granted));
        if target.is_none() && duration.is_none() {
            return;
        }
        self.update(id, |dialog| {
            if let Some(target) = target {
                dialog.remote_target.clone_from(target);
            }
            if let Some(granted) = duration {
                dialog.refresh(granted);
            }
        });
    }

    /// Apply what the 2xx to the SUBSCRIBE says to a dialog a NOTIFY already
    /// established.  A 2xx from another fork says nothing about it (RFC 6665
    /// §5.4.9).  From the dialog's notifier it supplies the remote target
    /// only when no NOTIFY has, and a shorter duration when it grants one
    /// (§4.1.2.1), so that the dialog holds the same whichever came first.
    fn reconcile_with_response(&self, subscription: &OutboundSubscription, notifier: &RemoteParty) {
        let OutboundState::Established { remote_tag } = &subscription.state else {
            return;
        };
        if *remote_tag != notifier.tag {
            return;
        }
        let Some(dialog) = self.get_local(&subscription.id) else {
            return;
        };
        if dialog.route_set != notifier.route_set {
            // RFC 3261 §12.1: fixed by whichever established the dialog.
            warn!(
                id = %subscription.id,
                from_notify = ?dialog.route_set,
                from_response = ?notifier.route_set,
                "subscribe_state: the 2xx and the NOTIFY that preceded it give different route \
                 sets; keeping the NOTIFY's"
            );
        }
        let target = notifier
            .target
            .as_ref()
            .filter(|target| !subscription.target_from_notify && **target != dialog.remote_target);
        let duration = notifier
            .expires
            .filter(|granted| shortens(&dialog, *granted));
        if target.is_none() && duration.is_none() {
            return;
        }
        // Not written through to L2 here: the caller does that once.
        if let Some(mut entry) = self.dialogs.get_mut(&subscription.id) {
            if let Some(target) = target {
                entry.remote_target.clone_from(target);
            }
            if let Some(granted) = duration {
                entry.refresh(granted);
            }
        }
    }

    /// The final response to a SUBSCRIBE whose `send()` had stopped waiting
    /// and returned the subscription a NOTIFY established.  `None` is a
    /// non-2xx: no subscription was created after all (RFC 6665 §4.1.2.1),
    /// and it is withdrawn.  A 2xx is reconciled with the dialog as it would
    /// have been in time.
    pub fn late_response(
        &self,
        call_id: &str,
        id: &str,
        response: Option<Result<RemoteParty, &'static str>>,
    ) {
        match response {
            Some(Ok(notifier)) => {
                let Some(subscription) = self.outbound.get(call_id) else {
                    return;
                };
                if subscription.id != id {
                    return;
                }
                self.reconcile_with_response(&subscription, &notifier);
                drop(subscription);
                if let Some(dialog) = self.get_local(id) {
                    self.persist(&dialog);
                }
            }
            // Established by a NOTIFY, so a 2xx that could not have
            // established it changes nothing.
            Some(Err(_)) => {}
            None => {
                let rejected = self
                    .outbound
                    .get(call_id)
                    .is_some_and(|subscription| subscription.id == id);
                if rejected {
                    self.discard(id);
                    warn!(
                        id,
                        "subscribe_state: the SUBSCRIBE was rejected after a NOTIFY had established \
                         the subscription; withdrawn"
                    );
                }
            }
        }
    }

    /// Keep waiting for the final response to a SUBSCRIBE whose `send()` has
    /// returned, and apply it with [`Self::late_response`] when it comes.
    /// Ends with the transaction: the receiver closes when the UAC gives the
    /// request up.
    pub fn await_late_response(
        self: &Arc<Self>,
        call_id: String,
        id: String,
        receiver: tokio::sync::oneshot::Receiver<crate::uac::UacResult>,
    ) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            if let Ok(crate::uac::UacResult::Response(response)) = receiver.await {
                let status = response.status_code().unwrap_or(0);
                let accepted = (200..300)
                    .contains(&status)
                    .then(|| RemoteParty::from_subscribe_response(&response));
                store.late_response(&call_id, &id, accepted);
            }
        });
    }

    /// The script unsubscribed: a SUBSCRIBE with Expires 0 has been sent.
    /// The subscription is not over until the notifier's terminating NOTIFY
    /// (RFC 6665 §4.1.2.3), which the script's handler has to be able to find
    /// it for.  It is given Timer N to arrive, and reaped with the expired
    /// dialogs when it does not.
    pub fn unsubscribed(&self, id: &str) {
        self.update(id, |dialog| dialog.refresh(TIMER_N.as_secs()));
    }

    /// Remove the outbound subscriptions whose SUBSCRIBE was accepted
    /// `older_than` ago with no NOTIFY since, and return them.  Timer N of
    /// RFC 6665 §4.1.2.4: the subscriber "considers the subscription failed,
    /// and cleans up any state associated with the subscription attempt".
    pub(super) fn take_unnotified(&self, older_than: Duration) -> Vec<SubscribeDialog> {
        let overdue: Vec<String> = self
            .outbound
            .iter()
            .filter(|subscription| {
                !subscription.notified
                    && !subscription.awaiting_response
                    && matches!(subscription.state, OutboundState::Established { .. })
                    && subscription.subscribed_at.elapsed() >= older_than
            })
            .map(|subscription| subscription.id.clone())
            .collect();
        let mut failed = Vec::with_capacity(overdue.len());
        for id in overdue {
            if let Some(dialog) = self.get_local(&id) {
                self.discard(&id);
                warn!(
                    %id,
                    call_id = %dialog.call_id,
                    "subscribe_state: no NOTIFY followed the 2xx within Timer N; the subscription \
                     attempt failed and its state is removed"
                );
                failed.push(dialog);
            }
        }
        failed
    }

    /// A dialog left the live dialogs: stop tracking it as an outbound
    /// subscription.  While its `send()` is still waiting, the entry stays as
    /// ended until that `send()` settles.
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
            subscription.state = OutboundState::Ended;
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

/// Whether the notifier keeping the subscription for `granted` seconds from
/// now ends it sooner than `dialog` assumes.  A second of slack, so that the
/// same duration read a moment apart is not a change.
fn shortens(dialog: &SubscribeDialog, granted: u64) -> bool {
    granted.saturating_add(1) < dialog.remaining_secs()
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
        // The NOTIFY that follows is the subscription's.  It is a target
        // refresh request, so its Contact is the remote target from here on
        // (RFC 6665 §4.4.1); the route set stays the dialog's.
        assert!(delivered(&store.notify_received(&active("a"))));
        assert_eq!(store.local_count(), 1);
        let dialog = store.get_local("a").expect("still there");
        assert_eq!(dialog.remote_target, "sip:notifier@192.0.2.30:5060");
        assert_eq!(dialog.route_set, ROUTE_OF_THE_NOTIFY);
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

        // Nothing revives it: not a later NOTIFY, not the 2xx.  The 2xx
        // still completes the attempt with the subscription's id, as it would
        // have had it come first.
        assert!(matches!(
            store.notify_received(&active("a")),
            NotifyDisposition::Reject
        ));
        assert_eq!(
            registration
                .accepted(two_hundred("a", NOTIFIER_TAG))
                .as_deref(),
            Ok("a")
        );
        assert_eq!(store.outbound_count(), 0);
        assert_eq!(store.local_count(), 0);
        assert!(store.get_local("a").is_none());
    }

    /// What one exchange leaves behind and hands its `send()`, for the events
    /// applied in the order given: `2` the 2xx, `a` an active NOTIFY, `t` a
    /// terminating NOTIFY, `x` a non-2xx, `u` no final response.
    fn outcome_of(order: &str) -> (Result<String, AttemptFailure>, usize, usize) {
        let store = Arc::new(SubscribeStore::new());
        let mut registration = Some(store.register_pending(subscription("a")));
        let mut result = Err(AttemptFailure::Unanswered);
        for event in order.chars() {
            match event {
                'a' => drop(store.notify_received(&active("a"))),
                't' => drop(store.notify_received(&notify(
                    "a",
                    NOTIFIER_TAG,
                    "reg",
                    "terminated;reason=timeout",
                ))),
                '2' => {
                    if let Some(registration) = registration.take() {
                        result = registration.accepted(two_hundred("a", NOTIFIER_TAG));
                    }
                }
                'u' => {
                    if let Some(registration) = registration.take() {
                        result = registration.unanswered();
                    }
                }
                'x' => drop(registration.take()),
                other => panic!("unknown event {other:?}"),
            }
        }
        (result, store.local_count(), store.outbound_count())
    }

    /// The 2xx and the NOTIFYs race, so the same events in another order are
    /// the same exchange and must leave the same state and the same answer.
    #[test]
    fn the_outcome_does_not_depend_on_which_message_arrived_first() {
        let kept = (Ok("a".to_string()), 1, 1);
        let ended = (Ok("a".to_string()), 0, 0);
        let refused = (Err(AttemptFailure::Unanswered), 0, 0);
        for (orders, expected) in [
            // Accepted and notified: the subscription stands.
            (&["2a", "a2"][..], &kept),
            // Accepted and terminated: send() has its id, nothing is left.
            (&["2t", "t2", "2at", "a2t", "at2"][..], &ended),
            // Rejected: nothing, whatever the notifier sent besides.
            (&["x", "ax", "tx", "atx"][..], &refused),
        ] {
            for order in orders {
                assert_eq!(
                    &outcome_of(order),
                    expected,
                    "events in the order {order:?}"
                );
            }
        }
        // Never answered: only a NOTIFY can have established it, and one that
        // then terminated it leaves the id of a subscription that is gone.
        assert_eq!(outcome_of("u"), refused);
        assert_eq!(outcome_of("au"), kept);
        assert_eq!(outcome_of("tu"), ended);
        assert_eq!(outcome_of("atu"), ended);
    }

    /// An event that arrives twice changes nothing the second time.
    #[test]
    fn a_repeated_event_changes_nothing() {
        assert_eq!(outcome_of("2aa"), outcome_of("2a"));
        assert_eq!(outcome_of("aa2"), outcome_of("a2"));
        assert_eq!(outcome_of("2tt"), outcome_of("2t"));
        assert_eq!(outcome_of("tt2"), outcome_of("t2"));
        assert_eq!(outcome_of("t2t"), outcome_of("t2"));
        assert_eq!(outcome_of("2ta"), outcome_of("2t"));
        assert_eq!(outcome_of("ta2"), outcome_of("t2"));
    }

    #[test]
    fn a_terminated_notify_after_an_active_one_also_ends_the_attempt() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        drop(store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "terminated")));

        assert_eq!(registration.unanswered().as_deref(), Ok("a"));
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

        assert_eq!(
            registration
                .accepted(two_hundred("a", NOTIFIER_TAG))
                .as_deref(),
            Ok("a")
        );
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

    /// The 2xx of `accepted`, with its Contact and Expires replaced or, for
    /// `None`, taken out.
    fn two_hundred_with(
        id: &str,
        contact: Option<&str>,
        expires: Option<u64>,
    ) -> Result<RemoteParty, &'static str> {
        let mut raw = format!(
            concat!(
                "SIP/2.0 200 OK\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uac-py-1\r\n",
                "From: <sip:watcher@example.com>;tag=local-{id}\r\n",
                "To: <sip:001010123456789@example.com>;tag={tag}\r\n",
                "Call-ID: call-{id}\r\n",
                "CSeq: 1 SUBSCRIBE\r\n",
                "Record-Route: <sip:far.example.com;lr>\r\n",
                "Record-Route: <sip:near.example.com;lr>\r\n",
            ),
            id = id,
            tag = NOTIFIER_TAG,
        );
        if let Some(contact) = contact {
            raw.push_str(&format!("Contact: <{contact}>\r\n"));
        }
        if let Some(expires) = expires {
            raw.push_str(&format!("Expires: {expires}\r\n"));
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        let response = parse_sip_message_bytes(raw.as_bytes()).expect("the 2xx parses");
        RemoteParty::from_subscribe_response(&response)
    }

    /// The NOTIFY of `notify`, with its Contact replaced or taken out.
    fn notify_with(id: &str, contact: Option<&str>, subscription_state: &str) -> SipMessage {
        let mut message = notify(id, NOTIFIER_TAG, "reg", subscription_state);
        match contact {
            Some(contact) => message.headers.set("Contact", format!("<{contact}>")),
            None => message.headers.remove("Contact"),
        }
        message
    }

    /// What the dialog of one exchange holds: its remote target, its route
    /// set, and its duration to the nearest ten seconds.
    fn dialog_after(
        order: &str,
        response: (Option<&str>, Option<u64>),
        notification: (Option<&str>, &str),
    ) -> (String, Vec<String>, u64) {
        let store = Arc::new(SubscribeStore::new());
        let mut registration = Some(store.register_pending(subscription("a")));
        for event in order.chars() {
            match event {
                '2' => {
                    let registration = registration.take().expect("one 2xx");
                    let accepted =
                        registration.accepted(two_hundred_with("a", response.0, response.1));
                    assert_eq!(accepted.as_deref(), Ok("a"));
                }
                'n' => {
                    drop(store.notify_received(&notify_with("a", notification.0, notification.1)))
                }
                other => panic!("unknown event {other:?}"),
            }
        }
        let dialog = store.get_local("a").expect("the subscription stands");
        (
            dialog.remote_target.clone(),
            dialog.route_set.clone(),
            (dialog.remaining_secs() + 5) / 10 * 10,
        )
    }

    /// The 2xx and the NOTIFY race, so the dialog must hold the same target
    /// and the same duration whichever arrived first.
    #[test]
    fn the_dialog_holds_the_same_whichever_message_came_first() {
        let accepted = "sip:accepted@192.0.2.30:5060";
        let notifier = "sip:notifier@192.0.2.30:5060";
        let route: Vec<String> = ROUTE_OF_THE_NOTIFY
            .iter()
            .map(ToString::to_string)
            .collect();
        for (response, notification, expected) in [
            // Both state a target and a duration: the NOTIFY's target, and
            // the shorter duration.
            (
                (Some(accepted), Some(300)),
                (Some(notifier), "active;expires=120"),
                (notifier, 120),
            ),
            (
                (Some(accepted), Some(120)),
                (Some(notifier), "active;expires=300"),
                (notifier, 120),
            ),
            // A NOTIFY without a Contact leaves the 2xx's.
            (
                (Some(accepted), Some(300)),
                (None, "active;expires=300"),
                (accepted, 300),
            ),
            // Neither states a duration: the one that was asked for.
            (
                (Some(accepted), None),
                (Some(notifier), "active"),
                (notifier, 600),
            ),
            // A notifier cannot grant more than was asked for.
            (
                (Some(accepted), Some(3600)),
                (Some(notifier), "active;expires=7200"),
                (notifier, 600),
            ),
        ] {
            let expected = (expected.0.to_string(), route.clone(), expected.1);
            for order in ["2n", "n2", "2nn", "n2n", "nn2"] {
                assert_eq!(
                    dialog_after(order, response, notification),
                    expected,
                    "events in the order {order:?}, 2xx {response:?}, NOTIFY {notification:?}"
                );
            }
        }
    }

    /// RFC 6665 §4.1.2.2: the notifier may shorten the subscription in any
    /// NOTIFY.  Only a refresh the subscriber sends lengthens it.
    #[test]
    fn a_notify_shortens_the_subscription_and_never_lengthens_it() {
        let store = Arc::new(SubscribeStore::new());
        assert!(store
            .register_pending(subscription("a"))
            .accepted(two_hundred("a", NOTIFIER_TAG))
            .is_ok());
        assert_eq!(store.get_local("a").map(|d| d.expires_secs), Some(600));

        let _ = store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "active;expires=90"));
        assert_eq!(store.get_local("a").map(|d| d.expires_secs), Some(90));

        let _ = store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "active;expires=900"));
        assert_eq!(store.get_local("a").map(|d| d.expires_secs), Some(90));
        // Read again a moment later it is the same duration, not a change.
        let _ = store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "active;expires=89"));
        assert_eq!(store.get_local("a").map(|d| d.expires_secs), Some(90));
    }

    #[test]
    fn subscription_state_expires_is_read_from_any_position() {
        assert_eq!(subscription_state_expires("active;expires=600"), Some(600));
        assert_eq!(
            subscription_state_expires("pending ; reason=x ; Expires = 30"),
            Some(30)
        );
        assert_eq!(subscription_state_expires("active"), None);
        assert_eq!(subscription_state_expires("active;expires=soon"), None);
        assert_eq!(
            subscription_state_expires("terminated;reason=timeout"),
            None
        );
    }

    /// RFC 6665 §4.1.2.4, Timer N: a 2xx that no NOTIFY follows is a failed
    /// attempt, and its state is cleaned up.
    #[test]
    fn a_2xx_that_no_notify_follows_is_reaped_at_timer_n() {
        let store = Arc::new(SubscribeStore::new());
        assert!(store
            .register_pending(subscription("silent"))
            .accepted(two_hundred("silent", NOTIFIER_TAG))
            .is_ok());
        assert!(store
            .register_pending(subscription("notified"))
            .accepted(two_hundred("notified", NOTIFIER_TAG))
            .is_ok());
        let _ = store.notify_received(&active("notified"));
        // Still in its transaction: Timer N has not been reached by a
        // `send()` that is still waiting, whatever its age.
        let _waiting = store.register_pending(subscription("waiting"));
        let _ = store.notify_received(&active("waiting"));
        let _unanswered = store.register_pending(subscription("unanswered"));

        // Inside Timer N nothing is touched.
        assert!(store.take_stale().is_empty());
        assert_eq!(store.local_count(), 3);

        let failed = store.take_unnotified(Duration::ZERO);
        assert_eq!(
            failed
                .iter()
                .map(|dialog| dialog.id.as_str())
                .collect::<Vec<_>>(),
            ["silent"]
        );
        assert!(store.get_local("silent").is_none());
        assert!(store.get_local("notified").is_some());
        assert!(store.get_local("waiting").is_some());
        assert_eq!(store.outbound_count(), 3);
        // Reaping it twice finds nothing more.
        assert!(store.take_unnotified(Duration::ZERO).is_empty());
        // A NOTIFY for it now matches no subscription.
        assert!(delivered(&store.notify_received(&active("silent"))));
        assert_eq!(store.local_count(), 2);
    }

    /// RFC 6665 §4.1.2.3: an unsubscribe is answered by a terminating NOTIFY,
    /// and the subscription exists until it arrives.
    #[test]
    fn an_unsubscribed_subscription_lasts_until_its_terminating_notify() {
        let store = Arc::new(SubscribeStore::new());
        assert!(store
            .register_pending(subscription("a"))
            .accepted(two_hundred("a", NOTIFIER_TAG))
            .is_ok());
        let _ = store.notify_received(&active("a"));

        store.unsubscribed("a");

        let dialog = store
            .find_by_tags("call-a", "local-a", NOTIFIER_TAG)
            .expect("the final NOTIFY has a subscription to find");
        assert!(dialog.remaining_secs() <= TIMER_N.as_secs());
        // A NOTIFY that crossed the unsubscribe does not give it its old
        // duration back.
        let _ = store.notify_received(&active("a"));
        assert!(store.get_local("a").expect("still there").remaining_secs() <= TIMER_N.as_secs());

        let last = store.notify_received(&notify(
            "a",
            NOTIFIER_TAG,
            "reg",
            "terminated;reason=timeout",
        ));
        assert!(matches!(last, NotifyDisposition::DeliverThenEnd(_)));
        assert!(store.get_local("a").is_some(), "found while it is handled");
        drop(last);
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);
    }

    /// And when that NOTIFY never comes, Timer N ends it.
    #[test]
    fn an_unsubscribed_subscription_is_reaped_when_no_notify_answers() {
        let store = Arc::new(SubscribeStore::new());
        assert!(store
            .register_pending(subscription("a"))
            .accepted(two_hundred("a", NOTIFIER_TAG))
            .is_ok());
        let _ = store.notify_received(&active("a"));
        store.unsubscribed("a");
        assert!(store.take_stale().is_empty(), "not before Timer N");

        // Timer N later.
        store.update("a", |dialog| dialog.created_at_unix -= TIMER_N.as_secs());
        assert_eq!(store.take_stale().len(), 1);
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);
    }

    /// RFC 6665 §4.1.2.1: a non-2xx says no subscription was created, also
    /// when it arrives after `send()` stopped waiting for it.
    #[test]
    fn a_late_rejection_withdraws_the_subscription_a_notify_established() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&active("a"));
        assert_eq!(registration.unanswered().as_deref(), Ok("a"));
        assert_eq!(store.local_count(), 1);

        // Another subscription's response does not touch this one.
        store.late_response("call-a", "someone-else", None);
        store.late_response("call-b", "a", None);
        assert_eq!(store.local_count(), 1);

        store.late_response("call-a", "a", None);
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);
        // And again: nothing is left to withdraw.
        store.late_response("call-a", "a", None);
        assert_eq!(store.local_count(), 0);
    }

    #[test]
    fn a_late_2xx_is_reconciled_as_one_in_time_would_have_been() {
        let store = Arc::new(SubscribeStore::new());
        let registration = store.register_pending(subscription("a"));
        let _ = store.notify_received(&notify_with("a", None, "active"));
        assert_eq!(registration.unanswered().as_deref(), Ok("a"));

        store.late_response(
            "call-a",
            "a",
            Some(two_hundred_with(
                "a",
                Some("sip:accepted@192.0.2.30:5060"),
                Some(120),
            )),
        );

        let dialog = store.get_local("a").expect("still there");
        assert_eq!(dialog.remote_target, "sip:accepted@192.0.2.30:5060");
        assert_eq!(dialog.expires_secs, 120);
        // A 2xx that could not have established a dialog changes nothing.
        store.late_response("call-a", "a", Some(untagged_2xx()));
        assert_eq!(store.local_count(), 1);
    }

    /// A subscription read back from the L2 cache, after a restart or on
    /// another replica, is placed against its NOTIFYs like one made here.
    #[test]
    fn a_restored_subscription_is_tracked_again() {
        let store = Arc::new(SubscribeStore::new());
        let mut restored = subscription("a");
        restored.remote_tag = NOTIFIER_TAG.to_string();
        store.dialogs.insert("a".to_string(), restored.clone());
        store.track_restored(&restored);
        // Loading it twice tracks it once.
        store.track_restored(&restored);
        assert_eq!(store.outbound_count(), 1);
        // It is past Timer N by definition.
        assert!(store.take_unnotified(Duration::ZERO).is_empty());

        assert!(matches!(
            store.notify_received(&notify("a", "another-fork", "reg", "active")),
            NotifyDisposition::Reject
        ));
        assert!(delivered(&store.notify_received(&active("a"))));
        drop(store.notify_received(&notify("a", NOTIFIER_TAG, "reg", "terminated")));
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);

        // A notifier-side dialog is never tracked as a subscription of ours.
        let mut inbound = subscription("b");
        inbound.is_outbound = false;
        store.track_restored(&inbound);
        assert_eq!(store.outbound_count(), 0);
    }

    /// A terminating NOTIFY for a subscription this map does not track ends
    /// the one its handler loaded, once the handler has returned.
    #[test]
    fn a_terminating_notify_ends_a_subscription_loaded_while_it_is_handled() {
        let store = Arc::new(SubscribeStore::new());
        let terminating = notify("a", NOTIFIER_TAG, "reg", "terminated;reason=timeout");

        let disposition = store.notify_received(&terminating);
        assert!(matches!(disposition, NotifyDisposition::DeliverThenEnd(_)));
        // The handler reads the subscription from the cache.
        let mut loaded = subscription("a");
        loaded.remote_tag = NOTIFIER_TAG.to_string();
        store.dialogs.insert("a".to_string(), loaded.clone());
        store.track_restored(&loaded);
        drop(disposition);
        assert_eq!(store.local_count(), 0);
        assert_eq!(store.outbound_count(), 0);

        // Nothing was loaded: nothing is removed, and nothing breaks.
        drop(store.notify_received(&terminating));
        // A notifier-side dialog with those tags is not a subscription of
        // ours, and a NOTIFY does not remove it.
        let mut inbound = subscription("b");
        inbound.is_outbound = false;
        inbound.remote_tag = NOTIFIER_TAG.to_string();
        store.put(inbound);
        drop(store.notify_received(&notify("b", NOTIFIER_TAG, "reg", "terminated")));
        assert_eq!(store.local_count(), 1);
        // An active NOTIFY it does not track costs it nothing.
        assert!(delivered(&store.notify_received(&active("c"))));
    }
}
