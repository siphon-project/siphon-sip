//! SIP presence server — subscription state machine and presence document store.
//!
//! Implements RFC 3856 (SIP presence) and RFC 3903 (SIP PUBLISH) state management.
//! Subscriptions track watchers of a presentity, while presence documents hold
//! the published presence state (typically PIDF XML).
//!
//! Uses `DashMap` for lock-free concurrent access from multiple Tokio tasks.

pub mod metrics;
pub mod persist;
pub mod pidf;
pub mod rls;
pub mod winfo;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

use crate::registrar::backend::WriteSequence;
use persist::{PresenceBackendWriter, StoredSubscription};

/// Process-wide presence store, installed at startup so background tasks
/// (the dispatcher cleanup tick) can reach it to expire stale documents and
/// subscriptions without going through the Python namespace singleton.
/// Mirrors [`crate::subscribe_state`]'s global handle.
static GLOBAL_STORE: OnceLock<Arc<PresenceStore>> = OnceLock::new();

/// Install the global presence store. Idempotent (first writer wins).
pub fn set_global_store(store: Arc<PresenceStore>) {
    let _ = GLOBAL_STORE.set(store);
}

/// Borrow the installed global presence store, if any.
pub fn global_store() -> Option<Arc<PresenceStore>> {
    GLOBAL_STORE.get().cloned()
}

/// Subscription dialog state per RFC 3265 §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Initial state — SUBSCRIBE received but not yet processed.
    Init,
    /// Active — subscription is established and receiving NOTIFYs.
    Active,
    /// Pending — awaiting authorization from the presentity.
    Pending,
    /// Terminated — subscription has ended (expired, deactivated, or rejected).
    Terminated,
}

impl std::fmt::Display for SubscriptionState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionState::Init => write!(formatter, "init"),
            SubscriptionState::Active => write!(formatter, "active"),
            SubscriptionState::Pending => write!(formatter, "pending"),
            SubscriptionState::Terminated => write!(formatter, "terminated"),
        }
    }
}

/// A single subscription — one watcher watching one resource.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Unique subscription identifier.
    pub id: String,
    /// Subscriber URI (the watcher).
    pub subscriber: String,
    /// Resource/presentity URI being watched.
    pub resource: String,
    /// Event package name (e.g. "presence", "dialog", "message-summary").
    pub event: String,
    /// Current subscription state.
    pub state: SubscriptionState,
    /// Subscription duration from creation/refresh.
    pub expires: Duration,
    /// When this subscription was created or last refreshed.
    pub created_at: Instant,
    /// Dialog identifier (Call-ID:from-tag:to-tag) if bound to a dialog.
    pub dialog_id: Option<String>,
    /// Accepted content types for NOTIFY bodies.
    pub accept: Vec<String>,
    // ── Dialog state for in-dialog NOTIFY (RFC 3265 §3.2.2) ──
    /// Call-ID from the SUBSCRIBE dialog.
    pub call_id: Option<String>,
    /// From-tag (the subscriber's tag — becomes To-tag in NOTIFY).
    pub from_tag: Option<String>,
    /// To-tag (the notifier's tag — becomes From-tag in NOTIFY).
    pub to_tag: Option<String>,
    /// Route set from Record-Route headers in the SUBSCRIBE dialog.
    pub route_set: Vec<String>,
    /// CSeq counter for NOTIFYs sent within this dialog.
    pub local_cseq: u32,
    /// Dialog **local URI** — the notifier's own address of record, taken from
    /// the SUBSCRIBE's To URI.  RFC 3261 §12.2.1.1 requires it in the `From` of
    /// every request sent within the dialog.
    ///
    /// `None` for subscriptions created before the URIs were captured; the
    /// notify path then falls back to `resource`, which is the notifier's URI
    /// for every package where the subscriber watches an AoR directly (the reg
    /// event package, TS 24.341 §5.3.2.4).
    pub local_uri: Option<String>,
    /// Dialog **remote URI** — the subscriber's address of record, taken from
    /// the SUBSCRIBE's From URI.  RFC 3261 §12.2.1.1 requires it in the `To` of
    /// every request sent within the dialog.
    ///
    /// This is NOT `subscriber`: that field holds the subscriber's *Contact*
    /// (the remote target), which belongs in the Request-URI only.  For the reg
    /// event package the two happen to differ only in that the Contact carries
    /// a UUID userpart and a port, which is exactly the difference a validating
    /// baseband rejects.
    pub remote_uri: Option<String>,
    /// Which incarnation of the subscription this is: assigned when it is
    /// added to a store and again on every refresh, from one process-wide
    /// counter, so no two incarnations ever share a value.  A NOTIFY records
    /// the generation it was sent under; its failure ends the subscription
    /// only while that generation is still current (see
    /// [`PresenceStore::remove_subscription_if_current`]).
    pub generation: u64,
    /// The version the next event-state document sent on this subscription
    /// carries (RFC 3680 §5.2, the reginfo `version`): 0 for a new
    /// subscription, one more for every document handed out since.  Lives
    /// with the subscription, so it goes when the subscription does.
    pub next_version: u32,
}

/// Source of [`Subscription::generation`] values.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

impl Subscription {
    /// Create a new subscription in `Init` state.
    pub fn new(
        id: String,
        subscriber: String,
        resource: String,
        event: String,
        expires: Duration,
        dialog_id: Option<String>,
        accept: Vec<String>,
    ) -> Self {
        Self {
            id,
            subscriber,
            resource,
            event,
            state: SubscriptionState::Init,
            expires,
            created_at: Instant::now(),
            dialog_id,
            accept,
            call_id: None,
            from_tag: None,
            to_tag: None,
            route_set: vec![],
            local_cseq: 0,
            local_uri: None,
            remote_uri: None,
            generation: 0,
            next_version: 0,
        }
    }

    /// Create a subscription with full dialog state from a SUBSCRIBE request.
    ///
    /// `local_uri` / `remote_uri` are the dialog's URIs (the SUBSCRIBE's To and
    /// From URIs).  They are what RFC 3261 §12.2.1.1 requires in the `From` and
    /// `To` of an in-dialog NOTIFY; `subscriber` holds the remote *target* (the
    /// Contact) and belongs in the Request-URI only.  `None` falls back to
    /// `resource` at notify time.
    #[allow(clippy::too_many_arguments)]
    pub fn with_dialog(
        id: String,
        subscriber: String,
        resource: String,
        event: String,
        expires: Duration,
        accept: Vec<String>,
        call_id: String,
        from_tag: String,
        to_tag: String,
        route_set: Vec<String>,
        local_uri: Option<String>,
        remote_uri: Option<String>,
    ) -> Self {
        let dialog_id = Some(format!("{}:{}:{}", call_id, from_tag, to_tag));
        Self {
            id,
            subscriber,
            resource,
            event,
            state: SubscriptionState::Active,
            expires,
            created_at: Instant::now(),
            dialog_id,
            accept,
            call_id: Some(call_id),
            from_tag: Some(from_tag),
            to_tag: Some(to_tag),
            route_set,
            local_cseq: 0,
            local_uri,
            remote_uri,
            generation: 0,
            next_version: 0,
        }
    }

    /// The dialog's local URI — what belongs in an in-dialog `From`.
    ///
    /// Falls back to `resource` when the dialog was created without it: for
    /// every package where the subscriber watches an AoR directly, the resource
    /// *is* the notifier's URI.  Never the Contact, which is what made a
    /// validating baseband reject the NOTIFY.
    pub fn notify_from_uri(&self) -> &str {
        self.local_uri.as_deref().unwrap_or(&self.resource)
    }

    /// The dialog's remote URI — what belongs in an in-dialog `To`.
    ///
    /// Falls back to `resource` for the same reason as
    /// [`notify_from_uri`](Self::notify_from_uri): for the reg event package the
    /// subscriber and the resource are the same AoR (TS 24.341 §5.3.2.4).  A
    /// watcher subscribed to *someone else's* resource must supply the URI at
    /// subscribe time — the Contact cannot be reduced to an AoR here, and
    /// guessing one would be worse than an AoR-shaped fallback.
    pub fn notify_to_uri(&self) -> &str {
        self.remote_uri.as_deref().unwrap_or(&self.resource)
    }

    /// Returns `true` if the subscription has exceeded its expiry duration.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.expires
    }

    /// Seconds remaining until expiry (saturates at zero).
    pub fn remaining_seconds(&self) -> u64 {
        let elapsed = self.created_at.elapsed();
        self.expires.as_secs().saturating_sub(elapsed.as_secs())
    }

    /// Transition to `Active` state.
    pub fn activate(&mut self) {
        if self.state == SubscriptionState::Terminated {
            warn!(
                subscription_id = %self.id,
                "attempted to activate a terminated subscription"
            );
            return;
        }
        debug!(subscription_id = %self.id, "subscription activated");
        self.state = SubscriptionState::Active;
    }

    /// Transition to `Terminated` state.
    pub fn terminate(&mut self) {
        debug!(subscription_id = %self.id, "subscription terminated");
        self.state = SubscriptionState::Terminated;
    }

    /// Increment and return the next CSeq for an in-dialog NOTIFY.
    pub fn next_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// The version for the next document sent on this subscription, and
    /// advance the count past it.
    ///
    /// RFC 3680 §5.2: "Versions start at 0, and increment by one for each new
    /// document sent to a subscriber.  Versions are scoped within a
    /// subscription.  Versions MUST be representable using a 32 bit
    /// integer."  Saturates at `u32::MAX` rather than wrapping to 0, which
    /// the subscriber would discard as older.
    pub fn take_version(&mut self) -> u32 {
        let version = self.next_version;
        self.next_version = version.saturating_add(1);
        version
    }

    /// Refresh the subscription with a new expiry duration, resetting the timer.
    pub fn refresh(&mut self, expires: Duration) {
        if self.state == SubscriptionState::Terminated {
            warn!(
                subscription_id = %self.id,
                "attempted to refresh a terminated subscription"
            );
            return;
        }
        debug!(
            subscription_id = %self.id,
            expires_secs = expires.as_secs(),
            "subscription refreshed"
        );
        self.expires = expires;
        self.created_at = Instant::now();
        self.generation = next_generation();
    }
}

/// A published presence document (RFC 3903 PUBLISH state).
#[derive(Debug, Clone)]
pub struct PresenceDocument {
    /// Presentity URI (the entity whose presence is published).
    pub entity: String,
    /// Entity-tag for conditional updates (RFC 3903 §4.1).
    pub etag: String,
    /// MIME content type (e.g. "application/pidf+xml").
    pub content_type: String,
    /// Presence body (PIDF XML or other format).
    pub body: String,
    /// Document expiry duration from publication time.
    pub expires: Duration,
    /// When this document was published or last refreshed.
    pub published_at: Instant,
}

impl PresenceDocument {
    /// Returns `true` if the document has exceeded its expiry duration.
    pub fn is_expired(&self) -> bool {
        self.published_at.elapsed() >= self.expires
    }
}

/// Generate a deterministic etag from entity, body content, and current time.
fn generate_etag(entity: &str, body: &str) -> String {
    let mut hasher = DefaultHasher::new();
    entity.hash(&mut hasher);
    body.hash(&mut hasher);
    // Include a monotonic timestamp to ensure uniqueness across updates
    // with identical content.
    Instant::now().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Why a NOTIFY's failure ended its subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyFailure {
    /// A final response from the set RFC 6665 §4.2.2 names.
    Rejected,
    /// No final response before Timer F, or a 408.
    TimedOut,
}

impl NotifyFailure {
    /// Every value, for exporting each metric series at zero.
    pub const ALL: [NotifyFailure; 2] = [NotifyFailure::Rejected, NotifyFailure::TimedOut];

    /// The `reason` label of `siphon_presence_subscriptions_removed_total`.
    pub fn label(self) -> &'static str {
        match self {
            NotifyFailure::Rejected => "notify_rejected",
            NotifyFailure::TimedOut => "notify_timeout",
        }
    }
}

/// Whether the outcome of a NOTIFY transaction ends its subscription:
/// `Some(status)` for the final response, `None` when none came before Timer
/// F.
///
/// RFC 6665 §4.2.2:
///
/// > If the NOTIFY request fails due to expiration of SIP Timer F
/// > (transaction timeout), the notifier SHOULD remove the subscription.
/// >
/// > If the NOTIFY transaction fails due to the receipt of a 404, 405,
/// > 410, 416, 480-485, 489, 501, or 604 response to the NOTIFY request,
/// > the notifier MUST remove the corresponding subscription.
///
/// 481 is the one a subscriber that lost the dialog answers with (§4.1.3:
/// "it MUST return a 481 (Subscription does not exist) response").  A 408
/// response counts as the timeout itself: "Receiving a 408 will have the same
/// effect on usages and dialogs as a real transaction timeout" (RFC 5057
/// §5.1, note 4).  Any other failure is a complaint about the transaction
/// only and keeps the subscription.
pub fn notify_failure(outcome: Option<u16>) -> Option<NotifyFailure> {
    match outcome {
        None | Some(408) => Some(NotifyFailure::TimedOut),
        Some(404 | 405 | 410 | 416 | 480..=485 | 489 | 501 | 604) => Some(NotifyFailure::Rejected),
        Some(_) => None,
    }
}

/// Dialog state required to build an in-dialog NOTIFY, as returned by
/// [`PresenceStore::prepare_notify`].
#[derive(Debug, Clone)]
pub struct NotifyDialogState {
    /// Subscriber Contact — the dialog's remote target, for the Request-URI
    /// and destination resolution only.
    pub subscriber: String,
    /// Dialog local URI — the `From` URI (RFC 3261 §12.2.1.1).
    pub local_uri: String,
    /// Dialog remote URI — the `To` URI (RFC 3261 §12.2.1.1).
    pub remote_uri: String,
    pub event: String,
    pub call_id: String,
    /// The subscriber's tag; becomes the NOTIFY's To-tag.
    pub from_tag: String,
    /// The notifier's tag; becomes the NOTIFY's From-tag.
    pub to_tag: String,
    pub route_set: Vec<String>,
    pub cseq: u32,
    /// The subscription's generation when the NOTIFY was prepared.
    pub generation: u64,
}

/// Concurrent presence store — manages subscriptions and published documents.
///
/// All operations are safe for concurrent access from multiple Tokio tasks
/// without external synchronization.
pub struct PresenceStore {
    /// Subscription ID → Subscription.
    subscriptions: DashMap<String, Subscription>,
    /// Presentity URI → list of published presence documents.
    documents: DashMap<String, Vec<PresenceDocument>>,
    /// Resource URI → list of subscription IDs watching that resource.
    watchers: DashMap<String, Vec<String>>,
    /// The write-through to the registrar's Redis, when it has one
    /// ([`persist`]).  Every change to a subscription is written through.
    backend: OnceLock<PresenceBackendWriter>,
}

/// A subscription's write-through, snapshotted under its entry.
type Snapshot = Option<(WriteSequence, StoredSubscription)>;

impl PresenceStore {
    /// Create an empty presence store.
    pub fn new() -> Self {
        Self {
            subscriptions: DashMap::new(),
            documents: DashMap::new(),
            watchers: DashMap::new(),
            backend: OnceLock::new(),
        }
    }

    /// Write every later change to a subscription through `writer`.  Set once,
    /// at boot, after the restore.
    pub fn set_backend_writer(&self, writer: PresenceBackendWriter) {
        let _ = self.backend.set(writer);
    }

    /// The write-through of `subscription` as it stands: call it while holding
    /// the entry, so the sequence orders the snapshot.
    fn snapshot(&self, subscription: &Subscription) -> Snapshot {
        let writer = self.backend.get()?;
        Some((writer.sequence(), StoredSubscription::of(subscription)))
    }

    /// Hand a snapshot taken under the entry to the writer.
    fn write_through(&self, snapshot: Snapshot) {
        if let (Some(writer), Some((sequence, stored))) = (self.backend.get(), snapshot) {
            writer.save_at(&stored, sequence);
        }
    }

    /// The sequence of a removal: call it while holding the entry.
    fn removal_sequence(&self) -> Option<WriteSequence> {
        self.backend.get().map(PresenceBackendWriter::sequence)
    }

    /// Hand the removal of `id` decided at `sequence` to the writer.
    fn write_removal(&self, id: &str, sequence: Option<WriteSequence>) {
        if let (Some(writer), Some(sequence)) = (self.backend.get(), sequence) {
            writer.remove_at(id, sequence);
        }
    }

    /// Add a subscription and register it in the watchers map.
    pub fn add_subscription(&self, mut subscription: Subscription) {
        subscription.generation = next_generation();
        let resource = subscription.resource.clone();
        let subscription_id = subscription.id.clone();

        debug!(
            subscription_id = %subscription_id,
            subscriber = %subscription.subscriber,
            resource = %resource,
            event = %subscription.event,
            "adding subscription"
        );

        let snapshot = {
            let entry = self
                .subscriptions
                .entry(subscription_id.clone())
                .insert(subscription);
            self.snapshot(&entry)
        };
        self.write_through(snapshot);

        self.watchers
            .entry(resource)
            .or_default()
            .push(subscription_id);
    }

    /// Put back a subscription read from the backend at boot: into the store
    /// and its resource's watchers, without writing it through again.
    pub fn restore_subscription(&self, mut subscription: Subscription) {
        subscription.generation = next_generation();
        let resource = subscription.resource.clone();
        let subscription_id = subscription.id.clone();
        if self
            .subscriptions
            .insert(subscription_id.clone(), subscription)
            .is_none()
        {
            self.watchers
                .entry(resource)
                .or_default()
                .push(subscription_id);
        }
    }

    /// Look up a subscription by ID, returning a clone.
    pub fn get_subscription(&self, id: &str) -> Option<Subscription> {
        self.subscriptions.get(id).map(|entry| entry.clone())
    }

    /// The version the next document on subscription `id` carries, advancing
    /// its count ([`Subscription::take_version`]).  `None` for an unknown id.
    pub fn next_version(&self, id: &str) -> Option<u32> {
        let (version, snapshot) = {
            let mut entry = self.subscriptions.get_mut(id)?;
            let version = entry.take_version();
            (version, self.snapshot(&entry))
        };
        self.write_through(snapshot);
        Some(version)
    }

    /// Prepare dialog state for an in-dialog NOTIFY, incrementing CSeq atomically.
    ///
    /// Returns `None` if the subscription doesn't exist or has no dialog state.
    pub fn prepare_notify(&self, id: &str) -> Option<NotifyDialogState> {
        let (dialog, snapshot) = {
            let mut entry = self.subscriptions.get_mut(id)?;
            let subscription = entry.value_mut();
            let call_id = subscription.call_id.clone()?;
            let local_uri = subscription.notify_from_uri().to_string();
            let remote_uri = subscription.notify_to_uri().to_string();
            let cseq = subscription.next_cseq();
            let dialog = NotifyDialogState {
                subscriber: subscription.subscriber.clone(),
                local_uri,
                remote_uri,
                event: subscription.event.clone(),
                call_id,
                from_tag: subscription.from_tag.clone().unwrap_or_default(),
                to_tag: subscription.to_tag.clone().unwrap_or_default(),
                route_set: subscription.route_set.clone(),
                cseq,
                generation: subscription.generation,
            };
            // The CSeq just taken is written through, so a restarted notifier
            // continues above it (RFC 3261 §12.2.1.1).
            (dialog, self.snapshot(subscription))
        };
        self.write_through(snapshot);
        Some(dialog)
    }

    /// Remove a subscription entirely (from both subscriptions and watchers maps).
    pub fn remove_subscription(&self, id: &str) {
        let mut sequence = None;
        if let Some((_, subscription)) = self.subscriptions.remove_if(id, |_, _| {
            sequence = self.removal_sequence();
            true
        }) {
            debug!(subscription_id = %id, "removing subscription");
            self.write_removal(id, sequence);
            self.forget_watcher(id, &subscription.resource);
        }
    }

    /// Remove a subscription only while `generation` is still its current one,
    /// and say whether it was removed.
    ///
    /// For a NOTIFY whose failure ends the subscription (RFC 6665 §4.2.2): the
    /// response arrives a round trip, or a whole Timer F, after the NOTIFY
    /// left.  A refresh SUBSCRIBE that landed meanwhile proves the subscriber
    /// still holds the dialog and moves the subscription to a new generation,
    /// so the late failure leaves it alone.  An id that is already gone is a
    /// no-op returning `false`.
    pub fn remove_subscription_if_current(&self, id: &str, generation: u64) -> bool {
        let mut sequence = None;
        let Some((_, subscription)) = self.subscriptions.remove_if(id, |_, subscription| {
            let current = subscription.generation == generation;
            if current {
                sequence = self.removal_sequence();
            }
            current
        }) else {
            return false;
        };
        debug!(subscription_id = %id, "removing subscription after a failed NOTIFY");
        self.write_removal(id, sequence);
        self.forget_watcher(id, &subscription.resource);
        true
    }

    /// Drop `id` from the watchers of `resource`, and the entry once empty.
    fn forget_watcher(&self, id: &str, resource: &str) {
        if let Some(mut watcher_list) = self.watchers.get_mut(resource) {
            watcher_list.retain(|watcher_id| watcher_id != id);
        }
        self.watchers
            .remove_if(resource, |_key, watcher_list| watcher_list.is_empty());
    }

    /// Refresh a subscription's expiry. Returns `true` if the subscription was found.
    pub fn refresh_subscription(&self, id: &str, expires: Duration) -> bool {
        let snapshot = match self.subscriptions.get_mut(id) {
            Some(mut entry) => {
                entry.refresh(expires);
                self.snapshot(&entry)
            }
            None => return false,
        };
        self.write_through(snapshot);
        true
    }

    /// Find a subscription by its dialog identifiers `(Call-ID, From-tag)`.
    ///
    /// An in-dialog SUBSCRIBE (RFC 6665 §4.4.1 refresh, or an un-SUBSCRIBE with
    /// `Expires: 0`) carries the dialog's Call-ID and the subscriber's From-tag —
    /// stable across the dialog's life. This resolves that pair back to the
    /// subscription id so the notifier can refresh, terminate, or NOTIFY it. The
    /// dialog's To-tag (the notifier's own tag) is intentionally not part of the
    /// key: `(Call-ID, From-tag)` already identifies a subscriber's dialog
    /// uniquely, and it's what the script has cheaply on the in-dialog request.
    ///
    /// Terminated subscriptions are skipped so a lingering pre-removal entry can't
    /// shadow a fresh re-SUBSCRIBE that reused the Call-ID. Returns the first
    /// live match, or `None`.
    pub fn find_subscription_by_dialog(&self, call_id: &str, from_tag: &str) -> Option<String> {
        self.subscriptions.iter().find_map(|entry| {
            let subscription = entry.value();
            if subscription.state != SubscriptionState::Terminated
                && subscription.call_id.as_deref() == Some(call_id)
                && subscription.from_tag.as_deref() == Some(from_tag)
            {
                Some(subscription.id.clone())
            } else {
                None
            }
        })
    }

    /// Terminate a subscription (sets state to `Terminated` but does not remove it).
    ///
    /// A terminated subscription is never restored, so its stored copy goes
    /// now rather than with the removal.
    pub fn terminate_subscription(&self, id: &str) {
        let sequence = match self.subscriptions.get_mut(id) {
            Some(mut entry) => {
                entry.terminate();
                self.removal_sequence()
            }
            None => return,
        };
        self.write_removal(id, sequence);
    }

    /// Get all active (non-terminated, non-expired) subscriptions for a resource URI.
    pub fn subscriptions_for(&self, resource: &str) -> Vec<Subscription> {
        let watcher_ids = match self.watchers.get(resource) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        watcher_ids
            .iter()
            .filter_map(|subscription_id| {
                self.subscriptions.get(subscription_id).and_then(|entry| {
                    let subscription = entry.value();
                    if subscription.state != SubscriptionState::Terminated
                        && !subscription.is_expired()
                    {
                        Some(subscription.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Publish or update a presence document for a presentity.
    ///
    /// If `etag` is `Some`, updates the existing document with that etag.
    /// If `etag` is `None`, creates a new publication.
    ///
    /// Returns the etag assigned to the document.
    pub fn publish(
        &self,
        entity: &str,
        content_type: String,
        body: String,
        etag: Option<String>,
        expires: Duration,
    ) -> String {
        let new_etag = generate_etag(entity, &body);

        let document = PresenceDocument {
            entity: entity.to_string(),
            etag: new_etag.clone(),
            content_type,
            body,
            expires,
            published_at: Instant::now(),
        };

        let mut documents = self.documents.entry(entity.to_string()).or_default();

        if let Some(existing_etag) = etag {
            // Update: replace the document with the matching etag.
            if let Some(position) = documents
                .iter()
                .position(|document| document.etag == existing_etag)
            {
                debug!(
                    entity = %entity,
                    old_etag = %existing_etag,
                    new_etag = %new_etag,
                    "updating presence document"
                );
                documents[position] = document;
            } else {
                // Etag not found — treat as new publication.
                debug!(
                    entity = %entity,
                    etag = %new_etag,
                    "etag not found, creating new presence document"
                );
                documents.push(document);
            }
        } else {
            debug!(
                entity = %entity,
                etag = %new_etag,
                "publishing new presence document"
            );
            documents.push(document);
        }

        new_etag
    }

    /// Remove a published document by entity and etag. Returns `true` if found and removed.
    pub fn unpublish(&self, entity: &str, etag: &str) -> bool {
        if let Some(mut documents) = self.documents.get_mut(entity) {
            let original_length = documents.len();
            documents.retain(|document| document.etag != etag);
            let removed = documents.len() < original_length;

            if removed {
                debug!(entity = %entity, etag = %etag, "unpublished presence document");
            }

            // Clean up empty entries.
            drop(documents);
            self.documents
                .remove_if(entity, |_key, documents| documents.is_empty());

            removed
        } else {
            false
        }
    }

    /// Get the latest (most recently published) presence document for an entity.
    pub fn get_presence(&self, entity: &str) -> Option<PresenceDocument> {
        self.documents.get(entity).and_then(|documents| {
            documents
                .iter()
                .filter(|document| !document.is_expired())
                .max_by_key(|document| document.published_at)
                .cloned()
        })
    }

    /// Total number of subscriptions in the store (including expired/terminated).
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Total number of entities with at least one published document.
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    /// Remove all expired subscriptions and documents.
    pub fn expire_stale(&self) {
        // Collect expired subscription IDs first to avoid holding locks during removal.
        let expired_subscription_ids: Vec<String> = self
            .subscriptions
            .iter()
            .filter(|entry| {
                let subscription = entry.value();
                subscription.is_expired() || subscription.state == SubscriptionState::Terminated
            })
            .map(|entry| entry.key().clone())
            .collect();

        let expired_subscription_count = expired_subscription_ids.len();
        for subscription_id in expired_subscription_ids {
            self.remove_subscription(&subscription_id);
        }

        // Remove expired documents.
        let mut expired_document_count = 0usize;
        let entity_keys: Vec<String> = self
            .documents
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for entity in entity_keys {
            if let Some(mut documents) = self.documents.get_mut(&entity) {
                let original_length = documents.len();
                documents.retain(|document| !document.is_expired());
                expired_document_count += original_length - documents.len();
            }

            // Clean up empty entries.
            self.documents
                .remove_if(&entity, |_key, documents| documents.is_empty());
        }

        if expired_subscription_count > 0 || expired_document_count > 0 {
            debug!(
                expired_subscriptions = expired_subscription_count,
                expired_documents = expired_document_count,
                "expired stale presence entries"
            );
        }
    }
}

impl Default for PresenceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "persist_tests.rs"]
mod persist_tests;

#[cfg(all(test, feature = "redis-backend"))]
#[path = "persist_redis_tests.rs"]
mod persist_redis_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_subscription(id: &str, subscriber: &str, resource: &str) -> Subscription {
        Subscription::new(
            id.to_string(),
            subscriber.to_string(),
            resource.to_string(),
            "presence".to_string(),
            Duration::from_secs(3600),
            None,
            vec!["application/pidf+xml".to_string()],
        )
    }

    fn make_short_lived_subscription(id: &str, resource: &str, expires: Duration) -> Subscription {
        Subscription::new(
            id.to_string(),
            "sip:watcher@example.com".to_string(),
            resource.to_string(),
            "presence".to_string(),
            expires,
            None,
            vec![],
        )
    }

    // ── Subscription state transitions ──────────────────────────────────

    #[test]
    fn subscription_initial_state_is_init() {
        let subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        assert_eq!(subscription.state, SubscriptionState::Init);
    }

    #[test]
    fn subscription_activate() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Active);
    }

    #[test]
    fn subscription_terminate() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        subscription.terminate();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    #[test]
    fn subscription_activate_after_terminated_is_noop() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.terminate();
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    #[test]
    fn subscription_refresh_after_terminated_is_noop() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.terminate();
        let original_expires = subscription.expires;
        subscription.refresh(Duration::from_secs(7200));
        assert_eq!(subscription.expires, original_expires);
    }

    #[test]
    fn subscription_refresh_resets_timer() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        let before_refresh = Instant::now();
        subscription.refresh(Duration::from_secs(1800));
        assert_eq!(subscription.expires, Duration::from_secs(1800));
        assert!(subscription.created_at >= before_refresh);
    }

    #[test]
    fn subscription_pending_to_active() {
        let mut subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.state = SubscriptionState::Pending;
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Active);
    }

    // ── Subscription expiry ─────────────────────────────────────────────

    #[test]
    fn subscription_not_expired_when_fresh() {
        let subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        assert!(!subscription.is_expired());
        assert!(subscription.remaining_seconds() > 0);
    }

    #[test]
    fn subscription_expired_with_zero_duration() {
        let subscription =
            make_short_lived_subscription("sub-1", "sip:bob@example.com", Duration::ZERO);
        assert!(subscription.is_expired());
        assert_eq!(subscription.remaining_seconds(), 0);
    }

    // ── Subscription state display ──────────────────────────────────────

    #[test]
    fn subscription_state_display() {
        assert_eq!(format!("{}", SubscriptionState::Init), "init");
        assert_eq!(format!("{}", SubscriptionState::Active), "active");
        assert_eq!(format!("{}", SubscriptionState::Pending), "pending");
        assert_eq!(format!("{}", SubscriptionState::Terminated), "terminated");
    }

    // ── PresenceStore: subscription management ──────────────────────────

    #[test]
    fn store_add_and_get_subscription() {
        let store = PresenceStore::new();
        let subscription =
            make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");

        store.add_subscription(subscription);

        let retrieved = store.get_subscription("sub-1").unwrap();
        assert_eq!(retrieved.id, "sub-1");
        assert_eq!(retrieved.subscriber, "sip:alice@example.com");
        assert_eq!(retrieved.resource, "sip:bob@example.com");
        assert_eq!(store.subscription_count(), 1);
    }

    #[test]
    fn store_get_nonexistent_subscription_returns_none() {
        let store = PresenceStore::new();
        assert!(store.get_subscription("nonexistent").is_none());
    }

    #[test]
    fn store_remove_subscription() {
        let store = PresenceStore::new();
        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            "sip:bob@example.com",
        ));

        store.remove_subscription("sub-1");

        assert!(store.get_subscription("sub-1").is_none());
        assert_eq!(store.subscription_count(), 0);
    }

    #[test]
    fn store_remove_nonexistent_subscription_is_noop() {
        let store = PresenceStore::new();
        store.remove_subscription("nonexistent"); // should not panic
    }

    #[test]
    fn store_refresh_subscription() {
        let store = PresenceStore::new();
        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            "sip:bob@example.com",
        ));

        let refreshed = store.refresh_subscription("sub-1", Duration::from_secs(1800));
        assert!(refreshed);

        let subscription = store.get_subscription("sub-1").unwrap();
        assert_eq!(subscription.expires, Duration::from_secs(1800));
    }

    #[test]
    fn store_refresh_nonexistent_returns_false() {
        let store = PresenceStore::new();
        assert!(!store.refresh_subscription("nonexistent", Duration::from_secs(3600)));
    }

    #[test]
    fn store_terminate_subscription() {
        let store = PresenceStore::new();
        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            "sip:bob@example.com",
        ));

        store.terminate_subscription("sub-1");

        let subscription = store.get_subscription("sub-1").unwrap();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    // ── PresenceStore: watchers tracking ────────────────────────────────

    #[test]
    fn store_watchers_tracking() {
        let store = PresenceStore::new();
        let resource = "sip:bob@example.com";

        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            resource,
        ));
        store.add_subscription(make_subscription(
            "sub-2",
            "sip:carol@example.com",
            resource,
        ));

        // Activate both so they show up in subscriptions_for.
        if let Some(mut entry) = store.subscriptions.get_mut("sub-1") {
            entry.activate();
        }
        if let Some(mut entry) = store.subscriptions.get_mut("sub-2") {
            entry.activate();
        }

        let watchers = store.subscriptions_for(resource);
        assert_eq!(watchers.len(), 2);

        let subscriber_uris: Vec<&str> = watchers.iter().map(|s| s.subscriber.as_str()).collect();
        assert!(subscriber_uris.contains(&"sip:alice@example.com"));
        assert!(subscriber_uris.contains(&"sip:carol@example.com"));
    }

    #[test]
    fn store_subscriptions_for_excludes_terminated() {
        let store = PresenceStore::new();
        let resource = "sip:bob@example.com";

        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            resource,
        ));
        store.add_subscription(make_subscription(
            "sub-2",
            "sip:carol@example.com",
            resource,
        ));

        if let Some(mut entry) = store.subscriptions.get_mut("sub-1") {
            entry.activate();
        }
        store.terminate_subscription("sub-2");

        let watchers = store.subscriptions_for(resource);
        assert_eq!(watchers.len(), 1);
        assert_eq!(watchers[0].subscriber, "sip:alice@example.com");
    }

    #[test]
    fn store_subscriptions_for_empty_resource() {
        let store = PresenceStore::new();
        let watchers = store.subscriptions_for("sip:nobody@example.com");
        assert!(watchers.is_empty());
    }

    #[test]
    fn store_remove_subscription_cleans_watchers() {
        let store = PresenceStore::new();
        let resource = "sip:bob@example.com";

        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            resource,
        ));
        store.remove_subscription("sub-1");

        // Watchers map should be cleaned up.
        assert!(store.watchers.get(resource).is_none());
    }

    // ── PresenceStore: publish/unpublish ────────────────────────────────

    #[test]
    fn store_publish_new_document() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        let etag = store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence/>".to_string(),
            None,
            Duration::from_secs(3600),
        );

        assert!(!etag.is_empty());
        assert_eq!(store.document_count(), 1);

        let document = store.get_presence(entity).unwrap();
        assert_eq!(document.entity, entity);
        assert_eq!(document.content_type, "application/pidf+xml");
        assert_eq!(document.body, "<presence/>");
        assert_eq!(document.etag, etag);
    }

    #[test]
    fn store_publish_update_with_etag() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        let etag1 = store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence status='open'/>".to_string(),
            None,
            Duration::from_secs(3600),
        );

        let etag2 = store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence status='closed'/>".to_string(),
            Some(etag1.clone()),
            Duration::from_secs(3600),
        );

        assert_ne!(etag1, etag2);

        let document = store.get_presence(entity).unwrap();
        assert_eq!(document.body, "<presence status='closed'/>");
        assert_eq!(document.etag, etag2);
    }

    #[test]
    fn store_publish_with_nonexistent_etag_creates_new() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence/>".to_string(),
            None,
            Duration::from_secs(3600),
        );

        // Update with a wrong etag — should create a second document.
        store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence status='away'/>".to_string(),
            Some("nonexistent-etag".to_string()),
            Duration::from_secs(3600),
        );

        // Two documents now exist for this entity.
        let documents = store.documents.get(entity).unwrap();
        assert_eq!(documents.len(), 2);
    }

    #[test]
    fn store_unpublish() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        let etag = store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence/>".to_string(),
            None,
            Duration::from_secs(3600),
        );

        assert!(store.unpublish(entity, &etag));
        assert_eq!(store.document_count(), 0);
        assert!(store.get_presence(entity).is_none());
    }

    #[test]
    fn store_unpublish_nonexistent_returns_false() {
        let store = PresenceStore::new();
        assert!(!store.unpublish("sip:bob@example.com", "no-such-etag"));
    }

    #[test]
    fn store_get_presence_returns_none_for_unknown_entity() {
        let store = PresenceStore::new();
        assert!(store.get_presence("sip:unknown@example.com").is_none());
    }

    // ── PresenceStore: expire_stale ─────────────────────────────────────

    #[test]
    fn store_expire_stale_removes_expired_subscriptions() {
        let store = PresenceStore::new();
        let resource = "sip:bob@example.com";

        // Create an already-expired subscription (zero duration).
        store.add_subscription(make_short_lived_subscription(
            "sub-expired",
            resource,
            Duration::ZERO,
        ));
        // Create a long-lived subscription.
        store.add_subscription(make_subscription(
            "sub-alive",
            "sip:alice@example.com",
            resource,
        ));

        assert_eq!(store.subscription_count(), 2);

        store.expire_stale();

        assert_eq!(store.subscription_count(), 1);
        assert!(store.get_subscription("sub-expired").is_none());
        assert!(store.get_subscription("sub-alive").is_some());
    }

    #[test]
    fn store_expire_stale_removes_terminated_subscriptions() {
        let store = PresenceStore::new();

        store.add_subscription(make_subscription(
            "sub-1",
            "sip:alice@example.com",
            "sip:bob@example.com",
        ));
        store.terminate_subscription("sub-1");

        store.expire_stale();

        assert_eq!(store.subscription_count(), 0);
    }

    #[test]
    fn store_expire_stale_removes_expired_documents() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        // Publish a document with zero expiry (immediately expired).
        store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence/>".to_string(),
            None,
            Duration::ZERO,
        );

        assert_eq!(store.document_count(), 1);

        store.expire_stale();

        assert_eq!(store.document_count(), 0);
    }

    #[test]
    fn store_expire_stale_keeps_fresh_documents() {
        let store = PresenceStore::new();
        let entity = "sip:bob@example.com";

        store.publish(
            entity,
            "application/pidf+xml".to_string(),
            "<presence/>".to_string(),
            None,
            Duration::from_secs(3600),
        );

        store.expire_stale();

        assert_eq!(store.document_count(), 1);
        assert!(store.get_presence(entity).is_some());
    }

    // ── PresenceStore: concurrency ──────────────────────────────────────

    #[test]
    fn store_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(PresenceStore::new());
        let mut handles = Vec::new();

        // Spawn threads that add subscriptions concurrently.
        for index in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let subscription_id = format!("sub-{}", index);
                let subscriber = format!("sip:user{}@example.com", index);
                let resource = "sip:shared@example.com";
                store_clone.add_subscription(make_subscription(
                    &subscription_id,
                    &subscriber,
                    resource,
                ));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.subscription_count(), 10);

        let watcher_list = store.watchers.get("sip:shared@example.com").unwrap();
        assert_eq!(watcher_list.len(), 10);
    }

    // ── PresenceDocument ────────────────────────────────────────────────

    #[test]
    fn presence_document_not_expired_when_fresh() {
        let document = PresenceDocument {
            entity: "sip:bob@example.com".to_string(),
            etag: "abc123".to_string(),
            content_type: "application/pidf+xml".to_string(),
            body: "<presence/>".to_string(),
            expires: Duration::from_secs(3600),
            published_at: Instant::now(),
        };
        assert!(!document.is_expired());
    }

    #[test]
    fn presence_document_expired_with_zero_duration() {
        let document = PresenceDocument {
            entity: "sip:bob@example.com".to_string(),
            etag: "abc123".to_string(),
            content_type: "application/pidf+xml".to_string(),
            body: "<presence/>".to_string(),
            expires: Duration::ZERO,
            published_at: Instant::now(),
        };
        assert!(document.is_expired());
    }

    // ── PresenceStore: dialog_id ────────────────────────────────────────

    #[test]
    fn subscription_with_dialog_id() {
        let subscription = Subscription::new(
            "sub-1".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            "presence".to_string(),
            Duration::from_secs(3600),
            Some("call-id-123:from-tag:to-tag".to_string()),
            vec!["application/pidf+xml".to_string()],
        );

        assert_eq!(
            subscription.dialog_id.as_deref(),
            Some("call-id-123:from-tag:to-tag")
        );
    }

    fn dialog_sub(id: &str, call_id: &str, from_tag: &str) -> Subscription {
        Subscription::with_dialog(
            id.to_string(),
            "sip:alice@ims.example.com".to_string(),
            "sip:alice@ims.example.com".to_string(),
            "reg".to_string(),
            Duration::from_secs(3600),
            vec![],
            call_id.to_string(),
            from_tag.to_string(),
            "scscf-notif".to_string(),
            vec![],
            None,
            None,
        )
    }

    #[test]
    fn find_subscription_by_dialog_resolves_pair() {
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-a", "callA", "ftagA"));
        store.add_subscription(dialog_sub("sub-b", "callB", "ftagB"));

        assert_eq!(
            store
                .find_subscription_by_dialog("callA", "ftagA")
                .as_deref(),
            Some("sub-a")
        );
        assert_eq!(
            store
                .find_subscription_by_dialog("callB", "ftagB")
                .as_deref(),
            Some("sub-b")
        );
        // A mismatched pair (right Call-ID, wrong From-tag) does not match.
        assert_eq!(store.find_subscription_by_dialog("callA", "ftagB"), None);
        assert_eq!(store.find_subscription_by_dialog("nope", "nope"), None);
    }

    #[test]
    fn find_subscription_by_dialog_skips_terminated() {
        // A terminated-but-not-yet-removed dialog must not shadow a re-SUBSCRIBE
        // that reused the same Call-ID/From-tag.
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-a", "callA", "ftagA"));
        store.terminate_subscription("sub-a");
        assert_eq!(store.find_subscription_by_dialog("callA", "ftagA"), None);
    }

    #[test]
    fn find_subscription_by_dialog_ignores_non_dialog_subscription() {
        // subscribe() (no dialog state) carries no call_id/from_tag → unfindable.
        let store = PresenceStore::new();
        store.add_subscription(Subscription::new(
            "sub-plain".to_string(),
            "sip:alice@ims.example.com".to_string(),
            "sip:alice@ims.example.com".to_string(),
            "reg".to_string(),
            Duration::from_secs(3600),
            None,
            vec![],
        ));
        assert_eq!(store.find_subscription_by_dialog("", ""), None);
    }

    #[test]
    fn refresh_subscription_reports_found_and_missing() {
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-x", "callX", "ftagX"));
        assert!(store.refresh_subscription("sub-x", Duration::from_secs(7200)));
        assert!(!store.refresh_subscription("sub-missing", Duration::from_secs(7200)));
    }

    // ── PresenceStore: event-state versions (RFC 3680 §5.2) ─────────────

    /// Two documents on one subscription carry v and v+1, starting at 0.
    #[test]
    fn next_version_starts_at_zero_and_counts_up() {
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-v", "callV", "ftagV"));
        assert_eq!(store.next_version("sub-v"), Some(0));
        assert_eq!(store.next_version("sub-v"), Some(1));
        assert_eq!(store.next_version("sub-v"), Some(2));
    }

    /// Versions are scoped within a subscription: two count independently.
    #[test]
    fn next_version_is_per_subscription() {
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-a", "callA", "ftagA"));
        store.add_subscription(dialog_sub("sub-b", "callB", "ftagB"));
        assert_eq!(store.next_version("sub-a"), Some(0));
        assert_eq!(store.next_version("sub-a"), Some(1));
        assert_eq!(store.next_version("sub-b"), Some(0));
        assert_eq!(store.next_version("sub-a"), Some(2));
        assert_eq!(store.next_version("sub-b"), Some(1));
    }

    /// A removed subscription's count goes with it; a refresh keeps it.
    #[test]
    fn next_version_goes_with_the_subscription() {
        let store = PresenceStore::new();
        store.add_subscription(dialog_sub("sub-r", "callR", "ftagR"));
        assert_eq!(store.next_version("sub-r"), Some(0));
        assert!(store.refresh_subscription("sub-r", Duration::from_secs(600)));
        assert_eq!(
            store.next_version("sub-r"),
            Some(1),
            "a refresh keeps the count"
        );
        store.remove_subscription("sub-r");
        assert_eq!(store.next_version("sub-r"), None);
        assert_eq!(store.next_version("never-added"), None);
    }

    /// The count saturates rather than wrapping to 0, which a subscriber would
    /// discard as older than what it holds.
    #[test]
    fn next_version_saturates() {
        let store = PresenceStore::new();
        let mut subscription = dialog_sub("sub-max", "callM", "ftagM");
        subscription.next_version = u32::MAX;
        store.add_subscription(subscription);
        assert_eq!(store.next_version("sub-max"), Some(u32::MAX));
        assert_eq!(store.next_version("sub-max"), Some(u32::MAX));
    }

    /// Concurrent takers never share a version.
    #[test]
    fn next_version_is_unique_under_concurrency() {
        let store = Arc::new(PresenceStore::new());
        store.add_subscription(dialog_sub("sub-c", "callC", "ftagC"));
        let takers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    (0..250)
                        .map(|_| store.next_version("sub-c").unwrap())
                        .collect::<Vec<u32>>()
                })
            })
            .collect();
        let mut versions: Vec<u32> = takers
            .into_iter()
            .flat_map(|taker| taker.join().unwrap())
            .collect();
        versions.sort_unstable();
        assert_eq!(versions, (0..2000).collect::<Vec<u32>>());
    }
}
