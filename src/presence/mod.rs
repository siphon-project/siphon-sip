//! SIP presence server — subscription state machine and presence document store.
//!
//! Implements RFC 3856 (SIP presence) and RFC 3903 (SIP PUBLISH) state management.
//! Subscriptions track watchers of a presentity, while presence documents hold
//! the published presence state (typically PIDF XML).
//!
//! Uses `DashMap` for lock-free concurrent access from multiple Tokio tasks.

pub mod pidf;
pub mod rls;
pub mod winfo;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

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
        }
    }

    /// Create a subscription with full dialog state from a SUBSCRIBE request.
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
        }
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

/// Dialog state required to build an in-dialog NOTIFY, as returned by
/// [`PresenceStore::prepare_notify`]:
/// `(subscriber, event, call_id, from_tag, to_tag, route_set, cseq)`.
type NotifyDialogState = (String, String, String, String, String, Vec<String>, u32);

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
}

impl PresenceStore {
    /// Create an empty presence store.
    pub fn new() -> Self {
        Self {
            subscriptions: DashMap::new(),
            documents: DashMap::new(),
            watchers: DashMap::new(),
        }
    }

    /// Add a subscription and register it in the watchers map.
    pub fn add_subscription(&self, subscription: Subscription) {
        let resource = subscription.resource.clone();
        let subscription_id = subscription.id.clone();

        debug!(
            subscription_id = %subscription_id,
            subscriber = %subscription.subscriber,
            resource = %resource,
            event = %subscription.event,
            "adding subscription"
        );

        self.subscriptions.insert(subscription_id.clone(), subscription);

        self.watchers
            .entry(resource)
            .or_default()
            .push(subscription_id);
    }

    /// Look up a subscription by ID, returning a clone.
    pub fn get_subscription(&self, id: &str) -> Option<Subscription> {
        self.subscriptions.get(id).map(|entry| entry.clone())
    }

    /// Prepare dialog state for an in-dialog NOTIFY, incrementing CSeq atomically.
    ///
    /// Returns `(subscriber, event, call_id, from_tag, to_tag, route_set, cseq)`
    /// or `None` if the subscription doesn't exist or has no dialog state.
    pub fn prepare_notify(&self, id: &str) -> Option<NotifyDialogState> {
        let mut entry = self.subscriptions.get_mut(id)?;
        let subscription = entry.value_mut();
        let call_id = subscription.call_id.clone()?;
        let cseq = subscription.next_cseq();
        Some((
            subscription.subscriber.clone(),
            subscription.event.clone(),
            call_id,
            subscription.from_tag.clone().unwrap_or_default(),
            subscription.to_tag.clone().unwrap_or_default(),
            subscription.route_set.clone(),
            cseq,
        ))
    }

    /// Remove a subscription entirely (from both subscriptions and watchers maps).
    pub fn remove_subscription(&self, id: &str) {
        if let Some((_, subscription)) = self.subscriptions.remove(id) {
            debug!(subscription_id = %id, "removing subscription");

            // Remove from watchers list for this resource.
            if let Some(mut watcher_list) = self.watchers.get_mut(&subscription.resource) {
                watcher_list.retain(|watcher_id| watcher_id != id);
            }

            // Clean up empty watcher entries.
            self.watchers
                .remove_if(&subscription.resource, |_key, watcher_list| {
                    watcher_list.is_empty()
                });
        }
    }

    /// Refresh a subscription's expiry. Returns `true` if the subscription was found.
    pub fn refresh_subscription(&self, id: &str, expires: Duration) -> bool {
        if let Some(mut entry) = self.subscriptions.get_mut(id) {
            entry.refresh(expires);
            true
        } else {
            false
        }
    }

    /// Terminate a subscription (sets state to `Terminated` but does not remove it).
    pub fn terminate_subscription(&self, id: &str) {
        if let Some(mut entry) = self.subscriptions.get_mut(id) {
            entry.terminate();
        }
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
            if let Some(position) = documents.iter().position(|document| document.etag == existing_etag) {
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
            self.documents.remove_if(entity, |_key, documents| documents.is_empty());

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
        let entity_keys: Vec<String> = self.documents.iter().map(|entry| entry.key().clone()).collect();

        for entity in entity_keys {
            if let Some(mut documents) = self.documents.get_mut(&entity) {
                let original_length = documents.len();
                documents.retain(|document| !document.is_expired());
                expired_document_count += original_length - documents.len();
            }

            // Clean up empty entries.
            self.documents.remove_if(&entity, |_key, documents| documents.is_empty());
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
        let subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        assert_eq!(subscription.state, SubscriptionState::Init);
    }

    #[test]
    fn subscription_activate() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Active);
    }

    #[test]
    fn subscription_terminate() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        subscription.terminate();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    #[test]
    fn subscription_activate_after_terminated_is_noop() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.terminate();
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    #[test]
    fn subscription_refresh_after_terminated_is_noop() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.terminate();
        let original_expires = subscription.expires;
        subscription.refresh(Duration::from_secs(7200));
        assert_eq!(subscription.expires, original_expires);
    }

    #[test]
    fn subscription_refresh_resets_timer() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.activate();
        let before_refresh = Instant::now();
        subscription.refresh(Duration::from_secs(1800));
        assert_eq!(subscription.expires, Duration::from_secs(1800));
        assert!(subscription.created_at >= before_refresh);
    }

    #[test]
    fn subscription_pending_to_active() {
        let mut subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        subscription.state = SubscriptionState::Pending;
        subscription.activate();
        assert_eq!(subscription.state, SubscriptionState::Active);
    }

    // ── Subscription expiry ─────────────────────────────────────────────

    #[test]
    fn subscription_not_expired_when_fresh() {
        let subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
        assert!(!subscription.is_expired());
        assert!(subscription.remaining_seconds() > 0);
    }

    #[test]
    fn subscription_expired_with_zero_duration() {
        let subscription = make_short_lived_subscription("sub-1", "sip:bob@example.com", Duration::ZERO);
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
        let subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");

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
        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com"));

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
        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com"));

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
        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com"));

        store.terminate_subscription("sub-1");

        let subscription = store.get_subscription("sub-1").unwrap();
        assert_eq!(subscription.state, SubscriptionState::Terminated);
    }

    // ── PresenceStore: watchers tracking ────────────────────────────────

    #[test]
    fn store_watchers_tracking() {
        let store = PresenceStore::new();
        let resource = "sip:bob@example.com";

        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", resource));
        store.add_subscription(make_subscription("sub-2", "sip:carol@example.com", resource));

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

        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", resource));
        store.add_subscription(make_subscription("sub-2", "sip:carol@example.com", resource));

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

        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", resource));
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
        store.add_subscription(make_short_lived_subscription("sub-expired", resource, Duration::ZERO));
        // Create a long-lived subscription.
        store.add_subscription(make_subscription("sub-alive", "sip:alice@example.com", resource));

        assert_eq!(store.subscription_count(), 2);

        store.expire_stale();

        assert_eq!(store.subscription_count(), 1);
        assert!(store.get_subscription("sub-expired").is_none());
        assert!(store.get_subscription("sub-alive").is_some());
    }

    #[test]
    fn store_expire_stale_removes_terminated_subscriptions() {
        let store = PresenceStore::new();

        store.add_subscription(make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com"));
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
}
