//! Integration tests for the presence module.
//!
//! Tests cover subscription state transitions, expiry detection, PresenceStore
//! operations (add/lookup/terminate/refresh/expire_stale), presence document
//! publish/unpublish, PIDF XML generation and parsing, and concurrent access.

use std::sync::Arc;
use std::time::Duration;

use siphon::presence::pidf::{compose, BasicStatus, PresenceBody, Tuple};
use siphon::presence::{PresenceDocument, PresenceStore, Subscription, SubscriptionState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Subscription state transitions
// ---------------------------------------------------------------------------

#[test]
fn subscription_init_to_active_to_terminated() {
    let mut subscription =
        make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
    assert_eq!(subscription.state, SubscriptionState::Init);

    subscription.activate();
    assert_eq!(subscription.state, SubscriptionState::Active);

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
fn subscription_refresh_resets_timer_and_duration() {
    let mut subscription =
        make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
    subscription.activate();

    let before = std::time::Instant::now();
    subscription.refresh(Duration::from_secs(1800));

    assert_eq!(subscription.expires, Duration::from_secs(1800));
    assert!(subscription.created_at >= before);
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

// ---------------------------------------------------------------------------
// Subscription expiry
// ---------------------------------------------------------------------------

#[test]
fn subscription_not_expired_when_fresh() {
    let subscription = make_subscription("sub-1", "sip:alice@example.com", "sip:bob@example.com");
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

// ---------------------------------------------------------------------------
// PresenceStore: subscription CRUD
// ---------------------------------------------------------------------------

#[test]
fn store_add_lookup_and_count() {
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
fn store_lookup_nonexistent_returns_none() {
    let store = PresenceStore::new();
    assert!(store.get_subscription("nonexistent").is_none());
}

#[test]
fn store_subscriptions_for_resource() {
    let store = PresenceStore::new();
    let resource = "sip:bob@example.com";

    let mut sub1 = make_subscription("sub-1", "sip:alice@example.com", resource);
    sub1.activate();
    let mut sub2 = make_subscription("sub-2", "sip:carol@example.com", resource);
    sub2.activate();

    store.add_subscription(sub1);
    store.add_subscription(sub2);

    // Need to activate through the store since add_subscription stores the original state.
    // The subscriptions were activated before adding, so they should show up.
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

    let mut sub1 = make_subscription("sub-active", "sip:alice@example.com", resource);
    sub1.activate();
    store.add_subscription(sub1);
    store.add_subscription(make_subscription(
        "sub-terminated",
        "sip:carol@example.com",
        resource,
    ));

    store.terminate_subscription("sub-terminated");

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

// ---------------------------------------------------------------------------
// PresenceStore: publish / lookup / unpublish
// ---------------------------------------------------------------------------

#[test]
fn store_publish_and_get_presence() {
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
fn store_unpublish_removes_document() {
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

// ---------------------------------------------------------------------------
// PresenceDocument expiry
// ---------------------------------------------------------------------------

#[test]
fn presence_document_not_expired_when_fresh() {
    let document = PresenceDocument {
        entity: "sip:bob@example.com".to_string(),
        etag: "abc123".to_string(),
        content_type: "application/pidf+xml".to_string(),
        body: "<presence/>".to_string(),
        expires: Duration::from_secs(3600),
        published_at: std::time::Instant::now(),
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
        published_at: std::time::Instant::now(),
    };
    assert!(document.is_expired());
}

// ---------------------------------------------------------------------------
// PresenceStore: expire_stale
// ---------------------------------------------------------------------------

#[test]
fn expire_stale_removes_expired_and_terminated() {
    let store = PresenceStore::new();
    let resource = "sip:bob@example.com";

    // Expired subscription (zero duration).
    store.add_subscription(make_short_lived_subscription(
        "sub-expired",
        resource,
        Duration::ZERO,
    ));

    // Terminated subscription.
    store.add_subscription(make_subscription(
        "sub-terminated",
        "sip:term@example.com",
        resource,
    ));
    store.terminate_subscription("sub-terminated");

    // Living subscription.
    store.add_subscription(make_subscription(
        "sub-alive",
        "sip:alice@example.com",
        resource,
    ));

    // Expired document.
    store.publish(
        "sip:expiring@example.com",
        "application/pidf+xml".to_string(),
        "<presence/>".to_string(),
        None,
        Duration::ZERO,
    );

    // Living document.
    store.publish(
        "sip:living@example.com",
        "application/pidf+xml".to_string(),
        "<presence/>".to_string(),
        None,
        Duration::from_secs(3600),
    );

    assert_eq!(store.subscription_count(), 3);
    assert_eq!(store.document_count(), 2);

    store.expire_stale();

    assert_eq!(store.subscription_count(), 1);
    assert!(store.get_subscription("sub-alive").is_some());
    assert_eq!(store.document_count(), 1);
    assert!(store.get_presence("sip:living@example.com").is_some());
}

// ---------------------------------------------------------------------------
// PIDF XML generation
// ---------------------------------------------------------------------------

#[test]
fn pidf_xml_generation_and_parse_roundtrip() {
    let mut body = PresenceBody::new("sip:alice@example.com".to_string());
    body.add_tuple(Tuple {
        id: "t1".to_string(),
        status: BasicStatus::Open,
        contact: Some("sip:alice@10.0.0.1".to_string()),
        note: Some("Online".to_string()),
        timestamp: Some("2025-01-01T00:00:00Z".to_string()),
    });

    let xml = body.to_xml();

    // Verify key XML elements.
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("entity=\"sip:alice@example.com\""));
    assert!(xml.contains("<tuple id=\"t1\">"));
    assert!(xml.contains("<status><basic>open</basic></status>"));
    assert!(xml.contains("<contact>sip:alice@10.0.0.1</contact>"));
    assert!(xml.contains("<note>Online</note>"));
    assert!(xml.contains("</presence>"));

    // Parse back and verify.
    let parsed = PresenceBody::parse(&xml).unwrap();
    assert_eq!(parsed.entity, "sip:alice@example.com");
    assert_eq!(parsed.tuples.len(), 1);
    assert_eq!(parsed.tuples[0].id, "t1");
    assert_eq!(parsed.tuples[0].status, BasicStatus::Open);
    assert_eq!(
        parsed.tuples[0].contact.as_deref(),
        Some("sip:alice@10.0.0.1")
    );
    assert_eq!(parsed.tuples[0].note.as_deref(), Some("Online"));
}

#[test]
fn pidf_xml_with_special_characters_roundtrip() {
    let mut original = PresenceBody::new("sip:test&user@example.com".to_string());
    original.add_tuple(Tuple {
        id: "id\"1".to_string(),
        status: BasicStatus::Open,
        contact: Some("sip:<special>@host".to_string()),
        note: Some("it's a \"fancy\" note & more".to_string()),
        timestamp: None,
    });

    let xml = original.to_xml();
    let parsed = PresenceBody::parse(&xml).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn pidf_compose_merges_multiple_documents() {
    let mut document_a = PresenceBody::new("sip:alice@example.com".to_string());
    document_a.add_tuple(Tuple {
        id: "desk".to_string(),
        status: BasicStatus::Open,
        contact: Some("sip:alice@desk".to_string()),
        note: None,
        timestamp: None,
    });

    let mut document_b = PresenceBody::new("sip:alice@example.com".to_string());
    document_b.add_tuple(Tuple {
        id: "mobile".to_string(),
        status: BasicStatus::Closed,
        contact: Some("sip:alice@mobile".to_string()),
        note: None,
        timestamp: None,
    });

    let merged = compose(&[document_a, document_b]);
    assert_eq!(merged.entity, "sip:alice@example.com");
    assert_eq!(merged.tuples.len(), 2);
    assert_eq!(merged.tuples[0].id, "desk");
    assert_eq!(merged.tuples[1].id, "mobile");
}

// ---------------------------------------------------------------------------
// Concurrent PresenceStore access
// ---------------------------------------------------------------------------

#[test]
fn concurrent_presence_store_access() {
    let store = Arc::new(PresenceStore::new());
    let mut handles = Vec::new();

    // 10 threads each adding a subscription.
    for index in 0..10 {
        let store_clone = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            let subscription_id = format!("sub-{index}");
            let subscriber = format!("sip:user{index}@example.com");
            let subscription = Subscription::new(
                subscription_id,
                subscriber,
                "sip:shared@example.com".to_string(),
                "presence".to_string(),
                Duration::from_secs(3600),
                None,
                vec!["application/pidf+xml".to_string()],
            );
            store_clone.add_subscription(subscription);
        }));
    }

    // 5 threads each publishing a document.
    for index in 0..5 {
        let store_clone = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            let entity = format!("sip:entity{index}@example.com");
            store_clone.publish(
                &entity,
                "application/pidf+xml".to_string(),
                format!("<presence entity='{entity}'/>"),
                None,
                Duration::from_secs(3600),
            );
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(store.subscription_count(), 10);
    assert_eq!(store.document_count(), 5);
}
