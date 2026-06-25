//! Integration tests for the gateway dispatcher module.
//!
//! Tests cover all three load-balancing algorithms (round-robin, weighted,
//! hash), priority failover, attribute filtering, dynamic group management,
//! health marking, and concurrent access.

use std::collections::HashMap;
use std::sync::Arc;

use siphon::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
use siphon::transport::Transport;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_destination(uri: &str, port: u16, weight: u32, priority: u32) -> Destination {
    Destination::new(
        uri.to_string(),
        format!("10.0.0.1:{port}").parse().unwrap(),
        Transport::Udp,
        weight,
        priority,
    )
}

fn make_destination_with_attrs(
    uri: &str,
    port: u16,
    weight: u32,
    priority: u32,
    attrs: HashMap<String, String>,
) -> Destination {
    Destination::new(
        uri.to_string(),
        format!("10.0.0.1:{port}").parse().unwrap(),
        Transport::Udp,
        weight,
        priority,
    )
    .with_attrs(attrs)
}

// ---------------------------------------------------------------------------
// Round-robin
// ---------------------------------------------------------------------------

#[test]
fn round_robin_even_distribution_across_three_destinations() {
    let group = DispatcherGroup::new(
        "round-robin-3".to_string(),
        Algorithm::RoundRobin,
        vec![
            make_destination("sip:gw1.example.com", 5060, 1, 1),
            make_destination("sip:gw2.example.com", 5061, 1, 1),
            make_destination("sip:gw3.example.com", 5062, 1, 1),
        ],
    );

    let mut counts: HashMap<String, u32> = HashMap::new();
    for _ in 0..6 {
        let selected = group.select(None, None).unwrap();
        *counts.entry(selected.uri.clone()).or_insert(0) += 1;
    }

    // Each destination should be selected exactly twice.
    assert_eq!(counts.len(), 3, "expected 3 destinations, got {counts:?}");
    for (uri, count) in &counts {
        assert_eq!(*count, 2, "{uri} was selected {count} times, expected 2");
    }
}

// ---------------------------------------------------------------------------
// Weighted
// ---------------------------------------------------------------------------

#[test]
fn weighted_selection_distribution() {
    let group = DispatcherGroup::new(
        "weighted-test".to_string(),
        Algorithm::Weighted,
        vec![
            make_destination("sip:heavy.carrier.com", 5060, 3, 1),
            make_destination("sip:light.carrier.com", 5061, 1, 1),
        ],
    );

    let mut heavy_count = 0u32;
    let mut light_count = 0u32;

    for _ in 0..100 {
        let selected = group.select(None, None).unwrap();
        if selected.uri == "sip:heavy.carrier.com" {
            heavy_count += 1;
        } else {
            light_count += 1;
        }
    }

    // With weights 3:1 over 100 selections, expect ~75/25 with +-10% tolerance.
    assert!(
        (65..=85).contains(&heavy_count),
        "heavy={heavy_count}, expected 65..85"
    );
    assert!(
        (15..=35).contains(&light_count),
        "light={light_count}, expected 15..35"
    );
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

#[test]
fn hash_same_key_returns_same_destination() {
    let group = DispatcherGroup::new(
        "hash-sticky".to_string(),
        Algorithm::Hash,
        vec![
            make_destination("sip:node1.example.com", 5060, 1, 1),
            make_destination("sip:node2.example.com", 5061, 1, 1),
            make_destination("sip:node3.example.com", 5062, 1, 1),
        ],
    );

    let key = "call-id-abc-123";
    let first = group.select(Some(key), None).unwrap();

    for _ in 0..20 {
        let selected = group.select(Some(key), None).unwrap();
        assert_eq!(selected.uri, first.uri, "hash not sticky for same key");
    }
}

#[test]
fn hash_different_keys_may_select_different_destinations() {
    let group = DispatcherGroup::new(
        "hash-spread".to_string(),
        Algorithm::Hash,
        vec![
            make_destination("sip:node1.example.com", 5060, 1, 1),
            make_destination("sip:node2.example.com", 5061, 1, 1),
        ],
    );

    let mut seen = std::collections::HashSet::new();
    for index in 0..100 {
        let key = format!("unique-call-id-{index}");
        let selected = group.select(Some(&key), None).unwrap();
        seen.insert(selected.uri.clone());
    }

    // With 100 different keys and 2 destinations, both should be hit.
    assert_eq!(seen.len(), 2, "hash did not distribute across both destinations");
}

// ---------------------------------------------------------------------------
// Priority failover
// ---------------------------------------------------------------------------

#[test]
fn priority_failover_selects_backup_when_primaries_down() {
    let group = DispatcherGroup::new(
        "failover-test".to_string(),
        Algorithm::Weighted,
        vec![
            make_destination("sip:primary1.example.com", 5060, 1, 1),
            make_destination("sip:primary2.example.com", 5061, 1, 1),
            make_destination("sip:backup1.example.com", 5062, 1, 2),
            make_destination("sip:backup2.example.com", 5063, 1, 2),
        ],
    );

    // While primaries are up, only priority-1 is selected.
    for _ in 0..10 {
        let selected = group.select(None, None).unwrap();
        assert!(
            selected.uri.contains("primary"),
            "expected primary, got {}",
            selected.uri
        );
    }

    // Mark all priority-1 destinations down.
    group.mark_down("sip:primary1.example.com");
    group.mark_down("sip:primary2.example.com");

    // Now only priority-2 should be selected.
    for _ in 0..10 {
        let selected = group.select(None, None).unwrap();
        assert!(
            selected.uri.contains("backup"),
            "expected backup after failover, got {}",
            selected.uri
        );
    }
}

// ---------------------------------------------------------------------------
// Attribute filtering
// ---------------------------------------------------------------------------

#[test]
fn attribute_filter_narrows_selection() {
    let attrs_east = HashMap::from([("region".to_string(), "us-east".to_string())]);
    let attrs_west = HashMap::from([("region".to_string(), "us-west".to_string())]);

    let group = DispatcherGroup::new(
        "attrs-test".to_string(),
        Algorithm::RoundRobin,
        vec![
            make_destination_with_attrs("sip:east.example.com", 5060, 1, 1, attrs_east),
            make_destination_with_attrs("sip:west.example.com", 5061, 1, 1, attrs_west),
        ],
    );

    let filter = HashMap::from([("region".to_string(), "us-east".to_string())]);

    for _ in 0..10 {
        let selected = group.select(None, Some(&filter)).unwrap();
        assert_eq!(
            selected.uri, "sip:east.example.com",
            "attr filter did not narrow to us-east"
        );
    }
}

#[test]
fn attribute_filter_no_match_returns_none() {
    let group = DispatcherGroup::new(
        "attrs-none".to_string(),
        Algorithm::RoundRobin,
        vec![make_destination("sip:gw.example.com", 5060, 1, 1)],
    );

    let filter = HashMap::from([("tier".to_string(), "premium".to_string())]);
    assert!(group.select(None, Some(&filter)).is_none());
}

// ---------------------------------------------------------------------------
// Dynamic groups
// ---------------------------------------------------------------------------

#[test]
fn dynamic_group_add_remove_and_list() {
    let manager = DispatcherManager::new();

    // Initially no groups.
    assert!(manager.group_names().is_empty());

    // Add two groups.
    manager.add_group(DispatcherGroup::new(
        "alpha".to_string(),
        Algorithm::RoundRobin,
        vec![make_destination("sip:a.example.com", 5060, 1, 1)],
    ));
    manager.add_group(DispatcherGroup::new(
        "beta".to_string(),
        Algorithm::Hash,
        vec![make_destination("sip:b.example.com", 5060, 1, 1)],
    ));

    let mut names = manager.group_names();
    names.sort();
    assert_eq!(names, vec!["alpha", "beta"]);

    // Select from both.
    assert!(manager.select("alpha", None, None).is_some());
    assert!(manager.select("beta", Some("key"), None).is_some());

    // Remove one.
    assert!(manager.remove_group("alpha"));
    assert!(manager.select("alpha", None, None).is_none());
    assert!(!manager.remove_group("alpha")); // already gone

    // The other still works.
    assert!(manager.select("beta", Some("key"), None).is_some());
}

// ---------------------------------------------------------------------------
// Health: mark_down / mark_up
// ---------------------------------------------------------------------------

#[test]
fn mark_down_skips_unhealthy_and_mark_up_restores() {
    let group = DispatcherGroup::new(
        "health-test".to_string(),
        Algorithm::Weighted,
        vec![
            make_destination("sip:gw1.example.com", 5060, 1, 1),
            make_destination("sip:gw2.example.com", 5061, 1, 1),
        ],
    );

    // Mark gw1 down — only gw2 should be selected.
    group.mark_down("sip:gw1.example.com");
    for _ in 0..10 {
        let selected = group.select(None, None).unwrap();
        assert_eq!(selected.uri, "sip:gw2.example.com");
    }

    // Mark gw1 back up — both should be selected again.
    group.mark_up("sip:gw1.example.com");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        let selected = group.select(None, None).unwrap();
        seen.insert(selected.uri.clone());
    }
    assert_eq!(seen.len(), 2, "expected both gateways after mark_up");
}

#[test]
fn all_down_returns_none() {
    let group = DispatcherGroup::new(
        "all-down".to_string(),
        Algorithm::RoundRobin,
        vec![
            make_destination("sip:gw1.example.com", 5060, 1, 1),
            make_destination("sip:gw2.example.com", 5061, 1, 1),
        ],
    );

    group.mark_down("sip:gw1.example.com");
    group.mark_down("sip:gw2.example.com");
    assert!(group.select(None, None).is_none());
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

#[test]
fn concurrent_select_and_health_toggling() {
    let manager = Arc::new(DispatcherManager::new());
    manager.add_group(DispatcherGroup::new(
        "concurrent".to_string(),
        Algorithm::RoundRobin,
        vec![
            make_destination("sip:gw1.concurrent.com", 5060, 1, 1),
            make_destination("sip:gw2.concurrent.com", 5061, 1, 1),
            make_destination("sip:gw3.concurrent.com", 5062, 1, 1),
        ],
    ));

    let mut handles = Vec::new();

    // 4 threads doing selects.
    for _ in 0..4 {
        let manager_clone = Arc::clone(&manager);
        handles.push(std::thread::spawn(move || {
            for _ in 0..500 {
                let _ = manager_clone.select("concurrent", None, None);
            }
        }));
    }

    // 2 threads toggling health.
    for uri in ["sip:gw1.concurrent.com", "sip:gw2.concurrent.com"] {
        let manager_clone = Arc::clone(&manager);
        let uri_owned = uri.to_string();
        handles.push(std::thread::spawn(move || {
            let group = manager_clone.get_group("concurrent").unwrap();
            for iteration in 0..250 {
                if iteration % 2 == 0 {
                    group.mark_down(&uri_owned);
                } else {
                    group.mark_up(&uri_owned);
                }
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked during concurrent gateway test");
    }

    // Restore health and verify the system still works.
    let group = manager.get_group("concurrent").unwrap();
    group.mark_up("sip:gw1.concurrent.com");
    group.mark_up("sip:gw2.concurrent.com");
    assert!(manager.select("concurrent", None, None).is_some());
}
