//! `gateway.groups[].inbound_limit`: which groups' limits a source is held to,
//! and that a group's count survives the group object being rebuilt.

use super::*;
use crate::admission::{AdmissionController, InboundLimits, RefusalReason};

const CARRIER_A: &str = "198.51.100.10";
const CARRIER_B: &str = "198.51.100.20";
const SHARED: &str = "203.0.113.7";
const STRANGER: &str = "192.0.2.99";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a literal address")
}

fn limits(max_concurrent_calls: u32, max_calls_per_second: u32) -> InboundLimits {
    InboundLimits {
        max_concurrent_calls,
        max_calls_per_second,
        ..InboundLimits::UNLIMITED
    }
}

fn destination(address: &str) -> Destination {
    Destination::new(
        format!("sip:{address}:5060"),
        format!("{address}:5060")
            .parse()
            .expect("a literal address"),
        Transport::Udp,
        1,
        1,
    )
}

/// A group whose one destination is at `address`, also admitting `networks`.
fn group(name: &str, address: &str, networks: &[&str]) -> DispatcherGroup {
    DispatcherGroup::new(
        name.to_string(),
        Algorithm::Weighted,
        vec![destination(address)],
    )
    .with_source_networks(
        networks
            .iter()
            .map(|spec| parse_source_network(spec).expect("a literal network"))
            .collect(),
    )
}

fn names(limits: &[crate::admission::GroupLimit]) -> Vec<&str> {
    limits.iter().map(|limit| &*limit.name).collect()
}

#[test]
fn a_manager_with_no_limited_group_holds_no_source_to_anything() {
    let manager = DispatcherManager::new();
    manager.add_group(group("carrier-a", CARRIER_A, &[]));
    assert!(manager.inbound_limits_admitting(ip(CARRIER_A)).is_empty());
    assert!(manager.inbound_usage().is_empty());
    assert_eq!(manager.inbound.held_states(), 0);
    assert_eq!(
        manager
            .get_group("carrier-a")
            .expect("the group")
            .inbound_calls_active(),
        None
    );
}

#[test]
fn a_source_is_held_to_the_limit_of_the_group_that_admits_it() {
    let manager = DispatcherManager::new();
    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(5, 0))));
    manager.add_group(group("carrier-b", CARRIER_B, &["203.0.113.0/24"]));

    assert_eq!(
        names(&manager.inbound_limits_admitting(ip(CARRIER_A))),
        ["carrier-a"]
    );
    assert!(
        manager.inbound_limits_admitting(ip(CARRIER_B)).is_empty(),
        "a group with no limit holds its sources to nothing"
    );
    assert!(manager.inbound_limits_admitting(ip(SHARED)).is_empty());
    assert!(manager.inbound_limits_admitting(ip(STRANGER)).is_empty());
}

#[test]
fn a_limit_that_sets_neither_ceiling_is_no_limit() {
    let manager = DispatcherManager::new();
    manager.add_group(
        group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(InboundLimits::UNLIMITED)),
    );
    assert!(manager.inbound_limits_admitting(ip(CARRIER_A)).is_empty());
    assert_eq!(manager.inbound.held_states(), 0);
}

/// Two groups admitting one address: `GatewayView::group_of` names one of
/// them, arbitrarily. The limits are found per group instead, and both apply.
#[test]
fn a_source_two_limited_groups_admit_is_counted_against_both() {
    let manager = DispatcherManager::new();
    manager.add_group(
        group("wide", CARRIER_A, &["203.0.113.0/24"]).with_inbound_limits(Some(limits(2, 0))),
    );
    manager
        .add_group(group("narrow", CARRIER_B, &[SHARED]).with_inbound_limits(Some(limits(1, 0))));

    let both = manager.inbound_limits_admitting(ip(SHARED));
    assert_eq!(names(&both), ["narrow", "wide"], "ordered by name");

    let controller = AdmissionController::unlimited();
    let _held = controller.admit_from(&both).expect("a slot in each");
    let usage = manager.inbound_usage();
    assert_eq!(
        usage
            .iter()
            .map(|usage| (&*usage.group, usage.active))
            .collect::<Vec<_>>(),
        [("narrow", 1), ("wide", 1)]
    );

    let refusal = controller.admit_from(&both).expect_err("narrow is full");
    assert_eq!(refusal.scope.gateway_group(), Some("narrow"));
    assert_eq!(refusal.reason, RefusalReason::Concurrent);
}

/// The reason the counters are not a field of the group: a refresh builds a
/// new group object, and a call that was up before it is still up after.
#[test]
fn a_group_rebuilt_under_its_name_keeps_its_live_count() {
    let manager = DispatcherManager::new();
    let controller = AdmissionController::unlimited();
    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(2, 0))));
    let before = manager.get_group("carrier-a").expect("the group");

    let first = controller
        .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
        .expect("the first slot");

    // What a source reconcile does: a new object, registered under the name.
    manager.add_group(
        DispatcherGroup::from_existing(
            "carrier-a".to_string(),
            Algorithm::Weighted,
            manager.destinations_of("carrier-a"),
        )
        .with_inbound_limits(Some(limits(2, 0))),
    );
    let after = manager.get_group("carrier-a").expect("the group");
    assert!(!Arc::ptr_eq(&before, &after), "the group was rebuilt");
    assert_eq!(after.inbound_calls_active(), Some(1));

    let limits_after = manager.inbound_limits_admitting(ip(CARRIER_A));
    let _second = controller
        .admit_from(&limits_after)
        .expect("the second slot");
    controller
        .admit_from(&limits_after)
        .expect_err("the call from before the rebuild still holds the first");

    drop(first);
    assert_eq!(after.inbound_calls_active(), Some(1));
    controller
        .admit_from(&limits_after)
        .expect("the freed slot");
}

#[test]
fn a_changed_limit_applies_to_the_calls_already_up() {
    let manager = DispatcherManager::new();
    let controller = AdmissionController::unlimited();
    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(3, 0))));
    let held: Vec<_> = (0..3)
        .map(|_| {
            controller
                .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
                .expect("a slot")
        })
        .collect();

    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(
        InboundLimits {
            max_concurrent_calls: 1,
            max_calls_per_second: 0,
            reject_code: 486,
            retry_after_secs: 0,
        },
    )));
    let usage = manager.inbound_usage();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].active, 3, "lowering a ceiling ends no call");
    assert_eq!(usage[0].limits.max_concurrent_calls, 1);

    let refusal = controller
        .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
        .expect_err("over the lowered ceiling");
    assert_eq!(refusal.reject_code, 486);
    drop(held);
}

#[test]
fn a_group_that_drops_its_limit_stops_holding_its_sources_to_one() {
    let manager = DispatcherManager::new();
    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(1, 0))));
    manager.add_group(group("carrier-a", CARRIER_A, &[]));
    assert!(manager.inbound_limits_admitting(ip(CARRIER_A)).is_empty());
    assert_eq!(manager.inbound.held_states(), 0);
}

/// A removed group's counters go with it. A call still up releases into the
/// counters it was admitted against, and a group later added under the name
/// starts from zero.
#[test]
fn a_removed_group_is_forgotten_and_re_added_starts_clean() {
    let manager = DispatcherManager::new();
    let controller = AdmissionController::unlimited();
    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(1, 0))));
    let held = controller
        .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
        .expect("the one slot");

    assert!(manager.remove_group("carrier-a"));
    assert!(manager.inbound_limits_admitting(ip(CARRIER_A)).is_empty());
    assert!(manager.inbound_usage().is_empty());
    assert_eq!(manager.inbound.held_states(), 0);

    manager.add_group(group("carrier-a", CARRIER_A, &[]).with_inbound_limits(Some(limits(1, 0))));
    assert_eq!(manager.inbound_usage()[0].active, 0);
    let _fresh = controller
        .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
        .expect("the re-added group's one slot");

    drop(held);
    assert_eq!(
        manager.inbound_usage()[0].active,
        1,
        "the old call released into the old counters, not these"
    );
    assert_eq!(controller.active(), 1);
}

/// The per-module leak gate: groups added, limited, rebuilt and removed leave
/// no counters held, and the calls admitted along the way leave none up.
#[test]
fn the_registry_drains_to_baseline_through_group_churn() {
    let manager = DispatcherManager::new();
    let controller = AdmissionController::unlimited();
    for round in 0..500u32 {
        let name = format!("carrier-{}", round % 7);
        manager.add_group(group(&name, CARRIER_A, &[]).with_inbound_limits(Some(limits(4, 0))));
        let held: Vec<_> = (0..6)
            .filter_map(|_| {
                controller
                    .admit_from(&manager.inbound_limits_admitting(ip(CARRIER_A)))
                    .ok()
            })
            .collect();
        manager.add_group(group(&name, CARRIER_A, &[]).with_inbound_limits(Some(limits(4, 0))));
        drop(held);
        assert_eq!(controller.active(), 0, "round {round}");
        assert!(
            manager
                .inbound_usage()
                .iter()
                .all(|usage| usage.active == 0),
            "round {round}"
        );
        if round % 3 == 0 {
            manager.remove_group(&name);
        }
    }
    for index in 0..7 {
        manager.remove_group(&format!("carrier-{index}"));
    }
    assert_eq!(manager.inbound.held_states(), 0);
    assert!(manager.inbound_usage().is_empty());
    assert!(manager.inbound_limits_admitting(ip(CARRIER_A)).is_empty());
}

#[test]
fn groups_added_at_once_all_end_up_in_the_snapshot() {
    let manager = Arc::new(DispatcherManager::new());
    let handles: Vec<_> = (0..16)
        .map(|index| {
            let manager = Arc::clone(&manager);
            std::thread::spawn(move || {
                manager.add_group(
                    group(&format!("carrier-{index:02}"), CARRIER_A, &[])
                        .with_inbound_limits(Some(limits(1, 0))),
                );
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("an adding thread");
    }
    assert_eq!(manager.inbound_usage().len(), 16);
    assert_eq!(manager.inbound_limits_admitting(ip(CARRIER_A)).len(), 16);
}
