//! Per-group `Allow` sets (`gateway.groups[].allow_methods`).
//!
//! A group with a set is the `Allow` siphon advertises to every peer the group
//! admits: its destinations' resolved addresses and its `source_networks`, the
//! same membership `call.from_gateway()` answers from. Read once per relayed
//! response, OPTIONS answer and B-leg INVITE, so the lookup reads a prebuilt
//! snapshot of only the groups that have a set, rebuilt when a group is added
//! or removed. With no such group it is one atomic load.
//!
//! A peer two groups with a set admit gets the set of the group registered
//! first. Groups from `gateway.groups` are registered in the order they are
//! written, so that is the group configured first; a group replaced under the
//! same name keeps its place.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::DispatcherGroup;

impl DispatcherGroup {
    /// Advertise `allow` (an `Allow` value already checked by
    /// [`crate::sip::allow::render_allow_methods`]) to this group's peers
    /// instead of every method siphon implements. `None` keeps the full set.
    pub fn with_allow_methods(mut self, allow: Option<String>) -> Self {
        self.allow_methods = allow.map(Arc::from);
        self
    }

    /// The `Allow` value this group's peers are shown, when the group narrows it.
    pub fn allow_methods(&self) -> Option<&Arc<str>> {
        self.allow_methods.as_ref()
    }
}

pub(super) struct AllowMethodsRegistry {
    /// The order each group name was first registered in.
    registered: DashMap<String, u64>,
    next: AtomicU64,
    /// The groups that have a set, in registration order.
    narrowed: ArcSwap<Vec<Arc<DispatcherGroup>>>,
    /// Serialises rebuilds, so two groups added at once cannot leave the
    /// snapshot of the one that read the group map first.
    rebuild: Mutex<()>,
}

impl AllowMethodsRegistry {
    pub(super) fn new() -> Self {
        Self {
            registered: DashMap::new(),
            next: AtomicU64::new(0),
            narrowed: ArcSwap::from_pointee(Vec::new()),
            rebuild: Mutex::new(()),
        }
    }

    /// Note `name` as registered, keeping the place of a name seen before.
    pub(super) fn register(&self, name: &str) {
        self.registered
            .entry(name.to_string())
            .or_insert_with(|| self.next.fetch_add(1, Ordering::Relaxed));
    }

    pub(super) fn forget(&self, name: &str) {
        self.registered.remove(name);
    }

    /// Rebuild the snapshot from the live groups.
    pub(super) fn rebuild(&self, groups: &DashMap<String, Arc<DispatcherGroup>>) {
        let _serialised = self
            .rebuild
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut narrowed: Vec<(u64, Arc<DispatcherGroup>)> = groups
            .iter()
            .filter(|entry| entry.value().allow_methods.is_some())
            .map(|entry| {
                let place = self
                    .registered
                    .get(entry.key())
                    .map(|place| *place)
                    .unwrap_or(u64::MAX);
                (place, Arc::clone(entry.value()))
            })
            .collect();
        narrowed.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.name.cmp(&right.1.name))
        });
        self.narrowed.store(Arc::new(
            narrowed.into_iter().map(|(_, group)| group).collect(),
        ));
    }

    /// Whether any group narrows `Allow` at all.
    pub(super) fn any(&self) -> bool {
        !self.narrowed.load().is_empty()
    }

    /// The `Allow` of the first-registered group with a set that admits `peer`.
    pub(super) fn for_peer(&self, peer: IpAddr) -> Option<Arc<str>> {
        let narrowed = self.narrowed.load();
        narrowed
            .iter()
            .find(|group| group.contains_source(peer))
            .and_then(|group| group.allow_methods.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Algorithm, Destination, DispatcherManager};
    use super::*;
    use crate::transport::Transport;

    const NO_REFER: &str = "INVITE, ACK, CANCEL, BYE, OPTIONS";
    const NO_MESSAGE: &str = "INVITE, ACK, CANCEL, BYE, REFER";

    fn group(name: &str, address: &str, allow: Option<&str>) -> DispatcherGroup {
        let destination = Destination::new(
            format!("sip:{address}"),
            address.parse().expect("a literal address"),
            Transport::Udp,
            1,
            1,
        );
        DispatcherGroup::new(name.to_string(), Algorithm::Weighted, vec![destination])
            .with_allow_methods(allow.map(str::to_string))
    }

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("a literal address")
    }

    #[test]
    fn a_peer_of_a_narrowed_group_gets_its_set_and_others_none() {
        let manager = DispatcherManager::new();
        manager.add_group(group("trunk", "198.51.100.7:5060", Some(NO_REFER)));
        manager.add_group(group("plain", "198.51.100.8:5060", None));
        assert_eq!(
            manager
                .allow_methods_for_peer(ip("198.51.100.7"))
                .as_deref(),
            Some(NO_REFER)
        );
        assert_eq!(manager.allow_methods_for_peer(ip("198.51.100.8")), None);
        assert_eq!(manager.allow_methods_for_peer(ip("192.0.2.10")), None);
    }

    #[test]
    fn source_networks_count_as_peers() {
        let manager = DispatcherManager::new();
        manager.add_group(
            group("trunk", "198.51.100.7:5060", Some(NO_REFER))
                .with_source_networks(vec!["203.0.113.0/24".parse().expect("a CIDR")]),
        );
        assert_eq!(
            manager
                .allow_methods_for_peer(ip("203.0.113.40"))
                .as_deref(),
            Some(NO_REFER)
        );
    }

    #[test]
    fn a_peer_in_two_groups_gets_the_first_registered_groups_set() {
        // Registered "zeta" first: registration order wins, not the name.
        let manager = DispatcherManager::new();
        manager.add_group(group("zeta", "198.51.100.7:5060", Some(NO_REFER)));
        manager.add_group(group("alpha", "198.51.100.7:5060", Some(NO_MESSAGE)));
        for _ in 0..16 {
            assert_eq!(
                manager
                    .allow_methods_for_peer(ip("198.51.100.7"))
                    .as_deref(),
                Some(NO_REFER)
            );
        }
        // Replacing the first group keeps its place.
        manager.add_group(group("zeta", "198.51.100.7:5060", Some(NO_REFER)));
        assert_eq!(
            manager
                .allow_methods_for_peer(ip("198.51.100.7"))
                .as_deref(),
            Some(NO_REFER)
        );
        // Removing it hands the peer to the other.
        assert!(manager.remove_group("zeta"));
        assert_eq!(
            manager
                .allow_methods_for_peer(ip("198.51.100.7"))
                .as_deref(),
            Some(NO_MESSAGE)
        );
    }

    #[test]
    fn replacing_a_group_without_a_set_drops_it_from_the_snapshot() {
        let manager = DispatcherManager::new();
        manager.add_group(group("trunk", "198.51.100.7:5060", Some(NO_REFER)));
        assert!(manager.narrows_allow());
        manager.add_group(group("trunk", "198.51.100.7:5060", None));
        assert!(!manager.narrows_allow());
        assert_eq!(manager.allow_methods_for_peer(ip("198.51.100.7")), None);
    }

    /// The health probe to a group with a set advertises it; one to a group
    /// without keeps the full set.
    #[tokio::test]
    async fn the_probe_options_carry_the_groups_allow() {
        let uac = super::super::tests::test_uac();
        let manager = Arc::new(DispatcherManager::new());
        super::super::spawn_health_probers(Arc::clone(&manager), Arc::clone(&uac.sender));
        for (name, allow, expected) in [
            ("trunk", Some(NO_REFER), NO_REFER),
            ("plain", None, crate::sip::SUPPORTED_METHODS),
        ] {
            manager.add_group(group(name, "198.51.100.7:5060", allow));
            let sent =
                tokio::time::timeout(std::time::Duration::from_secs(5), uac.udp.recv_async())
                    .await
                    .expect("the prober sent nothing")
                    .expect("outbound channel closed");
            let probe =
                crate::sip::parser::parse_sip_message_bytes(&sent.data).expect("the probe parses");
            assert_eq!(
                probe.headers.get_all("Allow"),
                Some(&vec![expected.to_string()]),
                "probe of {name}"
            );
            assert!(manager.remove_group(name));
        }
    }

    #[test]
    fn the_registry_forgets_removed_names() {
        let manager = DispatcherManager::new();
        manager.add_group(group("trunk", "198.51.100.7:5060", Some(NO_REFER)));
        assert!(manager.remove_group("trunk"));
        assert!(manager.allow.registered.is_empty());
        assert!(!manager.narrows_allow());
    }
}
