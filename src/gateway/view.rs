//! The live gateway view: every source any gateway group admits, published as
//! one immutable, lookup-ready snapshot.
//!
//! "Who is a gateway" has exactly one definition in siphon:
//! [`super::DispatcherGroup::admitted_sources`] — each resolved destination
//! address plus the group's `source_networks`. `request.from_gateway()` answers
//! from the same two inputs per group, and the kernel allow set publishes the
//! same list. This module merges it across every group (siphon.yaml, script and
//! `gateway.backend` source alike) into a sorted, non-overlapping range list, so
//! a question that has no group name to start from — *is this source any
//! gateway at all?* — costs one binary search instead of a walk over every
//! group.
//!
//! The snapshot is rebuilt off the request path, wherever membership changes:
//! a group added or removed (start-up, a script, a source reconcile), a probe
//! cycle re-resolving a group's destinations, and the allow-set floor tick
//! re-resolving the unprobed ones. Readers take the current snapshot through
//! an [`ArcSwap`] and never lock; a rebuild swaps a whole new snapshot in and
//! the old one is dropped with its last reader.
//!
//! Anything that has to act when a source *becomes* a gateway — lifting an
//! auto-ban, evicting an APIBAN entry — subscribes with
//! [`GatewayView::subscribe`] and is told which ranges each publish added.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use ipnet::IpNet;

/// One admitted range and the group that admits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedRange {
    pub network: IpNet,
    pub group: Arc<str>,
}

/// Called after a publish that changed the view, with the new snapshot and the
/// ranges it admits that the previous one did not.
pub type ViewListener = Arc<dyn Fn(&GatewaySnapshot, &[AdmittedRange]) + Send + Sync>;

/// One range of a snapshot, as the inclusive bounds a lookup compares against.
#[derive(Debug, PartialEq, Eq)]
struct Span<T> {
    first: T,
    last: T,
    network: IpNet,
    group: Arc<str>,
}

/// An immutable merge of every admitted range, per family, sorted by start and
/// non-overlapping. Built by [`GatewaySnapshot::build`]; never mutated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GatewaySnapshot {
    v4: Vec<Span<u32>>,
    v6: Vec<Span<u128>>,
}

impl GatewaySnapshot {
    /// Merge `sources` into a lookup-ready snapshot.
    ///
    /// A range nested inside another is dropped and the containing range's
    /// group is the one reported — the same merge the kernel allow set needs,
    /// since an interval set refuses overlapping elements.
    pub fn build(sources: Vec<AdmittedRange>) -> Self {
        let mut snapshot = Self::default();
        for range in normalise_by(sources, |range| range.network) {
            match range.network {
                IpNet::V4(network) => snapshot.v4.push(Span {
                    first: u32::from(network.network()),
                    last: u32::from(network.broadcast()),
                    network: range.network,
                    group: range.group,
                }),
                IpNet::V6(network) => snapshot.v6.push(Span {
                    first: u128::from(network.network()),
                    last: u128::from(network.broadcast()),
                    network: range.network,
                    group: range.group,
                }),
            }
        }
        snapshot
    }

    /// The group admitting `source`, or `None` when no gateway admits it.
    /// O(log n) in the number of merged ranges.
    pub fn group_of(&self, source: IpAddr) -> Option<&Arc<str>> {
        match source {
            IpAddr::V4(address) => find(&self.v4, u32::from(address)).map(|span| &span.group),
            IpAddr::V6(address) => find(&self.v6, u128::from(address)).map(|span| &span.group),
        }
    }

    /// Whether any gateway admits `source`.
    pub fn contains(&self, source: IpAddr) -> bool {
        self.group_of(source).is_some()
    }

    /// Whether the whole of `network` sits inside one admitted range.
    pub fn covers(&self, network: &IpNet) -> bool {
        match network {
            IpNet::V4(network) => find(&self.v4, u32::from(network.network()))
                .is_some_and(|span| u32::from(network.broadcast()) <= span.last),
            IpNet::V6(network) => find(&self.v6, u128::from(network.network()))
                .is_some_and(|span| u128::from(network.broadcast()) <= span.last),
        }
    }

    /// Every merged range with its group, v4 first, each family by start.
    pub fn ranges(&self) -> Vec<AdmittedRange> {
        let v4 = self.v4.iter().map(|span| AdmittedRange {
            network: span.network,
            group: Arc::clone(&span.group),
        });
        let v6 = self.v6.iter().map(|span| AdmittedRange {
            network: span.network,
            group: Arc::clone(&span.group),
        });
        v4.chain(v6).collect()
    }

    /// Number of merged ranges.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether no gateway admits anything.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// The span holding `key`: the last one starting at or before it, if it also
/// ends at or after it. Correct because the spans never overlap.
fn find<T: Ord + Copy>(spans: &[Span<T>], key: T) -> Option<&Span<T>> {
    let index = spans.partition_point(|span| span.first <= key);
    let span = spans.get(index.checked_sub(1)?)?;
    (key <= span.last).then_some(span)
}

/// Sort by start, deduplicate, and drop any range another already contains.
///
/// CIDR ranges are either disjoint or nested — a partial overlap is not
/// expressible — so dropping the contained one is exact. Sorted by start with
/// the broader range first on a tie, a range's container, when there is one,
/// is always the last range kept before it, so this is one pass after the sort
/// rather than a comparison of every pair. The result is in (start, prefix)
/// order, so an unchanged input compares equal to the last output.
pub fn normalise_by<T>(mut items: Vec<T>, network: impl Fn(&T) -> IpNet) -> Vec<T> {
    items.sort_by(|left, right| {
        let (left, right) = (network(left), network(right));
        left.network()
            .cmp(&right.network())
            .then_with(|| left.prefix_len().cmp(&right.prefix_len()))
    });
    let mut kept: Vec<T> = Vec::with_capacity(items.len());
    for item in items {
        if kept
            .last()
            .is_some_and(|held| network(held).contains(&network(&item)))
        {
            continue;
        }
        kept.push(item);
    }
    kept
}

/// The published gateway view: the current snapshot, swapped whole on change.
pub struct GatewayView {
    current: ArcSwap<GatewaySnapshot>,
    /// Subscribers to a change. The lock also serialises publishes, so two
    /// rebuilds racing — a probe cycle and a reconcile — can never store an
    /// older view over a newer one.
    listeners: Mutex<Vec<ViewListener>>,
}

impl GatewayView {
    /// An empty view: no source is a gateway.
    pub fn new() -> Self {
        Self {
            current: ArcSwap::from_pointee(GatewaySnapshot::default()),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// The current snapshot.
    pub fn snapshot(&self) -> Arc<GatewaySnapshot> {
        self.current.load_full()
    }

    /// Whether any gateway admits `source`. Lock-free; the request-path check.
    #[inline]
    pub fn contains(&self, source: IpAddr) -> bool {
        self.current.load().contains(source)
    }

    /// The group admitting `source`, for a log line.
    pub fn group_of(&self, source: IpAddr) -> Option<Arc<str>> {
        self.current.load().group_of(source).cloned()
    }

    /// Be told about every publish that changes the view, after it is visible
    /// to readers.
    pub fn subscribe(&self, listener: ViewListener) {
        self.lock_listeners().push(listener);
    }

    /// Rebuild from `sources` and swap the result in if it differs from the
    /// current snapshot. Returns whether it did.
    ///
    /// `sources` is read under the publish lock, so the view stored is never
    /// older than one another thread already stored.
    pub fn publish(&self, sources: impl FnOnce() -> Vec<AdmittedRange>) -> bool {
        let listeners = self.lock_listeners();
        let next = GatewaySnapshot::build(sources());
        let previous = self.current.load_full();
        if *previous == next {
            return false;
        }
        let added: Vec<AdmittedRange> = next
            .ranges()
            .into_iter()
            .filter(|range| !previous.covers(&range.network))
            .collect();
        drop(previous);
        let next = Arc::new(next);
        self.current.store(Arc::clone(&next));
        for listener in listeners.iter() {
            listener(&next, &added);
        }
        true
    }

    fn lock_listeners(&self) -> std::sync::MutexGuard<'_, Vec<ViewListener>> {
        self.listeners
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl Default for GatewayView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(spec: &str, group: &str) -> AdmittedRange {
        AdmittedRange {
            network: spec.parse().expect("test CIDR"),
            group: Arc::from(group),
        }
    }

    fn ip(spec: &str) -> IpAddr {
        spec.parse().expect("test address")
    }

    #[test]
    fn a_host_and_a_network_are_found_and_their_neighbours_are_not() {
        let snapshot = GatewaySnapshot::build(vec![
            range("192.0.2.7/32", "carriers"),
            range("198.51.100.0/24", "trunks"),
        ]);
        assert_eq!(
            snapshot.group_of(ip("192.0.2.7")).map(|g| &**g),
            Some("carriers")
        );
        assert!(!snapshot.contains(ip("192.0.2.6")));
        assert!(!snapshot.contains(ip("192.0.2.8")));
        assert_eq!(
            snapshot.group_of(ip("198.51.100.0")).map(|g| &**g),
            Some("trunks")
        );
        assert_eq!(
            snapshot.group_of(ip("198.51.100.255")).map(|g| &**g),
            Some("trunks")
        );
        assert!(!snapshot.contains(ip("198.51.101.0")));
        assert!(!snapshot.contains(ip("198.51.99.255")));
    }

    #[test]
    fn families_do_not_cross() {
        let snapshot = GatewaySnapshot::build(vec![
            range("0.0.0.0/0", "everything-v4"),
            range("2001:db8::1/128", "one-v6"),
        ]);
        assert!(snapshot.contains(ip("203.0.113.9")));
        assert!(snapshot.contains(ip("2001:db8::1")));
        assert!(!snapshot.contains(ip("2001:db8::2")));
        assert!(!snapshot.contains(ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn a_nested_range_reports_its_container() {
        let snapshot = GatewaySnapshot::build(vec![
            range("203.0.113.9/32", "inner"),
            range("203.0.113.0/24", "outer"),
        ]);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(
            snapshot.group_of(ip("203.0.113.9")).map(|g| &**g),
            Some("outer")
        );
    }

    #[test]
    fn an_empty_snapshot_admits_nothing() {
        let snapshot = GatewaySnapshot::build(Vec::new());
        assert!(snapshot.is_empty());
        assert!(!snapshot.contains(ip("192.0.2.1")));
        assert!(!snapshot.contains(ip("2001:db8::1")));
    }

    #[test]
    fn the_top_and_bottom_of_the_space_are_found() {
        let snapshot = GatewaySnapshot::build(vec![
            range("0.0.0.0/32", "bottom"),
            range("255.255.255.255/32", "top"),
            range("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "top6"),
        ]);
        assert!(snapshot.contains(ip("0.0.0.0")));
        assert!(snapshot.contains(ip("255.255.255.255")));
        assert!(!snapshot.contains(ip("255.255.255.254")));
        assert!(snapshot.contains(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
    }

    #[test]
    fn lookup_agrees_with_a_linear_scan_over_many_ranges() {
        // The binary search is the whole point of the snapshot; check it
        // against the obvious answer over a few thousand disjoint hosts and
        // networks, probing on, between and around every one.
        // Documentation space only (2001:db8::/32): hosts one per three
        // /112 blocks, and a /120 per /96.
        let mut sources = Vec::new();
        for high in 0..16u32 {
            for low in (0..=255u32).step_by(3) {
                sources.push(range(&format!("2001:db8:{high:x}::{low:x}:1/128"), "hosts"));
            }
            sources.push(range(&format!("2001:db8:ff:{high:x}::/120"), "nets"));
        }
        let snapshot = GatewaySnapshot::build(sources.clone());
        let networks: Vec<IpNet> = sources.iter().map(|range| range.network).collect();
        for high in 0..16u32 {
            for low in 0..=255u32 {
                for probe in [
                    format!("2001:db8:{high:x}::{low:x}:1"),
                    format!("2001:db8:{high:x}::{low:x}:2"),
                    format!("2001:db8:ff:{high:x}::{low:x}"),
                    format!("2001:db8:ff:{high:x}::1:{low:x}"),
                ] {
                    let address = ip(&probe);
                    let linear = networks.iter().any(|network| network.contains(&address));
                    assert_eq!(snapshot.contains(address), linear, "{probe}");
                }
            }
        }
    }

    #[test]
    fn covers_needs_the_whole_range_inside_one_span() {
        let snapshot = GatewaySnapshot::build(vec![range("198.51.100.0/25", "half")]);
        assert!(snapshot.covers(&"198.51.100.7/32".parse().expect("cidr")));
        assert!(snapshot.covers(&"198.51.100.0/25".parse().expect("cidr")));
        assert!(!snapshot.covers(&"198.51.100.0/24".parse().expect("cidr")));
        assert!(!snapshot.covers(&"198.51.100.200/32".parse().expect("cidr")));
    }

    // --- normalise_by ---

    fn networks(specs: &[&str]) -> Vec<IpNet> {
        specs
            .iter()
            .map(|spec| spec.parse().expect("cidr"))
            .collect()
    }

    #[test]
    fn normalise_drops_every_level_of_a_nesting() {
        let kept = normalise_by(
            networks(&[
                "192.0.2.0/24",
                "192.0.2.0/26",
                "192.0.2.16/28",
                "192.0.2.17/32",
            ]),
            |network| *network,
        );
        assert_eq!(kept, networks(&["192.0.2.0/24"]));
    }

    #[test]
    fn normalise_keeps_a_disjoint_range_after_a_nested_run() {
        let kept = normalise_by(
            networks(&[
                "192.0.2.128/26",
                "192.0.2.64/26",
                "192.0.2.72/29",
                "192.0.2.0/26",
            ]),
            |network| *network,
        );
        assert_eq!(
            kept,
            networks(&["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26"])
        );
    }

    // --- publishing ---

    #[test]
    fn an_unchanged_publish_is_not_a_change() {
        let view = GatewayView::new();
        assert!(view.publish(|| vec![range("192.0.2.1/32", "carriers")]));
        assert!(!view.publish(|| vec![range("192.0.2.1/32", "carriers")]));
    }

    #[test]
    fn listeners_hear_only_what_a_publish_added() {
        let view = GatewayView::new();
        let heard: Arc<Mutex<Vec<Vec<IpNet>>>> = Arc::default();
        let sink = Arc::clone(&heard);
        view.subscribe(Arc::new(move |_snapshot, added| {
            sink.lock()
                .expect("test lock")
                .push(added.iter().map(|range| range.network).collect());
        }));

        view.publish(|| vec![range("192.0.2.1/32", "a")]);
        view.publish(|| vec![range("192.0.2.1/32", "a"), range("192.0.2.2/32", "b")]);
        // A removal changes the view but adds nothing.
        view.publish(|| vec![range("192.0.2.2/32", "b")]);
        // Unchanged: no call at all.
        view.publish(|| vec![range("192.0.2.2/32", "b")]);

        let heard = heard.lock().expect("test lock");
        assert_eq!(
            *heard,
            vec![
                networks(&["192.0.2.1/32"]),
                networks(&["192.0.2.2/32"]),
                Vec::new(),
            ]
        );
    }

    #[test]
    fn a_replaced_snapshot_is_dropped_not_retained() {
        // The view is replaced, never grown: once swapped out and unreferenced,
        // the old snapshot must be freed.
        let view = GatewayView::new();
        view.publish(|| vec![range("192.0.2.1/32", "a")]);
        let old = Arc::downgrade(&view.snapshot());
        assert!(old.upgrade().is_some(), "the current snapshot is alive");
        view.publish(|| vec![range("192.0.2.2/32", "b")]);
        assert!(
            old.upgrade().is_none(),
            "the replaced snapshot outlived the swap"
        );
    }
}
