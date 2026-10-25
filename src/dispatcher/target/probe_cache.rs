//! A next hop whose TCP path just failed is not probed again for a while.
//!
//! The over-MTU switch from UDP to TCP (RFC 3261 §18.1.1) confirms a TCP path
//! with a blocking connect before it commits a request to TCP. Against a peer
//! that is up but no longer accepting (a node wedged behind a full accept
//! queue), every such connect runs its full timeout, and under load every
//! over-MTU request to that peer starts one: several a second, each holding a
//! `block_in_place`, so tokio keeps handing its worker cores to fresh
//! blocking-pool threads, each of which pins a Python thread state for its
//! short life. Nothing about the peer changes between those probes, so the
//! answer of the first one is reused: after a failure the next hop is skipped
//! for [`UNREACHABLE_WINDOW`], the request goes straight to the forced-UDP
//! fallback, and the warning is logged once per window instead of per request.
//! While one probe to a next hop is in flight, the others do not start their
//! own.
//!
//! Bounded: at most [`CAPACITY`] next hops are remembered, expired entries are
//! swept whenever the map is full, and a next hop past the bound is probed
//! without being remembered rather than growing the map.

use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// How long a next hop whose TCP path failed is not probed again.
pub(in crate::dispatcher) const UNREACHABLE_WINDOW: Duration = Duration::from_secs(30);

/// How many next hops are remembered at most.
const CAPACITY: usize = 4096;

/// The process-wide cache the dispatcher's over-MTU switches share.
pub(in crate::dispatcher) fn probe_cache() -> &'static ProbeCache {
    static CACHE: LazyLock<ProbeCache> =
        LazyLock::new(|| ProbeCache::new(UNREACHABLE_WINDOW, CAPACITY));
    &CACHE
}

/// What a next hop's entry says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A probe is running.
    Probing,
    /// The last probe failed; not probed again until then.
    Unreachable { until: Instant },
}

/// Next hops whose TCP path is being probed or just failed.
pub(in crate::dispatcher) struct ProbeCache {
    entries: DashMap<SocketAddr, State>,
    window: Duration,
    capacity: usize,
    /// Probes started per next hop, for the tests that count them.
    #[cfg(test)]
    started: DashMap<SocketAddr, usize>,
}

/// Why [`ProbeCache::claim`] said not to probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dispatcher) enum Skip {
    /// The last probe failed this long ago at most; this much of the window
    /// is left.
    Unreachable { remaining: Duration },
    /// Another request is probing this next hop right now.
    Probing,
}

/// The right to probe a next hop, from [`ProbeCache::claim`]. Report the
/// outcome with [`finish`](Self::finish); dropped unfinished (a panic in the
/// probe), it forgets the next hop so a later request probes again.
pub(in crate::dispatcher) struct Probe<'cache> {
    cache: &'cache ProbeCache,
    next_hop: SocketAddr,
    /// Whether the claim is in the map (false past the capacity bound).
    tracked: bool,
    finished: bool,
}

impl ProbeCache {
    pub(in crate::dispatcher) fn new(window: Duration, capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            window,
            capacity,
            #[cfg(test)]
            started: DashMap::new(),
        }
    }

    /// Whether to probe `next_hop` now.
    pub(in crate::dispatcher) fn claim(
        &self,
        next_hop: SocketAddr,
        now: Instant,
    ) -> Result<Probe<'_>, Skip> {
        let mut full = false;
        if !self.entries.contains_key(&next_hop) && self.entries.len() >= self.capacity {
            self.sweep(now);
            // Read before `entry` takes its shard lock: `len` locks every
            // shard. Concurrent claims can overshoot the bound by their count.
            full = self.entries.len() >= self.capacity;
        }
        let tracked = match self.entries.entry(next_hop) {
            Entry::Occupied(mut occupied) => match *occupied.get() {
                State::Probing => return Err(Skip::Probing),
                State::Unreachable { until } if until > now => {
                    return Err(Skip::Unreachable {
                        remaining: until - now,
                    })
                }
                State::Unreachable { .. } => {
                    occupied.insert(State::Probing);
                    true
                }
            },
            Entry::Vacant(_) if full => false,
            Entry::Vacant(vacant) => {
                vacant.insert(State::Probing);
                true
            }
        };
        #[cfg(test)]
        {
            *self.started.entry(next_hop).or_insert(0) += 1;
        }
        Ok(Probe {
            cache: self,
            next_hop,
            tracked,
            finished: false,
        })
    }

    /// Drop every entry whose window has passed.
    pub(in crate::dispatcher) fn sweep(&self, now: Instant) {
        self.entries.retain(|_, state| match state {
            State::Probing => true,
            State::Unreachable { until } => *until > now,
        });
    }

    #[cfg(test)]
    pub(in crate::dispatcher) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Forget `next_hop`, for a test that reuses an ephemeral port another
    /// test may have seen refused within the window.
    #[cfg(test)]
    pub(in crate::dispatcher) fn forget(&self, next_hop: SocketAddr) {
        self.entries.remove(&next_hop);
    }

    /// Probes started for `next_hop` so far.
    #[cfg(test)]
    pub(in crate::dispatcher) fn probes_started(&self, next_hop: SocketAddr) -> usize {
        self.started.get(&next_hop).map(|count| *count).unwrap_or(0)
    }
}

impl Probe<'_> {
    /// Record the outcome: a reachable next hop is forgotten (the next
    /// over-MTU request probes it again), an unreachable one is skipped for
    /// the window from `now`.
    pub(in crate::dispatcher) fn finish(mut self, reachable: bool, now: Instant) {
        self.finished = true;
        if !self.tracked {
            return;
        }
        if reachable {
            self.cache.entries.remove(&self.next_hop);
        } else {
            self.cache.entries.insert(
                self.next_hop,
                State::Unreachable {
                    until: now + self.cache.window,
                },
            );
        }
    }
}

impl Drop for Probe<'_> {
    fn drop(&mut self) {
        if !self.finished && self.tracked {
            self.cache
                .entries
                .remove_if(&self.next_hop, |_, state| *state == State::Probing);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 20], port))
    }

    /// After a failure the next hop is skipped for the window, then probed
    /// again.
    #[test]
    fn a_failed_next_hop_is_skipped_for_the_window() {
        let cache = ProbeCache::new(Duration::from_secs(30), 16);
        let start = Instant::now();
        cache
            .claim(hop(5060), start)
            .expect("the first request probes")
            .finish(false, start);
        assert_eq!(
            cache
                .claim(hop(5060), start + Duration::from_secs(10))
                .err(),
            Some(Skip::Unreachable {
                remaining: Duration::from_secs(20)
            })
        );
        assert!(
            cache
                .claim(hop(5060), start + Duration::from_secs(31))
                .is_ok(),
            "probed again once the window has passed"
        );
    }

    /// Of 100 over-MTU requests to a refusing next hop in one window, one
    /// probes; the others do not wait or connect.
    #[test]
    fn a_hundred_requests_to_a_refusing_next_hop_probe_once_per_window() {
        let cache = ProbeCache::new(Duration::from_secs(30), 16);
        let start = Instant::now();
        let mut probes = 0;
        for request in 0..100u32 {
            let now = start + Duration::from_millis(u64::from(request) * 100);
            if let Ok(probe) = cache.claim(hop(5061), now) {
                probes += 1;
                probe.finish(false, now);
            }
        }
        assert_eq!(probes, 1);
        assert_eq!(cache.probes_started(hop(5061)), 1);
    }

    /// A probe in flight keeps concurrent requests from starting their own.
    #[test]
    fn concurrent_requests_do_not_probe_a_next_hop_already_being_probed() {
        let cache = ProbeCache::new(Duration::from_secs(30), 16);
        let now = Instant::now();
        let probe = cache.claim(hop(5062), now).expect("the first probes");
        assert_eq!(cache.claim(hop(5062), now).err(), Some(Skip::Probing));
        probe.finish(true, now);
        assert!(
            cache.claim(hop(5062), now).is_ok(),
            "a reachable next hop is not remembered"
        );
    }

    /// An unfinished probe (its request panicked) does not leave the next hop
    /// stuck as probing.
    #[test]
    fn an_abandoned_probe_forgets_the_next_hop() {
        let cache = ProbeCache::new(Duration::from_secs(30), 16);
        let now = Instant::now();
        drop(cache.claim(hop(5063), now).expect("probes"));
        assert_eq!(cache.len(), 0);
        assert!(cache.claim(hop(5063), now).is_ok());
    }

    /// The leak gate: failures to many next hops fill the cache to its bound
    /// at most, and once their windows pass a sweep drains it to empty.
    #[test]
    fn the_cache_is_bounded_and_drains_once_the_windows_pass() {
        let cache = ProbeCache::new(Duration::from_secs(30), 64);
        let start = Instant::now();
        for port in 0..1000u16 {
            if let Ok(probe) = cache.claim(hop(20_000 + port), start) {
                probe.finish(false, start);
            }
            assert!(cache.len() <= 64, "bounded: {}", cache.len());
        }
        assert_eq!(cache.len(), 64);
        cache.sweep(start + Duration::from_secs(31));
        assert_eq!(cache.len(), 0, "every expired entry is swept");

        // A full cache sweeps itself on the next new next hop.
        for port in 0..64u16 {
            cache
                .claim(hop(30_000 + port), start)
                .expect("room")
                .finish(false, start);
        }
        let later = start + Duration::from_secs(31);
        cache
            .claim(hop(40_000), later)
            .expect("probes")
            .finish(false, later);
        assert_eq!(cache.len(), 1, "the expired 64 swept, the new one kept");
    }

    /// The process-wide cache is shared: every caller gets the same one.
    #[test]
    fn the_process_wide_cache_is_one_cache() {
        assert!(std::ptr::eq(probe_cache(), probe_cache()));
        assert_eq!(probe_cache().window, UNREACHABLE_WINDOW);
    }
}

#[cfg(test)]
#[path = "probe_storm_tests.rs"]
mod storm_tests;
