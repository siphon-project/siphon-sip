//! Backend peer pool for the Diameter server.
//!
//! A `PeerPool` is a named set of outbound peers (by name) that the Diameter server can
//! relay to. It resolves names to live [`DiameterClient`]s through the shared
//! [`DiameterManager`] using **state-as-truth**: a peer is eligible only when
//! its connection is [`PeerState::Open`]. Reconnects swap the `Arc` under the
//! same manager key, so the pool transparently picks up the fresh connection
//! without any deregister/re-register race.
//!
//! Selection strategies: round-robin, weighted, and sticky (session affinity).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::diameter::{DiameterClient, DiameterManager};

/// A pool of backend peers for one tenant + routing target.
pub struct PeerPool {
    tenant: String,
    manager: Arc<DiameterManager>,
    /// Candidate peer names, in configured order.
    peers: Vec<String>,
    /// Round-robin cursor (monotonic; probed modulo `peers.len()`).
    cursor: AtomicUsize,
    /// Sticky affinity: key → (peer name, expiry instant).
    sticky: DashMap<String, (String, Instant)>,
}

impl PeerPool {
    pub fn new(tenant: impl Into<String>, manager: Arc<DiameterManager>, peers: Vec<String>) -> Self {
        Self {
            tenant: tenant.into(),
            manager,
            peers,
            cursor: AtomicUsize::new(0),
            sticky: DashMap::new(),
        }
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn peer_names(&self) -> &[String] {
        &self.peers
    }

    /// Number of pool members currently `Open`.
    pub fn live_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|name| self.manager.live_client(name).is_some())
            .count()
    }

    /// Pick the next live peer in round-robin order, skipping dead ones.
    pub fn pick_round_robin(&self) -> Option<Arc<DiameterClient>> {
        self.pick_round_robin_named().map(|(_, client)| client)
    }

    /// Round-robin pick returning the chosen peer's name alongside the client.
    pub fn pick_round_robin_named(&self) -> Option<(String, Arc<DiameterClient>)> {
        let count = self.peers.len();
        if count == 0 {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        for offset in 0..count {
            let idx = (start.wrapping_add(offset)) % count;
            let name = &self.peers[idx];
            if let Some(client) = self.manager.live_client(name) {
                return Some((name.clone(), client));
            }
        }
        None
    }

    /// Pick a live peer weighted by `weights` (missing entries default to 1).
    /// Distribution is proportional to weight across live peers.
    pub fn pick_weighted(&self, weights: &HashMap<String, u32>) -> Option<Arc<DiameterClient>> {
        self.pick_weighted_named(weights).map(|(_, client)| client)
    }

    /// Weighted pick returning the chosen peer's name alongside the client.
    pub fn pick_weighted_named(
        &self,
        weights: &HashMap<String, u32>,
    ) -> Option<(String, Arc<DiameterClient>)> {
        let live: Vec<(&String, u32)> = self
            .peers
            .iter()
            .filter(|name| self.manager.live_client(name).is_some())
            .map(|name| (name, weights.get(name).copied().unwrap_or(1).max(1)))
            .collect();
        if live.is_empty() {
            return None;
        }
        let total: u32 = live.iter().map(|(_, weight)| *weight).sum();
        let tick = (self.cursor.fetch_add(1, Ordering::Relaxed) as u64 % total as u64) as u32;
        let mut accumulated = 0u32;
        for (name, weight) in live {
            accumulated += weight;
            if tick < accumulated {
                return self.manager.live_client(name).map(|client| (name.clone(), client));
            }
        }
        None
    }

    /// Pick a peer with session affinity: the same `key` returns the same peer
    /// while it stays live and within `ttl`; otherwise re-picks (round-robin)
    /// and records the new mapping. Stores the peer **name**, so a reconnected
    /// peer is transparently re-resolved.
    pub fn pick_sticky(&self, key: &str, ttl: Duration) -> Option<Arc<DiameterClient>> {
        self.pick_sticky_named(key, ttl).map(|(_, client)| client)
    }

    /// Sticky pick returning the chosen peer's name alongside the client.
    pub fn pick_sticky_named(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Option<(String, Arc<DiameterClient>)> {
        let now = Instant::now();
        if let Some(entry) = self.sticky.get(key) {
            let (name, expires) = entry.value();
            if *expires > now {
                if let Some(client) = self.manager.live_client(name) {
                    return Some((name.clone(), client));
                }
            }
        }
        // Stale, expired, or dead — re-pick and refresh the mapping.
        let (name, client) = self.pick_round_robin_named()?;
        self.sticky.insert(key.to_string(), (name.clone(), now + ttl));
        Some((name, client))
    }

    /// Drop expired sticky entries (lazy eviction also happens on lookup).
    pub fn sweep_sticky(&self) {
        let now = Instant::now();
        self.sticky.retain(|_, (_, expires)| *expires > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::{DiameterPeer, PeerConfig, PeerState};

    fn config(origin_host: &str) -> PeerConfig {
        PeerConfig {
            host: "h".to_string(),
            port: 3868,
            // Distinct per peer so tests can identify which one was picked.
            origin_host: origin_host.to_string(),
            origin_realm: "realm".to_string(),
            destination_host: None,
            destination_realm: "realm".to_string(),
            local_ip: "127.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        }
    }

    /// Identify which peer a pick landed on via its (test-unique) origin_host,
    /// which we set equal to the peer name.
    fn picked_name(client: &Arc<DiameterClient>) -> String {
        client.peer().config().origin_host.clone()
    }

    fn register(manager: &DiameterManager, name: &str, state: PeerState) -> Arc<DiameterClient> {
        let (write_tx, _rx) = tokio::sync::mpsc::channel(1);
        let peer = DiameterPeer::new_for_test(config(name), write_tx);
        peer.set_state_for_test(state);
        let client = Arc::new(DiameterClient::new(Arc::new(peer)));
        manager.register(name.to_string(), Arc::clone(&client));
        client
    }

    #[test]
    fn round_robin_cycles_live_peers() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "a", PeerState::Open);
        register(&manager, "b", PeerState::Open);
        register(&manager, "c", PeerState::Open);
        let pool = PeerPool::new(
            "t",
            Arc::clone(&manager),
            vec!["a".into(), "b".into(), "c".into()],
        );
        assert_eq!(pool.live_count(), 3);

        // Over 3 consecutive picks we touch all three distinct peers exactly.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            seen.insert(picked_name(&pool.pick_round_robin().unwrap()));
        }
        assert_eq!(seen.len(), 3);
        assert!(seen.contains("a") && seen.contains("b") && seen.contains("c"));
    }

    #[test]
    fn round_robin_skips_dead_peers() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "dead", PeerState::Closed);
        register(&manager, "live", PeerState::Open);
        let pool = PeerPool::new(
            "t",
            Arc::clone(&manager),
            vec!["dead".into(), "live".into()],
        );
        assert_eq!(pool.live_count(), 1);
        // Every pick must land on the live peer, never the dead one.
        for _ in 0..5 {
            assert_eq!(picked_name(&pool.pick_round_robin().unwrap()), "live");
        }
    }

    #[test]
    fn all_dead_returns_none() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "a", PeerState::Closed);
        register(&manager, "b", PeerState::Connecting);
        let pool = PeerPool::new("t", Arc::clone(&manager), vec!["a".into(), "b".into()]);
        assert_eq!(pool.live_count(), 0);
        assert!(pool.pick_round_robin().is_none());
        assert!(pool.pick_weighted(&HashMap::new()).is_none());
        assert!(pool.pick_sticky("k", Duration::from_secs(60)).is_none());
    }

    #[test]
    fn sticky_returns_same_peer_until_expiry_or_death() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "a", PeerState::Open);
        register(&manager, "b", PeerState::Open);
        let pool = PeerPool::new("t", Arc::clone(&manager), vec!["a".into(), "b".into()]);

        // First sticky pick records a mapping; subsequent picks for the same
        // key return the same peer name while live + within TTL.
        let _first = pool.pick_sticky("session-1", Duration::from_secs(60)).unwrap();
        let mapped_name = pool.sticky.get("session-1").unwrap().value().0.clone();
        for _ in 0..5 {
            pool.pick_sticky("session-1", Duration::from_secs(60)).unwrap();
            assert_eq!(pool.sticky.get("session-1").unwrap().value().0, mapped_name);
        }

        // Kill the mapped peer → next sticky pick must re-pick a different,
        // still-live peer.
        manager
            .live_client(&mapped_name)
            .unwrap()
            .peer()
            .set_state_for_test(PeerState::Closed);
        let repick = pool.pick_sticky("session-1", Duration::from_secs(60));
        assert!(repick.is_some());
        assert_ne!(pool.sticky.get("session-1").unwrap().value().0, mapped_name);
    }

    #[test]
    fn sticky_expiry_repicks() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "a", PeerState::Open);
        let pool = PeerPool::new("t", Arc::clone(&manager), vec!["a".into()]);
        // Zero TTL → entry is immediately expired on next lookup; still works.
        assert!(pool.pick_sticky("k", Duration::from_millis(0)).is_some());
        pool.sweep_sticky();
    }

    #[test]
    fn weighted_distribution_favours_higher_weight() {
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "heavy", PeerState::Open);
        register(&manager, "light", PeerState::Open);
        let pool = PeerPool::new(
            "t",
            Arc::clone(&manager),
            vec!["heavy".into(), "light".into()],
        );
        let mut weights = HashMap::new();
        weights.insert("heavy".to_string(), 9);
        weights.insert("light".to_string(), 1);

        // The cursor starts at 0; over exactly `total`=10 ticks the weighted
        // wheel yields "heavy" 9 times and "light" once.
        let mut heavy = 0;
        let mut light = 0;
        for _ in 0..10 {
            match picked_name(&pool.pick_weighted(&weights).unwrap()).as_str() {
                "heavy" => heavy += 1,
                "light" => light += 1,
                other => panic!("unexpected peer {other}"),
            }
        }
        assert_eq!(heavy, 9, "heavy should win 9/10");
        assert_eq!(light, 1, "light should win 1/10");
    }

    #[test]
    fn reconnect_swap_keeps_entry_live() {
        // State-as-truth: replacing the Arc under the same key (reconnect)
        // keeps the pool resolving the peer as live.
        let manager = Arc::new(DiameterManager::new());
        register(&manager, "a", PeerState::Open);
        let pool = PeerPool::new("t", Arc::clone(&manager), vec!["a".into()]);
        assert!(pool.pick_round_robin().is_some());

        // Simulate disconnect: old client goes Closed.
        manager.live_client("a"); // (no-op read)
        manager
            .client("a")
            .unwrap()
            .peer()
            .set_state_for_test(PeerState::Closed);
        assert!(pool.pick_round_robin().is_none());

        // Reconnect: register a fresh Open client under the same key.
        register(&manager, "a", PeerState::Open);
        assert!(pool.pick_round_robin().is_some());
    }
}
