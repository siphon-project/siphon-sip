//! RFC 5626 §4.4.1 CRLF keepalive for connection-oriented transports.
//!
//! A background task periodically sends `\r\n\r\n` (double CRLF "ping")
//! over every active TCP/TLS connection.  The peer should respond with a
//! single `\r\n` ("pong").  If no pong arrives after `failure_threshold`
//! consecutive pings, the connection is considered dead and closed.
//!
//! WebSocket connections are excluded — they use the native WebSocket
//! Ping/Pong mechanism instead.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::ConnectionId;
use crate::config::CrlfKeepaliveConfig;

/// Shared pong tracker — the dispatcher records pongs, the keepalive
/// task increments miss counters on each ping.
pub struct CrlfPongTracker {
    /// ConnectionId → consecutive missed pong count.
    missed: DashMap<ConnectionId, u32>,
    /// Connections that have responded to at least one CRLF ping.
    /// Only close connections that demonstrate CRLF support — peers
    /// that never respond simply don't implement RFC 5626 §4.4.1.
    pong_seen: DashMap<ConnectionId, ()>,
}

impl Default for CrlfPongTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CrlfPongTracker {
    pub fn new() -> Self {
        Self {
            missed: DashMap::new(),
            pong_seen: DashMap::new(),
        }
    }

    /// Called by the dispatcher when a bare CRLF arrives on a connection.
    pub fn record_pong(&self, id: ConnectionId) {
        self.missed.remove(&id);
        self.pong_seen.insert(id, ());
    }

    /// Returns true if this connection ever responded to a CRLF ping.
    pub fn has_seen_pong(&self, id: ConnectionId) -> bool {
        self.pong_seen.contains_key(&id)
    }

    /// Called by the keepalive task before sending a ping.
    /// Returns the new missed count (0 means a pong was received since last ping).
    fn record_ping(&self, id: ConnectionId) -> u32 {
        let mut entry = self.missed.entry(id).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Remove tracking state for a closed connection.
    fn remove(&self, id: ConnectionId) {
        self.missed.remove(&id);
        self.pong_seen.remove(&id);
    }
}

/// The double-CRLF ping payload (RFC 5626 §4.4.1).
const CRLF_PING: &[u8] = b"\r\n\r\n";

/// The single-CRLF pong payload (RFC 5626 §4.4.1).
const CRLF_PONG: &[u8] = b"\r\n";

/// Drain any leading CRLF keepalive bytes from a stream-transport accumulator.
///
/// Behavior (RFC 5626 §4.4.1, RFC 6223 Flow-Timer, RFC 3261 §7.5):
///   - `\r\n\r\n` at the head is a peer ping → consume 4 bytes, write `\r\n`
///     pong back over `writer`.  Always responded to regardless of whether
///     siphon's own keepalive prober is running — the response is part of
///     the protocol contract, not a feature flag.
///   - `\r\n` at the head is either a peer pong (response to siphon's
///     earlier ping) or a stray CRLF before a real SIP message (RFC 3261
///     §7.5 permits this).  In either case, consume 2 bytes; record the
///     pong on the tracker when present (idempotent — clearing the missed
///     counter for a stray CRLF is harmless).
///
/// Returns the number of keepalive frames drained.
pub fn drain_leading_crlf_keepalives(
    accumulator: &mut BytesMut,
    connection_id: ConnectionId,
    writer: &mpsc::Sender<Bytes>,
    tracker: Option<&Arc<CrlfPongTracker>>,
) -> usize {
    let mut drained = 0;
    loop {
        if accumulator.len() >= 4 && &accumulator[..4] == CRLF_PING {
            accumulator.advance(4);
            // Best-effort: if the per-connection write channel is full
            // the peer will re-ping; we don't want to back-pressure the
            // read path on keepalive responses.
            let _ = writer.try_send(Bytes::from_static(CRLF_PONG));
            drained += 1;
            continue;
        }
        if accumulator.len() >= 2 && &accumulator[..2] == CRLF_PONG {
            accumulator.advance(2);
            if let Some(t) = tracker {
                t.record_pong(connection_id);
            }
            drained += 1;
            continue;
        }
        return drained;
    }
}

/// A connection map that the keepalive task iterates.
type ConnectionMap = Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>;

/// Spawn the CRLF keepalive background task for TCP and TLS connections.
pub fn spawn(
    config: CrlfKeepaliveConfig,
    connection_maps: Vec<ConnectionMap>,
    pong_tracker: Arc<CrlfPongTracker>,
) {
    if !config.enabled {
        info!("CRLF keepalive disabled");
        return;
    }

    let interval = Duration::from_secs(config.interval_secs as u64);
    let threshold = config.failure_threshold;

    info!(
        interval_secs = config.interval_secs,
        failure_threshold = threshold,
        "CRLF keepalive started"
    );

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);

        loop {
            tick.tick().await;

            for map in &connection_maps {
                // Collect keys first to avoid holding DashMap iterators across awaits.
                let ids: Vec<ConnectionId> = map.iter().map(|e| *e.key()).collect();

                for id in ids {
                    let missed = pong_tracker.record_ping(id);

                    if missed > threshold {
                        if pong_tracker.has_seen_pong(id) {
                            // Peer previously responded but stopped — connection
                            // is likely dead.
                            warn!(
                                connection_id = id.0,
                                missed = missed,
                                "closing unresponsive connection (CRLF keepalive timeout)"
                            );
                            // Dropping the sender closes the mpsc channel, which
                            // causes the write task to exit and triggers cleanup
                            // in tcp.rs / tls.rs.
                            map.remove(&id);
                            pong_tracker.remove(id);
                        } else {
                            // Peer never responded to any CRLF ping — it probably
                            // doesn't support RFC 5626 §4.4.1.  Don't kill the
                            // connection; just stop tracking missed pings for it.
                            debug!(
                                connection_id = id.0,
                                "peer does not support CRLF keepalive — skipping"
                            );
                            pong_tracker.remove(id);
                        }
                        continue;
                    }

                    if let Some(sender) = map.get(&id) {
                        let _ = sender.try_send(Bytes::from_static(CRLF_PING));
                    }

                    debug!(connection_id = id.0, missed = missed, "CRLF ping sent");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pong_tracker_records_and_clears() {
        let tracker = CrlfPongTracker::new();
        let id = ConnectionId(1);

        assert_eq!(tracker.record_ping(id), 1);
        assert_eq!(tracker.record_ping(id), 2);

        tracker.record_pong(id);
        // After pong, counter resets
        assert_eq!(tracker.record_ping(id), 1);
    }

    #[test]
    fn pong_tracker_remove() {
        let tracker = CrlfPongTracker::new();
        let id = ConnectionId(42);

        tracker.record_ping(id);
        tracker.record_ping(id);
        tracker.remove(id);

        // After removal, starts fresh
        assert_eq!(tracker.record_ping(id), 1);
    }

    #[tokio::test]
    async fn sends_crlf_ping_to_connections() {
        let map: ConnectionMap = Arc::new(DashMap::new());
        let (tx, mut rx) = mpsc::channel(16);
        let id = ConnectionId(1);
        map.insert(id, tx);

        let tracker = Arc::new(CrlfPongTracker::new());

        let config = CrlfKeepaliveConfig {
            enabled: true,
            interval_secs: 1,
            failure_threshold: 10,
        };

        spawn(config, vec![Arc::clone(&map)], Arc::clone(&tracker));

        // Should receive a CRLF ping within ~1 second
        let data = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("timeout waiting for CRLF ping")
            .expect("channel closed");

        assert_eq!(&data[..], CRLF_PING);
    }

    #[tokio::test]
    async fn evicts_after_threshold_when_peer_supported_crlf() {
        let map: ConnectionMap = Arc::new(DashMap::new());
        let (tx, _rx) = mpsc::channel(16);
        let id = ConnectionId(99);
        map.insert(id, tx);

        let tracker = Arc::new(CrlfPongTracker::new());
        // Simulate peer responding once (proves CRLF support)
        tracker.record_pong(id);

        let config = CrlfKeepaliveConfig {
            enabled: true,
            interval_secs: 1,
            failure_threshold: 2,
        };

        spawn(config, vec![Arc::clone(&map)], Arc::clone(&tracker));

        // After 3+ ticks without pong, connection should be evicted
        // (threshold=2, so eviction happens on tick 3)
        tokio::time::sleep(Duration::from_millis(3500)).await;

        assert!(
            map.get(&id).is_none(),
            "connection should have been evicted after threshold"
        );
    }

    #[tokio::test]
    async fn drain_responds_to_peer_ping_with_pong() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(8);
        let tracker = Arc::new(CrlfPongTracker::new());
        let id = ConnectionId(7);
        let mut buf = BytesMut::from(&b"\r\n\r\n"[..]);

        let drained = drain_leading_crlf_keepalives(&mut buf, id, &tx, Some(&tracker));

        assert_eq!(drained, 1);
        assert!(buf.is_empty(), "ping bytes must be consumed");
        let pong = rx.try_recv().expect("pong should have been queued");
        assert_eq!(&pong[..], CRLF_PONG);
        // Peer ping is NOT a pong to siphon — tracker must not record one.
        assert!(!tracker.has_seen_pong(id));
    }

    #[tokio::test]
    async fn drain_records_peer_pong_without_writing_back() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(8);
        let tracker = Arc::new(CrlfPongTracker::new());
        let id = ConnectionId(11);
        // Prime the missed counter so record_pong has something to clear.
        let _ = tracker.record_ping(id);

        let mut buf = BytesMut::from(&b"\r\n"[..]);
        let drained = drain_leading_crlf_keepalives(&mut buf, id, &tx, Some(&tracker));

        assert_eq!(drained, 1);
        assert!(buf.is_empty());
        assert!(rx.try_recv().is_err(), "peer pong must not trigger a write");
        assert!(tracker.has_seen_pong(id));
    }

    #[tokio::test]
    async fn drain_leaves_sip_message_intact_after_keepalive() {
        let (tx, _rx) = mpsc::channel::<Bytes>(8);
        let tracker = Arc::new(CrlfPongTracker::new());
        let id = ConnectionId(13);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\r\n\r\n");
        buf.extend_from_slice(b"OPTIONS sip:server SIP/2.0\r\n\r\n");

        let drained = drain_leading_crlf_keepalives(&mut buf, id, &tx, Some(&tracker));

        assert_eq!(drained, 1);
        assert_eq!(&buf[..], b"OPTIONS sip:server SIP/2.0\r\n\r\n");
    }

    #[tokio::test]
    async fn drain_handles_multiple_back_to_back_pings() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(8);
        let tracker = Arc::new(CrlfPongTracker::new());
        let id = ConnectionId(19);

        let mut buf = BytesMut::from(&b"\r\n\r\n\r\n\r\n\r\n"[..]);
        let drained = drain_leading_crlf_keepalives(&mut buf, id, &tx, Some(&tracker));

        // Two pings + one trailing pong/stray CRLF
        assert_eq!(drained, 3);
        assert!(buf.is_empty());
        let pong_count = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert_eq!(pong_count, 2, "one pong per ping");
    }

    #[tokio::test]
    async fn drain_without_tracker_still_responds_to_pings() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(8);
        let id = ConnectionId(23);
        let mut buf = BytesMut::from(&b"\r\n\r\n"[..]);

        let drained = drain_leading_crlf_keepalives(&mut buf, id, &tx, None);

        assert_eq!(drained, 1);
        assert!(rx.try_recv().is_ok(), "pong should be sent regardless of tracker");
    }

    #[tokio::test]
    async fn does_not_evict_peer_without_crlf_support() {
        let map: ConnectionMap = Arc::new(DashMap::new());
        let (tx, _rx) = mpsc::channel(16);
        let id = ConnectionId(100);
        map.insert(id, tx);

        let tracker = Arc::new(CrlfPongTracker::new());
        // No pong recorded — peer doesn't support CRLF keepalive

        let config = CrlfKeepaliveConfig {
            enabled: true,
            interval_secs: 1,
            failure_threshold: 2,
        };

        spawn(config, vec![Arc::clone(&map)], Arc::clone(&tracker));

        // After 3+ ticks, connection should NOT be evicted (peer doesn't support CRLF)
        tokio::time::sleep(Duration::from_millis(3500)).await;

        assert!(
            map.get(&id).is_some(),
            "connection should NOT be evicted — peer never responded to CRLF"
        );
    }
}
