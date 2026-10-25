//! A destination whose connect just failed is not connected to again for a
//! short while, and concurrent connects to one destination coalesce.
//!
//! Without this, a peer that stops answering SYNs (a node wedged behind a full
//! accept queue, a UE whose SA is gone) costs one full connect timeout per send
//! to it. Sends with no live connection queue on a per-destination fallback
//! lane ([`crate::transport::stream`]) that runs them in order, and requests
//! wait on the establishment lock one behind the other, so 64 queued responses
//! took 64 timeouts to fail while every new one was shed. After a P-CSCF
//! restart that was most of a minute of REGISTER responses that never left an
//! I-CSCF.
//!
//! Now a failed or timed-out connect marks its destination down for a backoff
//! window. Inside the window every send to it, queued or new, fails at once
//! with [`DestinationDown`] and no connect, counted in
//! `siphon_pool_connect_suppressed_total` and logged once per
//! [`WARN_INTERVAL`] with the count. The first send after the window tries a
//! fresh connect and holds the destination down while that connect runs, so
//! the others still fail fast rather than queue behind it; a success clears
//! the record and a failure starts the next, longer window.
//!
//! The window starts at [`INITIAL_BACKOFF`] and doubles per consecutive
//! failure up to [`MAX_BACKOFF`]:
//!
//! - 1 s first: a peer that refused because it was restarting is retried
//!   within a second, and against one that drops SYNs the connect timeout
//!   (5 s) dominates anyway, so it is tried once per ~6 s to begin with.
//! - 4 s cap: finding a next hop that comes back after a pause matters more
//!   than the SYNs spent on one that stays dead. A recovered peer is reached
//!   at most 4 s plus one connect after it is back, an eighth of Timer F
//!   (64·T1 = 32 s, RFC 3261 §17.1.2.2), so the transactions running across
//!   the outage still get through; a peer that is down for good costs one
//!   connect per ~9 s (cap plus timeout), which is nothing.
//!
//! What a window covers is one pool key: destination, transport and source,
//! the same thing a pooled connection is. Only failures the peer is to blame
//! for open one: refused, reset, unreachable, timed out. A local bind
//! failure (`EADDRINUSE` on an IPsec 4-tuple) says nothing about the peer.
//!
//! This is not the over-MTU probe cache
//! ([`crate::dispatcher`]'s `probe_cache`): that one decides *whether* to
//! use TCP for a next hop, keeps its answer for 30 s and falls back to UDP;
//! this one is the connect to a destination already chosen, has no fallback
//! (a response goes to its Via over the same transport, RFC 3261 §18.2.2) and
//! must find a recovered peer within seconds. The probe connects through
//! [`ConnectionPool::connect_tcp_from`], so a destination down here fails the
//! probe at once and the probe cache records it as it would a real failure.
//!
//! Bounded: an entry exists only for a destination whose last connect failed,
//! is removed on the next success, and is swept [`FORGET_AFTER`] past the end
//! of its window if nothing tries it again. At most [`CAPACITY`] destinations
//! are tracked; past that a failure is not recorded and that destination is
//! connected to as it was before this existed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tracing::{info, warn};

use super::{Coalesced, ConnectionPool, PoolKey};
use crate::transport::ConnectionId;

/// The first backoff window after a connect fails.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// The longest backoff window.
const MAX_BACKOFF: Duration = Duration::from_secs(4);

/// How long past the end of its window a destination nothing tried again is
/// remembered (so its next failure keeps doubling the window) before it is
/// swept.
const FORGET_AFTER: Duration = Duration::from_secs(60);

/// How often a sweep runs at most.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// How many destinations are tracked at most.
const CAPACITY: usize = 16_384;

/// How often the warning for one destination's dropped sends is logged at most.
const WARN_INTERVAL: Duration = Duration::from_secs(1);

/// The error a send fails with while its destination is backing off.
#[derive(Debug)]
pub struct DestinationDown {
    destination: SocketAddr,
    remaining: Duration,
}

impl std::fmt::Display for DestinationDown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the last connect to {} failed; not connecting again for {:?}",
            self.destination, self.remaining
        )
    }
}

impl std::error::Error for DestinationDown {}

/// Whether `error` is a send failed fast because its destination is backing
/// off. Such a send has already been counted and logged (rate-limited), so a
/// caller that would log every failure can log this one quietly.
pub fn is_destination_down(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<DestinationDown>())
}

/// Whether a connect failure is the peer's: it opens a backoff window.
fn is_peer_failure(error: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        error.kind(),
        ConnectionRefused
            | ConnectionReset
            | ConnectionAborted
            | TimedOut
            | HostUnreachable
            | NetworkUnreachable
            | NetworkDown
    )
}

/// The window after `failures` consecutive failures.
fn window(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    INITIAL_BACKOFF
        .saturating_mul(1 << doublings)
        .min(MAX_BACKOFF)
}

/// One destination whose last connect failed.
#[derive(Debug)]
struct Down {
    /// No connect before this.
    until: Instant,
    /// Consecutive failed connects.
    failures: u32,
    /// Sends failed fast since the last warning.
    unreported: u64,
    /// Sends failed fast since the first failure.
    dropped: u64,
    last_warned: Option<Instant>,
}

/// Destinations whose last connect failed.
pub(super) struct ConnectBackoff {
    entries: DashMap<PoolKey, Down>,
    last_sweep: Mutex<Instant>,
}

impl ConnectBackoff {
    pub(super) fn new() -> Self {
        Self {
            entries: DashMap::new(),
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// Fail fast if `key` is inside its window. Counts and (rate-limited)
    /// logs the dropped send.
    fn check(&self, key: &PoolKey, now: Instant) -> Result<(), io::Error> {
        let (remaining, warning) = match self.entries.get_mut(key) {
            Some(mut down) if down.until > now => {
                down.unreported += 1;
                down.dropped += 1;
                let warn_now = down
                    .last_warned
                    .is_none_or(|warned| now.duration_since(warned) >= WARN_INTERVAL);
                let warning = warn_now.then(|| {
                    let report = (down.unreported, down.failures);
                    down.unreported = 0;
                    down.last_warned = Some(now);
                    report
                });
                (down.until - now, warning)
            }
            _ => return Ok(()),
        };
        crate::metrics::pool_connect::record_suppressed(key.transport);
        if let Some((dropped, failures)) = warning {
            warn!(
                destination = %key.destination,
                transport = %key.transport,
                dropped,
                failures,
                retry_in = ?remaining,
                "pool: outbound dropped without a connect: the last connect to this destination failed and it is backing off"
            );
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            DestinationDown {
                destination: key.destination,
                remaining,
            },
        ))
    }

    /// Under the establishment lock, just before connecting: fail fast inside
    /// the window, else hold a destination with a failure on record down for
    /// `attempt` so the sends that arrive while this connect runs fail fast
    /// instead of queueing behind it. A destination with no record is not
    /// held: its waiters share this connect's outcome through the lock.
    fn claim(&self, key: &PoolKey, now: Instant, attempt: Duration) -> Result<(), io::Error> {
        self.check(key, now)?;
        if let Some(mut down) = self.entries.get_mut(key) {
            down.until = now + attempt;
        }
        Ok(())
    }

    /// Record a connect's outcome.
    fn record(&self, key: &PoolKey, outcome: &Result<ConnectionId, io::Error>, now: Instant) {
        match outcome {
            Ok(_) => self.record_success(key),
            Err(error) if is_peer_failure(error) => self.record_failure(key, now),
            Err(_) => {}
        }
        self.maybe_sweep(now);
    }

    fn record_success(&self, key: &PoolKey) {
        if let Some((_, down)) = self.entries.remove(key) {
            info!(
                destination = %key.destination,
                transport = %key.transport,
                failures = down.failures,
                dropped = down.dropped,
                "pool: connected again after failed connects; sends dropped meanwhile"
            );
        }
    }

    fn record_failure(&self, key: &PoolKey, now: Instant) {
        crate::metrics::pool_connect::record_failure(key.transport);
        // `len` locks every shard, so read it before `entry` holds one.
        let full = !self.entries.contains_key(key) && {
            if self.entries.len() >= CAPACITY {
                self.sweep(now);
            }
            self.entries.len() >= CAPACITY
        };
        match self.entries.entry(key.clone()) {
            Entry::Occupied(mut occupied) => {
                let down = occupied.get_mut();
                down.failures = down.failures.saturating_add(1);
                down.until = now + window(down.failures);
            }
            Entry::Vacant(_) if full => {}
            Entry::Vacant(vacant) => {
                vacant.insert(Down {
                    until: now + window(1),
                    failures: 1,
                    unreported: 0,
                    dropped: 0,
                    last_warned: None,
                });
            }
        }
    }

    /// Sweep if the last sweep is [`SWEEP_INTERVAL`] old. Never waits on
    /// another sweep.
    fn maybe_sweep(&self, now: Instant) {
        let due = match self.last_sweep.try_lock() {
            Ok(mut last) if now.saturating_duration_since(*last) >= SWEEP_INTERVAL => {
                *last = now;
                true
            }
            _ => false,
        };
        if due {
            self.sweep(now);
        }
    }

    /// Forget every destination [`FORGET_AFTER`] past the end of its window.
    fn sweep(&self, now: Instant) {
        self.entries
            .retain(|_, down| down.until + FORGET_AFTER > now);
    }

    /// Destinations tracked, for the drains-to-baseline leak test.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl ConnectionPool {
    /// Run `establish` for `key` unless a live connection turns up or the
    /// destination is backing off.
    ///
    /// Concurrent callers for one key coalesce on its establishment lock: one
    /// connects and the rest wait, then reuse the connection it opened or fail
    /// with its failure ([`DestinationDown`]) rather than connect again. A
    /// second concurrent connect from the fixed IPsec source port would
    /// `bind`/`connect` the same `(src, dst)` 4-tuple and fail
    /// `EADDRNOTAVAIL`/`EADDRINUSE`, and against a peer that drops SYNs each
    /// one would run its own timeout. The lock is never held while
    /// enqueueing: parking there convoys every other caller for the
    /// destination, which is how one stuck peer became a per-destination stall.
    pub(super) async fn establish_coalesced<Establish, Connecting>(
        &self,
        key: &PoolKey,
        establish: Establish,
    ) -> Coalesced
    where
        Establish: FnOnce() -> Connecting,
        Connecting: Future<Output = Result<ConnectionId, io::Error>>,
    {
        if let Err(down) = self.backoff.check(key, Instant::now()) {
            return Coalesced::Established(Err(down));
        }
        let connect_lock = self
            .connect_locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let coalesced = {
            let _establish_guard = connect_lock.lock().await;
            // Re-check: another caller may have connected, or failed to, while
            // we waited for the lock.
            match self.pooled(key).filter(|(_, sender)| !sender.is_closed()) {
                Some(existing) => Coalesced::Reuse(existing),
                None => {
                    // A TLS connect is a TCP connect and a handshake, each
                    // bounded by the connect timeout.
                    let attempt = self.connect_timeout.saturating_mul(2);
                    match self.backoff.claim(key, Instant::now(), attempt) {
                        Err(down) => Coalesced::Established(Err(down)),
                        Ok(()) => {
                            let outcome = establish().await;
                            self.backoff.record(key, &outcome, Instant::now());
                            Coalesced::Established(outcome)
                        }
                    }
                }
            }
        };
        // Drop the lock once no waiter remains (map ref + our clone == 2), so
        // `connect_locks` stays bounded even as a UE's `port_us` rotates each
        // re-AKA.
        self.connect_locks
            .remove_if(key, |_, lock| Arc::strong_count(lock) <= 2);
        coalesced
    }

    /// Destinations backing off and establishment locks held, for the
    /// drains-to-baseline leak test.
    #[cfg(test)]
    pub(crate) fn connect_state_len(&self) -> (usize, usize) {
        (self.backoff.len(), self.connect_locks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;

    fn key(port: u16) -> PoolKey {
        PoolKey {
            destination: SocketAddr::from(([198, 51, 100, 7], port)),
            transport: Transport::Tcp,
            bind: None,
            verified_name: None,
        }
    }

    fn refused() -> Result<ConnectionId, io::Error> {
        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
    }

    #[test]
    fn the_window_doubles_from_one_second_to_a_four_second_cap() {
        let windows: Vec<u64> = (1..=6).map(|failures| window(failures).as_secs()).collect();
        assert_eq!(windows, vec![1, 2, 4, 4, 4, 4]);
        assert_eq!(window(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn a_failure_opens_a_window_and_a_success_closes_it() {
        let backoff = ConnectBackoff::new();
        let now = Instant::now();
        let destination = key(5060);
        assert!(backoff.check(&destination, now).is_ok());

        backoff.record(&destination, &refused(), now);
        let error = backoff
            .check(&destination, now + Duration::from_millis(500))
            .expect_err("inside the first window");
        assert!(is_destination_down(&error));
        assert!(backoff
            .check(&destination, now + Duration::from_millis(1_001))
            .is_ok());

        // Claimed for an attempt that fails: the next window is twice as long.
        let retry = now + Duration::from_millis(1_001);
        backoff
            .claim(&destination, retry, Duration::from_secs(10))
            .expect("the window has passed");
        assert!(
            backoff.check(&destination, retry).is_err(),
            "held down while the retry runs"
        );
        backoff.record(&destination, &refused(), retry);
        assert!(backoff
            .check(&destination, retry + Duration::from_millis(1_500))
            .is_err());
        assert!(backoff
            .check(&destination, retry + Duration::from_millis(2_001))
            .is_ok());

        backoff.record(&destination, &Ok(ConnectionId::default()), retry);
        assert_eq!(backoff.len(), 0, "a success forgets the destination");
    }

    #[test]
    fn a_local_failure_opens_no_window() {
        let backoff = ConnectBackoff::new();
        let now = Instant::now();
        backoff.record(
            &key(5060),
            &Err(io::Error::from(io::ErrorKind::AddrInUse)),
            now,
        );
        assert_eq!(backoff.len(), 0);
        assert!(backoff.check(&key(5060), now).is_ok());
    }

    #[test]
    fn a_destination_nobody_retries_is_swept() {
        // Per-module leak gate: the store drains to empty once its windows are
        // long past, however many destinations failed.
        let backoff = ConnectBackoff::new();
        let now = Instant::now();
        for port in 0..2_000 {
            backoff.record(&key(port), &refused(), now);
        }
        assert_eq!(backoff.len(), 2_000);
        backoff.sweep(now + MAX_BACKOFF);
        assert_eq!(backoff.len(), 2_000, "kept while still worth remembering");
        backoff.sweep(now + INITIAL_BACKOFF + FORGET_AFTER);
        assert_eq!(backoff.len(), 0);
    }

    #[test]
    fn the_store_is_bounded() {
        let backoff = ConnectBackoff::new();
        let now = Instant::now();
        for port in 0..(CAPACITY + 100) {
            let port = u16::try_from(port % 65_536).expect("a port");
            let mut destination = key(port);
            destination.destination = SocketAddr::from(([198, 51, 100, 8], port));
            if port < 100 {
                destination.transport = Transport::Tls;
            }
            backoff.record(&destination, &refused(), now);
        }
        assert!(backoff.len() <= CAPACITY);
    }

    #[test]
    fn concurrent_failures_and_checks_are_consistent() {
        let backoff = Arc::new(ConnectBackoff::new());
        let now = Instant::now();
        let threads: Vec<_> = (0..8u16)
            .map(|thread| {
                let backoff = Arc::clone(&backoff);
                std::thread::spawn(move || {
                    for port in 0..200 {
                        let destination = key(thread * 1_000 + port);
                        backoff.record(&destination, &refused(), now);
                        assert!(backoff.check(&destination, now).is_err());
                        backoff.record(&destination, &Ok(ConnectionId::default()), now);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("no panic");
        }
        assert_eq!(backoff.len(), 0);
    }

    #[test]
    fn the_down_error_names_the_destination() {
        let backoff = ConnectBackoff::new();
        let now = Instant::now();
        backoff.record(&key(5070), &refused(), now);
        let error = backoff.check(&key(5070), now).expect_err("down");
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(error.to_string().contains("198.51.100.7:5070"));
        assert!(!is_destination_down(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
    }
}
