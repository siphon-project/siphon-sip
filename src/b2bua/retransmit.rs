//! RFC 3261 §17.1 retransmission for siphon-originated B2BUA requests.
//!
//! The proxy datapath relays through the transaction layer, so a relayed
//! request gets a client transaction and with it Timer A (INVITE, §17.1.1.2)
//! or Timer E (non-INVITE, §17.1.2.2). The B2BUA does not: it owns its legs
//! and routes responses by branch through [`crate::b2bua::actor`], never
//! registering a client transaction. Everything it originated therefore left
//! the socket exactly once, and over an unreliable transport a single lost
//! datagram produced total silence until the 30 s answer-timeout sweep
//! synthesised a 408 — no INVITE retransmit at 500 ms, no BYE retransmit, no
//! recovery at all.
//!
//! This module supplies the missing UAC-side retransmission without pulling
//! B2BUA legs into the transaction FSM (which would also auto-ACK non-2xx
//! finals and change absorption semantics under the leg model). It is a plain
//! schedule store: the dispatcher arms an entry when it puts a
//! siphon-originated request on the wire, the 100 ms timer tick asks for what
//! is [`due`](B2buaRetransmits::due), and the first response on that branch
//! disarms it.
//!
//! Intervals come from [`TimerConfig`] (`T1`/`T2`), so a deployment that tunes
//! its transaction timers tunes these too — there are no constants here.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;

use crate::sip::message::Method;
use crate::transaction::timer::TimerConfig;
use crate::transport::{ConnectionId, Transport};

/// Identifies one in-flight siphon-originated request.
///
/// Keyed on branch **and** method: RFC 3261 §9.1 gives a CANCEL the same Via
/// branch as the INVITE it cancels, so a branch alone would make the two
/// collide and let one disarm the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RetransmitKey {
    pub branch: String,
    pub method: Method,
}

impl RetransmitKey {
    pub fn new(branch: impl Into<String>, method: Method) -> Self {
        Self {
            branch: branch.into(),
            method,
        }
    }
}

/// Where and how to put a retransmission back on the wire.
///
/// `source_local_addr` is the load-bearing field on a multi-homed or
/// IPsec-protected host: a retransmission that leaves a different socket than
/// the original is not a retransmission, it is a new (and on an SA, dropped)
/// packet. It carries the flow's `local_addr` for a flow-pinned leg.
#[derive(Debug, Clone)]
pub struct RetransmitTarget {
    pub destination: SocketAddr,
    pub transport: Transport,
    pub connection_id: ConnectionId,
    pub source_local_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
struct RetransmitEntry {
    data: Bytes,
    target: RetransmitTarget,
    /// When the next retransmission is due.
    next_at: Instant,
    /// Current interval; doubles on each fire.
    interval: Duration,
    /// Timer B (INVITE, §17.1.1.2) / Timer F (non-INVITE, §17.1.2.2) deadline:
    /// 64·T1 after arming.
    give_up_at: Instant,
    /// INVITE doubles without a ceiling; non-INVITE caps each interval at T2.
    invite: bool,
    /// Retransmissions emitted so far (the original send is not counted).
    attempts: u32,
}

/// One unit of work produced by [`B2buaRetransmits::due`].
#[derive(Debug, Clone)]
pub enum Due {
    /// Put these bytes back on the wire. The entry has already been
    /// rescheduled at its next interval.
    Send {
        key: RetransmitKey,
        data: Bytes,
        target: RetransmitTarget,
        /// 1 for the first retransmission, 2 for the second, and so on.
        attempt: u32,
    },
    /// 64·T1 elapsed with no response. The entry has already been removed;
    /// the caller only reports it.
    GaveUp {
        key: RetransmitKey,
        destination: SocketAddr,
        attempts: u32,
    },
}

/// Retransmission schedules for every siphon-originated B2BUA request that is
/// still awaiting its first response.
pub struct B2buaRetransmits {
    entries: DashMap<RetransmitKey, RetransmitEntry>,
    /// Live entry count, mirroring `entries.len()`.
    ///
    /// Exists purely so [`is_armed`](Self::is_armed) is a single relaxed load.
    /// The cancel path runs on **every** inbound response, including the whole
    /// proxy datapath where nothing is ever armed, and building a
    /// [`RetransmitKey`] there costs a `String` clone and a shard lock per
    /// message. `DashMap::len()` is no help — it sums every shard. This keeps
    /// the proxy hot path at one atomic read and zero allocations.
    armed: std::sync::atomic::AtomicUsize,
    timers: TimerConfig,
}

impl B2buaRetransmits {
    pub fn new(timers: TimerConfig) -> Self {
        Self {
            entries: DashMap::new(),
            armed: std::sync::atomic::AtomicUsize::new(0),
            timers,
        }
    }

    /// Whether any schedule is armed at all.
    ///
    /// The cheap guard callers use before doing anything per-message: false on
    /// every proxy-only deployment and on any B2BUA with no request in flight.
    pub fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::Relaxed) != 0
    }

    /// Arm a schedule for a request just handed to the transport.
    ///
    /// Returns `false` without storing anything when the transport is reliable
    /// — RFC 3261 §17.1.1.2 and §17.1.2.2 both make retransmission
    /// unreliable-transport-only, since a stream transport already recovers
    /// loss itself. Re-arming an existing key replaces it, which is what a
    /// 401/407 or 422 retry on the same leg wants.
    pub fn arm(
        &self,
        key: RetransmitKey,
        data: Bytes,
        target: RetransmitTarget,
        now: Instant,
    ) -> bool {
        if !matches!(
            crate::transaction::state::Transport::from(target.transport),
            crate::transaction::state::Transport::Udp
        ) {
            return false;
        }

        let interval = self.timers.timer_a_initial();
        let invite = key.method == Method::Invite;
        let replaced = self.entries.insert(
            key,
            RetransmitEntry {
                data,
                target,
                next_at: now + interval,
                interval,
                give_up_at: now + self.timers.timer_b(),
                invite,
                attempts: 0,
            },
        );
        // Re-arming an existing key (the 401/407 or 422 retry) replaces rather
        // than adds, so only a fresh key moves the counter.
        if replaced.is_none() {
            self.armed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        true
    }

    /// Stop retransmitting one request. Returns `true` if a schedule was armed.
    pub fn disarm(&self, key: &RetransmitKey) -> bool {
        if self.entries.remove(key).is_some() {
            self.armed
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Stop retransmitting every request on `branch`, whatever its method.
    ///
    /// Used on call teardown so an INVITE and its CANCEL both stop; nothing
    /// may outlive the call it belongs to.
    pub fn disarm_branch(&self, branch: &str) -> usize {
        let doomed: Vec<RetransmitKey> = self
            .entries
            .iter()
            .filter(|entry| entry.key().branch == branch)
            .map(|entry| entry.key().clone())
            .collect();
        let mut removed = 0;
        for key in doomed {
            if self.disarm(&key) {
                removed += 1;
            }
        }
        removed
    }

    /// Everything due at `now`: retransmissions to emit, and schedules that
    /// have reached 64·T1 and been dropped.
    ///
    /// Surviving entries are rescheduled in place before returning, so the
    /// caller can send without holding any lock.
    pub fn due(&self, now: Instant) -> Vec<Due> {
        let mut due = Vec::new();
        let mut expired = Vec::new();

        for mut entry in self.entries.iter_mut() {
            if now >= entry.give_up_at {
                expired.push((
                    entry.key().clone(),
                    entry.target.destination,
                    entry.attempts,
                ));
                continue;
            }
            if now < entry.next_at {
                continue;
            }

            // RFC 3261 §17.1.1.2: Timer A doubles without a ceiling.
            // §17.1.2.2: Timer E doubles but is capped at T2.
            let doubled = entry.interval.saturating_mul(2);
            entry.interval = if entry.invite {
                doubled
            } else {
                doubled.min(self.timers.t2)
            };
            entry.next_at = now + entry.interval;
            entry.attempts += 1;

            due.push(Due::Send {
                key: entry.key().clone(),
                data: entry.data.clone(),
                target: entry.target.clone(),
                attempt: entry.attempts,
            });
        }

        for (key, destination, attempts) in expired {
            if self.disarm(&key) {
                due.push(Due::GaveUp {
                    key,
                    destination,
                    attempts,
                });
            }
        }

        due
    }

    /// Number of armed schedules. The steady-state leak signal: it must return
    /// to its baseline once a batch of calls has completed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(transport: Transport) -> RetransmitTarget {
        RetransmitTarget {
            destination: "192.0.2.10:5060".parse().expect("test destination"),
            transport,
            connection_id: ConnectionId::default(),
            source_local_addr: Some("192.0.2.1:6100".parse().expect("test source")),
        }
    }

    fn store() -> B2buaRetransmits {
        B2buaRetransmits::new(TimerConfig::default())
    }

    fn invite_key() -> RetransmitKey {
        RetransmitKey::new("z9hG4bK-b-leg-1", Method::Invite)
    }

    /// Collect the intervals between successive retransmissions by walking a
    /// virtual clock forward to whatever the store says is next.
    fn schedule(store: &B2buaRetransmits, key: &RetransmitKey, count: usize) -> Vec<Duration> {
        let start = Instant::now();
        let mut now = start;
        let mut previous = start;
        let mut gaps = Vec::new();
        // Step in T1/10 increments so we observe the deadline, not a guess.
        let step = store.timers.t1 / 10;
        // Bound the walk at the 64·T1 give-up point so a scheduling bug fails
        // the test instead of hanging it.
        let deadline = start + store.timers.timer_b();
        while gaps.len() < count {
            now += step;
            assert!(
                now < deadline,
                "only {} of {} retransmits arrived before 64·T1",
                gaps.len(),
                count
            );
            for event in store.due(now) {
                if matches!(&event, Due::Send { key: fired, .. } if fired == key) {
                    gaps.push(now - previous);
                    previous = now;
                }
            }
        }
        gaps
    }

    #[test]
    fn invite_retransmits_at_t1_then_doubles_without_a_ceiling() {
        // RFC 3261 §17.1.1.2: Timer A fires at T1 and doubles on every fire.
        let store = store();
        let key = invite_key();
        assert!(store.arm(
            key.clone(),
            Bytes::from_static(b"INVITE"),
            target(Transport::Udp),
            Instant::now()
        ));

        let t1 = store.timers.t1;
        let gaps = schedule(&store, &key, 5);

        // Each gap lands within one sampling step of the ideal interval.
        let tolerance = t1 / 5;
        for (index, expected) in [t1, t1 * 2, t1 * 4, t1 * 8, t1 * 16].iter().enumerate() {
            let actual = gaps[index];
            assert!(
                actual >= *expected && actual - *expected <= tolerance,
                "retransmit {} landed at {:?}, expected ~{:?}",
                index + 1,
                actual,
                expected
            );
        }
        // The fifth interval (16·T1 = 8s) is past T2, proving INVITE is not
        // capped the way non-INVITE is.
        assert!(
            gaps[4] > store.timers.t2,
            "INVITE doubling must not be capped at T2"
        );
    }

    #[test]
    fn non_invite_retransmit_interval_caps_at_t2() {
        // RFC 3261 §17.1.2.2: Timer E doubles but never exceeds T2.
        let store = store();
        let key = RetransmitKey::new("z9hG4bK-bye-1", Method::Bye);
        assert!(store.arm(
            key.clone(),
            Bytes::from_static(b"BYE"),
            target(Transport::Udp),
            Instant::now()
        ));

        let t2 = store.timers.t2;
        let gaps = schedule(&store, &key, 5);
        let tolerance = store.timers.t1 / 5;

        for (index, gap) in gaps.iter().enumerate() {
            assert!(
                *gap <= t2 + tolerance,
                "non-INVITE retransmit {} waited {:?}, above the T2 cap {:?}",
                index + 1,
                gap,
                t2
            );
        }
        // And it actually reaches the cap rather than stalling early.
        assert!(
            gaps.last().copied().unwrap_or_default() >= t2 - tolerance,
            "non-INVITE interval should climb to T2"
        );
    }

    #[test]
    fn gives_up_at_64_t1_and_removes_the_entry() {
        // Timer B (§17.1.1.2) / Timer F (§17.1.2.2) = 64·T1.
        let store = store();
        let key = invite_key();
        let armed_at = Instant::now();
        store.arm(
            key.clone(),
            Bytes::from_static(b"INVITE"),
            target(Transport::Udp),
            armed_at,
        );

        // Just before the deadline the schedule is still live.
        let _ = store.due(armed_at + store.timers.timer_b() - Duration::from_millis(1));
        assert_eq!(store.len(), 1);

        let events = store.due(armed_at + store.timers.timer_b());
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Due::GaveUp { .. })),
            "64·T1 must produce a GaveUp"
        );
        assert!(
            !events.iter().any(|event| matches!(event, Due::Send { .. })),
            "an expired schedule must not also emit a retransmit"
        );
        assert_eq!(store.len(), 0, "the expired entry must be removed");
    }

    #[test]
    fn reliable_transports_never_arm() {
        // §17.1.1.2 / §17.1.2.2 — retransmission is unreliable-transport only.
        let store = store();
        for transport in [
            Transport::Tcp,
            Transport::Tls,
            Transport::WebSocket,
            Transport::WebSocketSecure,
            Transport::Sctp,
        ] {
            let key = RetransmitKey::new(format!("z9hG4bK-{transport}"), Method::Invite);
            assert!(
                !store.arm(
                    key,
                    Bytes::from_static(b"INVITE"),
                    target(transport),
                    Instant::now()
                ),
                "{transport} must not arm a retransmit schedule"
            );
        }
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn first_response_disarms_before_any_retransmit() {
        // §17.1.1.2: the first provisional moves Calling -> Proceeding and
        // cancels Timer A.
        let store = store();
        let key = invite_key();
        let armed_at = Instant::now();
        store.arm(
            key.clone(),
            Bytes::from_static(b"INVITE"),
            target(Transport::Udp),
            armed_at,
        );

        assert!(store.disarm(&key));
        assert!(store.due(armed_at + store.timers.timer_b() * 2).is_empty());
        assert_eq!(store.len(), 0);
        // Disarming twice is harmless — the teardown path may race the response.
        assert!(!store.disarm(&key));
    }

    #[test]
    fn cancel_and_its_invite_share_a_branch_but_not_a_schedule() {
        // RFC 3261 §9.1: CANCEL carries the INVITE's Via branch. Keying on the
        // branch alone would let the CANCEL's arrival stop the INVITE's timer.
        let store = store();
        let branch = "z9hG4bK-shared";
        let invite = RetransmitKey::new(branch, Method::Invite);
        let cancel = RetransmitKey::new(branch, Method::Cancel);
        let now = Instant::now();

        store.arm(
            invite.clone(),
            Bytes::from_static(b"INVITE"),
            target(Transport::Udp),
            now,
        );
        store.arm(
            cancel.clone(),
            Bytes::from_static(b"CANCEL"),
            target(Transport::Udp),
            now,
        );
        assert_eq!(store.len(), 2);

        store.disarm(&cancel);
        assert_eq!(
            store.len(),
            1,
            "disarming the CANCEL must leave the INVITE armed"
        );

        let events = store.due(now + store.timers.t1);
        match events.as_slice() {
            [Due::Send { key, .. }] => assert_eq!(key.method, Method::Invite),
            other => panic!("expected only the INVITE to retransmit, got {other:?}"),
        }
    }

    #[test]
    fn disarm_branch_clears_every_method_on_that_branch() {
        let store = store();
        let branch = "z9hG4bK-teardown";
        let now = Instant::now();
        store.arm(
            RetransmitKey::new(branch, Method::Invite),
            Bytes::from_static(b"I"),
            target(Transport::Udp),
            now,
        );
        store.arm(
            RetransmitKey::new(branch, Method::Cancel),
            Bytes::from_static(b"C"),
            target(Transport::Udp),
            now,
        );
        store.arm(
            RetransmitKey::new("other", Method::Bye),
            Bytes::from_static(b"B"),
            target(Transport::Udp),
            now,
        );

        assert_eq!(store.disarm_branch(branch), 2);
        assert_eq!(store.len(), 1, "an unrelated branch must survive");
    }

    #[test]
    fn retransmit_replays_the_original_bytes_and_source_pin() {
        // A retransmission that leaves a different socket is a new packet, not
        // a retransmission — on an IPsec SA the kernel selector drops it.
        let store = store();
        let key = invite_key();
        let now = Instant::now();
        let original = Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n");
        store.arm(key.clone(), original.clone(), target(Transport::Udp), now);

        match store.due(now + store.timers.t1).as_slice() {
            [Due::Send {
                data,
                target: sent,
                attempt,
                ..
            }] => {
                assert_eq!(data, &original, "retransmit must replay identical bytes");
                assert_eq!(
                    sent.source_local_addr,
                    Some("192.0.2.1:6100".parse().expect("test source")),
                    "retransmit must leave the same local socket as the original"
                );
                assert_eq!(
                    sent.destination,
                    "192.0.2.10:5060".parse().expect("test destination")
                );
                assert_eq!(*attempt, 1);
            }
            other => panic!("expected exactly one retransmit, got {other:?}"),
        }
    }

    #[test]
    fn re_arming_the_same_key_replaces_the_schedule() {
        // The 401/407 and 422 retry paths supersede a leg's INVITE in place.
        let store = store();
        let key = invite_key();
        let now = Instant::now();
        store.arm(
            key.clone(),
            Bytes::from_static(b"first"),
            target(Transport::Udp),
            now,
        );
        store.arm(
            key.clone(),
            Bytes::from_static(b"second"),
            target(Transport::Udp),
            now,
        );

        assert_eq!(store.len(), 1);
        match store.due(now + store.timers.t1).as_slice() {
            [Due::Send { data, .. }] => assert_eq!(data, &Bytes::from_static(b"second")),
            other => panic!("expected the replacement to be retransmitted, got {other:?}"),
        }
    }

    #[test]
    fn steady_state_arm_disarm_cycles_do_not_grow_the_store() {
        // Per-module leak gate: a completed request must leave nothing behind.
        let store = store();
        let baseline = store.len();

        for index in 0..2_000 {
            let key = RetransmitKey::new(format!("z9hG4bK-call-{index}"), Method::Invite);
            store.arm(
                key.clone(),
                Bytes::from_static(b"INVITE"),
                target(Transport::Udp),
                Instant::now(),
            );
            store.disarm(&key);
        }

        assert_eq!(store.len(), baseline, "armed schedules must not accumulate");
    }

    /// `is_armed` gates the per-response cancel on the proxy hot path, so it
    /// must never disagree with the map. A stuck-true counter would put a
    /// `String` clone and a shard lock back on every proxy response; a
    /// stuck-false one would stop cancelling retransmits altogether.
    #[test]
    fn is_armed_tracks_the_map_across_every_mutation_path() {
        let store = store();
        let now = Instant::now();
        let check = |store: &B2buaRetransmits, at: &str| {
            assert_eq!(
                store.is_armed(),
                !store.is_empty(),
                "is_armed disagreed with len() after {at}"
            );
        };

        check(&store, "construction");
        assert!(!store.is_armed());

        let invite = RetransmitKey::new("z9hG4bK-a", Method::Invite);
        let cancel = RetransmitKey::new("z9hG4bK-a", Method::Cancel);
        let bye = RetransmitKey::new("z9hG4bK-b", Method::Bye);

        store.arm(
            invite.clone(),
            Bytes::from_static(b"I"),
            target(Transport::Udp),
            now,
        );
        check(&store, "arm");
        assert!(store.is_armed());

        // Re-arming the same key replaces — the count must not double.
        store.arm(
            invite.clone(),
            Bytes::from_static(b"I2"),
            target(Transport::Udp),
            now,
        );
        check(&store, "re-arm");
        assert_eq!(store.len(), 1);

        // A refused (reliable-transport) arm must not move the counter.
        store.arm(
            RetransmitKey::new("z9hG4bK-tcp", Method::Invite),
            Bytes::from_static(b"I"),
            target(Transport::Tcp),
            now,
        );
        check(&store, "refused arm");
        assert_eq!(store.len(), 1);

        store.arm(
            cancel,
            Bytes::from_static(b"C"),
            target(Transport::Udp),
            now,
        );
        store.arm(
            bye.clone(),
            Bytes::from_static(b"B"),
            target(Transport::Udp),
            now,
        );
        check(&store, "more arms");

        // A no-op disarm must not move it either.
        assert!(!store.disarm(&RetransmitKey::new("z9hG4bK-nope", Method::Invite)));
        check(&store, "no-op disarm");

        assert!(store.disarm(&bye));
        check(&store, "disarm");

        store.disarm_branch("z9hG4bK-a");
        check(&store, "disarm_branch");
        assert!(!store.is_armed(), "the store is empty again");

        // And the give-up path.
        store.arm(
            invite.clone(),
            Bytes::from_static(b"I"),
            target(Transport::Udp),
            now,
        );
        let _ = store.due(now + store.timers.timer_b());
        check(&store, "give-up");
        assert!(!store.is_armed());
    }

    #[test]
    fn abandoned_schedules_drain_via_give_up_without_a_disarm() {
        // Backstop for the leak gate: even if nothing ever disarms (peer went
        // silent and the call teardown raced), 64·T1 reaps the entry.
        let store = store();
        let armed_at = Instant::now();
        for index in 0..500 {
            store.arm(
                RetransmitKey::new(format!("z9hG4bK-silent-{index}"), Method::Invite),
                Bytes::from_static(b"INVITE"),
                target(Transport::Udp),
                armed_at,
            );
        }
        assert_eq!(store.len(), 500);

        let events = store.due(armed_at + store.timers.timer_b());
        assert_eq!(events.len(), 500);
        assert!(events
            .iter()
            .all(|event| matches!(event, Due::GaveUp { .. })));
        assert_eq!(store.len(), 0, "give-up must drain the store");
    }
}
