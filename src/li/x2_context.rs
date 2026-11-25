//! Per-context sequence numbers for X2 PDUs (ETSI TS 103 221-2 clause 5.3.9).
//!
//! The sequence number numbers the PDUs of one *context*, an (XID, CID) pair,
//! not the PDUs of one connection: a receiver reassembling a session looks for
//! gaps in that session's own run. So the counter belongs to the context and
//! survives a reconnect, and two sessions interleaved on one connection each
//! count from 0 on their own.
//!
//! The map has one owner, the delivery task, so it takes no lock. An entry is
//! dropped when its session's End record has been handled
//! ([`ContextSequences::finish`]); a session whose End never comes (a lost
//! BYE, a record the channel dropped) is caught by an idle-age sweep.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a context may go without a PDU before the sweep forgets it.
///
/// An entry is only ever held for a call that has stopped signalling, so the
/// bound is on silence, not on call length: any PDU for the context renews it.
/// A day is far above any quiet stretch of a live call (session timers refresh
/// in minutes to an hour, and `b2bua` call ceilings are set in hours), so a
/// live call is never renumbered, while a context whose End was lost frees its
/// memory within a day.
pub(super) const CONTEXT_MAX_IDLE: Duration = Duration::from_secs(24 * 3600);

/// How often the sweep may run. It walks the whole map, so it is not per
/// record.
pub(super) const CONTEXT_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// One numbered context: the task and the session within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ContextKey {
    x_id: [u8; 16],
    correlation_id: u64,
}

impl ContextKey {
    pub(super) const fn new(x_id: [u8; 16], correlation_id: u64) -> Self {
        Self {
            x_id,
            correlation_id,
        }
    }
}

#[derive(Debug)]
struct Counter {
    /// The number the context's next PDU carries.
    next: u32,
    /// When the context last carried a PDU.
    last_used: Instant,
}

/// The sequence counters of every context delivered to one destination.
#[derive(Debug)]
pub(super) struct ContextSequences {
    contexts: HashMap<ContextKey, Counter>,
    last_sweep: Instant,
}

impl ContextSequences {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            contexts: HashMap::new(),
            last_sweep: now,
        }
    }

    /// The number the context's next PDU carries, without consuming it.
    ///
    /// A write that fails is retried on a fresh connection and must carry the
    /// same number, so the number is consumed by [`Self::commit`] only once the
    /// PDU is on the wire.
    pub(super) fn peek(&self, key: ContextKey) -> u32 {
        self.contexts.get(&key).map_or(0, |counter| counter.next)
    }

    /// Record that the PDU numbered [`Self::peek`] was delivered.
    pub(super) fn commit(&mut self, key: ContextKey, now: Instant) {
        let counter = self.contexts.entry(key).or_insert(Counter {
            next: 0,
            last_used: now,
        });
        counter.next = counter.next.wrapping_add(1);
        counter.last_used = now;
    }

    /// The context's session is over: forget its counter.
    pub(super) fn finish(&mut self, key: ContextKey) {
        self.contexts.remove(&key);
    }

    /// Forget every context idle for longer than [`CONTEXT_MAX_IDLE`],
    /// returning how many went.
    pub(super) fn sweep(&mut self, now: Instant) -> usize {
        let before = self.contexts.len();
        self.contexts.retain(|_, counter| {
            now.saturating_duration_since(counter.last_used) <= CONTEXT_MAX_IDLE
        });
        self.last_sweep = now;
        before - self.contexts.len()
    }

    /// [`Self::sweep`], when [`CONTEXT_SWEEP_INTERVAL`] has passed since the
    /// last one.
    pub(super) fn sweep_if_due(&mut self, now: Instant) -> usize {
        if now.saturating_duration_since(self.last_sweep) < CONTEXT_SWEEP_INTERVAL {
            return 0;
        }
        self.sweep(now)
    }

    /// Contexts currently held; what the leak tests assert drains.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.contexts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT_A: ContextKey = ContextKey::new([0xaa; 16], 1);
    const CONTEXT_B: ContextKey = ContextKey::new([0xaa; 16], 2);
    const CONTEXT_OTHER_TASK: ContextKey = ContextKey::new([0xbb; 16], 1);

    fn deliver(sequences: &mut ContextSequences, key: ContextKey, now: Instant) -> u32 {
        let sequence = sequences.peek(key);
        sequences.commit(key, now);
        sequence
    }

    /// Clause 5.3.9: each (XID, CID) context counts from 0 on its own, and an
    /// interleaving of contexts does not disturb any of them.
    #[test]
    fn interleaved_contexts_each_count_from_zero() {
        let now = Instant::now();
        let mut sequences = ContextSequences::new(now);
        let mut seen: Vec<(ContextKey, u32)> = Vec::new();
        for key in [
            CONTEXT_A,
            CONTEXT_B,
            CONTEXT_A,
            CONTEXT_OTHER_TASK,
            CONTEXT_B,
            CONTEXT_A,
            CONTEXT_B,
            CONTEXT_OTHER_TASK,
        ] {
            seen.push((key, deliver(&mut sequences, key, now)));
        }
        let of = |wanted: ContextKey| -> Vec<u32> {
            seen.iter()
                .filter(|(key, _)| *key == wanted)
                .map(|(_, sequence)| *sequence)
                .collect()
        };
        assert_eq!(of(CONTEXT_A), [0, 1, 2]);
        assert_eq!(of(CONTEXT_B), [0, 1, 2]);
        assert_eq!(of(CONTEXT_OTHER_TASK), [0, 1], "same CID, other XID");
    }

    /// A write that failed was not delivered, so the number is not consumed:
    /// the retry on a fresh connection carries the same one.
    #[test]
    fn a_number_is_consumed_only_when_the_write_succeeds() {
        let now = Instant::now();
        let mut sequences = ContextSequences::new(now);
        assert_eq!(sequences.peek(CONTEXT_A), 0);
        assert_eq!(sequences.peek(CONTEXT_A), 0, "peeking does not advance");
        assert_eq!(sequences.len(), 0, "nor does it create an entry");
        sequences.commit(CONTEXT_A, now);
        assert_eq!(sequences.peek(CONTEXT_A), 1);
    }

    #[test]
    fn a_finished_context_starts_again_at_zero_and_is_forgotten() {
        let now = Instant::now();
        let mut sequences = ContextSequences::new(now);
        deliver(&mut sequences, CONTEXT_A, now);
        deliver(&mut sequences, CONTEXT_A, now);
        sequences.finish(CONTEXT_A);
        assert_eq!(sequences.len(), 0);
        assert_eq!(sequences.peek(CONTEXT_A), 0);
        // Finishing what was never there is harmless.
        sequences.finish(CONTEXT_B);
    }

    /// The leak rule: N sessions that end and N whose End never comes leave
    /// nothing behind once the sweep has run.
    #[test]
    fn the_map_drains_after_completed_and_abandoned_sessions() {
        let start = Instant::now();
        let mut sequences = ContextSequences::new(start);
        let sessions: u64 = 500;
        for correlation in 0..sessions {
            let completed = ContextKey::new([1; 16], correlation);
            let abandoned = ContextKey::new([2; 16], correlation);
            for key in [completed, abandoned] {
                deliver(&mut sequences, key, start);
                deliver(&mut sequences, key, start);
            }
            sequences.finish(completed);
        }
        assert_eq!(
            sequences.len(),
            usize::try_from(sessions).unwrap_or(usize::MAX),
            "only the sessions whose End never came remain"
        );

        let later = start + CONTEXT_MAX_IDLE + Duration::from_secs(1);
        let swept = sequences.sweep(later);
        assert_eq!(swept, 500);
        assert_eq!(sequences.len(), 0, "the sweep drains the abandoned ones");
    }

    /// Idle, not old: a call that keeps signalling keeps its numbering however
    /// long it has run.
    #[test]
    fn the_sweep_spares_a_context_that_is_still_active() {
        let start = Instant::now();
        let mut sequences = ContextSequences::new(start);
        deliver(&mut sequences, CONTEXT_A, start);
        deliver(&mut sequences, CONTEXT_B, start);

        let almost = start + CONTEXT_MAX_IDLE - Duration::from_secs(1);
        deliver(&mut sequences, CONTEXT_A, almost);
        let later = start + CONTEXT_MAX_IDLE + Duration::from_secs(1);
        assert_eq!(sequences.sweep(later), 1, "only the idle one goes");
        assert_eq!(sequences.peek(CONTEXT_A), 2);
        assert_eq!(sequences.peek(CONTEXT_B), 0);
    }

    #[test]
    fn the_sweep_runs_at_its_own_interval_not_per_record() {
        let start = Instant::now();
        let mut sequences = ContextSequences::new(start);
        deliver(&mut sequences, CONTEXT_A, start);

        let too_soon = start + CONTEXT_SWEEP_INTERVAL - Duration::from_secs(1);
        assert_eq!(sequences.sweep_if_due(too_soon), 0);
        let due = start + CONTEXT_MAX_IDLE + CONTEXT_SWEEP_INTERVAL;
        assert_eq!(sequences.sweep_if_due(due), 1);
        assert_eq!(sequences.sweep_if_due(due), 0, "and then not again at once");
    }

    #[test]
    fn the_bound_is_well_above_any_call_the_node_runs() {
        // The B2BUA's own call ceiling is operator-set and in hours at most;
        // a context idle for a whole day is not a live call.
        assert!(CONTEXT_MAX_IDLE >= Duration::from_secs(24 * 3600));
    }
}
