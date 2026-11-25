//! Per-context sequence numbers for X2 PDUs (ETSI TS 103 221-2 clause 5.3.9).
//!
//! The sequence number numbers the PDUs of one *context*, an (XID, CID) pair,
//! not the PDUs of one connection: a receiver reassembling a session looks for
//! gaps in that session's own run. So the counter belongs to the context and
//! survives a reconnect, and two sessions interleaved on one connection each
//! count from 0 on their own. It wraps to zero.
//!
//! The map has one owner, the delivery task, so it takes no lock, and there is
//! one map per destination, each with its own lifetimes: a mediation function
//! checks its own copy of a context for gaps, whatever another received.
//!
//! An End record does not delete its context. The End is the BYE or CANCEL,
//! and the session still produces PDUs after it (the 200 to the BYE, a
//! retransmitted BYE), which belong to the same context and must carry on its
//! numbering. [`ContextSequences::finish`] marks the context ended, and the
//! sweep drops it once it has been silent for [`CONTEXT_END_LINGER`]. A
//! session whose End never comes (a lost BYE, a record the channel dropped) is
//! caught by the idle bound, [`CONTEXT_MAX_IDLE`].

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

/// How long an ended context lingers, silent, before the sweep drops it.
///
/// 64 * T1, with T1 the 500 ms of RFC 3261 section 17.1.1.1: the lifetime of
/// the BYE's transaction (Timer F, Timer H), which covers the 200 to the BYE
/// and every retransmission of it. Anything of the session that arrives later
/// than that starts a new context at 0.
pub(super) const CONTEXT_END_LINGER: Duration = Duration::from_secs(32);

/// How often the delivery loop runs the sweep. Well under the linger, so an
/// ended context is released close to the moment it is due.
pub(super) const CONTEXT_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// The three bounds, together, so the delivery loop can be run at a fraction
/// of them in a test.
#[derive(Debug, Clone, Copy)]
pub(super) struct ContextTimings {
    /// See [`CONTEXT_MAX_IDLE`]; also how long a destination with no contexts
    /// and no traffic is kept.
    pub(super) max_idle: Duration,
    /// See [`CONTEXT_END_LINGER`].
    pub(super) end_linger: Duration,
    /// See [`CONTEXT_SWEEP_INTERVAL`].
    pub(super) sweep_interval: Duration,
}

impl ContextTimings {
    pub(super) const DEFAULT: Self = Self {
        max_idle: CONTEXT_MAX_IDLE,
        end_linger: CONTEXT_END_LINGER,
        sweep_interval: CONTEXT_SWEEP_INTERVAL,
    };
}

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
    /// When the context last carried a PDU, or was ended.
    last_used: Instant,
    /// Its End record has been handled; only the linger keeps it now.
    ended: bool,
}

/// The sequence counters of every context delivered to one destination.
#[derive(Debug)]
pub(super) struct ContextSequences {
    contexts: HashMap<ContextKey, Counter>,
    timings: ContextTimings,
}

impl ContextSequences {
    pub(super) fn new(timings: ContextTimings) -> Self {
        Self {
            contexts: HashMap::new(),
            timings,
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
            ended: false,
        });
        counter.next = counter.next.wrapping_add(1);
        counter.last_used = now;
    }

    /// The context's End record has been handled, delivered or not.
    ///
    /// The context keeps counting for any PDU that still arrives, and is
    /// dropped by the sweep once silent for the linger, counted from now.
    pub(super) fn finish(&mut self, key: ContextKey, now: Instant) {
        if let Some(counter) = self.contexts.get_mut(&key) {
            counter.ended = true;
            counter.last_used = now;
        }
    }

    /// A new session opens the context again (a Call-ID reused for a new
    /// call): an earlier End no longer ages it out.
    pub(super) fn reopen(&mut self, key: ContextKey) {
        if let Some(counter) = self.contexts.get_mut(&key) {
            counter.ended = false;
        }
    }

    /// Forget every context that is ended and silent for the linger, or idle
    /// for the idle bound, returning how many went.
    pub(super) fn sweep(&mut self, now: Instant) -> usize {
        let before = self.contexts.len();
        let timings = self.timings;
        self.contexts.retain(|_, counter| {
            let silent = now.saturating_duration_since(counter.last_used);
            let bound = if counter.ended {
                timings.end_linger
            } else {
                timings.max_idle
            };
            silent <= bound
        });
        before - self.contexts.len()
    }

    /// Whether nothing is held.
    pub(super) fn is_empty(&self) -> bool {
        self.contexts.is_empty()
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

    fn fresh() -> ContextSequences {
        ContextSequences::new(ContextTimings::DEFAULT)
    }

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
        let mut sequences = fresh();
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
        let mut sequences = fresh();
        assert_eq!(sequences.peek(CONTEXT_A), 0);
        assert_eq!(sequences.peek(CONTEXT_A), 0, "peeking does not advance");
        assert_eq!(sequences.len(), 0, "nor does it create an entry");
        sequences.commit(CONTEXT_A, now);
        assert_eq!(sequences.peek(CONTEXT_A), 1);
    }

    /// Clause 5.3.9 numbers every PDU of the context, wrapping to zero.
    #[test]
    fn the_counter_wraps_to_zero() {
        let now = Instant::now();
        let mut sequences = fresh();
        sequences.commit(CONTEXT_A, now);
        if let Some(counter) = sequences.contexts.get_mut(&CONTEXT_A) {
            counter.next = u32::MAX;
        }
        assert_eq!(deliver(&mut sequences, CONTEXT_A, now), u32::MAX);
        assert_eq!(sequences.peek(CONTEXT_A), 0);
    }

    /// The End is the BYE or CANCEL, and the session still produces PDUs after
    /// it: the 200 to the BYE, a retransmitted BYE. They are the same context,
    /// so they continue its numbering instead of restarting at 0.
    #[test]
    fn an_ended_context_keeps_counting_through_the_bye_transaction() {
        let start = Instant::now();
        let mut sequences = fresh();
        deliver(&mut sequences, CONTEXT_A, start); // INVITE: 0
        assert_eq!(deliver(&mut sequences, CONTEXT_A, start), 1); // BYE (End)
        sequences.finish(CONTEXT_A, start);
        let inside = start + CONTEXT_END_LINGER - Duration::from_secs(1);
        assert_eq!(sequences.sweep(inside), 0, "not dropped inside the linger");
        assert_eq!(deliver(&mut sequences, CONTEXT_A, inside), 2); // its 200
        assert_eq!(deliver(&mut sequences, CONTEXT_A, inside), 3); // BYE again
    }

    /// Ended and silent past the linger: nothing more will come, so the entry
    /// is released.
    #[test]
    fn a_context_ended_and_silent_past_the_linger_is_dropped() {
        let start = Instant::now();
        let mut sequences = fresh();
        deliver(&mut sequences, CONTEXT_A, start);
        deliver(&mut sequences, CONTEXT_B, start);
        sequences.finish(CONTEXT_A, start);

        let later = start + CONTEXT_END_LINGER + Duration::from_secs(1);
        assert_eq!(sequences.sweep(later), 1);
        assert_eq!(sequences.peek(CONTEXT_A), 0, "a later session starts at 0");
        assert_eq!(sequences.peek(CONTEXT_B), 1, "the live one is untouched");
    }

    /// Finishing what was never there is harmless, and creates nothing.
    #[test]
    fn finishing_an_unknown_context_is_a_no_op() {
        let mut sequences = fresh();
        sequences.finish(CONTEXT_B, Instant::now());
        assert_eq!(sequences.len(), 0);
    }

    /// A Call-ID reused for a new call opens the same context again: the
    /// earlier End no longer ages it out.
    #[test]
    fn a_new_begin_reopens_an_ended_context() {
        let start = Instant::now();
        let mut sequences = fresh();
        deliver(&mut sequences, CONTEXT_A, start);
        sequences.finish(CONTEXT_A, start);
        sequences.reopen(CONTEXT_A);
        let later = start + CONTEXT_END_LINGER + Duration::from_secs(1);
        deliver(&mut sequences, CONTEXT_A, later);
        assert_eq!(sequences.sweep(later), 0);
        assert_eq!(sequences.len(), 1);
    }

    /// The leak rule: N sessions that end and N whose End never comes leave
    /// nothing behind once their bounds have passed.
    #[test]
    fn the_map_drains_after_completed_and_abandoned_sessions() {
        let start = Instant::now();
        let mut sequences = fresh();
        let sessions: u64 = 500;
        for correlation in 0..sessions {
            let completed = ContextKey::new([1; 16], correlation);
            let abandoned = ContextKey::new([2; 16], correlation);
            for key in [completed, abandoned] {
                deliver(&mut sequences, key, start);
                deliver(&mut sequences, key, start);
            }
            sequences.finish(completed, start);
        }
        let expected = usize::try_from(sessions).unwrap_or(usize::MAX);

        let after_linger = start + CONTEXT_END_LINGER + Duration::from_secs(1);
        assert_eq!(sequences.sweep(after_linger), expected);
        assert_eq!(sequences.len(), expected, "only the abandoned remain");

        let after_idle = start + CONTEXT_MAX_IDLE + Duration::from_secs(1);
        assert_eq!(sequences.sweep(after_idle), expected);
        assert_eq!(sequences.len(), 0, "the idle bound drains the abandoned");
    }

    /// Idle, not old: a call that keeps signalling keeps its numbering however
    /// long it has run.
    #[test]
    fn the_sweep_spares_a_context_that_is_still_active() {
        let start = Instant::now();
        let mut sequences = fresh();
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
    fn the_bounds_are_set_against_the_traffic_they_cover() {
        // A day of silence is not a live call.
        assert!(CONTEXT_MAX_IDLE >= Duration::from_secs(24 * 3600));
        // 64 * T1 (RFC 3261 Timer F / H, T1 = 500 ms): the BYE transaction and
        // its retransmissions are over by then.
        assert_eq!(CONTEXT_END_LINGER, Duration::from_secs(32));
        assert!(CONTEXT_SWEEP_INTERVAL < CONTEXT_END_LINGER);
    }
}
