//! Refused INVITEs remembered long enough to answer their retransmissions.
//!
//! A B2BUA INVITE has no server transaction, so nothing absorbs a
//! retransmission of one siphon refused. Without this table the retransmission
//! is a new call to the admission check: it spends another place in the rate
//! schedule, counts as a second refusal and writes a second CDR. With it, the
//! retransmission gets the response the original did (RFC 3261 §17.2.1) and
//! nothing is counted twice.
//!
//! An entry lasts until the caller ACKs the refusal, which is when it stops
//! retransmitting, or for the length of its INVITE client transaction if no ACK
//! comes. The table is bounded as well: past its ceiling a refusal is simply
//! not remembered, which is the behaviour without the table, so a flood cannot
//! grow it.

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// How long a refusal is remembered: 64*T1, the time an INVITE client
/// transaction keeps retransmitting (RFC 3261 §17.1.1.2, Timer B).
pub const REFUSAL_TTL: Duration = Duration::from_secs(32);

/// Refusals remembered at once.
pub const MAX_REMEMBERED: usize = 65_536;

/// The answer a refused INVITE was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedAnswer {
    pub reject_code: u16,
    pub retry_after_secs: u32,
}

#[derive(Debug, Clone, Copy)]
struct Remembered {
    answer: RefusedAnswer,
    refused_at: Instant,
}

/// Recently refused INVITEs, keyed on Call-ID and top Via branch.
///
/// The key is a hash of the two under a per-process random seed, so a lookup
/// allocates nothing and a peer cannot aim one INVITE at another's entry.
#[derive(Debug)]
pub struct RefusedInvites {
    entries: DashMap<u64, Remembered>,
    hasher: std::collections::hash_map::RandomState,
    /// Entries held. Kept beside the map so the admission path can tell an
    /// empty table from one atomic load, where `DashMap::len` locks every
    /// shard.
    remembered: AtomicUsize,
    ceiling: usize,
}

impl Default for RefusedInvites {
    fn default() -> Self {
        Self::with_ceiling(MAX_REMEMBERED)
    }
}

impl RefusedInvites {
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            entries: DashMap::new(),
            hasher: std::collections::hash_map::RandomState::new(),
            remembered: AtomicUsize::new(0),
            ceiling,
        }
    }

    fn key(&self, call_id: &str, branch: &str) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        call_id.hash(&mut hasher);
        branch.hash(&mut hasher);
        hasher.finish()
    }

    /// The answer this INVITE was refused with, if it was refused within the
    /// last [`REFUSAL_TTL`]. With nothing remembered this is one atomic load:
    /// no hash and no clock read.
    pub fn lookup(&self, call_id: &str, branch: &str) -> Option<RefusedAnswer> {
        self.lookup_with(call_id, branch, Instant::now)
    }

    /// [`lookup`](Self::lookup) at a stated time.
    pub fn lookup_at(&self, call_id: &str, branch: &str, now: Instant) -> Option<RefusedAnswer> {
        self.lookup_with(call_id, branch, || now)
    }

    fn lookup_with(
        &self,
        call_id: &str,
        branch: &str,
        now: impl FnOnce() -> Instant,
    ) -> Option<RefusedAnswer> {
        if self.remembered.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let remembered = *self.entries.get(&self.key(call_id, branch))?;
        (now().saturating_duration_since(remembered.refused_at) < REFUSAL_TTL)
            .then_some(remembered.answer)
    }

    /// Remember that this INVITE was refused at `now`. A no-op at the ceiling.
    pub fn remember(&self, call_id: &str, branch: &str, answer: RefusedAnswer, now: Instant) {
        if self.remembered.load(Ordering::Relaxed) >= self.ceiling {
            return;
        }
        let remembered = Remembered {
            answer,
            refused_at: now,
        };
        match self.entries.entry(self.key(call_id, branch)) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(remembered);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(remembered);
                self.remembered.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Forget this INVITE's refusal: the caller has ACKed it.
    ///
    /// A client ACKs a final response once, when it has it, and stops
    /// retransmitting the INVITE at the same moment (RFC 3261 §17.1.1.2), so
    /// nothing is left for the entry to answer. Dropping it here rather than at
    /// [`REFUSAL_TTL`] keeps the table to the refusals still in flight.
    pub fn forget(&self, call_id: &str, branch: &str) {
        if self.remembered.load(Ordering::Relaxed) == 0 {
            return;
        }
        if self.entries.remove(&self.key(call_id, branch)).is_some() {
            self.remembered.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Forget every refusal older than [`REFUSAL_TTL`] at `now`.
    pub fn prune(&self, now: Instant) {
        if self.remembered.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.entries.retain(|_, remembered| {
            let keep = now.saturating_duration_since(remembered.refused_at) < REFUSAL_TTL;
            if !keep {
                self.remembered.fetch_sub(1, Ordering::Relaxed);
            }
            keep
        });
    }

    /// Refusals currently remembered.
    pub fn len(&self) -> usize {
        self.remembered.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: RefusedAnswer = RefusedAnswer {
        reject_code: 503,
        retry_after_secs: 1,
    };

    #[test]
    fn a_refused_invite_is_found_until_the_ttl() {
        let refused = RefusedInvites::default();
        let now = Instant::now();
        assert_eq!(refused.lookup_at("call-1", "z9hG4bK-1", now), None);

        refused.remember("call-1", "z9hG4bK-1", ANSWER, now);
        assert_eq!(refused.lookup_at("call-1", "z9hG4bK-1", now), Some(ANSWER));
        assert_eq!(
            refused.lookup_at(
                "call-1",
                "z9hG4bK-1",
                now + REFUSAL_TTL - Duration::from_millis(1)
            ),
            Some(ANSWER)
        );
        assert_eq!(
            refused.lookup_at("call-1", "z9hG4bK-1", now + REFUSAL_TTL),
            None,
            "an expired entry answers nothing even before it is pruned"
        );
    }

    #[test]
    fn a_different_branch_or_call_id_is_a_different_invite() {
        let refused = RefusedInvites::default();
        let now = Instant::now();
        refused.remember("call-1", "z9hG4bK-1", ANSWER, now);
        assert_eq!(refused.lookup_at("call-1", "z9hG4bK-2", now), None);
        assert_eq!(refused.lookup_at("call-2", "z9hG4bK-1", now), None);
        // The pair is hashed as two fields, not one concatenated string.
        assert_eq!(refused.lookup_at("call-1z", "9hG4bK-1", now), None);
    }

    #[test]
    fn remembering_the_same_invite_twice_holds_one_entry() {
        let refused = RefusedInvites::default();
        let now = Instant::now();
        refused.remember("call-1", "z9hG4bK-1", ANSWER, now);
        let later = RefusedAnswer {
            reject_code: 486,
            retry_after_secs: 0,
        };
        refused.remember("call-1", "z9hG4bK-1", later, now);
        assert_eq!(refused.len(), 1);
        assert_eq!(refused.lookup_at("call-1", "z9hG4bK-1", now), Some(later));
    }

    #[test]
    fn an_acked_refusal_is_forgotten() {
        let refused = RefusedInvites::default();
        let now = Instant::now();
        refused.remember("call-1", "z9hG4bK-1", ANSWER, now);
        refused.remember("call-2", "z9hG4bK-1", ANSWER, now);

        refused.forget("call-1", "z9hG4bK-1");
        assert_eq!(refused.lookup_at("call-1", "z9hG4bK-1", now), None);
        assert_eq!(refused.lookup_at("call-2", "z9hG4bK-1", now), Some(ANSWER));
        assert_eq!(refused.len(), 1);

        // An ACK for something never refused, or ACKed twice, changes nothing.
        refused.forget("call-1", "z9hG4bK-1");
        refused.forget("call-9", "z9hG4bK-9");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused.entries.len(), 1);
    }

    #[test]
    fn the_table_stops_growing_at_its_ceiling() {
        let refused = RefusedInvites::with_ceiling(100);
        let now = Instant::now();
        for index in 0..1000 {
            refused.remember(&format!("call-{index}"), "z9hG4bK-1", ANSWER, now);
        }
        assert_eq!(refused.len(), 100);
        assert_eq!(refused.entries.len(), 100);
        assert_eq!(
            refused.lookup_at("call-999", "z9hG4bK-1", now),
            None,
            "past the ceiling a refusal is not remembered"
        );
    }

    /// The per-module leak gate: once the refusals have aged out, a prune
    /// leaves the table empty, and it fills and empties again the same way.
    #[test]
    fn the_table_drains_to_baseline_once_refusals_age_out() {
        let refused = RefusedInvites::default();
        let mut now = Instant::now();
        for round in 0..50 {
            for index in 0..500 {
                refused.remember(&format!("call-{round}-{index}"), "z9hG4bK-1", ANSWER, now);
            }
            assert_eq!(refused.len(), 500, "round {round}");
            refused.prune(now + REFUSAL_TTL - Duration::from_millis(1));
            assert_eq!(refused.len(), 500, "nothing has aged out in round {round}");

            now += REFUSAL_TTL;
            refused.prune(now);
            assert_eq!(refused.len(), 0, "round {round}");
            assert!(refused.is_empty());
            assert_eq!(refused.entries.len(), 0, "round {round}");
        }
    }

    #[test]
    fn a_prune_keeps_the_refusals_still_inside_the_ttl() {
        let refused = RefusedInvites::default();
        let start = Instant::now();
        refused.remember("old", "z9hG4bK-1", ANSWER, start);
        refused.remember("new", "z9hG4bK-1", ANSWER, start + Duration::from_secs(20));
        refused.prune(start + REFUSAL_TTL);
        assert_eq!(refused.len(), 1);
        assert_eq!(
            refused.lookup_at("new", "z9hG4bK-1", start + REFUSAL_TTL),
            Some(ANSWER)
        );
    }

    #[test]
    fn concurrent_remember_and_prune_keep_the_count_true() {
        let refused = std::sync::Arc::new(RefusedInvites::default());
        let start = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|thread| {
                let refused = std::sync::Arc::clone(&refused);
                std::thread::spawn(move || {
                    for index in 0..2000 {
                        refused.remember(
                            &format!("call-{thread}-{index}"),
                            "z9hG4bK-1",
                            ANSWER,
                            start,
                        );
                        if index % 500 == 0 {
                            refused.prune(start);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("a remembering thread");
        }
        assert_eq!(refused.len(), refused.entries.len());
        refused.prune(start + REFUSAL_TTL);
        assert_eq!(refused.len(), 0);
    }
}
