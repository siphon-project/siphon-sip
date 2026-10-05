//! Final responses of INVITEs the B2BUA has finished, kept for their
//! retransmissions.
//!
//! RFC 3261 §17.2.1: an INVITE server transaction that has sent a 300-699 stays
//! in Completed until the ACK or Timer H (64*T1), answering a retransmitted
//! INVITE with that final response again, and after the ACK stays in Confirmed
//! for Timer I (T4 on an unreliable transport, nothing on a reliable one) to
//! absorb what is still in flight. The B2BUA removes a failed or CANCELled call
//! as soon as it has answered the caller, so without this record a
//! retransmission (the caller did not get the response) finds no call and is
//! taken for a new one: `@b2bua.on_invite` runs a second time and the callee is
//! dialled again for a call the caller is about to give up on.
//!
//! Keyed by Call-ID and the topmost Via branch, the transaction a
//! retransmission repeats. An entry leaves at the end of that transaction's
//! life, and the oldest leave early past [`CAPACITY`], so a flood of rejected
//! INVITEs cannot grow it without bound.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;

use crate::dispatcher::*;

/// Timer H, 64*T1 (RFC 3261 §17.2.1): how long an unacknowledged final
/// response is owed again.
const TIMER_H: Duration = Duration::from_secs(32);

/// Timer I, T4 (RFC 3261 §17.2.1): how long an acknowledged one still is, on
/// an unreliable transport.
const TIMER_I: Duration = Duration::from_secs(5);

/// Most final responses kept at once.
const CAPACITY: usize = 10_000;

/// The final responses of recently finished INVITEs.
pub struct CompletedInvites {
    /// The response and when it stops being owed.
    responses: DashMap<String, (Bytes, Instant)>,
    /// One record per expiry an entry was given, for removal by age and by
    /// capacity. See [`ExpiryOrder`].
    order: Mutex<ExpiryOrder>,
    /// Entry count, so the per-INVITE lookup costs one load while this is empty.
    count: AtomicUsize,
    capacity: usize,
}

/// The expiries entries were given, in two queues that are each oldest first.
///
/// An ACK gives an entry an earlier expiry (Timer I). Queued behind the Timer H
/// records it would wait for all of those, so it has a queue of its own. The
/// entry's first record then names an expiry it no longer has and removes
/// nothing when it comes due.
#[derive(Default)]
struct ExpiryOrder {
    /// Timer H records, in the order the responses were sent.
    sent: VecDeque<(String, Instant)>,
    /// Timer I records, in the order the ACKs arrived.
    acknowledged: VecDeque<(String, Instant)>,
}

impl Default for CompletedInvites {
    fn default() -> Self {
        Self::with_capacity(CAPACITY)
    }
}

impl CompletedInvites {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            responses: DashMap::new(),
            order: Mutex::new(ExpiryOrder::default()),
            count: AtomicUsize::new(0),
            capacity,
        }
    }

    fn key(call_id: &str, via_branch: &str) -> String {
        format!("{call_id}\n{via_branch}")
    }

    /// Keep `response`, the final response just sent for the INVITE
    /// `call_id` / `via_branch`.
    pub fn remember(&self, call_id: &str, via_branch: &str, response: Bytes) {
        self.remember_at(call_id, via_branch, response, Instant::now());
    }

    fn remember_at(&self, call_id: &str, via_branch: &str, response: Bytes, now: Instant) {
        if call_id.is_empty() || via_branch.is_empty() {
            return;
        }
        let key = Self::key(call_id, via_branch);
        let expires = now + TIMER_H;
        let Some(mut order) = self.lock_order(call_id) else {
            return;
        };
        if self
            .responses
            .insert(key.clone(), (response, expires))
            .is_none()
        {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
        order.sent.push_back((key, expires));
        self.sweep(&mut order, now);
    }

    /// The caller has ACKed the final response of the INVITE `call_id` /
    /// `via_branch`: it has it, so it is owed again only for Timer I, and on a
    /// reliable transport not at all.
    pub fn acknowledged(&self, call_id: &str, via_branch: &str, reliable_transport: bool) {
        self.acknowledged_at(call_id, via_branch, reliable_transport, Instant::now());
    }

    fn acknowledged_at(
        &self,
        call_id: &str,
        via_branch: &str,
        reliable_transport: bool,
        now: Instant,
    ) {
        if self.is_unused() {
            return;
        }
        let key = Self::key(call_id, via_branch);
        let Some(mut order) = self.lock_order(call_id) else {
            return;
        };
        if reliable_transport {
            if self.responses.remove(&key).is_some() {
                self.count.fetch_sub(1, Ordering::Relaxed);
            }
        } else if let Some(mut entry) = self.responses.get_mut(&key) {
            let expires = now + TIMER_I;
            if expires < entry.1 {
                entry.1 = expires;
                drop(entry);
                order.acknowledged.push_back((key, expires));
            }
        }
        self.sweep(&mut order, now);
    }

    /// The final response owed to a retransmission of the INVITE
    /// `call_id` / `via_branch`, if one is still owed.
    pub fn get(&self, call_id: &str, via_branch: &str) -> Option<Bytes> {
        self.get_at(call_id, via_branch, Instant::now())
    }

    fn get_at(&self, call_id: &str, via_branch: &str, now: Instant) -> Option<Bytes> {
        if self.is_unused() {
            return None;
        }
        let entry = self.responses.get(&Self::key(call_id, via_branch))?;
        let (response, expires) = entry.value();
        (now < *expires).then(|| response.clone())
    }

    /// Whether nothing is kept: one atomic load, which is all a new INVITE or
    /// an ACK pays on a node that is rejecting nothing.
    fn is_unused(&self) -> bool {
        self.count.load(Ordering::Relaxed) == 0
    }

    fn lock_order(&self, call_id: &str) -> Option<std::sync::MutexGuard<'_, ExpiryOrder>> {
        match self.order.lock() {
            Ok(order) => Some(order),
            Err(error) => {
                error!("completed-INVITE order mutex poisoned, skipping {call_id}: {error}");
                None
            }
        }
    }

    /// Drop the records that are due, each with the entry it still describes,
    /// and then the oldest responses the capacity pushes out.
    fn sweep(&self, order: &mut ExpiryOrder, now: Instant) {
        while let Some((key, expires)) = order.acknowledged.front() {
            if *expires > now {
                break;
            }
            self.remove_expiring(key, *expires);
            order.acknowledged.pop_front();
        }
        while let Some((key, expires)) = order.sent.front() {
            if *expires > now && self.count.load(Ordering::Relaxed) <= self.capacity {
                break;
            }
            // Over capacity the oldest response goes whatever expiry it has now.
            if *expires > now {
                if self.responses.remove(key).is_some() {
                    self.count.fetch_sub(1, Ordering::Relaxed);
                }
            } else {
                self.remove_expiring(key, *expires);
            }
            order.sent.pop_front();
        }
    }

    /// Remove `key` if it still has the expiry `expires`: a record whose entry
    /// was since remembered again, or acknowledged, describes it no longer.
    fn remove_expiring(&self, key: &str, expires: Instant) {
        if self
            .responses
            .remove_if(key, |_, (_, current)| *current == expires)
            .is_some()
        {
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Number of final responses currently kept.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Whether nothing is kept.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.is_unused()
    }
}

/// The topmost Via branch of `message`, the transaction it belongs to.
fn top_via_branch(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|via| via.branch)
}

/// Record `message` when it is a final non-2xx response to an INVITE that a
/// B2BUA is answering, with `data` its bytes as they go on the wire.
///
/// Called for every message siphon serialises to send. Anything that is not a
/// 300-699 leaves on the first comparison.
pub(super) fn remember_invite_final(message: &SipMessage, data: &Bytes, state: &DispatcherState) {
    let StartLine::Response(status_line) = &message.start_line else {
        return;
    };
    if status_line.status_code < 300 {
        return;
    }
    let to_an_invite = message
        .headers
        .cseq()
        .is_some_and(|cseq| cseq.trim_end().ends_with("INVITE"));
    if !to_an_invite || !b2bua_mode_active(&state.engine.state(), state) {
        return;
    }
    let (Some(call_id), Some(via_branch)) = (message.headers.call_id(), top_via_branch(message))
    else {
        return;
    };
    state
        .completed_invites
        .remember(call_id, &via_branch, data.clone());
}

/// An ACK arrived: if it acknowledges a final response kept here, that
/// response is owed only for what is left of its transaction (Timer I).
///
/// The ACK for a non-2xx carries the INVITE's own Via branch (RFC 3261
/// §17.1.1.3), which is how it is matched. An ACK for a 2xx has a branch of its
/// own and matches nothing.
pub(super) fn acknowledge_invite_final(
    message: &SipMessage,
    transport: Transport,
    state: &DispatcherState,
) {
    if state.completed_invites.is_unused() {
        return;
    }
    let (Some(call_id), Some(via_branch)) = (message.headers.call_id(), top_via_branch(message))
    else {
        return;
    };
    state
        .completed_invites
        .acknowledged(call_id, &via_branch, transport != Transport::Udp);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(text: &'static str) -> Bytes {
        Bytes::from_static(text.as_bytes())
    }

    #[test]
    fn a_final_response_is_found_by_its_transaction() {
        let store = CompletedInvites::default();
        assert!(store.is_empty());
        assert!(store.get("call-1", "z9hG4bK-1").is_none());

        store.remember(
            "call-1",
            "z9hG4bK-1",
            response("SIP/2.0 486 Busy Here\r\n\r\n"),
        );
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.get("call-1", "z9hG4bK-1"),
            Some(response("SIP/2.0 486 Busy Here\r\n\r\n"))
        );
        // Another transaction of the same call, and the same branch on another
        // call, are different INVITEs.
        assert!(store.get("call-1", "z9hG4bK-2").is_none());
        assert!(store.get("call-2", "z9hG4bK-1").is_none());
    }

    #[test]
    fn a_response_without_a_transaction_is_not_kept() {
        let store = CompletedInvites::default();
        store.remember("", "z9hG4bK-1", response("x"));
        store.remember("call-1", "", response("x"));
        assert!(store.is_empty());
    }

    /// Timer H: an unacknowledged response is owed for 32 s, and the next
    /// insert after that removes the entry.
    #[test]
    fn an_unacknowledged_response_expires_after_timer_h() {
        let store = CompletedInvites::with_capacity(100);
        let start = Instant::now();
        store.remember_at("call-1", "z9hG4bK-1", response("first"), start);

        let within = start + Duration::from_secs(31);
        assert!(store.get_at("call-1", "z9hG4bK-1", within).is_some());
        let past = start + Duration::from_secs(33);
        assert!(store.get_at("call-1", "z9hG4bK-1", past).is_none());

        store.remember_at("call-2", "z9hG4bK-2", response("second"), past);
        assert_eq!(store.len(), 1);
        assert!(store.get_at("call-2", "z9hG4bK-2", past).is_some());
    }

    /// Timer I: once ACKed over UDP the response is owed for 5 s more, so an
    /// INVITE that reuses the transaction's identifiers after that is a new
    /// call again.
    #[test]
    fn an_acknowledged_response_expires_after_timer_i() {
        let store = CompletedInvites::with_capacity(100);
        let start = Instant::now();
        store.remember_at("call-1", "z9hG4bK-1", response("busy"), start);

        let acked = start + Duration::from_secs(1);
        store.acknowledged_at("call-1", "z9hG4bK-1", false, acked);
        assert!(store
            .get_at("call-1", "z9hG4bK-1", acked + Duration::from_secs(4))
            .is_some());
        assert!(store
            .get_at("call-1", "z9hG4bK-1", acked + Duration::from_secs(6))
            .is_none());

        // And the entry itself leaves at the next sweep past that point, not
        // at the Timer H it was first given.
        store.acknowledged_at("call-9", "z9hG4bK-9", false, acked + Duration::from_secs(6));
        assert!(store.is_empty());
    }

    /// A reliable transport loses nothing in flight: Timer I is zero and the
    /// ACK ends the transaction.
    #[test]
    fn an_ack_over_a_reliable_transport_ends_the_transaction() {
        let store = CompletedInvites::with_capacity(100);
        let start = Instant::now();
        store.remember_at("call-1", "z9hG4bK-1", response("busy"), start);
        store.acknowledged_at("call-1", "z9hG4bK-1", true, start);
        assert!(store.is_empty());
        assert!(store.get_at("call-1", "z9hG4bK-1", start).is_none());
    }

    /// An ACK never lengthens what is owed, and one for a transaction that is
    /// not kept changes nothing.
    #[test]
    fn an_ack_only_ever_shortens() {
        let store = CompletedInvites::with_capacity(100);
        let start = Instant::now();
        store.remember_at("call-1", "z9hG4bK-1", response("busy"), start);

        let late = start + Duration::from_secs(30);
        store.acknowledged_at("call-1", "z9hG4bK-1", false, late);
        assert!(store
            .get_at("call-1", "z9hG4bK-1", start + Duration::from_secs(33))
            .is_none());

        store.acknowledged_at("call-2", "z9hG4bK-2", false, start);
        assert_eq!(store.len(), 1);
    }

    /// Steady-state leak check: any number of finished INVITEs leaves at most
    /// the capacity behind, and all of them leave once they have aged out.
    #[test]
    fn the_store_is_bounded_by_capacity_and_drains_by_age() {
        let store = CompletedInvites::with_capacity(50);
        let start = Instant::now();
        for index in 0..5_000 {
            let call_id = format!("call-{index}");
            store.remember_at(
                &call_id,
                "z9hG4bK-1",
                response("SIP/2.0 503 Service Unavailable\r\n\r\n"),
                start,
            );
            if index % 2 == 0 {
                store.acknowledged_at(&call_id, "z9hG4bK-1", false, start);
            }
            assert!(store.len() <= 50);
        }
        assert_eq!(store.len(), 50);
        // The newest survive, the oldest went first.
        assert!(store.get_at("call-4999", "z9hG4bK-1", start).is_some());
        assert!(store.get_at("call-0", "z9hG4bK-1", start).is_none());

        let later = start + Duration::from_secs(40);
        store.remember_at("call-late", "z9hG4bK-1", response("late"), later);
        assert_eq!(store.len(), 1);
        let order = store.order.lock().unwrap();
        assert_eq!(
            (order.sent.len(), order.acknowledged.len()),
            (1, 0),
            "no order record outlives its entry"
        );
    }

    /// The same transaction remembered twice keeps one entry, and the older
    /// order record expiring does not take the newer response with it.
    #[test]
    fn remembering_a_transaction_again_keeps_the_newer_response() {
        let store = CompletedInvites::with_capacity(100);
        let start = Instant::now();
        store.remember_at("call-1", "z9hG4bK-1", response("first"), start);
        let later = start + Duration::from_secs(20);
        store.remember_at("call-1", "z9hG4bK-1", response("second"), later);
        assert_eq!(store.len(), 1);

        // The first record is now past Timer H; the second is not.
        let after_first = start + Duration::from_secs(40);
        store.remember_at("call-2", "z9hG4bK-2", response("other"), after_first);
        assert_eq!(
            store.get_at("call-1", "z9hG4bK-1", after_first),
            Some(response("second"))
        );
    }

    #[test]
    fn concurrent_inserts_stay_within_the_capacity() {
        let store = std::sync::Arc::new(CompletedInvites::with_capacity(200));
        let handles: Vec<_> = (0..8)
            .map(|thread| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    for index in 0..1_000 {
                        let call_id = format!("call-{thread}-{index}");
                        store.remember(
                            &call_id,
                            "z9hG4bK-1",
                            response("SIP/2.0 480 Temporarily Unavailable\r\n\r\n"),
                        );
                        if index % 3 == 0 {
                            store.acknowledged(&call_id, "z9hG4bK-1", index % 2 == 0);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(store.len() <= 200, "kept {}", store.len());
    }
}
