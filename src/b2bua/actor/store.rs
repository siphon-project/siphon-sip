//! [`CallActorStore`]: the concurrent map of live calls.
//!
//! Every dispatcher path that touches a call goes through here, so the methods
//! are deliberately thin: take the entry, mutate under the shard lock, drop it.
//! The store also keeps the short-lived record of recently-terminated calls
//! that answers a late or glaring in-dialog request.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::warn;

use crate::sip::message::SipMessage;

use super::*;

/// How long a torn-down call's SIP Call-IDs stay answerable with 481.
///
/// 32 s = Timer H / 64·T1 (RFC 3261 §17), the same expiry the zombie re-INVITE
/// and post-CANCEL absorbers use: once the peer's own client transaction has
/// timed out it stops retransmitting, so remembering the dialog past that point
/// buys nothing.
pub(super) const TERMINATED_CALL_TTL: Duration = Duration::from_secs(32);
/// Hard ceiling on remembered torn-down Call-IDs.
///
/// Unlike the zombie absorbers — which only gain entries on rare paths — this
/// set gains an entry per leg on *every* teardown, so the TTL alone is not a
/// bound: at 40k cps it would hold 32 s × 40k ≈ 1.3M Call-IDs. The cap keeps the
/// footprint flat while still covering ~1.6 s of teardowns at that rate, far
/// wider than the sub-second glare window this exists for. At realistic per-NF
/// call rates the TTL evicts long before the cap is in play.
pub(super) const TERMINATED_CALL_CAPACITY: usize = 65_536;
/// Manages all active B2BUA calls.
///
/// Stores `CallActor` instances in a concurrent map, indexed by internal
/// call ID. Uses `LegRegistry` for SIP-level routing.
#[derive(Debug)]
pub struct CallActorStore {
    /// Internal call ID → CallActor.
    /// Boxed: `CallActor` is ~2.2 KB (an inline `a_leg: Leg`, the `b_legs`
    /// vectors, session-timer and transfer state), and `hashbrown` sizes its
    /// bucket array for the peak number of live calls and never shrinks it.
    /// Stored inline that is a ~2.3 KB bucket retained at the busiest moment
    /// the process ever saw, for the rest of its life, with `calls.len()`
    /// reading 0 — the same shape fixed for the transaction map and the timer
    /// wheel. Boxed the bucket is 32 bytes.
    calls: DashMap<String, Box<CallActor>>,
    /// SIP identifier routing table.
    pub registry: LegRegistry,
    /// Post-teardown re-INVITE ACK absorber, keyed by B-leg SIP Call-ID.
    pub zombie_reinvites: DashMap<String, ZombieReInviteEntry>,
    /// Post-CANCEL glare absorber (RFC 3261 §9.1): a 2xx that raced our CANCEL
    /// is ACKed + BYEd here, keyed by B-leg SIP Call-ID.
    pub zombie_cancelled: DashMap<String, ZombieCancelledLeg>,
    /// SIP Call-IDs of calls this node has torn down → when they were torn down,
    /// so a late in-dialog request naming one can be answered 481 instead of
    /// dropped ([`Self::is_recently_terminated`]). Read on the request path, so
    /// it is the lock-free half of the pair.
    pub(super) terminated: DashMap<String, Instant>,
    /// Teardown order backing [`Self::terminated`], for eviction by age and by
    /// capacity. Only touched on teardown, never on the read path.
    ///
    /// A Call-ID can appear more than once — a peer may reuse one for its next
    /// call, and both B2BUA legs may share one. The timestamp doubles as a
    /// generation stamp so evicting a stale entry can't drop a Call-ID that has
    /// since been remembered again; see [`Self::evict_terminated`].
    pub(super) terminated_order: Mutex<VecDeque<(String, Instant)>>,
}
impl CallActorStore {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            registry: LegRegistry::new(),
            zombie_reinvites: DashMap::new(),
            zombie_cancelled: DashMap::new(),
            terminated: DashMap::new(),
            terminated_order: Mutex::new(VecDeque::new()),
        }
    }

    /// Remember `sip_call_id` as a dialog this node has torn down.
    ///
    /// Evicts from the front on the way in (amortised O(1), no timer task):
    /// entries older than [`TERMINATED_CALL_TTL`] first, then any overflow past
    /// [`TERMINATED_CALL_CAPACITY`].
    fn remember_terminated(&self, sip_call_id: &str) {
        if sip_call_id.is_empty() {
            return;
        }
        let mut order = match self.terminated_order.lock() {
            Ok(guard) => guard,
            Err(error) => {
                // Never remember without the order half — nothing would ever
                // evict it. A late in-dialog request for this call falls through
                // to the script instead of drawing a 481; that is the lesser
                // failure next to an unbounded map.
                warn!(
                    "terminated-call order mutex poisoned, not remembering {sip_call_id}: {error}"
                );
                return;
            }
        };
        // Always stamp and enqueue, even for a Call-ID already present: the
        // stamp is the generation, and the newest one is what must survive.
        let now = Instant::now();
        self.terminated.insert(sip_call_id.to_string(), now);
        order.push_back((sip_call_id.to_string(), now));
        Self::evict_terminated(
            &self.terminated,
            &mut order,
            now,
            TERMINATED_CALL_TTL,
            TERMINATED_CALL_CAPACITY,
        );
    }

    /// Drop remembered Call-IDs from the front of `order`: everything older than
    /// `ttl` as of `now`, then whatever still overflows `capacity`.
    ///
    /// An expiring entry only removes the Call-ID if its stamp is still the
    /// current generation. Without that check, re-terminating a Call-ID seen
    /// before would un-remember it: the stale entry ages out and takes the
    /// freshly-remembered Call-ID with it, which is how a peer that reuses
    /// Call-IDs across calls lost its 481.
    ///
    /// Split out (and given `now` / `ttl` / `capacity` explicitly) so both
    /// eviction rules are testable without a 32-second sleep.
    pub(super) fn evict_terminated(
        terminated: &DashMap<String, Instant>,
        order: &mut VecDeque<(String, Instant)>,
        now: Instant,
        ttl: Duration,
        capacity: usize,
    ) {
        loop {
            let evict = match order.front() {
                Some((_, stamped)) => {
                    now.saturating_duration_since(*stamped) >= ttl || order.len() > capacity
                }
                None => false,
            };
            if !evict {
                break;
            }
            if let Some((call_id, stamped)) = order.pop_front() {
                terminated.remove_if(&call_id, |_, current| *current == stamped);
            }
        }
    }

    /// Did this node recently tear down a call carrying `sip_call_id`?
    ///
    /// An in-dialog request naming it can no longer be bridged or routed — both
    /// dialogs are gone here — so it MUST be answered 481 Call/Transaction Does
    /// Not Exist (RFC 3261 §12.2.2, §15.1.2 for BYE) rather than dropped.
    /// Dropping it leaves the peer retransmitting to its own timer F; a VoNR UE
    /// reads that 32 s silence as a dead IMS and recovers by releasing its IMS
    /// PDU session and re-registering, which costs ~40 s of terminating service.
    ///
    /// Eviction is lazy (it happens on insert), so an entry can outlive the TTL
    /// by a while. That is harmless — the answer is still correct — and it keeps
    /// this to a single hash on the request path.
    pub fn is_recently_terminated(&self, sip_call_id: &str) -> bool {
        !sip_call_id.is_empty() && self.terminated.contains_key(sip_call_id)
    }

    /// Number of active calls.
    pub fn count(&self) -> usize {
        self.calls.len()
    }

    /// Create a new call from an A-leg and return the internal call ID.
    ///
    /// Registers the A-leg's SIP Call-ID in the registry.
    pub fn create_call(&self, a_leg: Leg) -> String {
        let sip_call_id = a_leg.dialog.call_id.clone();
        let a_branch = a_leg.branch.clone();
        let call = CallActor::new(a_leg);
        let id = call.id.clone();
        self.registry.register_call_id(&sip_call_id, &id);
        self.registry.register_branch(&a_branch, &id);
        self.calls.insert(id.clone(), Box::new(call));
        id
    }

    /// Add a B-leg to a call. Registers branch in the registry.
    pub fn add_b_leg(&self, call_id: &str, leg: Leg) -> bool {
        let branch = leg.branch.clone();
        let sip_call_id = leg.dialog.call_id.clone();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.add_b_leg(leg);
            self.registry.register_branch(&branch, call_id);
            // Only register Call-ID if not already mapped to this call.
            // Re-INVITE tracking legs reuse the A-leg or B-leg Call-ID;
            // re-registering would overwrite the original mapping, and
            // remove_b_leg would then delete it, breaking BYE routing.
            if self.registry.lookup_call_id(&sip_call_id).as_deref() != Some(call_id) {
                self.registry.register_call_id(&sip_call_id, call_id);
            }
            true
        } else {
            false
        }
    }

    /// Supersede a B-leg in place and re-point the routing registry from the
    /// old branch to the new one.
    ///
    /// Used by the 401/407 (RFC 3261 §9.1) and 422 (RFC 4028) retry paths: the
    /// retry continues the same logical B-leg rather than forking a new one, so
    /// a later CANCEL fans out to the live transaction only. See
    /// [`CallActor::replace_b_leg`]. The dialog Call-ID is unchanged (the retry
    /// reuses it), so the Call-ID registration is left untouched. Returns true
    /// on success, false if the call or `index` is unknown.
    pub fn replace_b_leg(&self, call_id: &str, index: usize, leg: Leg) -> bool {
        let new_branch = leg.branch.clone();
        let old_branch = match self.calls.get_mut(call_id) {
            Some(mut call) => call.replace_b_leg(index, leg),
            None => return false,
        };
        match old_branch {
            Some(old) => {
                if old != new_branch {
                    self.registry.remove_branch(&old);
                }
                self.registry.register_branch(&new_branch, call_id);
                true
            }
            None => false,
        }
    }

    /// Remove a B-leg by index.
    pub fn remove_b_leg(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(removed) = call.remove_b_leg(index) {
                self.registry.remove_branch(&removed.branch);
                // Only remove Call-ID mapping if no other leg uses it.
                // Re-INVITE tracking legs share the A-leg or winning B-leg
                // Call-ID; removing it here would break BYE/in-dialog routing.
                let cid = &removed.dialog.call_id;
                let still_used = call.a_leg.dialog.call_id == *cid
                    || call.b_legs.iter().any(|b| b.dialog.call_id == *cid);
                if !still_used {
                    self.registry.remove_call_id(cid);
                }
            }
        }
    }

    /// Update the target_uri of a B-leg (used to mark re-INVITE entries as done).
    pub fn set_b_leg_target_uri(&self, call_id: &str, index: usize, target_uri: String) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(b_leg) = call.b_legs.get_mut(index) {
                b_leg.dialog.target_uri = Some(target_uri);
            }
        }
    }

    /// Find any call that contains a leg matching the supplied dialog
    /// triple. Used to validate the `Replaces` header on an incoming
    /// INVITE (RFC 3891 §3): the referenced dialog must exist or the
    /// INVITE MUST be rejected with 481 Call/Transaction Does Not
    /// Exist.
    ///
    /// The `from_tag` in the `Replaces` header is the tag of the UA
    /// that *sent* the original dialog request (the "remote" side from
    /// our perspective); `to_tag` is *our* tag for that dialog.
    /// Reports which leg matched as well as which call, because the party that
    /// survives a takeover is the *peer* of the named dialog and the caller
    /// cannot work that out from the call id alone.
    pub fn find_call_by_replaces_dialog(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<ReplacesMatch> {
        for entry in self.calls.iter() {
            let call = entry.value();
            let leg_matches = |leg: &Leg| {
                leg.dialog.call_id == call_id
                    && leg.dialog.local_tag == to_tag
                    && (leg.dialog.remote_tag.as_deref() == Some(from_tag))
            };
            if leg_matches(&call.a_leg) {
                return Some(ReplacesMatch {
                    call_id: entry.key().clone(),
                    on_a_leg: true,
                });
            }
            if call.b_legs.iter().any(leg_matches) {
                return Some(ReplacesMatch {
                    call_id: entry.key().clone(),
                    on_a_leg: false,
                });
            }
        }
        None
    }

    /// Record the `Replaces` match resolved for a call still being admitted.
    pub fn set_pending_replaces(&self, call_id: &str, pending: PendingReplaces) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pending_replaces = Some(pending);
        }
    }

    /// Take the recorded `Replaces` match, if any, leaving none behind.
    pub fn take_pending_replaces(&self, call_id: &str) -> Option<PendingReplaces> {
        self.calls
            .get_mut(call_id)
            .and_then(|mut call| call.pending_replaces.take())
    }

    /// Lift a call's A-leg out and drop the (now empty) call, WITHOUT retiring
    /// the dialog.
    ///
    /// The leg is moving to another call, not ending, so this deliberately does
    /// none of what [`remove_call`](Self::remove_call) does: the Call-ID keeps
    /// its registry entry (re-pointed by [`adopt_replaced_dialog`]) and is never
    /// marked terminated, because doing either would make the ACK for the 200
    /// this leg is about to receive resolve to nothing and answer 481.
    ///
    /// [`adopt_replaced_dialog`]: Self::adopt_replaced_dialog
    pub fn detach_a_leg_for_adoption(&self, call_id: &str) -> Option<Leg> {
        let (_, call) = self.calls.remove(call_id)?;
        call.shutdown_actors();
        self.registry.remove_branch(&call.a_leg.branch);
        Some(call.a_leg)
    }

    /// Hand a call's dialog over to a new party (RFC 3891 `Replaces`).
    ///
    /// `new_leg` takes the place of the leg named by the `Replaces`, and the
    /// call is rebuilt around the pair that is left: the new leg in the A-leg
    /// slot and the surviving party as the sole B-leg. The A-leg slot is not
    /// negotiable — the inbound-ACK path resolves a call by Call-ID and then
    /// marks `a_leg` acked, so a UAS leg parked anywhere else would never have
    /// its ACK recorded and would retransmit its 200 to Timer B.
    ///
    /// Returns the replaced leg so the caller can BYE it (RFC 3891 §3 requires
    /// the replaced dialog to be terminated once the new INVITE is accepted),
    /// together with the survivor.
    ///
    /// The replaced dialog is retired here — registry entries dropped and the
    /// Call-ID remembered as terminated — so a late in-dialog request on it
    /// answers 481 rather than resolving to a call it is no longer part of.
    pub fn adopt_replaced_dialog(
        &self,
        replaced_call_id: &str,
        replaced_on_a_leg: bool,
        new_leg: Leg,
    ) -> Option<(Leg, Leg)> {
        let new_sip_call_id = new_leg.dialog.call_id.clone();
        let new_branch = new_leg.branch.clone();
        let (replaced, survivor) = {
            let mut call = self.calls.get_mut(replaced_call_id)?;
            let winner = call.winner?;
            if winner >= call.b_legs.len() {
                return None;
            }
            let (replaced, survivor) = if replaced_on_a_leg {
                let survivor = call.b_legs.swap_remove(winner);
                let replaced = std::mem::replace(&mut call.a_leg, new_leg);
                (replaced, survivor)
            } else {
                let replaced = call.b_legs.swap_remove(winner);
                // The old A-leg becomes the surviving B-leg; the new party takes
                // the A-leg slot it vacates.
                let survivor = std::mem::replace(&mut call.a_leg, new_leg);
                (replaced, survivor)
            };
            // Rebuild around the surviving pair. Any other B-leg on the call is
            // a settled fork loser and has no dialog left to carry over.
            call.b_legs.clear();
            call.b_leg_status.clear();
            call.b_leg_handles.clear();
            call.b_legs.push(survivor.clone());
            call.b_leg_status.push(BLegStatus::Answered);
            call.b_leg_handles.push(None);
            call.winner = Some(0);
            call.transition_to(CallState::Answered);
            (replaced, survivor)
        };

        // The new party's dialog now belongs to this call, so its Call-ID has to
        // resolve here — its ACK, re-INVITEs and BYE all arrive on it.
        self.registry
            .register_call_id(&new_sip_call_id, replaced_call_id);
        self.registry.register_branch(&new_branch, replaced_call_id);

        self.registry.remove_call_id(&replaced.dialog.call_id);
        self.registry.remove_branch(&replaced.branch);
        self.remember_terminated(&replaced.dialog.call_id);

        Some((replaced, survivor))
    }

    /// Resolve the `Replaces` triple a referrer supplied (its own view of the
    /// dialog to be replaced) into the triple the *far* party of that dialog
    /// would recognise, together with the internal call id the dialog belongs to.
    ///
    /// On a B2BUA the two ends of a call never share dialog identifiers: the
    /// referrer names its held call by the Call-ID and tag pair of the leg
    /// facing *it*, while the transfer target only knows the leg facing itself.
    /// A `Replaces` forwarded verbatim therefore names a dialog the target has
    /// never seen, and RFC 3891 §3 requires it to answer `481`. This returns the
    /// far leg's identifiers *as the far party sees them* — its Call-ID,
    /// siphon's local tag as the `from-tag`, and the far party's own tag as the
    /// `to-tag` (RFC 3891 §3 matches those against the remote and local tag of
    /// the dialog at the receiving UAS, respectively).
    ///
    /// `None` when the dialog is not one this node hosts (a referrer
    /// transferring against a call that never traversed siphon), when the far
    /// leg has no tag yet (nothing to replace), or when the far leg has not been
    /// chosen — the caller passes the referrer's own triple through in that case.
    pub fn replaces_as_seen_by_peer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<(String, ReplacesDialog)> {
        for entry in self.calls.iter() {
            let call = entry.value();
            let matches = |leg: &Leg| {
                leg.dialog.call_id == call_id
                    && leg.dialog.local_tag == to_tag
                    && leg.dialog.remote_tag.as_deref() == Some(from_tag)
            };
            let peer = if matches(&call.a_leg) {
                call.winner.and_then(|index| call.b_legs.get(index))
            } else if call.b_legs.iter().any(matches) {
                Some(&call.a_leg)
            } else {
                continue;
            }?;
            return Some((
                entry.key().clone(),
                ReplacesDialog {
                    call_id: peer.dialog.call_id.clone(),
                    from_tag: peer.dialog.local_tag.clone(),
                    to_tag: peer.dialog.remote_tag.clone()?,
                },
            ));
        }
        None
    }

    /// Atomically increment the local CSeq counter on the A-leg or the
    /// winning B-leg and return the new value. Used when the B2BUA needs
    /// to originate an in-dialog request (PRACK, BYE, re-INVITE) and must
    /// allocate a CSeq number that is monotonically increasing within
    /// the dialog (RFC 3261 §12.2.1.1).
    pub fn next_local_cseq(&self, call_id: &str, on_a_leg: bool) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            // Two-step indirection because `winner` borrows `call` immutably
            // while `b_legs.get_mut` needs the mutable borrow exclusively.
            let idx = call.winner?;
            call.b_legs.get_mut(idx)
        };
        leg.map(|leg| {
            leg.dialog.local_cseq = leg.dialog.local_cseq.saturating_add(1);
            leg.dialog.local_cseq
        })
    }

    /// Like `next_local_cseq` but addresses a specific B-leg by index —
    /// used when the call hasn't picked a winner yet (e.g. early media on
    /// a forked INVITE where the 1xx arrives before any 2xx).
    pub fn next_b_leg_local_cseq(&self, call_id: &str, b_leg_index: usize) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = call.b_legs.get_mut(b_leg_index)?;
        leg.dialog.local_cseq = leg.dialog.local_cseq.saturating_add(1);
        Some(leg.dialog.local_cseq)
    }

    /// RFC 3262 auto-PRACK dedup: returns `true` exactly once for each new RSeq
    /// value seen on the given B-leg's early dialog (identified by its remote
    /// To-tag), and `false` for retransmits of an already-PRACKed reliable
    /// provisional. Used so the B2BUA emits a single PRACK per RSeq instead of
    /// one per 1xx retransmit. Keyed per To-tag so a forked pair of early
    /// dialogs — whose RSeq spaces are independent (RFC 3262 §3) and commonly
    /// both start at 1 — each get their own PRACK rather than the second being
    /// swallowed as a "retransmit" of the first.
    pub fn try_mark_prack_acked(
        &self,
        call_id: &str,
        b_leg_index: usize,
        to_tag: &str,
        rseq: u32,
    ) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let Some(leg) = call.b_legs.get_mut(b_leg_index) else {
            return false;
        };
        if leg.prack_acked_rseq.get(to_tag).is_some_and(|&v| v >= rseq) {
            return false;
        }
        leg.prack_acked_rseq.insert(to_tag.to_string(), rseq);
        true
    }

    /// 401/407 auth-retry dedup: returns `true` exactly once for the first
    /// digest challenge seen on the given B-leg, and `false` for retransmits
    /// of that challenge on the same branch. The trunk retransmits the 401/407
    /// until it is ACKed (RFC 3261 §17.1.1.3); without this guard each
    /// retransmit would emit a second authenticated INVITE at the same CSeq on
    /// a new branch, which the trunk rejects as a merged request (§8.2.2.2 →
    /// 482). A chained re-challenge (e.g. stale nonce) lands on the *retry*
    /// leg's branch, which is a distinct B-leg with its own flag, so legitimate
    /// re-authentication still proceeds.
    pub fn try_mark_auth_challenged(&self, call_id: &str, b_leg_index: usize) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let Some(leg) = call.b_legs.get_mut(b_leg_index) else {
            return false;
        };
        if leg.auth_challenged {
            return false;
        }
        leg.auth_challenged = true;
        true
    }

    /// Current count of credentialed outbound INVITEs sent on the 401/407
    /// auto-retry path for this call (0 if the call is unknown). Read by the
    /// dispatcher's retry cap before deciding whether to re-auth or surface the
    /// failure.
    pub fn auth_retry_count(&self, call_id: &str) -> u32 {
        self.calls
            .get(call_id)
            .map_or(0, |call| call.auth_retry_count)
    }

    /// Increment and return the per-call credentialed-retry counter. Called
    /// once per committed retry (after the per-leg dedup), so retransmitted
    /// challenges don't inflate it.
    pub fn incr_auth_retry_count(&self, call_id: &str) -> u32 {
        match self.calls.get_mut(call_id) {
            Some(mut call) => {
                call.auth_retry_count = call.auth_retry_count.saturating_add(1);
                call.auth_retry_count
            }
            None => 0,
        }
    }

    /// Set the `pending_reinvite` flag on the A-leg or the winning B-leg.
    ///
    /// Returns the previous value so callers can implement the RFC 3261
    /// §14.1 glare check in one step: take-and-check if there was already
    /// a pending re-INVITE toward this leg.
    pub fn set_pending_reinvite(&self, call_id: &str, on_a_leg: bool, pending: bool) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            call.winner.and_then(|idx| call.b_legs.get_mut(idx))
        };
        match leg {
            Some(leg) => {
                let previous = leg.pending_reinvite;
                leg.pending_reinvite = pending;
                previous
            }
            None => false,
        }
    }

    /// Look up internal call ID by SIP Call-ID.
    pub fn find_by_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.registry.lookup_call_id(sip_call_id)
    }

    /// Look up internal call ID by Via branch.
    pub fn call_id_for_branch(&self, branch: &str) -> Option<String> {
        self.registry.lookup_branch(branch)
    }

    /// Record a siphon-originated REFER awaiting its response.
    pub fn register_originated_refer(&self, branch: &str, refer: OriginatedRefer) {
        self.registry.register_originated_refer(branch, refer);
    }

    /// Peek at the originated REFER a branch belongs to.
    pub fn lookup_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.registry.lookup_originated_refer(branch)
    }

    /// Take the originated REFER a branch belongs to, ending its transaction.
    pub fn take_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.registry.take_originated_refer(branch)
    }

    /// Drop any originated REFER still awaiting a response on this call.
    pub fn clear_originated_refers(&self, call_id: &str) {
        self.registry.clear_originated_refers(call_id);
    }

    /// Mark a call as one siphon *placed* (`originate`) and index its INVITE's
    /// Via branch so the response path routes to the UAC-side handler.
    pub fn mark_originated(&self, call_id: &str, branch: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.originated = true;
        }
        self.registry.register_originated_call(branch, call_id);
    }

    /// Whether this call was placed by siphon (`originate`).
    pub fn is_originated(&self, call_id: &str) -> bool {
        self.calls.get(call_id).is_some_and(|call| call.originated)
    }

    /// The internal call id of the originate whose INVITE carried `branch`.
    pub fn lookup_originated_call(&self, branch: &str) -> Option<String> {
        self.registry.lookup_originated_call(branch)
    }

    /// Record the media anchor an offerless originate must apply to the
    /// callee's 2xx offer.
    pub fn set_originate_anchor(&self, call_id: &str, anchor: OriginateAnchor) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.originate_anchor = Some(anchor);
        }
    }

    /// The media anchor plan of an originated call, if it went out offerless.
    pub fn originate_anchor(&self, call_id: &str) -> Option<OriginateAnchor> {
        self.calls
            .get(call_id)
            .and_then(|call| call.originate_anchor.clone())
    }

    /// Attach one half of a bridge to a call. Overwrites any previous half —
    /// the caller has already refused a leg that is `AlreadyBridged`.
    pub fn set_bridge(&self, call_id: &str, context: crate::b2bua::bridge::BridgeContext) -> bool {
        match self.calls.get_mut(call_id) {
            Some(mut call) => {
                call.bridge = Some(context);
                true
            }
            None => false,
        }
    }

    /// This call's half of a bridge, if it has one.
    pub fn bridge(&self, call_id: &str) -> Option<crate::b2bua::bridge::BridgeContext> {
        self.calls.get(call_id).and_then(|call| call.bridge.clone())
    }

    /// Advance this call's bridge to `stage`. Returns `false` when the call is
    /// gone or was never bridged, so a response arriving after teardown is a
    /// clean no-op rather than a resurrection.
    pub fn set_bridge_stage(
        &self,
        call_id: &str,
        stage: crate::b2bua::bridge::BridgeStage,
    ) -> bool {
        match self.calls.get_mut(call_id) {
            Some(mut call) => match call.bridge.as_mut() {
                Some(bridge) => {
                    bridge.stage = stage;
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// Detach and return this call's half of a bridge. Idempotent: `None` when
    /// the call is gone or was not bridged.
    pub fn take_bridge(&self, call_id: &str) -> Option<crate::b2bua::bridge::BridgeContext> {
        self.calls
            .get_mut(call_id)
            .and_then(|mut call| call.bridge.take())
    }

    /// Get a call by internal ID.
    pub fn get_call(
        &self,
        call_id: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, Box<CallActor>>> {
        self.calls.get(call_id)
    }

    /// Whether a call is still live, without taking a guard on it.
    ///
    /// Deliberately not `get_call(..).is_some()`: this is called from inside a
    /// `retain` closure on a *different* map, and returning a `Ref` there would
    /// hold a shard read guard on this map for the body of that closure.
    pub fn contains_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Get a mutable reference to a call.
    pub fn get_call_mut(
        &self,
        call_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, Box<CallActor>>> {
        self.calls.get_mut(call_id)
    }

    /// Set call state.
    ///
    /// Delegates to [`CallActor::transition_to`] so a transition to `Answered`
    /// stamps [`CallActor::answered_at`], the anchor
    /// [`take_calls_over_max_duration`](Self::take_calls_over_max_duration)
    /// measures a call's maximum duration from.
    pub fn set_state(&self, call_id: &str, state: CallState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transition_to(state);
        }
    }

    /// Set the winning B-leg.
    pub fn set_winner(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_winner(index);
        }
    }

    /// Atomically claim the answer for the B-leg at `index`.
    ///
    /// If the call is not yet `Answered`, sets the winner (which also flips the
    /// state to `Answered`) and returns [`WinOutcome::FirstWin`]. Otherwise the
    /// call was already answered — this 2xx is a retransmit of the winning
    /// B-leg's answer (or a losing fork branch) — and it returns
    /// [`WinOutcome::AlreadyAnswered`] with the winning B-leg's `initial_acked`.
    ///
    /// The check-and-set runs under the DashMap per-key lock, closing the race
    /// where two concurrent B-leg 200s both observe a stale "not answered"
    /// snapshot and both forward to the A-leg, delivering a duplicate 200 to a
    /// call the caller already ACKed.
    pub fn try_win(&self, call_id: &str, index: usize) -> WinOutcome {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return WinOutcome::AlreadyAnswered { b_leg_acked: false };
        };
        if call.state == CallState::Answered {
            let b_leg_acked = call
                .winner
                .and_then(|w| call.b_legs.get(w))
                .map(|leg| leg.initial_acked)
                .unwrap_or(false);
            WinOutcome::AlreadyAnswered { b_leg_acked }
        } else {
            call.set_winner(index);
            WinOutcome::FirstWin
        }
    }

    /// Atomically decide whether a 1xx provisional should be forwarded to the
    /// A-leg, moving the call `Calling -> Ringing` when it is.
    ///
    /// Returns `false` (drop the provisional) when the call is already
    /// `Answered`: a 1xx that arrives after the final response must not be
    /// forwarded, nor may it downgrade the confirmed dialog back to `Ringing`
    /// (RFC 3261 §12.1). Under multi-worker dispatch a B-leg's 180 and 200 —
    /// received in order but processed on different workers — can be handled
    /// concurrently; checking the call state under the per-call lock here (not
    /// a stale snapshot read ~1600 lines earlier) is what stops a late 180 from
    /// being forwarded behind its 200 and aborting the A-leg UAC.
    ///
    /// Returns `false` too when the call is gone (a provisional for a call that
    /// no longer exists is dropped).
    pub fn try_mark_ringing(&self, call_id: &str) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        if call.state == CallState::Answered {
            return false;
        }
        if call.state == CallState::Calling {
            call.transition_to(CallState::Ringing);
        }
        true
    }

    /// Begin a sequential route/failover sequence for a call.
    pub fn start_route_sequence(&self, call_id: &str, sequence: RouteSequenceState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.route_sequence = Some(sequence);
        }
    }

    /// Pop the next carrier for a call's failover queue (marks it active).
    pub fn take_next_route(&self, call_id: &str) -> Option<crate::lcr::Route> {
        self.calls.get_mut(call_id)?.take_next_route()
    }

    /// Record a failed attempt against a call's in-flight carrier, returning it
    /// so the caller can log it and dispatch `@b2bua.on_route_failure`.
    pub fn record_route_failure(&self, call_id: &str, status_code: u16) -> Option<RouteAttempt> {
        self.calls
            .get_mut(call_id)?
            .record_route_failure(status_code)
    }

    /// Record a carrier burned without ever being dialled — see
    /// [`CallActor::record_route_undialed`].
    pub fn record_route_undialed(&self, call_id: &str, status_code: u16) -> Option<RouteAttempt> {
        self.calls
            .get_mut(call_id)?
            .record_route_undialed(status_code)
    }

    /// Every failed attempt of a call's failover sequence, in order tried.
    pub fn route_attempts(&self, call_id: &str) -> Vec<RouteAttempt> {
        self.calls
            .get(call_id)
            .map(|call| call.route_attempts().to_vec())
            .unwrap_or_default()
    }

    /// Whether a call has more carriers to try in its failover queue.
    pub fn has_pending_routes(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.has_pending_routes())
    }

    /// Mark every not-yet-settled B-leg (Trying/Ringing) as Cancelled — used
    /// when a failover-advance CANCELs the in-flight carrier, so that carrier's
    /// stray `487 Request Terminated` is absorbed rather than mistaken for a
    /// fresh carrier failure (which would trigger another advance).
    pub fn mark_active_b_legs_cancelled(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            for status in call.b_leg_status.iter_mut() {
                if matches!(status, BLegStatus::Trying | BLegStatus::Ringing) {
                    *status = BLegStatus::Cancelled;
                }
            }
        }
    }

    /// Whether a call is running a sequential route/failover sequence.
    pub fn is_route_sequence(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.is_route_sequence())
    }

    /// The best (highest-priority) error across a call's exhausted attempts.
    pub fn best_route_error(&self, call_id: &str) -> Option<u16> {
        self.calls
            .get(call_id)
            .and_then(|call| call.best_route_error())
    }

    /// When the call was created — i.e. when its A-leg INVITE arrived.  Rf
    /// charging needs it to stamp `SIP-Request-Timestamp` on a record built at
    /// answer time (TS 32.299 §7.2.183).
    pub fn created_at(&self, call_id: &str) -> Option<std::time::Instant> {
        self.calls.get(call_id).map(|call| call.created_at)
    }

    /// The carrier route currently in flight / that won, cloned.
    pub fn active_route(&self, call_id: &str) -> Option<crate::lcr::Route> {
        self.calls
            .get(call_id)
            .and_then(|call| call.active_route().cloned())
    }

    /// The call-level send-socket pin for a call's sequential attempts, cloned.
    pub fn route_send_socket(&self, call_id: &str) -> Option<String> {
        self.calls
            .get(call_id)
            .and_then(|call| call.route_send_socket().map(String::from))
    }

    /// Store the original A-leg INVITE.
    pub fn set_a_leg_invite(&self, call_id: &str, message: Arc<Mutex<SipMessage>>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_a_leg_invite(message);
        }
    }

    /// Set session timer state.
    pub fn set_session_timer(&self, call_id: &str, timer: SessionTimerState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_session_timer(timer);
        }
    }

    /// Reset session timer.
    pub fn reset_session_timer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.reset_session_timer();
        }
    }

    /// Set transfer context.
    pub fn set_transfer(&self, call_id: &str, transfer: crate::b2bua::transfer::TransferContext) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = Some(transfer);
        }
    }

    /// Clear transfer context.
    pub fn clear_transfer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = None;
        }
    }

    /// Record a siphon-owned REFER subscription for a transfer in progress.
    pub fn push_refer_subscription(&self, call_id: &str, subscription: ReferSubscription) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.refer_subscriptions.push(subscription);
        }
    }

    /// True if the call carries a siphon-owned *subscriber* REFER subscription
    /// on the given leg (siphon-originated transfer: siphon sent the REFER and
    /// receives the referee's sipfrag NOTIFYs, rather than sending them).
    pub fn has_subscriber_refer_subscription(&self, call_id: &str, on_a_leg: bool) -> bool {
        self.calls
            .get(call_id)
            .map(|call| {
                call.refer_subscriptions.iter().any(|subscription| {
                    !subscription.siphon_notifies && subscription.on_a_leg == on_a_leg
                })
            })
            .unwrap_or(false)
    }

    /// Record that the referrer of an in-flight siphon-terminated transfer has
    /// ended its dialog (sent BYE) before the dialed target resolved, and report
    /// whether that was the case.
    ///
    /// `true` means the BYE closed the *referrer's* leg of a transfer that is
    /// still running, so the call must NOT be torn down: the surviving party is
    /// waiting to be bridged to the transfer target (RFC 5589 §7 — the
    /// transferor is free to leave as soon as the REFER is accepted). Every
    /// matching notifier subscription is flagged so the completion path skips
    /// the terminating NOTIFY and the referrer BYE it can no longer deliver
    /// (RFC 3515 §2.4.4 — the implicit subscription died with the dialog).
    ///
    /// `false` for every other BYE — a plain hangup, the surviving party's own
    /// BYE, a transparent-mode transfer (siphon owns no subscription there), or
    /// a transfer whose target already resolved — and those take the normal
    /// teardown path unchanged.
    ///
    /// Idempotent: a retransmitted BYE re-flags an already-flagged subscription
    /// and still reports `true`, so the retransmission is answered the same way
    /// rather than falling through to a teardown.
    pub fn mark_transfer_referrer_gone(&self, call_id: &str, on_a_leg: bool) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let mut matched = false;
        for subscription in call.refer_subscriptions.iter_mut() {
            if subscription.siphon_notifies
                && subscription.on_a_leg == on_a_leg
                && subscription.target_leg_call_id.is_some()
            {
                subscription.referrer_gone = true;
                matched = true;
            }
        }
        matched
    }

    /// True when the referrer of the in-flight siphon-terminated transfer on
    /// this leg has already left (see [`mark_transfer_referrer_gone`]).
    ///
    /// [`mark_transfer_referrer_gone`]: Self::mark_transfer_referrer_gone
    pub fn transfer_referrer_gone(&self, call_id: &str, on_a_leg: bool) -> bool {
        self.calls
            .get(call_id)
            .map(|call| {
                call.refer_subscriptions.iter().any(|subscription| {
                    subscription.siphon_notifies
                        && subscription.on_a_leg == on_a_leg
                        && subscription.referrer_gone
                })
            })
            .unwrap_or(false)
    }

    /// Drop any REFER subscriptions recorded on the given leg (e.g. on the
    /// terminating NOTIFY of a siphon-owned subscription).
    pub fn clear_refer_subscriptions_on_leg(&self, call_id: &str, on_a_leg: bool) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.refer_subscriptions
                .retain(|subscription| subscription.on_a_leg != on_a_leg);
        }
    }

    /// Reserve the next local CSeq for one leg of a call (increments the stored
    /// value and returns the number to use). Returns `None` if the call or the
    /// requested leg is not present. Used for siphon-originated in-dialog
    /// requests on a leg (REFER-subscription NOTIFYs, outbound REFER).
    pub fn reserve_leg_cseq(&self, call_id: &str, on_a_leg: bool) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let winner = call.winner;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            winner.and_then(|index| call.b_legs.get_mut(index))
        }?;
        let cseq = leg.dialog.local_cseq;
        leg.dialog.local_cseq += 1;
        Some(cseq)
    }

    /// Reserve siphon's owned SDP `o=` identity for the next SDP emitted toward
    /// one leg of a call: returns `(sdp_session_id, sdp_version)` and
    /// post-increments the stored version so the next emit is strictly greater
    /// (RFC 3264 §8). Returns `None` if the call or the requested leg is absent.
    /// The session-id is stable for the dialog's life; only the version advances.
    pub fn reserve_leg_sdp_version(&self, call_id: &str, on_a_leg: bool) -> Option<(u64, u64)> {
        let mut call = self.calls.get_mut(call_id)?;
        let winner = call.winner;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            winner.and_then(|index| call.b_legs.get_mut(index))
        }?;
        let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
        leg.dialog.sdp_version += 1;
        Some(identity)
    }

    /// Reserve the SDP `o=` identity for a specific B-leg by index (used for a
    /// freshly-dialed leg — e.g. a transfer target — that is not the winner).
    pub fn reserve_b_leg_sdp_version_by_index(
        &self,
        call_id: &str,
        index: usize,
    ) -> Option<(u64, u64)> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = call.b_legs.get_mut(index)?;
        let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
        leg.dialog.sdp_version += 1;
        Some(identity)
    }

    /// Record one leg's own most-recent endpoint SDP (raw). Stored so a
    /// siphon-terminated transfer can offer the surviving leg's real media to
    /// the transfer target. `on_a_leg` selects the A-leg or the winning B-leg;
    /// a no-op if the call or leg is absent, or if `sdp` is empty.
    pub fn set_leg_last_sdp(&self, call_id: &str, on_a_leg: bool, sdp: &[u8]) {
        if sdp.is_empty() {
            return;
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            let winner = call.winner;
            let leg = if on_a_leg {
                Some(&mut call.a_leg)
            } else {
                winner.and_then(|index| call.b_legs.get_mut(index))
            };
            if let Some(leg) = leg {
                leg.last_sdp = Some(sdp.to_vec());
            }
        }
    }

    /// Clone one leg of a call (the A-leg, or the winning B-leg). Used to build
    /// siphon-originated in-dialog requests off a snapshot without holding the
    /// call lock across the send.
    pub fn clone_leg(&self, call_id: &str, on_a_leg: bool) -> Option<Leg> {
        let call = self.calls.get(call_id)?;
        if on_a_leg {
            Some(call.a_leg.clone())
        } else {
            call.winner
                .and_then(|index| call.b_legs.get(index).cloned())
        }
    }

    /// Complete a siphon-terminated transfer: promote the just-answered transfer
    /// target (`target_idx` in `b_legs`) to be the surviving party's new peer,
    /// and return the referrer leg (the party being transferred away) so the
    /// caller can BYE it.
    ///
    /// - `referrer_on_a_leg == true` — the referrer is the A-leg and the
    ///   surviving party is the winning B-leg: the target replaces the A-leg (it
    ///   becomes the new `a_leg`, the winner is preserved, the old A-leg is
    ///   returned). This is the Microsoft Teams blind-transfer shape.
    /// - `referrer_on_a_leg == false` — the referrer is the winning B-leg and the
    ///   surviving party is the A-leg: the target becomes the new winner and the
    ///   old winning B-leg is returned.
    ///
    /// The parallel per-B-leg vectors are kept aligned when a slot is removed.
    pub fn promote_transfer_target(
        &self,
        call_id: &str,
        target_idx: usize,
        referrer_on_a_leg: bool,
    ) -> Option<Leg> {
        let mut call = self.calls.get_mut(call_id)?;
        if target_idx >= call.b_legs.len() {
            return None;
        }
        if referrer_on_a_leg {
            let target = call.b_legs.remove(target_idx);
            if target_idx < call.b_leg_status.len() {
                call.b_leg_status.remove(target_idx);
            }
            if target_idx < call.b_leg_handles.len() {
                call.b_leg_handles.remove(target_idx);
            }
            // Removing the slot shifts higher indices down by one — fix the
            // winner pointer (the surviving B-leg) accordingly.
            match call.winner {
                Some(winner) if winner == target_idx => call.winner = None,
                Some(winner) if winner > target_idx => call.winner = Some(winner - 1),
                _ => {}
            }
            let old_referrer = std::mem::replace(&mut call.a_leg, target);
            drop(call);
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        } else {
            let old_winner_idx = call.winner?;
            let old_referrer = call.b_legs.get(old_winner_idx).cloned()?;
            call.winner = Some(target_idx);
            drop(call);
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        }
    }

    /// Retire the dialog the transfer promoted away from.
    ///
    /// The referrer's leg leaves the call at promotion, so `remove_call` will
    /// never see it at teardown — it only walks the legs still attached. Without
    /// this its `Call-ID → call` registry entry outlives the call forever, and
    /// the next INVITE that reuses that Call-ID matches the dispatcher's
    /// "call already exists" guard and is silently absorbed as a retransmission:
    /// the caller gets no response at all, not even a 100. Retiring it here also
    /// makes a late in-dialog request on the retired dialog answer 481 rather
    /// than resolving to a call that has moved on (RFC 3261 §12.2.2), which is
    /// the same treatment every other torn-down leg gets.
    fn retire_promoted_referrer(&self, referrer: &Leg) {
        self.registry.remove_call_id(&referrer.dialog.call_id);
        self.registry.remove_branch(&referrer.branch);
        self.remember_terminated(&referrer.dialog.call_id);
    }

    /// Remove a call and clean up all registry entries.
    ///
    /// Sends `Shutdown` to all active B-leg actor handles before removing.
    /// B-leg entries with `reinvite_done:` or `reinvite:` target_uri are moved
    /// to `zombie_reinvites` so retransmitted 200 OKs can still be ACKed.
    ///
    /// Every leg's SIP Call-ID is remembered as terminated on the way out, so an
    /// in-dialog request that arrives after the teardown — the BYE glare where
    /// both parties hang up at once — is answered 481 rather than dropped. Both
    /// sides need it: on a B2BUA the A-leg and B-leg Call-IDs differ, and either
    /// peer can be the one whose BYE loses the race.
    pub fn remove_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            // Bill the call out on the way down. This is the one funnel every
            // ended call passes through — a normal BYE, an admin hangup, a
            // failure teardown — so counting here cannot miss a disposition the
            // way hooking the BYE path alone would.
            crate::metrics::record_call_cost(
                call.active_route(),
                call.answered_at.map(|at| at.elapsed().as_secs()),
            );
            // Shutdown any active B-leg actors
            call.shutdown_actors();
            // Any REFER siphon originated on this call is now moot — the call it
            // would transfer is gone. Cleared here rather than left to age out,
            // so an abandoned transfer does not leak an entry per call.
            self.registry.clear_originated_refers(call_id);
            // Likewise the originate branch index: one entry per placed call,
            // dropped with the call so it can never outlive it.
            self.registry.clear_originated_calls(call_id);
            // Clean up A-leg registry entries
            self.registry.remove_call_id(&call.a_leg.dialog.call_id);
            self.registry.remove_branch(&call.a_leg.branch);
            self.remember_terminated(&call.a_leg.dialog.call_id);
            // Clean up B-leg registry entries, preserving re-INVITE state
            for b_leg in &call.b_legs {
                self.registry.remove_call_id(&b_leg.dialog.call_id);
                self.registry.remove_branch(&b_leg.branch);
                self.remember_terminated(&b_leg.dialog.call_id);
                // Move re-INVITE tracking entries to zombie map
                if let Some(ref target) = b_leg.dialog.target_uri {
                    if target.starts_with("reinvite_done:") || target.starts_with("reinvite:") {
                        self.zombie_reinvites.insert(
                            b_leg.dialog.call_id.clone(),
                            ZombieReInviteEntry {
                                destination: b_leg.transport.remote_addr,
                                transport: b_leg.transport.transport,
                                local_addr: b_leg.transport.local_addr,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Look up a zombie re-INVITE entry by SIP Call-ID.
    pub fn get_zombie_reinvite(&self, sip_call_id: &str) -> Option<ZombieReInviteEntry> {
        self.zombie_reinvites.get(sip_call_id).map(|e| e.clone())
    }

    /// Remove a zombie re-INVITE entry.
    pub fn remove_zombie_reinvite(&self, sip_call_id: &str) {
        self.zombie_reinvites.remove(sip_call_id);
    }

    /// Tear down a CANCELled call, but first preserve every still-pending
    /// leg (INVITE sent, no final response yet — status `Trying`/`Ringing`) as
    /// a [`ZombieCancelledLeg`], so the final response the CANCEL provokes is
    /// still answerable after the call is gone: the ordinary `487` gets its ACK
    /// (RFC 3261 §17.1.1.3) and a 2xx that raced the CANCEL (§9.1) gets ACK
    /// (§13.2.2.4) + BYE (§15). Used by the CANCEL paths in place of
    /// `remove_call`.
    ///
    /// Returns true if any zombie-cancelled entries were captured (so the
    /// caller can schedule their expiry).
    pub fn remove_call_after_cancel(&self, call_id: &str) -> bool {
        let mut captured = false;
        if let Some(call) = self.calls.get(call_id) {
            // A call siphon placed (`originate`) carries its pending INVITE on
            // the A-leg, not a B-leg, so the loop below would capture nothing
            // and the final response to our CANCEL would be dropped — leaving
            // the callee retransmitting a 487 nobody ACKs (RFC 3261 §17.1.1.3),
            // or a 200 for a dialog nobody ACKs or BYEs (§9.1 glare, §13.2.2.4,
            // §15).
            if call.originated && matches!(call.state, CallState::Calling | CallState::Ringing) {
                if let Some(invite) = call.a_leg_invite.as_ref() {
                    self.zombie_cancelled.insert(
                        call.a_leg.dialog.call_id.clone(),
                        ZombieCancelledLeg {
                            leg: call.a_leg.clone(),
                            invite_ruri: request_uri_of(invite),
                            byed: false,
                        },
                    );
                    captured = true;
                }
            }
            for (index, b_leg) in call.b_legs.iter().enumerate() {
                let pending = matches!(
                    call.b_leg_status.get(index),
                    Some(BLegStatus::Trying) | Some(BLegStatus::Ringing)
                );
                // Only legs whose INVITE actually went on the wire can answer.
                if pending {
                    if let Some(invite) = b_leg.b_leg_invite.as_ref() {
                        self.zombie_cancelled.insert(
                            b_leg.dialog.call_id.clone(),
                            ZombieCancelledLeg {
                                leg: b_leg.clone(),
                                invite_ruri: request_uri_of(invite),
                                byed: false,
                            },
                        );
                        captured = true;
                    }
                }
            }
        }
        self.remove_call(call_id);
        captured
    }

    /// Resolve a racing 2xx to a CANCELled leg by SIP Call-ID.
    ///
    /// Returns the captured leg plus a `first_2xx` flag: the first racing 2xx
    /// for a Call-ID returns `(leg, true)` so the caller sends ACK + BYE; later
    /// 200 OK retransmits return `(leg, false)` so the caller re-ACKs only (a
    /// lost ACK still gets retried) without a second BYE. The entry stays until
    /// the 32 s cleanup so retransmits keep matching.
    pub fn zombie_cancelled_for_2xx(&self, sip_call_id: &str) -> Option<(Leg, bool)> {
        self.zombie_cancelled.get_mut(sip_call_id).map(|mut entry| {
            let first_2xx = !entry.byed;
            entry.byed = true;
            (entry.leg.clone(), first_2xx)
        })
    }

    /// Resolve a final non-2xx — in practice the `487 Request Terminated` that
    /// RFC 3261 §9.1 makes the ordinary outcome of a CANCEL — to a CANCELled
    /// leg by SIP Call-ID.
    ///
    /// Returns the captured leg and the CANCELled INVITE's Request-URI, so the
    /// caller can build the ACK §17.1.1.3 requires on the INVITE's own branch.
    ///
    /// Unlike [`Self::zombie_cancelled_for_2xx`] there is no first-response
    /// flag: the ACK for a final non-2xx belongs to the INVITE's client
    /// transaction, which §17.1.1.3 has re-pass it to the transport on *every*
    /// retransmission of the response while it sits in `Completed`. Answering
    /// only the first would leave a peer whose ACK was lost retransmitting to
    /// Timer H regardless — the exact stall this entry exists to end.
    pub fn zombie_cancelled_for_non2xx(&self, sip_call_id: &str) -> Option<(Leg, Option<String>)> {
        self.zombie_cancelled
            .get(sip_call_id)
            .map(|entry| (entry.leg.clone(), entry.invite_ruri.clone()))
    }

    /// Iterate over all active calls (for session timer sweep).
    pub fn iter_calls(&self) -> dashmap::iter::Iter<'_, String, Box<CallActor>> {
        self.calls.iter()
    }

    /// Find a call matching a Replaces header (for attended transfer).
    pub fn find_by_replaces(
        &self,
        replaces_call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<String> {
        for entry in self.calls.iter() {
            if crate::b2bua::transfer::replaces_matches(
                &crate::sip::headers::refer::Replaces {
                    call_id: replaces_call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.to_string(),
                    early_only: false,
                },
                &entry.a_leg.dialog.call_id,
                entry.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                from_tag,
            ) {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Sweep stale calls older than the given duration.
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let stale_ids: Vec<String> = self
            .calls
            .iter()
            .filter(|entry| now.duration_since(entry.created_at) > max_age)
            .map(|entry| entry.id.clone())
            .collect();
        let removed = stale_ids.len();
        for call_id in stale_ids {
            self.remove_call(&call_id);
        }
        removed
    }

    /// Set the answer deadline for a call (from `call.fork`/`dial` `timeout=`).
    pub fn set_answer_deadline(&self, call_id: &str, deadline: std::time::Instant) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.answer_deadline = Some(deadline);
        }
    }

    /// Mark a call parked under external control (`call.handover("app")`).
    /// Sets the control app + control-loss policy and flags the call as awaiting
    /// the controller's first action.
    pub fn set_control_owner(&self, call_id: &str, app: &str, on_control_loss: Option<&str>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.control_app = Some(app.to_string());
            call.on_control_loss = on_control_loss.map(String::from);
            call.handoff_pending = true;
        }
    }

    /// The control app owning a call, if any (cloned).
    pub fn control_app(&self, call_id: &str) -> Option<String> {
        self.calls
            .get(call_id)
            .and_then(|call| call.control_app.clone())
    }

    /// Record that the controlling app has acted on a parked call: clear the
    /// handoff deadline so the sweep no longer applies the default action, and
    /// clear the pending flag. Idempotent.
    pub fn mark_controller_acted(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if call.control_app.is_some() {
                call.handoff_pending = false;
                call.answer_deadline = None;
            }
        }
    }

    /// Release a parked call from external control: clear the control owner + the
    /// control-loss policy + the handoff-pending flag, so the call becomes an
    /// ordinary autonomous B2BUA call. Used when the controller hands control
    /// back to siphon with a routing decision (`route`): siphon dials the B-leg
    /// itself and owns the call thereafter. Clearing `control_app` is what
    /// disarms the handoff-timeout path in `fail_b2bua_call_on_timeout`
    /// (`is_handoff_pending` gates on `control_app.is_some()`), so a later B-leg
    /// ring-timeout takes the normal 408 path, not the parked-503 default.
    /// Idempotent.
    pub fn release_control_owner(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.control_app = None;
            call.on_control_loss = None;
            call.handoff_pending = false;
        }
    }

    /// Internal call IDs of calls that have blown their answer deadline while
    /// still un-answered (`Calling`/`Ringing`).
    ///
    /// Does NOT remove them — the dispatcher runs the full timeout teardown
    /// (CANCEL pending legs, `@b2bua.on_failure`, `408` to the A-leg) which
    /// needs the call state and the Python engine. Answered/terminated calls
    /// and calls without a deadline are skipped, so a long answered call (whose
    /// `created_at` is old but which is past `Answered`) is never touched.
    pub fn take_timed_out_calls(&self, now: std::time::Instant) -> Vec<String> {
        self.calls
            .iter()
            .filter(|entry| {
                matches!(entry.state, CallState::Calling | CallState::Ringing)
                    && entry
                        .answer_deadline
                        .is_some_and(|deadline| now >= deadline)
            })
            .map(|entry| entry.id.clone())
            .collect()
    }

    /// Internal call IDs of answered calls that have been up longer than their
    /// maximum duration (`call.dial(max_duration=…)`, else `default_secs` from
    /// `b2bua.max_call_duration_secs`).
    ///
    /// The counterpart of [`take_timed_out_calls`](Self::take_timed_out_calls)
    /// for the other half of a call's life: that one bounds the ring and only
    /// ever looks at `Calling`/`Ringing`, so nothing bounded an *answered* call
    /// except the optional RFC 4028 session timer.
    ///
    /// A per-call `Some(0)` is an explicit opt-out and wins over `default_secs`
    /// — that is how a script escapes a configured ceiling. Does NOT remove
    /// anything: the dispatcher runs the real teardown (BYE both legs, charging
    /// stop, CDR, media release), which needs to build and send messages.
    pub fn take_calls_over_max_duration(
        &self,
        now: std::time::Instant,
        default_secs: Option<u32>,
    ) -> Vec<String> {
        self.calls
            .iter()
            .filter(|entry| {
                if entry.state != CallState::Answered {
                    return false;
                }
                let Some(seconds) = entry.max_duration_secs.or(default_secs).filter(|s| *s > 0)
                else {
                    return false;
                };
                entry.answered_at.is_some_and(|answered_at| {
                    now.duration_since(answered_at)
                        >= std::time::Duration::from_secs(seconds as u64)
                })
            })
            .map(|entry| entry.id.clone())
            .collect()
    }

    /// Leg replacements whose dialed target has blown its deadline, as
    /// `(internal call id, target leg Call-ID)`.
    ///
    /// The counterpart of [`take_timed_out_calls`](Self::take_timed_out_calls)
    /// for the *answered* calls that one skips. A replacement dials a new leg
    /// on a call that is already `Answered`, so nothing in the answer-timeout
    /// path can see it: a target that never sends a final response would leave
    /// the subscription armed for the life of the call.
    ///
    /// Does NOT remove anything — the dispatcher runs the teardown (CANCEL the
    /// target leg, drop it, clear the subscription), which needs to build and
    /// send messages. Only notifier-role subscriptions that actually dialed a
    /// target and carry a deadline are eligible.
    pub fn take_timed_out_replacements(&self, now: std::time::Instant) -> Vec<(String, String)> {
        self.calls
            .iter()
            .flat_map(|entry| {
                entry
                    .refer_subscriptions
                    .iter()
                    .filter(|subscription| {
                        subscription.siphon_notifies
                            && subscription
                                .deadline
                                .is_some_and(|deadline| now >= deadline)
                    })
                    .filter_map(|subscription| {
                        subscription
                            .target_leg_call_id
                            .clone()
                            .map(|target| (entry.id.clone(), target))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
impl Default for CallActorStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process-wide call store handle (read-only observability)
/// The Request-URI of a stashed outbound request, as it went on the wire.
///
/// Read back for a leg being torn down, so an ACK built after the leg's INVITE
/// is gone still carries the Request-URI RFC 3261 §17.1.1.3 requires it to
/// share with the INVITE. Returns `None` on a poisoned mutex or a message that
/// is somehow not a request — the callers treat that as "cannot build an ACK",
/// which is the honest outcome; a placeholder R-URI on the wire is worse.
fn request_uri_of(stashed: &Arc<Mutex<SipMessage>>) -> Option<String> {
    let guard = match stashed.lock() {
        Ok(guard) => guard,
        Err(_) => {
            warn!("cancelled leg: stashed INVITE mutex poisoned, no Request-URI for its ACK");
            return None;
        }
    };
    match &guard.start_line {
        crate::sip::message::StartLine::Request(request_line) => {
            Some(request_line.request_uri.to_string())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
