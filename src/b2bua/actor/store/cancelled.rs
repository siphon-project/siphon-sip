//! The branches siphon gave up on before their final response: each is kept
//! answerable apart from its call, and CANCELled only once RFC 3261 §9.1
//! allows it.
//!
//! §9.1: "If no provisional response has been received, the CANCEL request
//! MUST NOT be sent; rather, the client MUST wait for the arrival of a
//! provisional response before sending the request." So giving up on an INVITE
//! is two things that may be apart in time. The decision is taken at once, and
//! everything that follows from it (events, records, media) with it. The CANCEL
//! goes out when the far end has shown, with any 1xx, that it holds the INVITE:
//! right away for a branch that already rang, and on its first provisional for
//! one that has said nothing. Until then the INVITE stays what it was, an
//! unanswered request retransmitted on Timer A.
//!
//! A branch waiting like that ends in one of four ways:
//!
//! * a provisional arrives: the CANCEL is sent, and the `487` it draws is ACKed;
//! * a 2xx arrives: it is ACKed and its dialog released with a BYE, and no
//!   CANCEL is sent (§9.1 has none for a request with a final response);
//! * any other final arrives: it is ACKed and nothing more is sent;
//! * nothing arrives: Timer B ends the INVITE's transaction and the branch.
//!
//! The record of all this is the [`ZombieCancelledLeg`], keyed by the INVITE's
//! Via branch, because by then the call it belonged to may be gone and the
//! branch is all a response still carries. Whether a provisional has arrived is
//! read off the branch registry ([`LegRegistry::provisional_received`]).

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;

use super::*;

/// How long a branch siphon gave up on stays answerable: 32 s, Timer H and
/// 64·T1 (RFC 3261 §17). The far end's INVITE server transaction has stopped
/// retransmitting its final response by then.
///
/// Counted from the moment siphon gave up, and again from the CANCEL when that
/// went out later, on the branch's first provisional: the `487` it draws is
/// owed its ACK for as long as the far end may retransmit it.
pub const CANCELLED_BRANCH_LIFETIME: Duration = Duration::from_secs(32);

/// Post-teardown state for a leg siphon gave up on while its INVITE was still
/// owed a final response.
///
/// Every outcome reaches this entry, and each would otherwise be dropped as
/// "unknown branch" — the paths that give up remove the call, unregistering the
/// leg's branch, as they do:
///
///  * a **provisional**, when the INVITE had drawn none yet: the CANCEL waited
///    for it (RFC 3261 §9.1) and is sent now.
///  * the **ordinary** final, a `487 Request Terminated` (§9.1): every
///    CANCELled INVITE draws a final non-2xx, and §17.1.1.3 makes ACKing it the
///    client transaction's job. Unacknowledged, the peer's INVITE server
///    transaction retransmits on Timer G until Timer H (64*T1 = 32 s, §17.2.1),
///    holding transaction state on both sides for the whole window.
///  * the **glare** one, a 2xx the callee put on the wire before a CANCEL
///    arrived, or instead of the provisional one waited for (§9.1). That 2xx
///    still establishes a dialog, which the B2BUA MUST ACK (§13.2.2.4) and then
///    BYE (§15) to release.
///
/// Keyed by the Via branch of the INVITE, which every response to it carries
/// (RFC 3261 §17.1.3). Not by the Call-ID: under `call.preserve_call_id()`
/// every branch of a fork shares one, and a key per Call-ID kept only the last
/// cancelled branch answerable. Expires [`CANCELLED_BRANCH_LIFETIME`] after it
/// was last given a reason to stay.
#[derive(Debug, Clone)]
pub struct ZombieCancelledLeg {
    /// The cancelled leg's dialog + transport, used to build the CANCEL, the ACK
    /// and the BYE. `remote_tag` / `remote_contact` are filled from the racing
    /// 2xx at handling time (they were unknown when siphon gave up).
    pub leg: Leg,
    /// Request-URI of the INVITE that was given up on, captured at teardown.
    ///
    /// RFC 3261 §17.1.1.3 requires the ACK for a final non-2xx to carry the
    /// same Request-URI as the INVITE it acknowledges, and by the time the
    /// `487` lands the call — and with it the stashed INVITE — is gone. `None`
    /// only when the INVITE could not be read back (poisoned mutex); no ACK is
    /// built in that case, because a `sip:invalid` R-URI on the wire is worse
    /// than none.
    pub invite_ruri: Option<String>,
    /// Whether the BYE has already been sent. The first racing 2xx triggers
    /// ACK + BYE; later 200 OK retransmits re-ACK only (so a lost ACK still
    /// gets retried) without emitting a second BYE.
    pub byed: bool,
    /// Whether the CANCEL this leg is owed has still to be sent, because its
    /// INVITE has drawn no response at all (RFC 3261 §9.1). Cleared by whatever
    /// comes first: the claim that sends the CANCEL, or the final response
    /// that makes it moot.
    pub awaiting_provisional: bool,
    /// Whether the INVITE had drawn a provisional by the time siphon gave up
    /// on it, as the branch registry had it then. Kept here because the
    /// registry's own record goes when the leg is taken off its call.
    pub provisional_received: bool,
    /// When this entry stops being kept.
    pub expires_at: Instant,
}

impl CallActorStore {
    /// Keep legs siphon is giving up on answerable from here on, as
    /// [`ZombieCancelledLeg`]s. Only a leg whose INVITE is stashed went on the
    /// wire, so only such a leg can answer and only it is kept.
    ///
    /// Each is entered as still owed its CANCEL. Whether that CANCEL may go at
    /// once is [`Self::claim_cancel`]'s to say, and the caller asks it for every
    /// leg it kept; a leg nobody asks about is CANCELled on its first
    /// provisional like any other.
    ///
    /// Returns whether any leg was kept, so the caller can schedule the expiry.
    pub fn keep_answerable<'a>(&self, legs: impl IntoIterator<Item = &'a Leg>) -> bool {
        let mut kept = false;
        for leg in legs {
            if let Some(invite) = leg.b_leg_invite.as_ref() {
                self.keep_leg(leg.clone(), invite);
                kept = true;
            }
        }
        kept
    }

    /// Enter `leg`, whose stashed INVITE is `invite`, among the kept branches.
    ///
    /// One already kept stays as it is: a call's teardown comes across the legs
    /// its CANCEL path kept a moment earlier, and what has happened to one
    /// since (its CANCEL sent, its 2xx released) must not be forgotten.
    fn keep_leg(&self, leg: Leg, invite: &Arc<Mutex<SipMessage>>) {
        let branch = leg.branch.clone();
        match self.zombie_cancelled.entry(branch.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => return,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(ZombieCancelledLeg {
                    invite_ruri: request_uri_of(invite),
                    leg,
                    byed: false,
                    awaiting_provisional: true,
                    provisional_received: false,
                    expires_at: Instant::now() + CANCELLED_BRANCH_LIFETIME,
                });
            }
        }
        // After the insert: a response that reads this count as non-zero must
        // find the entry (see `provisional_received`).
        self.deferred_cancels.fetch_add(1, Ordering::SeqCst);
        // Read now, while the leg is still on its call and its branch still
        // registered. The caller may take the leg off the call before it asks
        // whether to CANCEL, and a branch that rang must not read as silent
        // then: a far end that has sent its provisional may never send another,
        // and the CANCEL waiting for one would never go.
        if self.registry.provisional_received(&branch) {
            if let Some(mut entry) = self.zombie_cancelled.get_mut(&branch) {
                entry.provisional_received = true;
            }
        }
    }

    /// Keep every leg of `call_id` still waiting for its final response
    /// answerable, and return them for the caller to CANCEL: the B-legs whose
    /// INVITE is on the wire (status `Trying` / `Ringing`), and the leg of a
    /// call siphon placed itself (`originate`), which carries its pending
    /// INVITE on the A-leg.
    ///
    /// The originated leg comes back with that INVITE as its `b_leg_invite`,
    /// as a B-leg has it: the CANCEL is built from it, and a 2xx that carries
    /// the offer, because the INVITE went out without one, is owed an answer
    /// in its ACK (RFC 3261 §13.2.2.4), which is decided from it.
    pub fn keep_pending_answerable(&self, call_id: &str) -> Vec<Leg> {
        let Some(call) = self.calls.get(call_id) else {
            return Vec::new();
        };
        let mut pending = Vec::new();
        if call.originated && matches!(call.state, CallState::Calling | CallState::Ringing) {
            if let Some(invite) = call.a_leg_invite.as_ref() {
                let mut leg = call.a_leg.clone();
                leg.b_leg_invite = Some(Arc::clone(invite));
                pending.push(leg);
            }
        }
        pending.extend(
            call.b_legs
                .iter()
                .enumerate()
                .filter(|(index, leg)| {
                    leg.b_leg_invite.is_some()
                        && matches!(
                            call.b_leg_status.get(*index),
                            Some(BLegStatus::Trying) | Some(BLegStatus::Ringing)
                        )
                })
                .map(|(_, leg)| leg.clone()),
        );
        self.keep_answerable(&pending);
        pending
    }

    /// Whether `branch` is a leg siphon gave up on and is keeping answerable.
    pub fn is_cancelled_branch(&self, branch: &str) -> bool {
        self.zombie_cancelled.contains_key(branch)
    }

    /// Whether the CANCEL the kept leg on `branch` is owed may be sent now, and
    /// if so take it: `true` is returned once per branch, to the caller that
    /// then sends it.
    ///
    /// It may when a provisional has arrived on the branch (RFC 3261 §9.1).
    /// `false` otherwise, and the INVITE is left retransmitting: the CANCEL
    /// follows its first provisional ([`Self::provisional_received`]). `false`
    /// too for a branch whose CANCEL was already taken, or whose final response
    /// has arrived and left nothing to cancel.
    pub fn claim_cancel(&self, branch: &str) -> bool {
        let Some(mut entry) = self.zombie_cancelled.get_mut(branch) else {
            return false;
        };
        if !entry.awaiting_provisional {
            return false;
        }
        if !entry.provisional_received && !self.registry.provisional_received(branch) {
            return false;
        }
        entry.awaiting_provisional = false;
        self.deferred_cancels.fetch_sub(1, Ordering::SeqCst);
        true
    }

    /// A provisional response arrived on `branch`: record it, and hand back the
    /// kept leg whose CANCEL was waiting for it, for the caller to send.
    ///
    /// On the response path for every provisional to an INVITE. For a branch
    /// with no CANCEL waiting, which is nearly all of them, it is the registry's
    /// two map reads and one atomic load; nothing is allocated and no call is
    /// locked.
    ///
    /// The order matters, against [`Self::keep_answerable`] followed by
    /// [`Self::claim_cancel`] on another worker: this records the provisional
    /// and then reads the count, they raise the count and then read the record.
    /// Whichever comes second sees the other, so the CANCEL is sent by exactly
    /// one of the two, the entry's own lock deciding when both get that far.
    pub fn provisional_received(&self, branch: &str) -> Option<Leg> {
        self.registry.note_provisional(branch);
        if self.deferred_cancels.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut entry = self.zombie_cancelled.get_mut(branch)?;
        if !entry.awaiting_provisional {
            return None;
        }
        entry.awaiting_provisional = false;
        self.deferred_cancels.fetch_sub(1, Ordering::SeqCst);
        // The 487 this CANCEL draws is owed its ACK for a transaction's length
        // from now, not from when siphon gave up.
        entry.expires_at = Instant::now() + CANCELLED_BRANCH_LIFETIME;
        Some(entry.leg.clone())
    }

    /// Resolve a 2xx to a kept leg by the Via branch it answers.
    ///
    /// Returns the captured leg plus a `first_2xx` flag: the first 2xx on a
    /// branch returns `(leg, true)` so the caller sends ACK + BYE; later 200 OK
    /// retransmits return `(leg, false)` so the caller re-ACKs only (a lost ACK
    /// still gets retried) without a second BYE. The entry stays until its
    /// expiry so retransmits keep matching.
    ///
    /// A CANCEL the leg was still owed is owed no longer: the INVITE has its
    /// final response (RFC 3261 §9.1).
    pub fn zombie_cancelled_for_2xx(&self, branch: &str) -> Option<(Leg, bool)> {
        self.zombie_cancelled.get_mut(branch).map(|mut entry| {
            self.settle_owed_cancel(&mut entry);
            let first_2xx = !entry.byed;
            entry.byed = true;
            (entry.leg.clone(), first_2xx)
        })
    }

    /// Resolve a final non-2xx — in practice the `487 Request Terminated` that
    /// RFC 3261 §9.1 makes the ordinary outcome of a CANCEL — to a kept leg by
    /// the Via branch it answers.
    ///
    /// Returns the captured leg and the INVITE's Request-URI, so the caller can
    /// build the ACK §17.1.1.3 requires on the INVITE's own branch.
    ///
    /// Unlike [`Self::zombie_cancelled_for_2xx`] there is no first-response
    /// flag: the ACK for a final non-2xx belongs to the INVITE's client
    /// transaction, which §17.1.1.3 has re-pass it to the transport on *every*
    /// retransmission of the response while it sits in `Completed`. Answering
    /// only the first would leave a peer whose ACK was lost retransmitting to
    /// Timer H regardless — the exact stall this entry exists to end.
    ///
    /// A CANCEL the leg was still owed is owed no longer, as for a 2xx.
    pub fn zombie_cancelled_for_non2xx(&self, branch: &str) -> Option<(Leg, Option<String>)> {
        self.zombie_cancelled.get_mut(branch).map(|mut entry| {
            self.settle_owed_cancel(&mut entry);
            (entry.leg.clone(), entry.invite_ruri.clone())
        })
    }

    /// The INVITE on `entry` has its final response: no CANCEL is owed it.
    fn settle_owed_cancel(&self, entry: &mut ZombieCancelledLeg) {
        if entry.awaiting_provisional {
            entry.awaiting_provisional = false;
            self.deferred_cancels.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Timer B fired for the INVITE on `branch` (RFC 3261 §17.1.1.2): no
    /// response came in 64·T1 and its client transaction is over. A kept leg
    /// still waiting for a provisional to send its CANCEL on is released with
    /// it, and no CANCEL is ever sent.
    pub fn invite_transaction_timed_out(&self, branch: &str) {
        if self.deferred_cancels.load(Ordering::SeqCst) == 0 {
            return;
        }
        if self
            .zombie_cancelled
            .remove_if(branch, |_, entry| entry.awaiting_provisional)
            .is_some()
        {
            self.deferred_cancels.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Stop keeping the leg on `branch` if its time is up at `now`. One given a
    /// later expiry since this was scheduled, by a CANCEL that waited for its
    /// provisional, stays for the expiry scheduled then.
    pub fn expire_cancelled_branch(&self, branch: &str, now: Instant) {
        if let Some((_, entry)) = self
            .zombie_cancelled
            .remove_if(branch, |_, entry| now >= entry.expires_at)
        {
            if entry.awaiting_provisional {
                self.deferred_cancels.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// Number of legs kept answerable (leak-test accessor): back to its
    /// baseline once every branch given up on has expired.
    #[cfg(test)]
    pub fn cancelled_branch_count(&self) -> usize {
        self.zombie_cancelled.len()
    }

    /// Number of kept legs still owed their CANCEL (leak-test accessor): back
    /// to zero as soon as each has had a response or timed out.
    #[cfg(test)]
    pub fn deferred_cancel_count(&self) -> usize {
        self.deferred_cancels.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ConnectionId, Transport};

    const BRANCH: &str = "z9hG4bK-waiting";

    /// A store holding one call with a B-leg on [`BRANCH`] whose INVITE is on
    /// the wire, and that leg.
    fn store_with_leg() -> (CallActorStore, String, Leg) {
        let transport = TransportInfo {
            remote_addr: "192.0.2.20:5060".parse().expect("an address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        };
        let store = CallActorStore::new();
        let call_id = store.create_call(Leg::new_a_leg(
            "caller@example.com".to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-caller".to_string(),
            transport.clone(),
        ));
        let mut leg = Leg::new_b_leg(
            "callee@example.com".to_string(),
            "siphon-tag".to_string(),
            "sip:callee@192.0.2.20".to_string(),
            BRANCH.to_string(),
            transport,
        );
        let invite = crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "INVITE sip:callee@192.0.2.20 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-waiting\r\n",
                "From: <sip:caller@example.com>;tag=siphon-tag\r\n",
                "To: <sip:callee@example.com>\r\n",
                "Call-ID: callee@example.com\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n\r\n",
            )
            .as_bytes(),
        )
        .expect("the INVITE parses");
        leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
        assert!(store.add_b_leg(&call_id, leg.clone()));
        (store, call_id, leg)
    }

    fn after_lifetime() -> Instant {
        Instant::now() + CANCELLED_BRANCH_LIFETIME
    }

    #[test]
    fn a_branch_with_no_provisional_is_not_cancelled_until_one_arrives() {
        let (store, _, leg) = store_with_leg();
        assert!(store.keep_answerable(std::iter::once(&leg)));
        assert!(!store.claim_cancel(BRANCH), "RFC 3261 §9.1: wait");
        assert_eq!(store.deferred_cancel_count(), 1);

        let owed = store.provisional_received(BRANCH);
        assert_eq!(owed.map(|leg| leg.branch), Some(BRANCH.to_string()));
        assert_eq!(store.deferred_cancel_count(), 0);
        // Once: neither a second provisional nor a late claim sends another.
        assert!(store.provisional_received(BRANCH).is_none());
        assert!(!store.claim_cancel(BRANCH));

        assert_eq!(store.cancelled_branch_count(), 1, "kept for its 487");
        store.expire_cancelled_branch(BRANCH, after_lifetime());
        assert_eq!(store.cancelled_branch_count(), 0);
    }

    #[test]
    fn a_branch_that_already_had_a_provisional_is_cancelled_at_once() {
        let (store, _, leg) = store_with_leg();
        assert!(store.provisional_received(BRANCH).is_none());
        store.keep_answerable(std::iter::once(&leg));
        assert!(store.claim_cancel(BRANCH));
        assert_eq!(store.deferred_cancel_count(), 0);
        assert!(!store.claim_cancel(BRANCH), "claimed once");
        assert!(
            store.provisional_received(BRANCH).is_none(),
            "a later provisional sends no second CANCEL"
        );
    }

    #[test]
    fn a_branch_that_rang_is_cancelled_at_once_even_once_its_leg_is_off_the_call() {
        let (store, call_id, leg) = store_with_leg();
        assert!(store.provisional_received(BRANCH).is_none());
        store.keep_answerable(std::iter::once(&leg));
        // The call goes, and the branch registry's record of the provisional
        // with it, before anyone asks whether the CANCEL may be sent.
        store.remove_call(&call_id);
        assert!(
            store.claim_cancel(BRANCH),
            "what the branch had drawn was read when it was kept"
        );
    }

    #[test]
    fn a_final_response_ends_the_wait_and_no_cancel_follows() {
        for success in [true, false] {
            let (store, _, leg) = store_with_leg();
            store.keep_answerable(std::iter::once(&leg));
            if success {
                assert!(matches!(
                    store.zombie_cancelled_for_2xx(BRANCH),
                    Some((_, true))
                ));
            } else {
                assert!(store.zombie_cancelled_for_non2xx(BRANCH).is_some());
            }
            assert_eq!(store.deferred_cancel_count(), 0);
            assert!(store.provisional_received(BRANCH).is_none());
            assert!(!store.claim_cancel(BRANCH));
            store.expire_cancelled_branch(BRANCH, after_lifetime());
            assert_eq!(store.cancelled_branch_count(), 0);
        }
    }

    #[test]
    fn timer_b_releases_a_branch_still_waiting_and_only_such_a_branch() {
        let (store, _, leg) = store_with_leg();
        store.keep_answerable(std::iter::once(&leg));
        store.invite_transaction_timed_out(BRANCH);
        assert_eq!(store.cancelled_branch_count(), 0);
        assert_eq!(store.deferred_cancel_count(), 0);
        assert!(store.provisional_received(BRANCH).is_none());

        // A branch whose CANCEL went out is still owed the ACK of its 487.
        let (store, _, leg) = store_with_leg();
        store.provisional_received(BRANCH);
        store.keep_answerable(std::iter::once(&leg));
        assert!(store.claim_cancel(BRANCH));
        store.invite_transaction_timed_out(BRANCH);
        assert_eq!(store.cancelled_branch_count(), 1);
    }

    #[test]
    fn an_expiry_scheduled_before_a_late_cancel_does_not_end_the_branch_early() {
        let (store, _, leg) = store_with_leg();
        store.keep_answerable(std::iter::once(&leg));
        let first_expiry = after_lifetime();
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.provisional_received(BRANCH).is_some());
        store.expire_cancelled_branch(BRANCH, first_expiry);
        assert_eq!(
            store.cancelled_branch_count(),
            1,
            "still kept for the 487 the late CANCEL draws"
        );
        store.expire_cancelled_branch(BRANCH, after_lifetime());
        assert_eq!(store.cancelled_branch_count(), 0);
    }

    #[test]
    fn a_branch_kept_twice_keeps_what_happened_to_it_in_between() {
        let (store, call_id, _) = store_with_leg();
        assert_eq!(store.keep_pending_answerable(&call_id).len(), 1);
        assert!(store.provisional_received(BRANCH).is_some());
        // The teardown that follows comes across the same leg again.
        assert!(store.remove_call_after_cancel(&call_id));
        assert_eq!(store.deferred_cancel_count(), 0);
        assert!(!store.claim_cancel(BRANCH), "its CANCEL already went");
    }

    #[test]
    fn a_branch_that_is_not_registered_has_had_no_provisional() {
        let (store, call_id, leg) = store_with_leg();
        store.remove_call(&call_id);
        store.keep_answerable(std::iter::once(&leg));
        assert!(!store.claim_cancel(BRANCH));
        assert!(store.provisional_received(BRANCH).is_some());
    }
}
