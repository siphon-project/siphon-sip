//! The store side of a leg replacement's targets: which one answered first,
//! when the replacement has failed, and what is left to end either way.
//!
//! Every decision here is taken under the call's shard lock and returned whole,
//! because the responses that drive it arrive on different workers. Two targets
//! answering at once must come out as one winner and one dialog to release, and
//! two failing at once as one failure: a check here and an act in the caller
//! would let both through.
//!
//! A target siphon gives up on is kept answerable, as a cancelled fork branch
//! is ([`CallActorStore::keep_answerable`]), so the `487` its CANCEL draws is
//! ACKed and a 2xx that crossed the CANCEL is ACKed and released with a BYE.

use super::*;
use crate::b2bua::transfer::{transfer_result_from_response, TransferState};

/// Mark every target of `subscription` still ringing, bar `keep`, cancelled.
/// Returns the ones whose INVITE is on the wire; one whose INVITE is not
/// stashed yet is flagged for the send path to CANCEL when it is (RFC 3261
/// §9.1 builds a CANCEL from its INVITE).
fn cancel_pending_targets(
    subscription: &mut ReferSubscription,
    b_legs: &mut [Leg],
    b_leg_status: &mut [BLegStatus],
    keep: Option<&str>,
) -> Vec<Leg> {
    let mut cancelled = Vec::new();
    for target in subscription.targets.iter_mut() {
        if target.outcome != ReplacementOutcome::Pending || Some(target.branch.as_str()) == keep {
            continue;
        }
        target.outcome = ReplacementOutcome::Cancelled;
        let Some(index) = b_legs.iter().position(|leg| leg.branch == target.branch) else {
            continue;
        };
        if let Some(status) = b_leg_status.get_mut(index) {
            *status = BLegStatus::Cancelled;
        }
        let leg = &mut b_legs[index];
        if leg.b_leg_invite.is_some() {
            cancelled.push(leg.clone());
        } else {
            leg.pending_cancel = true;
        }
    }
    cancelled
}

/// Take the engine calls still held for the targets of `subscription`, bar the
/// one on `keep`.
fn take_target_media(
    subscription: &mut ReferSubscription,
    keep: Option<&str>,
) -> Vec<ReplacementMedia> {
    subscription
        .targets
        .iter_mut()
        .filter(|target| Some(target.branch.as_str()) != keep)
        .filter_map(|target| target.media.take())
        .collect()
}

/// End `subscription` as failed on `status_code`: cancel what still rings and
/// hand back everything the caller has to send and release.
fn fail_replacement(
    subscription: &mut ReferSubscription,
    b_legs: &mut [Leg],
    b_leg_status: &mut [BLegStatus],
    status_code: u16,
) -> FailedReplacement {
    subscription.state = transfer_result_from_response(status_code);
    subscription.deadline = None;
    FailedReplacement {
        replaced_on_a_leg: subscription.on_a_leg,
        referrer_gone: subscription.referrer_gone,
        origin: subscription.origin,
        event_id: subscription.event_id,
        status_code,
        branches: subscription
            .targets
            .iter()
            .map(|target| target.branch.clone())
            .collect(),
        cancelled: cancel_pending_targets(subscription, b_legs, b_leg_status, None),
        released_media: take_target_media(subscription, None),
    }
}

impl CallActorStore {
    /// Whether the replacement of the leg on this side is still waiting on its
    /// targets, and so may still be given another to ring.
    pub fn replacement_is_open(&self, call_id: &str, replaced_on_a_leg: bool) -> bool {
        self.calls.get(call_id).is_some_and(|call| {
            call.refer_subscriptions.iter().any(|subscription| {
                subscription.siphon_notifies
                    && subscription.on_a_leg == replaced_on_a_leg
                    && subscription.state == TransferState::Trying
            })
        })
    }

    /// Record a target a replacement just dialled, and arm its deadline.
    ///
    /// Each is entered as its own INVITE goes out, not once all of them have:
    /// a target can answer while its siblings are still being sent.
    ///
    /// Which is also why this can come too late. A sibling that answered, or
    /// the call ending, may have settled the replacement between this target's
    /// INVITE leaving and its being entered, and then nothing is left that
    /// would ever CANCEL it. That target is cancelled here instead, kept
    /// answerable, and handed back for the caller to send the CANCEL and
    /// release its engine call. `None` when it was entered.
    pub fn add_replacement_target(
        &self,
        call_id: &str,
        replaced_on_a_leg: bool,
        mut target: ReplacementTarget,
        deadline: std::time::Instant,
    ) -> Option<AbandonedReplacements> {
        let Some(mut guard) = self.calls.get_mut(call_id) else {
            // The call is gone, and its legs with it: only the engine call
            // opened for this target is left to give back.
            return Some(AbandonedReplacements {
                released_media: target.media.take().into_iter().collect(),
                ..AbandonedReplacements::default()
            });
        };
        let call: &mut CallActor = &mut guard;
        // The newest one: the replacement that just dialled this target.
        let open = call
            .refer_subscriptions
            .iter_mut()
            .rev()
            .find(|subscription| {
                subscription.siphon_notifies
                    && subscription.on_a_leg == replaced_on_a_leg
                    && subscription.state == TransferState::Trying
            });
        if let Some(subscription) = open {
            subscription.targets.push(target);
            subscription.deadline = Some(deadline);
            return None;
        }
        let mut late = AbandonedReplacements {
            released_media: target.media.take().into_iter().collect(),
            ..AbandonedReplacements::default()
        };
        if let Some(index) = call
            .b_legs
            .iter()
            .position(|leg| leg.branch == target.branch)
        {
            if let Some(status) = call.b_leg_status.get_mut(index) {
                *status = BLegStatus::Cancelled;
            }
            let leg = &mut call.b_legs[index];
            if leg.b_leg_invite.is_some() {
                late.cancelled.push(leg.clone());
            } else {
                leg.pending_cancel = true;
            }
        }
        self.keep_answerable(&late.cancelled);
        Some(late)
    }

    /// The replacement of the leg on this side sent no INVITE at all: every
    /// target failed before anything reached the transport. End it as failed
    /// on `status_code`, so it is concluded like one whose targets all refused
    /// and does not stay on the call holding off the next.
    ///
    /// `None` when there is no such replacement: one that entered a target is
    /// that target's to settle, and one the call's teardown already ended is
    /// over.
    pub fn fail_undialled_replacement(
        &self,
        call_id: &str,
        replaced_on_a_leg: bool,
        status_code: u16,
    ) -> Option<FailedReplacement> {
        let mut guard = self.calls.get_mut(call_id)?;
        let call: &mut CallActor = &mut guard;
        let subscription = call
            .refer_subscriptions
            .iter_mut()
            .rev()
            .find(|subscription| {
                subscription.siphon_notifies
                    && subscription.on_a_leg == replaced_on_a_leg
                    && subscription.state == TransferState::Trying
                    && subscription.targets.is_empty()
            })?;
        Some(fail_replacement(
            subscription,
            &mut call.b_legs,
            &mut call.b_leg_status,
            status_code,
        ))
    }

    /// Where the leg whose INVITE rode Via `branch` sits among the call's
    /// B-legs right now. A position is only good until the next leg is taken
    /// off the call, so one read earlier is re-read through this before use.
    pub fn b_leg_index(&self, call_id: &str, branch: &str) -> Option<usize> {
        self.calls
            .get(call_id)?
            .b_legs
            .iter()
            .position(|leg| leg.branch == branch)
    }

    /// What the leg whose INVITE rode Via `branch` is to the replacements on
    /// the call.
    ///
    /// A response is checked against the cancelled branches when it arrives,
    /// and against this a little later. In between, on another worker, a
    /// sibling target may have answered, been brought in, and had its
    /// replacement cleared: the response in hand then belongs to no replacement
    /// any more, and handled as an ordinary answer its dialog would be
    /// confirmed and never released. The claim marks the losers cancelled and
    /// keeps them answerable before anything is cleared, so that is what is
    /// looked for once the replacement itself is gone.
    pub fn replacement_branch(&self, call_id: &str, branch: &str) -> ReplacementBranch {
        let Some(call) = self.calls.get(call_id) else {
            return ReplacementBranch::Other;
        };
        if call.refer_subscriptions.iter().any(|subscription| {
            subscription.siphon_notifies && subscription.target(branch).is_some()
        }) {
            return ReplacementBranch::Target;
        }
        // Still on the call and cancelled, or already taken off it: a
        // replacement that fails removes its targets' legs, and one of those
        // may have a response on its way in too. Any other leg is a live one,
        // and is not looked up among the cancelled branches at all.
        let status = call
            .b_legs
            .iter()
            .zip(call.b_leg_status.iter())
            .find(|(leg, _)| leg.branch == branch)
            .map(|(_, status)| status);
        let given_up = matches!(status, None | Some(BLegStatus::Cancelled));
        if given_up && self.zombie_cancelled.contains_key(branch) {
            ReplacementBranch::Settled
        } else {
            ReplacementBranch::Other
        }
    }

    /// The target on Via `branch` answered with a 2xx: make it the party its
    /// replacement brings in, unless another already is.
    ///
    /// The one place a replacement is won. Under the call's lock it checks the
    /// replacement is still open, gives it to this branch, marks every other
    /// target still ringing cancelled and keeps those answerable. Two 2xx
    /// handled at the same moment therefore come out as one
    /// [`ReplacementClaim::Won`] and one [`ReplacementClaim::Lost`], and the
    /// loser's dialog is released instead of being promoted over the winner's.
    pub fn claim_replacement(&self, call_id: &str, branch: &str) -> ReplacementClaim {
        let Some(mut guard) = self.calls.get_mut(call_id) else {
            return ReplacementClaim::NotATarget;
        };
        let call: &mut CallActor = &mut guard;
        let Some(subscription) = call.refer_subscriptions.iter_mut().find(|subscription| {
            subscription.siphon_notifies && subscription.target(branch).is_some()
        }) else {
            return ReplacementClaim::NotATarget;
        };
        let outcome = subscription
            .target(branch)
            .map(|target| target.outcome)
            .unwrap_or(ReplacementOutcome::Cancelled);
        if outcome == ReplacementOutcome::Answered {
            return ReplacementClaim::Duplicate;
        }
        if outcome != ReplacementOutcome::Pending || subscription.state != TransferState::Trying {
            return ReplacementClaim::Lost;
        }
        let Some(target_leg) = call.b_legs.iter().find(|leg| leg.branch == branch).cloned() else {
            return ReplacementClaim::Lost;
        };
        subscription.state = TransferState::Succeeded;
        subscription.deadline = None;
        let mut won = None;
        for target in subscription.targets.iter_mut() {
            if target.branch == branch {
                target.outcome = ReplacementOutcome::Answered;
                won = Some(target.clone());
            }
        }
        let Some(target) = won else {
            return ReplacementClaim::Lost;
        };
        let cancelled = cancel_pending_targets(
            subscription,
            &mut call.b_legs,
            &mut call.b_leg_status,
            Some(branch),
        );
        let win = ReplacementWin {
            replaced_on_a_leg: subscription.on_a_leg,
            referrer_gone: subscription.referrer_gone,
            origin: subscription.origin,
            event_id: subscription.event_id,
            media_profile: subscription.media_profile.clone(),
            target,
            target_leg,
            released_media: take_target_media(subscription, Some(branch)),
            cancelled,
        };
        self.keep_answerable(&win.cancelled);
        ReplacementClaim::Won(Box::new(win))
    }

    /// The target on Via `branch` answered with a final non-2xx.
    ///
    /// Records it, and fails the replacement only when no target is left that
    /// could still answer (RFC 3261 §16.7): one phone busy while another rings
    /// is not the transfer failing. `None` when the branch is no target still
    /// waiting for its response (a retransmission, or one already cancelled),
    /// which is owed its ACK and nothing else.
    pub fn record_replacement_failure(
        &self,
        call_id: &str,
        branch: &str,
        status_code: u16,
    ) -> Option<ReplacementTargetFailure> {
        let mut guard = self.calls.get_mut(call_id)?;
        let call: &mut CallActor = &mut guard;
        let subscription = call.refer_subscriptions.iter_mut().find(|subscription| {
            subscription.siphon_notifies && subscription.target(branch).is_some()
        })?;
        let target = subscription
            .targets
            .iter_mut()
            .find(|target| target.branch == branch)?;
        if target.outcome != ReplacementOutcome::Pending {
            return None;
        }
        target.outcome = ReplacementOutcome::Failed(status_code);
        let released_media = target.media.take();
        if let Some(index) = call.b_legs.iter().position(|leg| leg.branch == branch) {
            if let Some(status) = call.b_leg_status.get_mut(index) {
                *status = BLegStatus::Failed(status_code);
            }
        }
        let ringing = subscription
            .targets
            .iter()
            .any(|target| target.outcome == ReplacementOutcome::Pending);
        let settled = (!ringing && subscription.state == TransferState::Trying).then(|| {
            let best = subscription.best_failure(None).unwrap_or(status_code);
            fail_replacement(subscription, &mut call.b_legs, &mut call.b_leg_status, best)
        });
        if let Some(failed) = &settled {
            self.keep_answerable(&failed.cancelled);
        }
        Some(ReplacementTargetFailure {
            released_media,
            settled,
        })
    }

    /// Give up on the call's replacement once its deadline has passed: every
    /// target still ringing is cancelled and kept answerable, and the
    /// replacement fails on the best response a target gave, one that never
    /// answered counting as a 408 (RFC 3261 §16.8).
    ///
    /// `None` when there is nothing to give up on: no replacement past its
    /// deadline, or one a target's own answer or failure settled first.
    pub fn expire_replacement(
        &self,
        call_id: &str,
        now: std::time::Instant,
    ) -> Option<FailedReplacement> {
        let mut guard = self.calls.get_mut(call_id)?;
        let call: &mut CallActor = &mut guard;
        let subscription = call.refer_subscriptions.iter_mut().find(|subscription| {
            subscription.is_open_replacement()
                && subscription
                    .deadline
                    .is_some_and(|deadline| now >= deadline)
        })?;
        let best = subscription.best_failure(Some(408)).unwrap_or(408);
        let failed = fail_replacement(subscription, &mut call.b_legs, &mut call.b_leg_status, best);
        self.keep_answerable(&failed.cancelled);
        Some(failed)
    }

    /// The call is ending: cancel every target a replacement on it still has
    /// ringing, keeping each answerable, and hand back what to CANCEL and
    /// release. A replacement a target already won is left to that target.
    pub fn abandon_replacements(&self, call_id: &str) -> AbandonedReplacements {
        let mut abandoned = AbandonedReplacements::default();
        let Some(mut guard) = self.calls.get_mut(call_id) else {
            return abandoned;
        };
        let call: &mut CallActor = &mut guard;
        for subscription in call.refer_subscriptions.iter_mut() {
            // One that has dialled nothing yet is ended too: its first INVITE
            // may be on its way out, and finding the replacement settled is
            // what has that target taken back (`add_replacement_target`).
            if !subscription.siphon_notifies || subscription.state != TransferState::Trying {
                continue;
            }
            let failed =
                fail_replacement(subscription, &mut call.b_legs, &mut call.b_leg_status, 487);
            abandoned.cancelled.extend(failed.cancelled);
            abandoned.released_media.extend(failed.released_media);
        }
        self.keep_answerable(&abandoned.cancelled);
        abandoned
    }

    /// Take the legs whose INVITEs rode `branches` off the call: the targets
    /// of a replacement that failed, once none of them is in flight.
    ///
    /// Each is found by its branch under the lock. A position read earlier is
    /// not safe to act on here, since removing one leg moves every later one.
    pub fn remove_b_legs_by_branch(&self, call_id: &str, branches: &[String]) {
        let mut ended = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            for branch in branches {
                if let Some(index) = call.b_legs.iter().position(|leg| &leg.branch == branch) {
                    ended.extend(self.remove_b_leg_of(&mut call, index));
                }
            }
        }
        publish_dialog_states(ended);
    }

    /// Complete a siphon-terminated transfer: promote the just-answered transfer
    /// target (`target_idx` in `b_legs`) to be the surviving party's new peer,
    /// and return the referrer leg (the party being transferred away) so the
    /// caller can BYE it.
    ///
    /// - `referrer_on_a_leg == true` — the referrer is the A-leg and the
    ///   surviving party is the winning B-leg: the target replaces the A-leg (it
    ///   becomes the new `a_leg`, the winner is preserved, the old A-leg is
    ///   returned). This is a blind transfer the caller's side asks for.
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
        let call = self.calls.get_mut(call_id)?;
        self.promote_target_of(call, target_idx, referrer_on_a_leg)
    }

    /// [`promote_transfer_target`](Self::promote_transfer_target) for the
    /// target whose INVITE rode Via `branch`, found under the same lock that
    /// promotes it: with several targets on the call a position read before
    /// the lock may no longer be this leg's.
    pub fn promote_replacement_target(
        &self,
        call_id: &str,
        branch: &str,
        referrer_on_a_leg: bool,
    ) -> Option<Leg> {
        let call = self.calls.get_mut(call_id)?;
        let target_idx = call.b_legs.iter().position(|leg| leg.branch == branch)?;
        self.promote_target_of(call, target_idx, referrer_on_a_leg)
    }

    fn promote_target_of(
        &self,
        mut call: dashmap::mapref::one::RefMut<'_, String, Box<CallActor>>,
        target_idx: usize,
        referrer_on_a_leg: bool,
    ) -> Option<Leg> {
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
            // The referrer is transferred away and BYEd next: its dialog ends.
            let ended = call.end_orphaned_dialogs();
            drop(call);
            publish_dialog_states(ended);
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        } else {
            let old_winner_idx = call.winner?;
            let old_referrer = call.b_legs.get(old_winner_idx).cloned()?;
            call.winner = Some(target_idx);
            // The referrer stays in its slot until the call ends, but it is
            // transferred away and BYEd next: its dialog ends now.
            let ended = call.advance_dialog(&old_referrer.id.0, DialogState::Terminated, None);
            drop(call);
            publish_dialog_states(ended.into_iter().collect());
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        }
    }

    /// Leg replacements past their deadline, as `(internal call id, target leg
    /// Call-ID)`, one entry per target still ringing.
    ///
    /// The counterpart of [`take_timed_out_calls`](Self::take_timed_out_calls)
    /// for the *answered* calls that one skips. A replacement dials a new leg
    /// on a call that is already `Answered`, so nothing in the answer-timeout
    /// path can see it: a target that never sends a final response would leave
    /// the subscription armed for the life of the call.
    ///
    /// Does NOT remove anything — the dispatcher runs the teardown (CANCEL the
    /// targets, drop their legs, clear the subscription), which needs to build
    /// and send messages, and takes the decision itself with
    /// [`expire_replacement`](Self::expire_replacement). Only notifier-role
    /// subscriptions that actually dialed a target and carry a deadline are
    /// eligible.
    pub fn take_timed_out_replacements(&self, now: std::time::Instant) -> Vec<(String, String)> {
        self.calls
            .iter()
            .flat_map(|entry| {
                entry
                    .refer_subscriptions
                    .iter()
                    .filter(|subscription| {
                        subscription.is_open_replacement()
                            && subscription
                                .deadline
                                .is_some_and(|deadline| now >= deadline)
                    })
                    .flat_map(|subscription| {
                        subscription
                            .targets
                            .iter()
                            .filter(|target| target.outcome == ReplacementOutcome::Pending)
                            .map(|target| (entry.id.clone(), target.leg_call_id.clone()))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b2bua::transfer::ReplacementOrigin;
    use crate::transport::{ConnectionId, Transport};

    fn transport(address: &str) -> TransportInfo {
        TransportInfo {
            remote_addr: address.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    /// A target leg whose INVITE went on the wire: the stashed copy is what a
    /// CANCEL for it is built from, and what keeps it answerable.
    fn target_leg(name: &str) -> Leg {
        let mut leg = Leg::new_b_leg(
            format!("{name}@192.0.2.1"),
            format!("tag-{name}"),
            format!("sip:{name}@198.51.100.7"),
            format!("z9hG4bK-{name}"),
            transport("198.51.100.7:5060"),
        );
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("198.51.100.7".to_string()),
            )
            .via(format!("SIP/2.0/UDP 192.0.2.1:5060;branch={}", leg.branch))
            .from(format!(
                "<sip:caller@example.com>;tag={}",
                leg.dialog.local_tag
            ))
            .to(format!("<sip:{name}@example.com>"))
            .call_id(leg.dialog.call_id.clone())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .expect("the INVITE builds");
        leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
        leg
    }

    /// An answered call between a caller and a callee, with a replacement of
    /// the callee ringing `targets`. Returns the store and the call's id.
    fn ringing(targets: &[&str], deadline: Option<Instant>) -> (CallActorStore, String) {
        let store = CallActorStore::new();
        let call_id = store.create_call(Leg::new_a_leg(
            "caller@192.0.2.10".to_string(),
            "tag-caller".to_string(),
            "z9hG4bK-caller".to_string(),
            transport("192.0.2.10:5060"),
        ));
        assert!(store.add_b_leg(&call_id, target_leg("callee")));
        store.set_winner(&call_id, 0);
        store.push_refer_subscription(
            &call_id,
            ReferSubscription {
                on_a_leg: false,
                siphon_notifies: true,
                origin: ReplacementOrigin::SiphonInitiated,
                event_id: 0,
                notify_cseq: 0,
                state: TransferState::Trying,
                targets: Vec::new(),
                referrer_gone: false,
                deadline: None,
                media_profile: None,
            },
        );
        for name in targets {
            let leg = target_leg(name);
            let target = ReplacementTarget::ringing(
                leg.branch.clone(),
                leg.dialog.call_id.clone(),
                Some(ReplacementMedia {
                    call_id: format!("media-{name}"),
                    from_tag: "tag-caller".to_string(),
                }),
            );
            assert!(store.add_b_leg(&call_id, leg));
            assert!(store
                .add_replacement_target(
                    &call_id,
                    false,
                    target,
                    deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(60)),
                )
                .is_none());
        }
        (store, call_id)
    }

    fn outcomes(store: &CallActorStore, call_id: &str) -> Vec<ReplacementOutcome> {
        store
            .get_call(call_id)
            .map(|call| {
                call.refer_subscriptions
                    .iter()
                    .flat_map(|subscription| subscription.targets.iter())
                    .map(|target| target.outcome)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn media_ids(media: &[ReplacementMedia]) -> Vec<&str> {
        media.iter().map(|media| media.call_id.as_str()).collect()
    }

    /// Two targets answer at the same moment on two threads. Exactly one is
    /// given the replacement, and the other is told its 2xx belongs to a dialog
    /// to release: never two winners, which would promote the second over the
    /// first and BYE a party that had just been brought in.
    #[test]
    fn two_targets_answering_at_once_come_out_as_one_winner_and_one_loser() {
        for round in 0..500 {
            let (store, call_id) = ringing(&["desk", "mobile"], None);
            let store = Arc::new(store);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let claims: Vec<ReplacementClaim> = ["z9hG4bK-desk", "z9hG4bK-mobile"]
                .into_iter()
                .map(|branch| {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    let call_id = call_id.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        store.claim_replacement(&call_id, branch)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|thread| thread.join().expect("the claiming thread ran"))
                .collect();

            let wins: Vec<&ReplacementWin> = claims
                .iter()
                .filter_map(|claim| match claim {
                    ReplacementClaim::Won(win) => Some(win.as_ref()),
                    _ => None,
                })
                .collect();
            let losses = claims
                .iter()
                .filter(|claim| matches!(claim, ReplacementClaim::Lost))
                .count();
            assert_eq!(wins.len(), 1, "round {round}: exactly one winner");
            assert_eq!(losses, 1, "round {round}: the other answer is a loser's");

            // The winner is handed the loser to CANCEL and its engine call to
            // release, and keeps its own.
            let win = wins[0];
            let loser = if win.target.branch == "z9hG4bK-desk" {
                "mobile"
            } else {
                "desk"
            };
            assert_eq!(win.cancelled.len(), 1);
            assert_eq!(win.cancelled[0].branch, format!("z9hG4bK-{loser}"));
            assert_eq!(
                media_ids(&win.released_media),
                [format!("media-{loser}").as_str()]
            );
            assert!(
                win.target.media.is_some(),
                "the winner keeps its engine call"
            );
            // And the loser is answerable for the 2xx it sent, exactly once.
            let (_, first) = store
                .zombie_cancelled_for_2xx(&format!("z9hG4bK-{loser}"))
                .expect("the loser was kept answerable");
            assert!(first, "its dialog is released once");
            assert!(!store.is_cancelled_branch(&win.target.branch));
            let mut settled = outcomes(&store, &call_id);
            settled.sort_by_key(|outcome| *outcome == ReplacementOutcome::Cancelled);
            assert_eq!(
                settled,
                [ReplacementOutcome::Answered, ReplacementOutcome::Cancelled]
            );
        }
    }

    /// The winner's own 2xx again, while it is being brought in, is neither a
    /// second win nor a dialog to release.
    #[test]
    fn a_retransmitted_winning_answer_is_a_duplicate() {
        let (store, call_id) = ringing(&["desk", "mobile"], None);
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-desk"),
            ReplacementClaim::Won(_)
        ));
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-desk"),
            ReplacementClaim::Duplicate
        ));
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-mobile"),
            ReplacementClaim::Lost
        ));
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-callee"),
            ReplacementClaim::NotATarget
        ));
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-mobile"),
            ReplacementBranch::Target
        );
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-callee"),
            ReplacementBranch::Other
        );
        // The winner is in and its replacement cleared: the loser is told
        // apart by having been cancelled and kept answerable, which is what
        // has a response of its own, already on its way in, released.
        store.clear_refer_subscriptions_on_leg(&call_id, false);
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-mobile"),
            ReplacementBranch::Settled
        );
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-desk"),
            ReplacementBranch::Other,
            "the winner is an ordinary leg again"
        );
        assert_eq!(
            store.replacement_branch("no-such-call", "z9hG4bK-mobile"),
            ReplacementBranch::Other
        );
        // Taken off the call as well, as a failed replacement's targets are:
        // still a cancelled branch for as long as it is kept answerable.
        store.remove_b_legs_by_branch(&call_id, &["z9hG4bK-mobile".to_string()]);
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-mobile"),
            ReplacementBranch::Settled
        );
        assert_eq!(
            store.replacement_branch(&call_id, "z9hG4bK-never-dialled"),
            ReplacementBranch::Other
        );
    }

    /// One target failing while another rings fails nothing. The last one
    /// failing fails the replacement once, on the best of the two responses
    /// (RFC 3261 §16.7 step 6), and each failure releases that target's engine
    /// call.
    #[test]
    fn the_replacement_fails_only_when_no_target_is_left_and_on_the_best_response() {
        let (store, call_id) = ringing(&["desk", "mobile"], None);
        let first = store
            .record_replacement_failure(&call_id, "z9hG4bK-desk", 486)
            .expect("a pending target");
        assert!(first.settled.is_none(), "the mobile still rings");
        assert_eq!(
            first.released_media.map(|media| media.call_id).as_deref(),
            Some("media-desk")
        );
        // A retransmission of that failure records nothing.
        assert!(store
            .record_replacement_failure(&call_id, "z9hG4bK-desk", 486)
            .is_none());

        let last = store
            .record_replacement_failure(&call_id, "z9hG4bK-mobile", 503)
            .expect("a pending target");
        let failed = last.settled.expect("no target is left");
        assert_eq!(
            failed.status_code, 486,
            "the best response, not the last: a 4xx outranks a 5xx (RFC 3261 §16.7 step 6)"
        );
        assert!(failed.cancelled.is_empty(), "nothing was still ringing");
        assert!(
            failed.released_media.is_empty(),
            "each was released as it failed"
        );
        assert_eq!(failed.branches, ["z9hG4bK-desk", "z9hG4bK-mobile"]);
        assert_eq!(
            outcomes(&store, &call_id),
            [
                ReplacementOutcome::Failed(486),
                ReplacementOutcome::Failed(503)
            ]
        );
        // Settled: a deadline that passes now has nothing to give up on.
        assert!(store
            .expire_replacement(&call_id, Instant::now() + Duration::from_secs(600))
            .is_none());

        // The legs come off by branch, and the callee's slot is untouched.
        store.remove_b_legs_by_branch(&call_id, &failed.branches);
        let call = store.get_call(&call_id).expect("the call is kept");
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.b_legs[0].branch, "z9hG4bK-callee");
        assert_eq!(call.winner, Some(0));
    }

    /// Two targets failing at once on two threads report one failure.
    #[test]
    fn two_targets_failing_at_once_fail_the_replacement_once() {
        for round in 0..300 {
            let (store, call_id) = ringing(&["desk", "mobile"], None);
            let store = Arc::new(store);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let settled = [("z9hG4bK-desk", 486), ("z9hG4bK-mobile", 503)]
                .into_iter()
                .map(|(branch, status_code)| {
                    let store = Arc::clone(&store);
                    let barrier = Arc::clone(&barrier);
                    let call_id = call_id.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        store.record_replacement_failure(&call_id, branch, status_code)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .filter_map(|thread| thread.join().expect("the failing thread ran"))
                .filter_map(|failure| failure.settled)
                .collect::<Vec<_>>();
            assert_eq!(settled.len(), 1, "round {round}: one failure");
            assert_eq!(settled[0].status_code, 486);
        }
    }

    /// The deadline cancels every target still ringing, keeps each answerable,
    /// and fails on 408 unless a target already gave a better response.
    #[test]
    fn the_deadline_cancels_what_still_rings_and_keeps_it_answerable() {
        let past = Instant::now() - Duration::from_secs(1);
        let (store, call_id) = ringing(&["desk", "mobile"], Some(past));
        assert_eq!(store.take_timed_out_replacements(Instant::now()).len(), 2);
        let failed = store
            .expire_replacement(&call_id, Instant::now())
            .expect("past its deadline");
        assert_eq!(failed.status_code, 408);
        assert_eq!(failed.cancelled.len(), 2);
        assert_eq!(
            media_ids(&failed.released_media),
            ["media-desk", "media-mobile"]
        );
        for branch in ["z9hG4bK-desk", "z9hG4bK-mobile"] {
            assert!(
                store.is_cancelled_branch(branch),
                "{branch} stays answerable"
            );
        }
        // Given up on once: neither the sweep nor a second expiry finds it.
        assert!(store.take_timed_out_replacements(Instant::now()).is_empty());
        assert!(store.expire_replacement(&call_id, Instant::now()).is_none());
        // A 2xx that crossed the CANCEL is a loser's.
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-desk"),
            ReplacementClaim::Lost
        ));

        // A target that had already refused outranks the timeout's 408.
        let (store, call_id) = ringing(&["desk", "mobile"], Some(past));
        assert!(store
            .record_replacement_failure(&call_id, "z9hG4bK-desk", 486)
            .is_some_and(|failure| failure.settled.is_none()));
        let failed = store
            .expire_replacement(&call_id, Instant::now())
            .expect("past its deadline");
        assert_eq!(failed.status_code, 486);
        assert_eq!(failed.cancelled.len(), 1, "only the one still ringing");
        assert_eq!(media_ids(&failed.released_media), ["media-mobile"]);

        // Not yet due: nothing is touched.
        let (store, call_id) = ringing(&["desk"], None);
        assert!(store.expire_replacement(&call_id, Instant::now()).is_none());
        assert_eq!(outcomes(&store, &call_id), [ReplacementOutcome::Pending]);
    }

    /// A call that ends with targets ringing cancels them all, and leaves a
    /// replacement a target already won to that target.
    #[test]
    fn a_call_ending_cancels_its_pending_targets_and_leaves_a_won_one_alone() {
        let (store, call_id) = ringing(&["desk", "mobile"], None);
        let abandoned = store.abandon_replacements(&call_id);
        assert_eq!(abandoned.cancelled.len(), 2);
        assert_eq!(
            media_ids(&abandoned.released_media),
            ["media-desk", "media-mobile"]
        );
        assert!(store.is_cancelled_branch("z9hG4bK-desk"));
        assert!(store.is_cancelled_branch("z9hG4bK-mobile"));
        assert!(
            store.abandon_replacements(&call_id).is_empty(),
            "nothing is left to end a second time"
        );

        let (store, call_id) = ringing(&["desk", "mobile"], None);
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-desk"),
            ReplacementClaim::Won(_)
        ));
        assert!(store.abandon_replacements(&call_id).is_empty());

        assert!(CallActorStore::new()
            .abandon_replacements("no-such-call")
            .is_empty());

        // A replacement whose first INVITE is still on its way out is ended
        // too, so that target is taken back when it is entered. And one
        // entered for a call that is gone gives its engine call back.
        let (store, call_id) = ringing(&[], None);
        assert!(store.replacement_is_open(&call_id, false));
        assert!(store.abandon_replacements(&call_id).is_empty());
        assert!(!store.replacement_is_open(&call_id, false));
        let leg = target_leg("desk");
        let target = |media: &str| {
            ReplacementTarget::ringing(
                "z9hG4bK-desk".to_string(),
                "desk@192.0.2.1".to_string(),
                Some(ReplacementMedia {
                    call_id: media.to_string(),
                    from_tag: "tag-caller".to_string(),
                }),
            )
        };
        assert!(store.add_b_leg(&call_id, leg));
        let deadline = Instant::now() + Duration::from_secs(60);
        let late = store
            .add_replacement_target(&call_id, false, target("media-desk"), deadline)
            .expect("the replacement ended with the call");
        assert_eq!(late.cancelled.len(), 1);
        assert_eq!(media_ids(&late.released_media), ["media-desk"]);
        let gone = store
            .add_replacement_target("no-such-call", false, target("media-gone"), deadline)
            .expect("the call is gone");
        assert!(gone.cancelled.is_empty());
        assert_eq!(media_ids(&gone.released_media), ["media-gone"]);
    }

    /// A replacement that entered no target is failed as a whole, once, and
    /// one a target was entered for is left to that target.
    #[test]
    fn a_replacement_with_no_target_entered_is_failed_and_one_with_a_target_is_not() {
        let (store, call_id) = ringing(&[], None);
        assert!(
            store
                .fail_undialled_replacement(&call_id, true, 503)
                .is_none(),
            "the other side's leg is not being replaced"
        );
        let failed = store
            .fail_undialled_replacement(&call_id, false, 503)
            .expect("nothing was dialled");
        assert_eq!(failed.status_code, 503);
        assert!(!failed.replaced_on_a_leg);
        assert!(failed.branches.is_empty());
        assert!(failed.cancelled.is_empty());
        assert!(failed.released_media.is_empty());
        assert!(!store.replacement_is_open(&call_id, false));
        assert!(
            store
                .fail_undialled_replacement(&call_id, false, 503)
                .is_none(),
            "failed once"
        );

        let (store, call_id) = ringing(&["desk"], None);
        assert!(store
            .fail_undialled_replacement(&call_id, false, 503)
            .is_none());
        assert_eq!(outcomes(&store, &call_id), [ReplacementOutcome::Pending]);
        assert!(store
            .fail_undialled_replacement("no-such-call", false, 503)
            .is_none());
    }

    /// A target whose INVITE is not on the wire yet cannot be CANCELled (RFC
    /// 3261 §9.1 builds the CANCEL from the INVITE): it is flagged for the send
    /// path instead, and is not handed back.
    #[test]
    fn a_target_not_yet_on_the_wire_is_flagged_for_its_cancel() {
        let (store, call_id) = ringing(&["desk", "mobile"], None);
        if let Some(mut call) = store.get_call_mut(&call_id) {
            if let Some((_, leg)) = call.find_b_leg_by_branch_mut("z9hG4bK-mobile") {
                leg.b_leg_invite = None;
            }
        }
        let ReplacementClaim::Won(win) = store.claim_replacement(&call_id, "z9hG4bK-desk") else {
            panic!("the desk answered first");
        };
        assert!(win.cancelled.is_empty());
        assert!(!store.is_cancelled_branch("z9hG4bK-mobile"));
        let call = store.get_call(&call_id).expect("the call exists");
        let (_, mobile) = call
            .find_b_leg_by_branch("z9hG4bK-mobile")
            .expect("the mobile's leg");
        assert!(mobile.pending_cancel);
    }

    /// A target whose INVITE left after a sibling had already answered has
    /// nothing left that would CANCEL it: entering it finds the replacement
    /// settled, and hands it back cancelled and answerable instead.
    #[test]
    fn a_target_entered_after_the_replacement_settled_is_handed_back_to_cancel() {
        let (store, call_id) = ringing(&["desk"], None);
        assert!(store.replacement_is_open(&call_id, false));
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-desk"),
            ReplacementClaim::Won(_)
        ));
        assert!(!store.replacement_is_open(&call_id, false));

        let leg = target_leg("mobile");
        let late = ReplacementTarget::ringing(
            leg.branch.clone(),
            leg.dialog.call_id.clone(),
            Some(ReplacementMedia {
                call_id: "media-mobile".to_string(),
                from_tag: "tag-caller".to_string(),
            }),
        );
        assert!(store.add_b_leg(&call_id, leg));
        let handed_back = store
            .add_replacement_target(
                &call_id,
                false,
                late,
                Instant::now() + Duration::from_secs(60),
            )
            .expect("the replacement is settled");
        assert_eq!(handed_back.cancelled.len(), 1);
        assert_eq!(handed_back.cancelled[0].branch, "z9hG4bK-mobile");
        assert_eq!(media_ids(&handed_back.released_media), ["media-mobile"]);
        assert!(store.is_cancelled_branch("z9hG4bK-mobile"));
        assert_eq!(
            outcomes(&store, &call_id),
            [ReplacementOutcome::Answered],
            "it never joined the replacement"
        );
        // The other side's replacement is another matter entirely.
        assert!(!store.replacement_is_open(&call_id, true));
    }

    /// The promotion finds its leg by branch under its own lock, so a sibling
    /// taken off the call in between cannot make it promote another leg.
    #[test]
    fn the_winner_is_promoted_by_branch_whatever_its_position() {
        let (store, call_id) = ringing(&["desk", "mobile"], None);
        assert!(matches!(
            store.claim_replacement(&call_id, "z9hG4bK-mobile"),
            ReplacementClaim::Won(_)
        ));
        // The desk, ahead of the mobile in the leg list, leaves the call.
        store.remove_b_legs_by_branch(&call_id, &["z9hG4bK-desk".to_string()]);
        let replaced = store
            .promote_replacement_target(&call_id, "z9hG4bK-mobile", false)
            .expect("the callee is replaced");
        assert_eq!(replaced.branch, "z9hG4bK-callee");
        let winner = store
            .get_call(&call_id)
            .and_then(|call| call.winning_b_leg().map(|leg| leg.branch.clone()));
        assert_eq!(winner.as_deref(), Some("z9hG4bK-mobile"));
        assert!(store
            .promote_replacement_target(&call_id, "z9hG4bK-gone", false)
            .is_none());
        // A position is re-read by branch: the mobile moved down when the desk
        // left, and a leg that is gone has none.
        assert_eq!(store.b_leg_index(&call_id, "z9hG4bK-mobile"), Some(1));
        assert_eq!(store.b_leg_index(&call_id, "z9hG4bK-desk"), None);
    }

    /// Nothing a replacement holds per target outlives it: once it has failed
    /// and its legs are off the call, and the subscription is cleared, the
    /// call is back to the two legs and no subscription it started with.
    #[test]
    fn a_settled_replacement_leaves_no_target_behind() {
        for _ in 0..200 {
            let (store, call_id) = ringing(&["desk", "mobile"], None);
            let _ = store.record_replacement_failure(&call_id, "z9hG4bK-desk", 486);
            let failed = store
                .record_replacement_failure(&call_id, "z9hG4bK-mobile", 486)
                .and_then(|failure| failure.settled)
                .expect("the replacement failed");
            store.remove_b_legs_by_branch(&call_id, &failed.branches);
            store.clear_refer_subscriptions_on_leg(&call_id, false);
            let call = store.get_call(&call_id).expect("the call is kept");
            assert!(call.refer_subscriptions.is_empty());
            assert_eq!(call.b_legs.len(), 1);
            assert_eq!(call.b_leg_status.len(), 1);
            drop(call);
            assert!(store.zombie_cancelled.is_empty());
            assert!(store.call_id_for_branch("z9hG4bK-desk").is_none());
            assert!(store.call_id_for_branch("z9hG4bK-mobile").is_none());
        }
    }
}
