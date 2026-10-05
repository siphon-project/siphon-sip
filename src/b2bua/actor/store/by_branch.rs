//! Addressing a B-leg by the Via branch of its INVITE.
//!
//! A leg's position among the call's B-legs is only good until a leg ahead of
//! it is taken off the call: the tracking leg of an in-dialog request once it
//! is answered, a failed replacement's targets, a promoted target. A response
//! handler reads the position when the response arrives and acts on it after
//! its hooks, retries and media engine calls have run, and a PRACK waits for
//! the caller's for as long as the caller takes. Acted on then, a position
//! names whichever leg sits there now, or none.
//!
//! The Via branch is unique to the leg's INVITE (RFC 3261 §8.1.1.7) and every
//! response to it carries it. Each method here finds the leg by it under the
//! same lock that acts on the leg.

use super::*;

/// RFC 3262 §4 dedup on one leg: `true` exactly once for each new `rseq` on
/// the early dialog `to_tag`, `false` for a retransmission of a reliable
/// provisional already received. Per To-tag, since forked early dialogs number
/// their provisionals independently (§3).
pub(super) fn mark_prack_acked(leg: &mut Leg, to_tag: &str, rseq: u32) -> bool {
    if leg
        .prack_acked_rseq
        .get(to_tag)
        .is_some_and(|&seen| seen >= rseq)
    {
        return false;
    }
    leg.prack_acked_rseq.insert(to_tag.to_string(), rseq);
    true
}

/// 401/407 dedup on one leg: `true` exactly once, for the first challenge the
/// leg's INVITE draws, `false` for every retransmission of it.
pub(super) fn mark_auth_challenged(leg: &mut Leg) -> bool {
    !std::mem::replace(&mut leg.auth_challenged, true)
}

impl CallActorStore {
    /// [`record_branch_failure`](Self::record_branch_failure) for the leg
    /// whose INVITE rode Via `branch`. `None` when the call, or that leg, is
    /// gone.
    pub fn record_branch_failure_on(
        &self,
        call_id: &str,
        branch: &str,
        status_code: u16,
        response: &SipMessage,
    ) -> Option<BranchSettlement> {
        let mut call = self.calls.get_mut(call_id)?;
        let (index, _) = call.find_b_leg_by_branch(branch)?;
        let settlement = call.record_branch_failure(index, status_code, response);
        self.keep_answerable(&settlement.cancelled);
        Some(settlement)
    }

    /// [`is_ended_branch`](Self::is_ended_branch) for the leg whose INVITE
    /// rode Via `branch`. `true` when the call or that leg is gone, which
    /// ended it.
    pub fn is_ended_branch_on(&self, call_id: &str, branch: &str) -> bool {
        // `map_or(true, …)` not `is_none_or`: MSRV 1.80, and that is 1.82.
        self.calls.get(call_id).map_or(true, |call| {
            call.find_b_leg_by_branch(branch)
                .map_or(true, |(index, _)| call.is_ended_branch(index))
        })
    }

    /// [`try_mark_prack_acked`](Self::try_mark_prack_acked) for the leg whose
    /// INVITE rode Via `branch`. `false` when the call or that leg is gone.
    pub fn try_mark_prack_acked_on(
        &self,
        call_id: &str,
        branch: &str,
        to_tag: &str,
        rseq: u32,
    ) -> bool {
        self.calls.get_mut(call_id).is_some_and(|mut call| {
            call.find_b_leg_by_branch_mut(branch)
                .is_some_and(|(_, leg)| mark_prack_acked(leg, to_tag, rseq))
        })
    }

    /// [`try_win`](Self::try_win) for the leg whose INVITE rode Via `branch`,
    /// found under the lock that claims the answer for it. `None` when the
    /// call, or that leg, is gone.
    pub fn try_win_on(&self, call_id: &str, branch: &str) -> Option<WinOutcome> {
        let mut call = self.calls.get_mut(call_id)?;
        let (index, _) = call.find_b_leg_by_branch(branch)?;
        Some(self.claim_answer(&mut call, index))
    }

    /// Claim the answer of a call already held for the leg at `index`.
    pub(super) fn claim_answer(&self, call: &mut CallActor, index: usize) -> WinOutcome {
        if call.state == CallState::Answered {
            return WinOutcome::AlreadyAnswered;
        }
        call.set_winner(index);
        let cancelled = call.cancel_pending_branches(Some(index));
        self.keep_answerable(&cancelled);
        WinOutcome::FirstWin { cancelled }
    }

    /// [`rewind_failed_answer`](Self::rewind_failed_answer) for the leg whose
    /// INVITE rode Via `branch`. The call is rewound whether or not that leg
    /// is still on it.
    pub fn rewind_failed_answer_on(&self, call_id: &str, branch: &str, status_code: u16) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            let index = call.find_b_leg_by_branch(branch).map(|(index, _)| index);
            call.rewind_failed_answer(index, status_code);
        }
    }

    /// [`try_mark_auth_challenged`](Self::try_mark_auth_challenged) for the
    /// leg whose INVITE rode Via `branch`. `false` when the call or that leg is
    /// gone: a challenge on a branch already superseded is a retransmission.
    pub fn try_mark_auth_challenged_on(&self, call_id: &str, branch: &str) -> bool {
        self.update_b_leg_on(call_id, branch, mark_auth_challenged)
            .unwrap_or(false)
    }

    /// [`replace_b_leg`](Self::replace_b_leg) for the leg whose INVITE rode
    /// Via `branch`. `false` when the call or that leg is gone and nothing was
    /// replaced.
    pub fn replace_b_leg_on(&self, call_id: &str, branch: &str, leg: Leg) -> bool {
        let new_branch = leg.branch.clone();
        let replaced = self.calls.get_mut(call_id).and_then(|mut call| {
            let (index, _) = call.find_b_leg_by_branch(branch)?;
            call.replace_b_leg(index, leg)
        });
        match replaced {
            Some(old_branch) => {
                self.repoint_branch(call_id, &old_branch, &new_branch);
                true
            }
            None => false,
        }
    }

    /// Move the registry's entry for a superseded leg to its new Via branch.
    pub(super) fn repoint_branch(&self, call_id: &str, old_branch: &str, new_branch: &str) {
        if old_branch != new_branch {
            self.registry.remove_branch(old_branch);
        }
        self.registry.register_branch(new_branch, call_id);
    }

    /// [`settle_route_branch`](Self::settle_route_branch) for the carrier leg
    /// whose INVITE rode Via `branch`. `false` when the call or that leg is
    /// gone, which makes the response a straggler.
    pub fn settle_route_branch_on(&self, call_id: &str, branch: &str, status_code: u16) -> bool {
        self.calls.get_mut(call_id).is_some_and(|mut call| {
            call.find_b_leg_by_branch(branch)
                .map(|(index, _)| index)
                .is_some_and(|index| call.settle_route_branch(index, status_code))
        })
    }

    /// [`remove_b_leg`](Self::remove_b_leg) for the leg whose request rode Via
    /// `branch`. Nothing is removed when no leg carries that branch.
    pub fn remove_b_leg_on(&self, call_id: &str, branch: &str) {
        let mut ended = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(index) = call.find_b_leg_by_branch(branch).map(|(index, _)| index) {
                ended = self.remove_b_leg_of(&mut call, index);
            }
        }
        publish_dialog_states(ended);
    }

    /// Read off the leg whose request rode Via `branch`, as it stands now.
    /// `None` when the call or that leg is gone.
    pub fn read_b_leg_on<T>(
        &self,
        call_id: &str,
        branch: &str,
        read: impl FnOnce(&Leg) -> T,
    ) -> Option<T> {
        self.calls
            .get(call_id)
            .and_then(|call| call.find_b_leg_by_branch(branch).map(|(_, leg)| read(leg)))
    }

    /// Change the leg whose request rode Via `branch`, under the call's lock.
    /// `None`, with nothing changed, when the call or that leg is gone.
    pub fn update_b_leg_on<T>(
        &self,
        call_id: &str,
        branch: &str,
        update: impl FnOnce(&mut Leg) -> T,
    ) -> Option<T> {
        self.calls.get_mut(call_id).and_then(|mut call| {
            call.find_b_leg_by_branch_mut(branch)
                .map(|(_, leg)| update(leg))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ConnectionId, Transport};

    fn transport() -> TransportInfo {
        TransportInfo {
            remote_addr: "198.51.100.7:5060".parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    /// A branch whose INVITE went on the wire, which is what makes it one that
    /// can still answer.
    fn leg(name: &str) -> Leg {
        let mut leg = Leg::new_b_leg(
            format!("{name}@192.0.2.1"),
            format!("tag-{name}"),
            format!("sip:{name}@198.51.100.7"),
            format!("z9hG4bK-{name}"),
            transport(),
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

    fn failure(status_code: u16) -> SipMessage {
        crate::sip::builder::SipMessageBuilder::new()
            .response(status_code, "Failure".to_string())
            .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-failure".to_string())
            .from("<sip:caller@example.com>;tag=caller".to_string())
            .to("<sip:callee@example.com>;tag=callee".to_string())
            .call_id("failure@192.0.2.1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .expect("the response builds")
    }

    /// A call ringing two branches behind a leg that is then taken off it.
    fn forked_behind_a_leg_that_leaves() -> (CallActorStore, String) {
        let store = CallActorStore::new();
        let call_id = store.create_call(Leg::new_a_leg(
            "caller@192.0.2.10".to_string(),
            "tag-caller".to_string(),
            "z9hG4bK-caller".to_string(),
            transport(),
        ));
        for name in ["leaving", "desk", "mobile"] {
            assert!(store.add_b_leg(&call_id, leg(name)));
        }
        (store, call_id)
    }

    /// With a leg ahead of them gone, each branch is still the one acted on:
    /// the failure is recorded against the leg that failed, and the PRACK
    /// dedup is kept on the leg that sent the provisional.
    #[test]
    fn a_leg_is_found_by_its_branch_after_the_legs_ahead_of_it_moved() {
        let (store, call_id) = forked_behind_a_leg_that_leaves();
        // Read while the leg list was whole, as a response handler reads it.
        let stale = store
            .b_leg_index(&call_id, "z9hG4bK-mobile")
            .expect("the mobile's leg");
        assert_eq!(stale, 2);
        store.remove_b_leg(&call_id, 0);
        assert_eq!(store.b_leg_index(&call_id, "z9hG4bK-mobile"), Some(1));

        assert!(store.try_mark_prack_acked_on(&call_id, "z9hG4bK-mobile", "tag-m", 1));
        assert!(
            !store.try_mark_prack_acked_on(&call_id, "z9hG4bK-mobile", "tag-m", 1),
            "a retransmission"
        );
        assert!(
            store.try_mark_prack_acked_on(&call_id, "z9hG4bK-desk", "tag-m", 1),
            "the desk's dialogs are its own"
        );
        assert!(!store.try_mark_prack_acked_on(&call_id, "z9hG4bK-leaving", "tag", 1));
        assert!(!store.try_mark_prack_acked_on("no-such-call", "z9hG4bK-mobile", "tag", 1));

        assert!(!store.is_ended_branch_on(&call_id, "z9hG4bK-mobile"));
        let settlement = store
            .record_branch_failure_on(&call_id, "z9hG4bK-mobile", 486, &failure(486))
            .expect("the mobile's leg is on the call");
        assert!(settlement.failure.is_none(), "the desk still rings");
        assert!(store.is_ended_branch_on(&call_id, "z9hG4bK-mobile"));
        assert!(
            !store.is_ended_branch_on(&call_id, "z9hG4bK-desk"),
            "the failure was the mobile's, not the leg now in its old place"
        );
        // The position read earlier now names no leg at all.
        assert!(store.is_ended_branch(&call_id, stale));

        assert!(
            store.is_ended_branch_on(&call_id, "z9hG4bK-leaving"),
            "a leg that left has ended"
        );
        assert!(store.is_ended_branch_on("no-such-call", "z9hG4bK-desk"));
        assert!(store
            .record_branch_failure_on(&call_id, "z9hG4bK-leaving", 486, &failure(486))
            .is_none());
        assert!(store
            .record_branch_failure_on("no-such-call", "z9hG4bK-desk", 486, &failure(486))
            .is_none());
    }
}
