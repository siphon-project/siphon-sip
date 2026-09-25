//! The B-legs a controller-issued `dial` rang, as the controller is told of them.
//!
//! Each branch is its own SIP dialog, with a Call-ID siphon generated, so
//! nothing on the wire ties it back to the call the controller owns. This is the
//! record that does: every branch is entered when its INVITE is built, settled
//! once with its outcome, and handed back whole when the dial fails, so the
//! controller hears about each branch exactly once and `DialFailed` can list
//! them all.

use super::*;

/// How a branch of a controller-issued `dial` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialBranchCause {
    /// It answered: the call is bridged to this leg.
    Answered,
    /// The far end sent a final non-2xx.
    Rejected,
    /// Nothing final arrived before the dial's (or the attempt's) ring timeout.
    Timeout,
    /// siphon CANCELled it: another branch answered or declined for all, or the
    /// caller went away.
    Cancelled,
    /// Its INVITE was built but could not be handed to the transport.
    Unsent,
}

impl DialBranchCause {
    /// The `cause` string the control plane reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Rejected => "rejected",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Unsent => "unsent",
        }
    }
}

/// A branch's outcome: the status it ended on and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialBranchOutcome {
    /// The final status: the far end's own, or the one siphon's action draws
    /// (`487` for a CANCEL, `408` for a ring timeout, `503` for an unsent
    /// INVITE).
    pub code: u16,
    /// The reason phrase that goes with `code`.
    pub reason: String,
    pub cause: DialBranchCause,
}

impl DialBranchOutcome {
    pub fn new(code: u16, reason: &str, cause: DialBranchCause) -> Self {
        Self {
            code,
            reason: reason.to_string(),
            cause,
        }
    }
}

/// One branch of a controller-issued `dial`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialBranch {
    /// The B-leg's [`LegId`], which survives a 401/407 or 422 retry of the leg.
    pub leg_id: String,
    /// The Call-ID the branch's INVITE went out with.
    pub leg_sip_call_id: String,
    /// The target the branch was dialled at.
    pub target: String,
    /// The registered AoR the branch was dialled for, when the target was one
    /// of the contacts an `{aor}` target resolved to. `None` for a raw URI.
    pub aor: Option<String>,
    /// `None` while it may still answer.
    pub outcome: Option<DialBranchOutcome>,
}

impl DialBranch {
    /// A branch just created from `leg`, dialled at `target` for `aor`.
    pub fn of_leg(leg: &Leg, target: &str, aor: Option<String>) -> Self {
        Self {
            leg_id: leg.id.to_string(),
            leg_sip_call_id: leg.dialog.call_id.clone(),
            target: target.to_string(),
            aor,
            outcome: None,
        }
    }
}

impl CallActor {
    /// Enter `leg`, dialled at `target`, as a branch of the controller's dial,
    /// returning the branch. `None`, and nothing recorded or allocated, when no
    /// controller-issued dial is awaiting its outcome: a script's dial, or a
    /// transfer's re-dial on a call already answered, is nobody's to report.
    /// Every B-leg INVITE passes through here, so that case costs one flag test.
    pub fn record_dial_branch(&mut self, leg: &Leg, target: &str) -> Option<DialBranch> {
        if !self.control_dial {
            return None;
        }
        let aor = self.control_dial_aor(target);
        let branch = DialBranch::of_leg(leg, target, aor);
        self.dial_branches.push(branch.clone());
        Some(branch)
    }

    /// The registered AoR the controller's `dial` resolved `target` from, if it
    /// was one of an `{aor}` target's contacts.
    pub fn control_dial_aor(&self, target: &str) -> Option<String> {
        self.control_dial_aors
            .iter()
            .find(|(uri, _)| uri == target)
            .map(|(_, aor)| aor.clone())
    }

    /// Settle the branch for `leg_id` as ended on `code` / `reason` for `cause`,
    /// returning it settled. `None` when it is not a branch of the dial or has
    /// already been settled, so each branch is reported once whichever path
    /// reaches it first.
    pub fn settle_dial_branch(
        &mut self,
        leg_id: &str,
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Option<DialBranch> {
        let branch = self
            .dial_branches
            .iter_mut()
            .find(|branch| branch.leg_id == leg_id && branch.outcome.is_none())?;
        branch.outcome = Some(DialBranchOutcome::new(code, reason, cause));
        Some(branch.clone())
    }

    /// [`Self::settle_dial_branch`] for the B-leg whose INVITE rides Via
    /// `via_branch`, which is what a response matches on.
    pub fn settle_dial_branch_by_via(
        &mut self,
        via_branch: &str,
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Option<DialBranch> {
        // Every B-leg final response comes through here; a call with no dial to
        // report on leaves at once.
        if self.dial_branches.is_empty() {
            return None;
        }
        let leg_id = self.find_b_leg_by_branch(via_branch)?.1.id.0.clone();
        self.settle_dial_branch(&leg_id, code, reason, cause)
    }

    /// Settle every branch that has no outcome yet, returning them settled.
    pub fn settle_open_dial_branches(
        &mut self,
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Vec<DialBranch> {
        self.dial_branches
            .iter_mut()
            .filter(|branch| branch.outcome.is_none())
            .map(|branch| {
                branch.outcome = Some(DialBranchOutcome::new(code, reason, cause));
                branch.clone()
            })
            .collect()
    }

    /// Hand back every branch of the dial and forget them, so a later dial on
    /// the same channel starts from none.
    pub fn take_dial_branches(&mut self) -> Vec<DialBranch> {
        std::mem::take(&mut self.dial_branches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ConnectionId;

    fn a_leg() -> Leg {
        Leg::new_a_leg(
            "a-leg@192.0.2.10".to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-a".to_string(),
            TransportInfo {
                remote_addr: "192.0.2.10:5060".parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: crate::transport::Transport::Udp,
                local_addr: None,
            },
        )
    }

    fn b_leg(call_id: &str, via_branch: &str) -> Leg {
        Leg::new_b_leg(
            call_id.to_string(),
            "b-tag".to_string(),
            "sip:15550100077@198.51.100.7".to_string(),
            via_branch.to_string(),
            TransportInfo {
                remote_addr: "198.51.100.7:5060".parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: crate::transport::Transport::Udp,
                local_addr: None,
            },
        )
    }

    fn dialling_call() -> (CallActor, Leg) {
        let mut call = CallActor::new(a_leg());
        call.control_dial = true;
        let leg = b_leg("b-leg-1@siphon", "z9hG4bK-b1");
        call.add_b_leg(leg.clone());
        assert!(call
            .record_dial_branch(&leg, "sip:15550100077@198.51.100.7")
            .is_some());
        (call, leg)
    }

    fn busy() -> DialBranchOutcome {
        DialBranchOutcome::new(486, "Busy Here", DialBranchCause::Rejected)
    }

    fn settle_busy(call: &mut CallActor, via_branch: &str) -> Option<DialBranch> {
        call.settle_dial_branch_by_via(via_branch, 486, "Busy Here", DialBranchCause::Rejected)
    }

    #[test]
    fn a_branch_names_its_leg_and_its_call_id() {
        let (call, leg) = dialling_call();
        assert_eq!(call.dial_branches.len(), 1);
        assert_eq!(call.dial_branches[0].leg_id, leg.id.to_string());
        assert_eq!(call.dial_branches[0].leg_sip_call_id, "b-leg-1@siphon");
        assert_eq!(call.dial_branches[0].target, "sip:15550100077@198.51.100.7");
        assert!(call.dial_branches[0].outcome.is_none());
    }

    #[test]
    fn nothing_is_recorded_without_a_controller_dial() {
        let mut call = CallActor::new(a_leg());
        let leg = b_leg("b-leg-1@siphon", "z9hG4bK-b1");
        call.add_b_leg(leg.clone());
        assert!(call
            .record_dial_branch(&leg, "sip:x@198.51.100.7")
            .is_none());
        assert!(call.dial_branches.is_empty());
        assert!(settle_busy(&mut call, "z9hG4bK-b1").is_none());
    }

    #[test]
    fn a_branch_is_settled_once() {
        let (mut call, _) = dialling_call();
        let settled = settle_busy(&mut call, "z9hG4bK-b1").expect("the branch settles");
        assert_eq!(settled.outcome, Some(busy()));
        assert!(call
            .settle_dial_branch_by_via(
                "z9hG4bK-b1",
                487,
                "Request Terminated",
                DialBranchCause::Cancelled
            )
            .is_none());
        assert!(call
            .settle_open_dial_branches(487, "Request Terminated", DialBranchCause::Cancelled)
            .is_empty());
        assert_eq!(call.dial_branches[0].outcome, Some(busy()));
    }

    #[test]
    fn an_unknown_via_branch_settles_nothing() {
        let (mut call, _) = dialling_call();
        assert!(settle_busy(&mut call, "z9hG4bK-other").is_none());
    }

    #[test]
    fn open_branches_settle_together_and_taking_forgets_them() {
        let (mut call, _) = dialling_call();
        let second = b_leg("b-leg-2@siphon", "z9hG4bK-b2");
        call.add_b_leg(second.clone());
        assert!(call
            .record_dial_branch(&second, "sip:y@198.51.100.8")
            .is_some());
        let _ = settle_busy(&mut call, "z9hG4bK-b1");

        let settled =
            call.settle_open_dial_branches(408, "Request Timeout", DialBranchCause::Timeout);
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].leg_sip_call_id, "b-leg-2@siphon");
        assert_eq!(
            settled[0].outcome,
            Some(DialBranchOutcome::new(
                408,
                "Request Timeout",
                DialBranchCause::Timeout
            ))
        );

        let taken = call.take_dial_branches();
        assert_eq!(taken.len(), 2);
        assert!(call.dial_branches.is_empty());
    }

    /// A 401/407 or 422 retry replaces the leg in its slot but is the same
    /// logical branch (RFC 3261 §22.2), so its outcome still settles the branch
    /// the controller was told about.
    #[test]
    fn a_retried_leg_keeps_the_branch_it_was_named_as() {
        let (mut call, leg) = dialling_call();
        let retry = b_leg("b-leg-1@siphon", "z9hG4bK-b1-retry");
        assert!(call.replace_b_leg(0, retry).is_some());
        assert_eq!(call.b_legs[0].id, leg.id);
        let settled = settle_busy(&mut call, "z9hG4bK-b1-retry")
            .expect("the retried leg settles the branch it was named as");
        assert_eq!(settled.leg_id, leg.id.to_string());
    }

    /// A branch dialled at a contact an `{aor}` target resolved to names that
    /// AoR; one dialled at a raw URI names none.
    #[test]
    fn a_branch_names_the_aor_it_was_dialled_for() {
        let mut call = CallActor::new(a_leg());
        call.control_dial = true;
        call.control_dial_aors = vec![(
            "sip:201@198.51.100.21:5060".to_string(),
            "sip:201@example.com".to_string(),
        )];
        let registered = b_leg("b-leg-1@siphon", "z9hG4bK-b1");
        let raw = b_leg("b-leg-2@siphon", "z9hG4bK-b2");
        call.add_b_leg(registered.clone());
        call.add_b_leg(raw.clone());
        let named = call
            .record_dial_branch(&registered, "sip:201@198.51.100.21:5060")
            .expect("recorded");
        assert_eq!(named.aor.as_deref(), Some("sip:201@example.com"));
        let unnamed = call
            .record_dial_branch(&raw, "sip:15550100077@198.51.100.7")
            .expect("recorded");
        assert!(unnamed.aor.is_none());
    }

    #[test]
    fn causes_have_their_wire_names() {
        assert_eq!(DialBranchCause::Answered.as_str(), "answered");
        assert_eq!(DialBranchCause::Rejected.as_str(), "rejected");
        assert_eq!(DialBranchCause::Timeout.as_str(), "timeout");
        assert_eq!(DialBranchCause::Cancelled.as_str(), "cancelled");
        assert_eq!(DialBranchCause::Unsent.as_str(), "unsent");
    }
}
