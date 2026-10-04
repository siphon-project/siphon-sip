//! Giving up on a controller's `dial` while it still rings.
//!
//! A dial ends on its own in three ways: a phone answers, every phone fails, or
//! the ring timeout passes. This is the fourth, and the only one the controller
//! chooses: the phones are CANCELled (RFC 3261 §9.1) and the caller is left as
//! the dial found it — answered and anchored for a bridging dial, unanswered and
//! parked for a connecting one — still owned and free to be dialled for again.
//!
//! The caller's own dialog is never touched, which is the whole difference from
//! `hangup` (it ends the caller) and from letting the timeout run.

use crate::dispatcher::b2bua::CancelRequest;
use crate::dispatcher::*;

/// The `reason` a cancelled dial fails with when the controller names none.
pub const DIAL_CANCELLED: &str = "cancelled";

/// Which dial a cancel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialCancelled {
    /// A bridging dial: its phones were rung for an answered caller.
    Bridge,
    /// A connecting dial: its phones were rung for a caller still waiting.
    Connect,
}

impl DialCancelled {
    /// The `on_answer` value the dial was issued with.
    pub fn on_answer(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Connect => "connect",
        }
    }
}

/// Why a dial was not cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialCancelRefusal {
    /// There is no such call.
    Gone,
    /// No dial is ringing for the call.
    NoDial,
    /// A phone has answered and its bridge to the caller is in motion.
    Answered,
}

impl DialCancelRefusal {
    /// The machine-readable reason a refusal carries in its details.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Gone => "call_gone",
            Self::NoDial => "no_dial_in_progress",
            Self::Answered => "dial_answered",
        }
    }
}

impl std::fmt::Display for DialCancelRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone => write!(formatter, "call is gone"),
            Self::NoDial => write!(
                formatter,
                "no dial is ringing for this call — it already ended in DialAnswered or DialFailed, or none was issued"
            ),
            Self::Answered => write!(
                formatter,
                "a phone has answered and is being bridged to the caller — wait for DialAnswered or BridgeFailed; cancelling now would release a leg the caller's media is being pointed at"
            ),
        }
    }
}

/// Cancel the dial ringing for the call behind `sip_call_id`, reporting it as
/// failed with `reason`.
///
/// A bridging dial fails with `DialFailed {code: 487, cause: reason}` after a
/// `DialBranchFailed` for each phone; a connecting dial with `DialFailed {code:
/// 487}`. Either way the caller's dialog is not touched.
pub fn b2bua_cancel_dial_with_state(
    state: &DispatcherState,
    sip_call_id: &str,
    reason: &str,
) -> Result<DialCancelled, DialCancelRefusal> {
    let internal_call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(DialCancelRefusal::Gone)?;

    if state.dial_bridges.is_ringing(sip_call_id) {
        // A phone whose bridge is in motion is the one leg a cancel cannot
        // release: the bridge has re-pointed the caller's media at it, and a
        // bridged leg that goes takes its peer with it.
        if state.dial_bridges.is_bridging(sip_call_id) {
            return Err(DialCancelRefusal::Answered);
        }
        return match state.dial_bridges.request_cancel(sip_call_id, reason) {
            // Between the claim and the group: the dial ends as it starts.
            CancelRequest::Deferred => Ok(DialCancelled::Bridge),
            CancelRequest::Group(group_id) => {
                let cancelled = cancel_originate_group(
                    state,
                    &group_id,
                    OriginateGroupEnd::Cancelled {
                        reason: reason.to_string(),
                    },
                );
                if cancelled {
                    info!(
                        caller = %sip_call_id,
                        %group_id,
                        %reason,
                        "control plane: dial — cancelled by its controller, the caller stays answered"
                    );
                    Ok(DialCancelled::Bridge)
                } else {
                    // Concluded a moment ago: its own outcome is on its way.
                    Err(DialCancelRefusal::NoDial)
                }
            }
            CancelRequest::Gone => Err(DialCancelRefusal::NoDial),
        };
    }

    if !state.call_actors.is_control_dial(&internal_call_id) {
        return Err(DialCancelRefusal::NoDial);
    }
    cancel_connecting_dial(&internal_call_id, state);
    info!(
        call_id = %internal_call_id,
        %reason,
        "control plane: dial — cancelled by its controller, the caller stays unanswered and parked"
    );
    Ok(DialCancelled::Connect)
}

/// CANCEL every branch of a connecting dial and report it failed, as its ring
/// timeout does, with the hunt's remaining targets and its deadline dropped so
/// neither can move the call afterwards.
fn cancel_connecting_dial(call_id: &str, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        for b_leg in &call.b_legs {
            state.b2bua_retransmits.disarm_branch(&b_leg.branch);
        }
    }
    // Named as cancelled ahead of the CANCELs, and before the hunt could place
    // another attempt.
    control_dial_open_branches_ended(
        call_id,
        487,
        "Request Terminated",
        crate::b2bua::actor::DialBranchCause::Cancelled,
        state,
    );
    state.call_actors.abandon_dial_hunt(call_id);
    crate::dispatcher::b2bua::shutdown::cancel_pending_branches(call_id, state);
    report_control_dial_failure(call_id, 487, "Request Terminated", false, state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_names_its_reason() {
        assert_eq!(DialCancelRefusal::Gone.reason(), "call_gone");
        assert_eq!(DialCancelRefusal::NoDial.reason(), "no_dial_in_progress");
        assert_eq!(DialCancelRefusal::Answered.reason(), "dial_answered");
        assert!(DialCancelRefusal::Answered
            .to_string()
            .contains("BridgeFailed"));
    }

    #[test]
    fn a_cancelled_dial_says_which_kind_it_was() {
        assert_eq!(DialCancelled::Bridge.on_answer(), "bridge");
        assert_eq!(DialCancelled::Connect.on_answer(), "connect");
    }
}
