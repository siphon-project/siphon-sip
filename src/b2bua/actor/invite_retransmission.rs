//! What a retransmission of the caller's INVITE is owed (RFC 3261 §17.2.1).
//!
//! The call keeps the most recent 101-199 it sent the caller
//! (`CallActor::a_leg_last_provisional`), as it went on the wire, until the
//! INVITE has its final response. Bytes, not a parsed message: it is only ever
//! re-sent.

use super::{CallActor, CallState};

/// What [`CallActor::invite_retransmission_reply`] owes a retransmitted INVITE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteRetransmissionReply {
    /// The most recent provisional, as it was sent.
    Provisional(bytes::Bytes),
    /// No provisional beyond `100 Trying` has been sent: that one again.
    Trying,
    /// Not this transaction, or it already has its final response.
    Nothing,
}

impl CallActor {
    /// What a retransmission of the caller's INVITE is owed (RFC 3261 §17.2.1).
    ///
    /// While the INVITE has no final response, a retransmission means the
    /// caller has not seen a provisional and gets the most recent one again, or
    /// a `100 Trying` when none beyond that has been sent. Once the call is
    /// answered or over, the final response has its own retransmission and
    /// nothing is sent here. `via_branch` is the retransmission's: an INVITE on
    /// another branch is not a retransmission of this transaction.
    pub fn invite_retransmission_reply(&self, via_branch: &str) -> InviteRetransmissionReply {
        if self.a_leg.branch != via_branch
            || !matches!(self.state, CallState::Calling | CallState::Ringing)
        {
            return InviteRetransmissionReply::Nothing;
        }
        match &self.a_leg_last_provisional {
            Some(provisional) => InviteRetransmissionReply::Provisional(provisional.clone()),
            None => InviteRetransmissionReply::Trying,
        }
    }

    /// Drop the stored provisional when the call moves to `state`, unless the
    /// INVITE is still without its final response there.
    pub(super) fn forget_provisional_once_final(&mut self, state: &CallState) {
        if !matches!(state, CallState::Calling | CallState::Ringing) {
            self.a_leg_last_provisional = None;
        }
    }
}
