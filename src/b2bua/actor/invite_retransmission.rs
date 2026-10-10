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
    /// The caller's INVITE again on another branch: the same request over
    /// another path, a merged request, owed `482 Loop Detected` (RFC 3261
    /// §8.2.2.2).
    Merged,
    /// Not this transaction, or it already has its final response.
    Nothing,
}

impl CallActor {
    /// Whether an INVITE with this Call-ID and From tag, and no To tag, is the
    /// one that opened this call: the caller's dialog is the A-leg's, and the
    /// From tag of a request on it is the tag the call holds as its remote one.
    ///
    /// `false` for a Call-ID this call only dialled (the From tag is then
    /// siphon's own), and for a call siphon placed itself.
    pub fn is_caller_dialog(&self, sip_call_id: &str, from_tag: &str) -> bool {
        self.a_leg.dialog.call_id == sip_call_id
            && self.a_leg.dialog.remote_tag.as_deref() == Some(from_tag)
    }

    /// What an INVITE without a To tag on the caller's dialog is owed: one
    /// that is not the first of its transaction (RFC 3261 §17.2.1, §8.2.2.2).
    ///
    /// On the INVITE's own branch it is a retransmission. While the INVITE has
    /// no final response, that means the caller has not seen a provisional and
    /// gets the most recent one again, or a `100 Trying` when none beyond that
    /// has been sent. Once the call is answered or over, the final response has
    /// its own retransmission and nothing is sent here.
    ///
    /// On another branch it is not this transaction. With the INVITE's own
    /// CSeq number (`cseq_number`, `None` when it cannot be read) it is the
    /// same request arriving over a second path, which is refused; with any
    /// other it is left to the caller's own transaction, as before.
    pub fn invite_retransmission_reply(
        &self,
        via_branch: &str,
        cseq_number: Option<u32>,
    ) -> InviteRetransmissionReply {
        if self.a_leg.branch != via_branch {
            let same_request =
                cseq_number.is_some() && self.a_leg.dialog.remote_cseq == cseq_number;
            return if same_request {
                InviteRetransmissionReply::Merged
            } else {
                InviteRetransmissionReply::Nothing
            };
        }
        if !matches!(self.state, CallState::Calling | CallState::Ringing) {
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
