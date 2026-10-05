//! The typed `cancel_dial` verb: give up on a dial that still rings.
//!
//! Split from [`sip`](crate::sip) for the reason
//! [`recording`](crate::recording) is: that file is at its size budget.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::sip::Call;

impl Call {
    /// Give up on the dial ringing for this call and leave the caller alone.
    ///
    /// Every phone still ringing is CANCELled (RFC 3261 §9.1), each reported by
    /// `DialBranchFailed` with cause `cancelled`, and the dial ends in
    /// `DialFailed` with code 487. The caller is exactly as the dial found it —
    /// answered and anchored for a bridging dial, unanswered and parked for a
    /// connecting one — still this application's, and free to be dialled for
    /// again. [`Call::hangup`] ends the caller as well, and letting the ring
    /// timeout run keeps the phones ringing until it does.
    ///
    /// `reason` is reported as the `cause` of a bridging dial's `DialFailed`
    /// (default `cancelled`), so the handler that hears it can tell its own
    /// cancel from a dial that failed by itself.
    ///
    /// Resolves to [`ControlError::Command`] with
    /// `ControlErrorCode::InvalidState` when nothing is ringing (`details.reason`
    /// is `no_dial_in_progress`), and once a phone has answered and is being
    /// bridged (`dial_answered`), whose outcome arrives as `DialAnswered` or
    /// `BridgeFailed`.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::Call;
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// call.cancel_dial(Some("gave_up")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cancel_dial(&self, reason: Option<&str>) -> Result<(), ControlError> {
        self.sip(SipVerb::CancelDial, cancel_dial_args(reason))
            .await
            .map(|_| ())
    }
}

/// The `cancel_dial` arguments: the reason only when one is given, so the
/// server's default applies otherwise.
fn cancel_dial_args(reason: Option<&str>) -> serde_json::Value {
    match reason {
        Some(reason) => json!({ "reason": reason }),
        None => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reason_goes_on_the_wire_only_when_given() {
        assert_eq!(cancel_dial_args(None), json!({}));
        assert_eq!(
            cancel_dial_args(Some("gave_up")),
            json!({ "reason": "gave_up" })
        );
    }
}
