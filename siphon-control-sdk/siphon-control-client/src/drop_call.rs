//! The typed `drop` verb: abandon an un-answered call silently.
//!
//! Split from [`sip`](crate::sip) for the reason
//! [`recording`](crate::recording) is: that file is at its size budget.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::sip::Call;

impl Call {
    /// Abandon this **un-answered** call with nothing on the wire — no final
    /// response, no CANCEL — and release it.
    ///
    /// The third way out of a parked call, and the only silent one.
    /// [`Call::reject`] and an un-answered [`Call::hangup`] both answer, and on
    /// a SIP port reachable from the internet that answer is the prize: a `404`
    /// to an INVITE for a number nobody claims confirms the number to an
    /// enumeration sweep, where silence leaves it unable to tell a missing
    /// extension from a filtered one. Your controller holds the only knowledge
    /// of which numbers are real, so it is the only thing that can decide an
    /// INVITE is unsolicited.
    ///
    /// Not a way to hang up. An answered dialog is owed a BYE (RFC 3261 §15), so
    /// an answered call resolves to [`ControlError::Command`] with
    /// `ControlErrorCode::InvalidState` rather than being orphaned — use
    /// [`Call::hangup`] there. A call that has already ended is `not_found`.
    ///
    /// `reason` is for the record, not the wire: it reaches siphon's log and the
    /// CDR (`sip_reason`, beside `disconnect_initiator: "control"` and no
    /// response code), so a dropped call reads as deliberate rather than as a
    /// leak.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::Call;
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// call.drop(Some("no flow claims this number")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn drop(&self, reason: Option<&str>) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        if let Some(reason) = reason {
            args.insert("reason".to_string(), json!(reason));
        }
        self.sip(SipVerb::Drop, serde_json::Value::Object(args))
            .await
            .map(|_| ())
    }
}
