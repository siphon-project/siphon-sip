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
    /// To also score the caller's source toward an auto-ban, use
    /// [`Call::drop_and_ban`].
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::Call;
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// call.drop(Some("no flow claims this number")).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn drop(&self, reason: Option<&str>) -> Result<(), ControlError> {
        self.sip(SipVerb::Drop, drop_args(reason, false))
            .await
            .map(|_| ())
    }

    /// [`Call::drop`], and also score the caller's source address toward an
    /// auto-ban, so a source the controller keeps dropping is refused at the
    /// transport before its next INVITE is parsed.
    ///
    /// Silence alone costs a scanner nothing: it moves on to the next number at
    /// the same rate, below any sensible rate limit. The score goes into
    /// siphon's `security.failed_auth_ban` store and is weighed by how far the
    /// address can be believed: one drop is a strong signal over TCP, TLS, WS
    /// or WSS, whose handshake proved the address, and counts once over UDP,
    /// where a datagram can name any address. A no-op without
    /// `failed_auth_ban`; `trusted_cidrs` are never scored; and only a drop that
    /// succeeds scores, so a refused one leaves the source alone.
    pub async fn drop_and_ban(&self, reason: Option<&str>) -> Result<(), ControlError> {
        self.sip(SipVerb::Drop, drop_args(reason, true))
            .await
            .map(|_| ())
    }
}

/// The `drop` arguments. `ban` goes on the wire only when set, so a plain drop
/// stays the shape a server that predates it reads.
fn drop_args(reason: Option<&str>, ban: bool) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    if let Some(reason) = reason {
        args.insert("reason".to_string(), json!(reason));
    }
    if ban {
        args.insert("ban".to_string(), json!(true));
    }
    serde_json::Value::Object(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_drop_carries_no_ban() {
        assert_eq!(drop_args(None, false), json!({}));
        assert_eq!(
            drop_args(Some("no flow claims this number"), false),
            json!({ "reason": "no flow claims this number" })
        );
    }

    /// `ban` is a boolean on the wire: the server refuses anything else, since a
    /// `"true"` read as false would drop the call and ban nothing.
    #[test]
    fn drop_and_ban_sends_a_boolean_ban() {
        assert_eq!(
            drop_args(Some("scanner"), true),
            json!({ "reason": "scanner", "ban": true })
        );
        assert_eq!(drop_args(None, true), json!({ "ban": true }));
    }
}
