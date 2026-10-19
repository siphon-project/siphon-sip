//! Growing a call the engine answered itself (`answer_local`) into a relay
//! toward a far party, and taking the far party away again.
//!
//! The shape is a pre-call announcement: the caller is answered in early media
//! by the engine, hears a prompt, and is then connected to a callee. The caller
//! already holds its answer, which may not change without a new offer (RFC 3261
//! §13.2.1, RFC 3264 §8), so the engine binds a far leg behind it (`offer_far`)
//! and the callee's answer completes it with an ordinary `answer`, which gives
//! back the caller's original answer unchanged.

use siphon_rtp_proto::Command;

use super::{expect_ok, expect_sdp, profile_flags_from_ng, SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;

impl SiphonRtpClient {
    /// Send an `offer_far`, returning the SDP offer for the far leg.
    pub async fn offer_far(
        &self,
        call_id: &str,
        from_tag: &str,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::OfferFar {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        expect_sdp(result)
    }

    /// Drop the far leg `offer_far` grew, answered (`to_tag`) or not, and put
    /// the caller back on the engine's own pipeline. The call itself stays, so
    /// its active-session entry does too.
    pub async fn delete_far_leg(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let result = self
            .request(Command::Delete {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: Some(to_tag.to_string()),
            })
            .await?;
        expect_ok(result)
    }
}

impl SiphonRtpClientSet {
    /// `offer_far` on the instance already holding the call.
    pub async fn offer_far(
        &self,
        call_id: &str,
        from_tag: &str,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.select(call_id)
            .offer_far(call_id, from_tag, flags)
            .await
    }

    /// Drop the far leg on the instance already holding the call.
    pub async fn delete_far_leg(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .delete_far_leg(call_id, from_tag, to_tag)
            .await
    }
}
