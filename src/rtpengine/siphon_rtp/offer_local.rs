//! `offer_local`: the engine's own offer for a call whose INVITE carried no
//! SDP (a delayed offer, RFC 3261 §13.2.1), and the answer that completes it.
//!
//! The engine allocates the one leg toward the caller and returns an offer for
//! the 2xx. The caller's answer comes back in its ACK, and an ordinary
//! `answer` (the caller's tag as `from_tag`, the 2xx's tag as `to_tag`)
//! completes the call, which then behaves as an `answer_local` one. Until it
//! does the engine takes only `answer`, `delete`, `query`, `attach_x3`,
//! `detach_x3` and `offer_local` on the call (`offer-local-pending`).

use siphon_rtp_proto::Command;

use super::node_features::require_feature;
use super::per_call::scoped_key;
use super::{expect_sdp, profile_flags_from_ng, SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;

/// What `node_info.features` lists when the engine serves `offer_local`.
pub(crate) const OFFER_LOCAL_FEATURE: &str = "offer_local";

impl SiphonRtpClient {
    /// Send an `offer_local`, returning the engine's SDP offer.
    ///
    /// Refused as unsupported, with nothing sent, by an engine that does not
    /// list `offer_local`. A `ws_uri` or `ws_tee` in `flags` is kept by the
    /// engine and acted on when the answer arrives.
    pub async fn offer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        require_feature(
            self.request_in(None, Command::NodeInfo).await?,
            OFFER_LOCAL_FEATURE,
            "offer_local",
            "siphon-rtp (needs an engine that lists offer_local)",
        )?;
        let result = self
            .request(Command::OfferLocal {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        let offer = expect_sdp(result)?;
        self.sessions.insert(
            scoped_key(call_id, super::per_call::frame_scope().as_ref()).into_owned(),
            (),
        );
        Ok(String::from_utf8_lossy(&offer).into_owned())
    }
}

impl SiphonRtpClientSet {
    /// [`SiphonRtpClient::offer_local`], binding the call to the instance that
    /// made the offer.
    pub async fn offer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let offer = self
            .select(call_id)
            .offer_local(call_id, from_tag, flags)
            .await?;
        self.bind_affinity(call_id);
        Ok(offer)
    }

    /// Complete an `offer_local` with the caller's answer (`sdp`, from its
    /// ACK): `from_tag` is the caller's tag and `to_tag` the one the 2xx
    /// carried. The call is then a single-leg one the engine answers itself,
    /// and is told to the observer as such, not as a relay answered. The SDP
    /// the engine returns is its own offer again and is not needed.
    pub async fn complete_offer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<(), RtpEngineError> {
        // The engine kept the WebSocket takeover and tee the offer named and
        // acts on them with this answer: naming them again would re-point a
        // takeover that is not live yet.
        let mut answer_flags = flags.clone();
        answer_flags.ws_uri = None;
        answer_flags.ws_tee = None;
        self.select(call_id)
            .answer_in(None, call_id, from_tag, to_tag, sdp, &answer_flags)
            .await?;
        self.calls.answered_locally(call_id, from_tag, flags);
        Ok(())
    }
}
