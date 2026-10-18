//! What `rtpengine.offer()` sends to the media engine.
//!
//! A script hands over the offering party's SDP one of two ways. The message
//! mode reads it off a SIP request (or a Call's INVITE) and writes the rewritten
//! SDP back into that body. The raw mode (`sdp=`) is for an SDP that reached the
//! script some other way, such as one party's new SDP on an access transfer that
//! arrives in a different dialog: the script names the offerer and passes the
//! SDP, and gets the rewritten one back. Nothing is read from or written into a
//! message body.
//!
//! Either way, an offer on a call this process has already anchored is a
//! re-offer and goes to the engine as `reoffer`, addressed by the call-id the
//! engine knows the call by, which is not the SIP Call-ID once a transfer has
//! re-anchored the call. On any other call it is the first offer, and it
//! records the media session.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use tracing::debug;

use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::session::{MediaSession, MediaSessionStore};
use crate::rtpengine::MediaBackend;
use crate::sip::message::SipMessage;

use super::{
    extract_delete_params, extract_message, extract_offer_params, extract_raw_sdp,
    extract_source_ip, PyCall, PyReply, PyRequest,
};

/// What an `offer` call hands the engine, from either mode.
pub(super) struct OfferInput {
    /// SIP Call-ID of the call: the media session's store key.
    pub(super) call_id: String,
    /// The engine tag of the offering party.
    pub(super) from_tag: String,
    /// The offering party's SDP.
    pub(super) sdp: Vec<u8>,
    /// The message the rewritten SDP goes back into: `None` in raw mode.
    pub(super) body: Option<Arc<Mutex<SipMessage>>>,
    /// Where `call_id` / `from_tag` came from, for a `ws_uri` template.
    pub(super) identity: Option<Arc<Mutex<SipMessage>>>,
    /// Where the offerer signals from: none in raw mode, whose SDP did not
    /// arrive in a message from that party, so a profile's `received_from`
    /// does not gate its media.
    pub(super) source_ip: Option<String>,
}

impl OfferInput {
    /// Read the offer off `request` (message mode), or take `sdp` and the
    /// offerer `request` names (raw mode).
    pub(super) fn resolve(
        request: &Bound<'_, PyAny>,
        sdp: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if let Some(sdp) = sdp {
            let sdp = extract_raw_sdp(sdp, "offer")?;
            let target = resolve_raw_offer_target(request)?;
            return Ok(Self {
                call_id: target.call_id,
                from_tag: target.from_tag,
                sdp,
                body: None,
                identity: target.message,
                source_ip: None,
            });
        }
        let message = extract_message(request)?;
        let (call_id, from_tag, sdp) = extract_offer_params(&message)?;
        Ok(Self {
            call_id,
            from_tag,
            sdp,
            body: Some(Arc::clone(&message)),
            identity: Some(message),
            source_ip: extract_source_ip(request),
        })
    }
}

/// The offerer a raw-SDP `offer` names.
pub(super) struct RawOfferTarget {
    /// SIP Call-ID of the call: the media session's store key.
    pub(super) call_id: String,
    /// The engine tag of the party whose SDP this is.
    pub(super) from_tag: String,
    /// Where `call_id` / `from_tag` came from, for `{from_user}` / `{to_user}`
    /// in a `ws_uri`. `None` for a tuple target.
    pub(super) message: Option<Arc<Mutex<SipMessage>>>,
}

/// Resolve the offerer a raw-SDP `offer` names: a Request, Reply or Call (its
/// Call-ID and From-tag, as the message mode reads them), or a
/// `(call_id, from_tag)` tuple. A bare `call_id` does not: it names no party,
/// and the engine resolves the re-offering party by its tag.
pub(super) fn resolve_raw_offer_target(target: &Bound<'_, PyAny>) -> PyResult<RawOfferTarget> {
    if target.cast::<PyRequest>().is_ok()
        || target.cast::<PyReply>().is_ok()
        || target.cast::<PyCall>().is_ok()
    {
        let message = extract_message(target)?;
        let (call_id, from_tag) = extract_delete_params(&message)?;
        return Ok(RawOfferTarget {
            call_id,
            from_tag,
            message: Some(message),
        });
    }
    // Checked before the pair form: a `str` is itself a sequence of 1-char strings.
    if target.extract::<String>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "rtpengine.offer(sdp=...) needs the offerer's tag: pass the Call, Request \
             or Reply, or a (call_id, from_tag) tuple, not a bare call_id",
        ));
    }
    if let Ok((call_id, from_tag)) = target.extract::<(String, String)>() {
        return Ok(RawOfferTarget {
            call_id,
            from_tag,
            message: None,
        });
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "rtpengine.offer(sdp=...) target must be a Call, Request or Reply, or a \
         (call_id, from_tag) tuple",
    ))
}

/// An offer ready for the engine, from either mode.
pub(super) struct OfferCommand {
    /// SIP Call-ID of the call: the media session's store key.
    pub(super) call_id: String,
    /// The call-id the engine knows the call by: the stored session's own on a
    /// re-offer, the SIP Call-ID on a first offer.
    pub(super) engine_call_id: String,
    /// The engine tag of the offering party.
    pub(super) from_tag: String,
    pub(super) sdp: Vec<u8>,
    /// The call is already in the session store.
    pub(super) is_reoffer: bool,
    /// Recorded on the session a first offer creates.
    pub(super) profile: String,
    pub(super) ws_uri: Option<String>,
}

impl OfferCommand {
    /// The command for the offer of `from_tag` on the call stored, or to be
    /// stored, under `call_id`.
    pub(super) fn new(
        sessions: &MediaSessionStore,
        call_id: String,
        from_tag: String,
        sdp: Vec<u8>,
        profile: String,
        ws_uri: Option<String>,
    ) -> Self {
        // A call this process has already anchored is a *re*-offer — a
        // re-INVITE or an UPDATE, the shape hold/unhold and an ICE restart
        // arrive in, or an access transfer re-pointing one party. It has to keep
        // the ports it already holds, so it goes out as `reoffer`; a plain
        // `offer` on a live call-id replaces it on the siphon-rtp backend,
        // taking its WebSocket bridge, tee and SIPREC subscription with it.
        // Address the engine by the session's own id, not the SIP Call-ID: a
        // siphon-terminated transfer re-anchors the surviving pair on a fresh
        // engine call-id while the store key stays the SIP one.
        let existing = sessions.get(&call_id);
        let engine_call_id = existing
            .as_ref()
            .map(|session| session.rtpengine_id().to_string())
            .unwrap_or_else(|| call_id.clone());
        Self {
            is_reoffer: existing.is_some(),
            engine_call_id,
            call_id,
            from_tag,
            sdp,
            profile,
            ws_uri,
        }
    }

    /// Send the offer to the engine and return the SDP it rewrote. A first
    /// offer records the media session.
    pub(super) async fn send(
        self,
        client: &MediaBackend,
        sessions: &MediaSessionStore,
        flags: &NgFlags,
    ) -> PyResult<Vec<u8>> {
        let rewritten_sdp = if self.is_reoffer {
            client
                .reoffer(&self.engine_call_id, &self.from_tag, &self.sdp, flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.offer failed (re-offer): {error}"
                    ))
                })?
        } else {
            client
                .offer(&self.engine_call_id, &self.from_tag, &self.sdp, flags)
                .await
                .map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "rtpengine.offer failed: {error}"
                    ))
                })?
        };

        debug!(
            call_id = %self.call_id,
            sdp_len = rewritten_sdp.len(),
            "RTPEngine offer: SDP rewritten"
        );

        // Only an *initial* offer creates the session. Re-inserting on a
        // re-offer would reset `rtpengine_call_id` to the SIP Call-ID —
        // stranding a transfer-re-anchored call, whose engine id is
        // deliberately different — and clear the `to_tag` the answer set,
        // which is what every later `answer`/`delete` addresses the leg by.
        if !self.is_reoffer {
            sessions.insert(MediaSession {
                rtpengine_call_id: self.call_id.clone(),
                call_id: self.call_id,
                from_tag: self.from_tag,
                to_tag: None,
                profile: self.profile,
                ws_uri: self.ws_uri,
                ws_tee: flags.ws_tee.clone(),
                ws_bridge_attached: false,
                bridge_sides: None,
                created_at: std::time::Instant::now(),
            });
        }

        Ok(rewritten_sdp)
    }
}
