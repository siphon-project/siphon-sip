//! An SDP offer on the INVITE of a leg a bridging `dial` places
//! (`offer: "early"`), for peers that refuse a delayed-offer INVITE.
//!
//! A bridging dial rings each phone as a call siphon places itself. By default
//! that INVITE goes out offerless: the phone offers in its 2xx and the engine
//! answers it locally, on the ACK, and the bridge then re-INVITEs the phone
//! with the pair's media. A peer that refuses an INVITE with no SDP never gets
//! that far.
//!
//! With `offer: "early"` the leg is offered what the bridge would have offered
//! it, made before the INVITE instead of after the answer: the bridge's own
//! [`crate::b2bua::bridge::MediaStep::Offer`] — the caller's media description
//! on an engine call of the leg's own beside the caller's session, shaped by
//! the leg's media profile ([`allocate_leg_offer`]). The leg's 2xx carries the
//! answer (RFC 3264 §5), and when the leg is bridged that answer completes the
//! allocation and the caller is re-INVITEd with the result
//! ([`super::bridge_offered`]): the phone is never re-INVITEd.
//!
//! The engine relays nothing on an allocation until it is answered, so a phone
//! sending early media on its allocation reaches nobody: the caller keeps
//! hearing its ringback on its own session until the bridge. Nothing a
//! provisional carries is given to the engine for the same reason; originated
//! legs offer no `100rel`, so the 2xx is the one reliable response the answer
//! can come in (RFC 3261 §13.2.1).
//!
//! The allocation is the leg's media session, stored under the leg's own SIP
//! Call-ID from the moment it is made, so every way the leg ends — rejected,
//! CANCELled, timed out, released after another answer, its bridge failing —
//! deletes it through the store; the bridge alone takes it over instead.

use crate::dispatcher::*;

/// The answered caller a bridging dial's early-offer legs are offered from:
/// what the engine is told the offering party looks like, as the bridge tells
/// it ([`crate::b2bua::bridge::AnchorOffer`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegOfferCaller {
    /// The caller's SIP Call-ID, the dialog whose SDP the offer carries.
    pub sip_call_id: String,
    /// The caller's tag on its media session: the monologue each allocation
    /// is keyed on, as the pair's session is.
    pub from_tag: String,
    /// The caller endpoint's media description, restated as siphon's own
    /// `sendrecv` (RFC 3264 §6.1), as the bridge offers it.
    pub sdp: Vec<u8>,
    /// Where the caller signals from, pinned as its media ingress when its
    /// policy asks for it.
    pub source: std::net::IpAddr,
    /// Whose `received_from` policy pins the caller's ingress
    /// ([`crate::b2bua::bridge::bridge_anchor_ingress`]).
    pub ingress: crate::rtpengine::session::SideFlags,
    /// Whether the caller's session already relays to a second party (an
    /// earlier bridge, since parted). Such a session is renegotiated in place
    /// by a bridge, which an allocation made per leg ahead of the answer
    /// cannot be, so an early offer is refused for it.
    pub relaying: bool,
}

impl LegOfferCaller {
    /// The caller as a bridge snapshot of it sees it; `None` when its media is
    /// not anchored.
    pub fn of_snapshot(caller: &BridgeLegSnapshot) -> Option<Self> {
        use crate::b2bua::bridge::{bridge_anchor_ingress, set_media_direction, MediaDirection};
        let media = caller.media.as_ref()?;
        Some(Self {
            sip_call_id: caller.sip_call_id.clone(),
            from_tag: media.from_tag.clone(),
            sdp: set_media_direction(&caller.last_sdp, MediaDirection::SendRecv),
            source: caller.source_ip,
            ingress: bridge_anchor_ingress(None, media),
            relaying: media.relaying,
        })
    }
}

/// Whether any of `targets` resolves to an early offer, its own `offer` over
/// the dial's (`dial_offer`).
pub fn any_early_offer(targets: &[DialTarget], dial_offer: Option<DialOffer>) -> bool {
    targets
        .iter()
        .any(|target| target.offer.or(dial_offer) == Some(DialOffer::Early))
}

/// Allocate the offer a leg's INVITE carries: the caller's media description
/// offered under the leg's media `profile`, on an engine call of the leg's own.
/// Returns the offer and the allocation it was made on.
///
/// Runs the bridge's own offer step ([`bridge_run_media_step`]), so the leg is
/// offered exactly what a bridge would offer it, pinned by the same policies.
pub(crate) fn allocate_leg_offer(
    caller: &LegOfferCaller,
    profile: &str,
    state: &DispatcherState,
) -> Result<(Vec<u8>, crate::b2bua::actor::OriginateOffer), OriginateError> {
    use crate::b2bua::bridge::{BridgeError, MediaStep};

    if caller.relaying {
        return Err(OriginateError::Unsupported(
            "offer \"early\" needs the caller on a media session of its own; it relays to \
             another party since an earlier bridge"
                .to_string(),
        ));
    }
    let backend = state.rtpengine_set.as_ref().ok_or_else(|| {
        OriginateError::Unsupported(
            "offer \"early\" requires a media backend, none configured".to_string(),
        )
    })?;
    let media_call_id = crate::b2bua::actor::generate_call_id();
    let step = MediaStep::Offer {
        media_call_id: media_call_id.clone(),
        from_tag: caller.from_tag.clone(),
        profile: profile.to_string(),
        sdp: caller.sdp.clone(),
        received_from: Some(caller.source),
        ingress: caller.ingress.clone(),
        sip_call_id: caller.sip_call_id.clone(),
    };
    let profiles = state.rtpengine_profiles.as_ref();
    let offered = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(bridge_run_media_step(backend, profiles, &step))
    });
    match offered {
        Ok(Some(offer)) => Ok((
            offer,
            crate::b2bua::actor::OriginateOffer {
                media_call_id,
                offerer_tag: caller.from_tag.clone(),
            },
        )),
        Ok(None) => Err(OriginateError::Unavailable(
            "the media engine returned no offer for the leg".to_string(),
        )),
        Err(BridgeError::Unsupported(detail)) => Err(OriginateError::Unsupported(detail)),
        Err(error) => Err(OriginateError::Unavailable(format!(
            "the media engine could not allocate the leg's offer: {error}"
        ))),
    }
}

/// The media session an early-offer leg holds from its INVITE until it is
/// bridged: the allocation, stored under the leg's own SIP Call-ID so every
/// teardown of the leg deletes it.
pub(crate) fn leg_offer_session(
    leg_sip_call_id: &str,
    profile: &str,
    offered: &crate::b2bua::actor::OriginateOffer,
) -> crate::rtpengine::MediaSession {
    crate::rtpengine::MediaSession {
        call_id: leg_sip_call_id.to_string(),
        rtpengine_call_id: offered.media_call_id.clone(),
        from_tag: offered.offerer_tag.clone(),
        to_tag: None,
        profile: profile.to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    }
}

/// Why a 2xx to an INVITE that carried an offer cannot be taken.
pub(crate) const NO_ANSWER_STATUS: u16 = 488;

/// The answer a 2xx to an INVITE carrying siphon's offer has to carry
/// (RFC 3261 §13.2.1, RFC 3264 §5): its SDP, the SDP part of a multipart body
/// included (RFC 5621). A 2xx without one leaves the offer unanswered, a
/// protocol error the leg cannot be bridged across: the reason is returned.
pub(crate) fn offered_leg_answer(response: &SipMessage) -> Result<Vec<u8>, String> {
    if response.body.iter().all(u8::is_ascii_whitespace) {
        return Err(
            "the 2xx carries no SDP answer to the offer its INVITE carried (RFC 3261 §13.2.1)"
                .to_string(),
        );
    }
    crate::media::body::sdp_from_body(message_content_type(response), &response.body)
        .map_err(|detail| format!("the 2xx carries no SDP answer to the INVITE's offer: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offer_modes_parse_by_their_control_names() {
        assert_eq!(DialOffer::parse("early"), Some(DialOffer::Early));
        assert_eq!(DialOffer::parse("delayed"), Some(DialOffer::Delayed));
        assert_eq!(DialOffer::parse("Early"), None, "names are exact");
        assert_eq!(DialOffer::parse("late"), None);
        assert_eq!(DialOffer::default(), DialOffer::Delayed);
        for mode in [DialOffer::Early, DialOffer::Delayed] {
            assert_eq!(DialOffer::parse(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn a_targets_own_offer_mode_outranks_the_dials() {
        let target = |offer| DialTarget {
            uri: "sip:201@198.51.100.7".to_string(),
            offer,
            ..Default::default()
        };
        assert!(any_early_offer(&[target(None)], Some(DialOffer::Early)));
        assert!(!any_early_offer(
            &[target(Some(DialOffer::Delayed))],
            Some(DialOffer::Early)
        ));
        assert!(any_early_offer(
            &[target(None), target(Some(DialOffer::Early))],
            None
        ));
        assert!(
            !any_early_offer(&[target(None)], None),
            "delayed by default"
        );
    }

    fn response(content_type: Option<&str>, body: &str) -> SipMessage {
        let content_type = content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        parse_sip_message_bytes(
            format!(
                concat!(
                    "SIP/2.0 200 OK\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-offered\r\n",
                    "From: <sip:caller@example.com>;tag=caller\r\n",
                    "To: <sip:201@example.com>;tag=phone\r\n",
                    "Call-ID: offered@example.com\r\n",
                    "CSeq: 1 INVITE\r\n",
                    "{}",
                    "Content-Length: {}\r\n\r\n{}"
                ),
                content_type,
                body.len(),
                body
            )
            .as_bytes(),
        )
        .unwrap()
    }

    const ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n";

    #[test]
    fn a_2xx_answers_the_offer_with_its_sdp() {
        assert_eq!(
            offered_leg_answer(&response(Some("application/sdp"), ANSWER)).unwrap(),
            ANSWER.as_bytes()
        );
    }

    #[test]
    fn a_2xx_with_no_sdp_is_a_protocol_error_after_an_offer() {
        let reason = offered_leg_answer(&response(None, "")).unwrap_err();
        assert!(reason.contains("13.2.1"), "{reason}");
        assert!(offered_leg_answer(&response(Some("text/plain"), "hello")).is_err());
    }
}
