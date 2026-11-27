//! `webrtc: auto` — a media profile half that becomes WebRTC only where the
//! party it faces is a WebRTC endpoint.
//!
//! A half marked `webrtc: auto` is written for the ordinary peer (plain RTP,
//! SDES, a latching relay) and takes the WebRTC media set when the party it
//! faces is a browser: `UDP/TLS/RTP/SAVPF`, ICE forced, DTLS keying, and RTCP
//! multiplexing required (RFC 8829 §5.1.1, RFC 5764, RFC 9429 §4.1.1). One
//! profile then serves a ring that reaches a browser and a desk phone together.
//!
//! What "faces a WebRTC endpoint" means depends on what is known of the party:
//!
//! * the half facing a forked contact (the profile's `offer` half) is decided
//!   by the transport that contact registered over, `ws` or `wss` (RFC 7118) —
//!   siphon has not yet seen an SDP from it;
//! * the half facing the party that made the offer (the `answer` half) is
//!   decided by that offer: `UDP/TLS/RTP/SAVPF` carrying `a=ice-ufrag` and
//!   `a=fingerprint`, the pair no non-WebRTC offerer sends together.

use crate::transport::Transport;

/// The media protocol RFC 8829 / RFC 5764 name for a browser's audio.
pub const WEBRTC_PROTOCOL: &str = "UDP/TLS/RTP/SAVPF";

/// The name a profile takes once its `webrtc: auto` halves are resolved:
/// `base#webrtc-offer`, `base#webrtc-answer` or `base#webrtc-both`. The `#`
/// cannot be typed into a `media.profiles` key by accident, and a name with
/// neither half WebRTC is the base itself.
pub(super) fn variant_name(base: &str, offer: bool, answer: bool) -> String {
    match (offer, answer) {
        (false, false) => base.to_string(),
        (true, false) => format!("{base}#webrtc-offer"),
        (false, true) => format!("{base}#webrtc-answer"),
        (true, true) => format!("{base}#webrtc-both"),
    }
}

/// Whether a SIP transport is WebSocket, the one a browser registers over
/// (RFC 7118).
pub fn transport_is_webrtc(transport: Transport) -> bool {
    matches!(transport, Transport::WebSocket | Transport::WebSocketSecure)
}

/// Whether `sdp` is a WebRTC offer: its first live audio section (an `m=audio`
/// whose port is not 0) is `UDP/TLS/RTP/SAVPF` and carries both `a=ice-ufrag`
/// and `a=fingerprint`, each its own or inherited from the session level.
///
/// `a=ice-ufrag` (RFC 8839 §5.4) and `a=fingerprint` (RFC 8122 §5) are valid at
/// either level, and a media-level one overrides the session's, so the
/// verdict is made for the one section the answer half will shape, never over
/// attributes pooled from every section: an audio section with a fingerprint
/// and no ICE is not made WebRTC by a video section that has an ice-ufrag.
///
/// The protocol alone is not enough. A desk phone doing SDES-over-DTLS-less
/// SAVPF names `RTP/SAVPF`, and a plain DTLS-SRTP peer without ICE would be
/// answered with an ICE-forcing profile it cannot take.
pub fn offer_is_webrtc(sdp: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(sdp) else {
        return false;
    };
    // `a=` lines before the first `m=` are session level; after it they belong
    // to the section being read, which only matters while that is the live
    // audio section.
    let mut session = (false, false);
    let mut section = (false, false);
    let mut seen_media = false;
    let mut in_audio = false;
    let mut audio_protocol = false;
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(media) = line.strip_prefix("m=") {
            if in_audio {
                break;
            }
            seen_media = true;
            let mut fields = media.split_whitespace();
            let kind = fields.next();
            let port = fields.next();
            in_audio = kind == Some("audio") && port != Some("0");
            audio_protocol = in_audio && fields.next() == Some(WEBRTC_PROTOCOL);
        } else if !seen_media || in_audio {
            let target = if seen_media {
                &mut section
            } else {
                &mut session
            };
            if line.starts_with("a=ice-ufrag:") {
                target.0 = true;
            } else if line.starts_with("a=fingerprint:") {
                target.1 = true;
            }
        }
    }
    in_audio && audio_protocol && (session.0 || section.0) && (session.1 || section.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdp(protocol: &str, attributes: &[&str]) -> Vec<u8> {
        let mut text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 9 {protocol} 111\r\n"
        );
        for attribute in attributes {
            text.push_str(&format!("a={attribute}\r\n"));
        }
        text.into_bytes()
    }

    #[test]
    fn websocket_transports_are_webrtc_and_the_rest_are_not() {
        assert!(transport_is_webrtc(Transport::WebSocket));
        assert!(transport_is_webrtc(Transport::WebSocketSecure));
        for transport in [Transport::Udp, Transport::Tcp, Transport::Tls] {
            assert!(!transport_is_webrtc(transport), "{transport:?}");
        }
    }

    #[test]
    fn a_savpf_offer_with_ice_and_fingerprint_is_webrtc() {
        let offer = sdp(
            WEBRTC_PROTOCOL,
            &[
                "ice-ufrag:abcd",
                "ice-pwd:secret",
                "fingerprint:sha-256 AA:BB",
            ],
        );
        assert!(offer_is_webrtc(&offer));
    }

    #[test]
    fn a_savpf_offer_missing_ice_ufrag_is_not_webrtc() {
        let offer = sdp(WEBRTC_PROTOCOL, &["fingerprint:sha-256 AA:BB"]);
        assert!(!offer_is_webrtc(&offer));
    }

    #[test]
    fn a_savpf_offer_missing_fingerprint_is_not_webrtc() {
        let offer = sdp(WEBRTC_PROTOCOL, &["ice-ufrag:abcd"]);
        assert!(!offer_is_webrtc(&offer));
    }

    #[test]
    fn ice_and_fingerprint_on_another_protocol_are_not_webrtc() {
        for protocol in ["RTP/AVP", "RTP/SAVPF", "RTP/SAVP"] {
            let offer = sdp(protocol, &["ice-ufrag:abcd", "fingerprint:sha-256 AA:BB"]);
            assert!(!offer_is_webrtc(&offer), "{protocol}");
        }
    }

    fn raw(text: &str) -> Vec<u8> {
        text.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn attributes_in_another_section_do_not_complete_the_audio_section() {
        // Audio is SAVPF with a fingerprint but no ICE; the video section has
        // the ice-ufrag. Pooled over the SDP that looks WebRTC; audio is not.
        let offer = raw("v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\nc=IN IP4 192.0.2.10\na=fingerprint:sha-256 AA:BB\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 192.0.2.10\na=ice-ufrag:abcd\n");
        assert!(!offer_is_webrtc(&offer));
    }

    #[test]
    fn session_level_ice_and_fingerprint_are_inherited_by_the_audio_section() {
        let offer = raw("v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\n\
             a=ice-ufrag:abcd\na=fingerprint:sha-256 AA:BB\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\nc=IN IP4 192.0.2.10\n");
        assert!(offer_is_webrtc(&offer));
    }

    #[test]
    fn a_session_level_attribute_and_a_media_level_one_combine_for_the_section() {
        let offer = raw(
            "v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\na=fingerprint:sha-256 AA:BB\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\nc=IN IP4 192.0.2.10\na=ice-ufrag:abcd\n",
        );
        assert!(offer_is_webrtc(&offer));
    }

    #[test]
    fn a_rejected_audio_section_does_not_decide_the_offer() {
        // The first audio section is port 0 (rejected); the live one decides.
        let offer = raw("v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\n\
             m=audio 0 UDP/TLS/RTP/SAVPF 111\na=ice-ufrag:abcd\na=fingerprint:sha-256 AA:BB\n\
             m=audio 9 RTP/AVP 0\nc=IN IP4 192.0.2.10\n");
        assert!(!offer_is_webrtc(&offer));
        let live = raw("v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\n\
             m=audio 0 RTP/AVP 0\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\nc=IN IP4 192.0.2.10\na=ice-ufrag:abcd\na=fingerprint:sha-256 AA:BB\n");
        assert!(offer_is_webrtc(&live));
    }

    #[test]
    fn an_offer_without_an_audio_section_is_not_webrtc() {
        let offer = raw("v=0\no=- 1 1 IN IP4 192.0.2.10\ns=-\nt=0 0\n\
             a=ice-ufrag:abcd\na=fingerprint:sha-256 AA:BB\n\
             m=video 9 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 192.0.2.10\n");
        assert!(!offer_is_webrtc(&offer));
    }

    #[test]
    fn a_body_that_is_not_utf8_is_not_webrtc() {
        assert!(!offer_is_webrtc(&[0xff, 0xfe, 0x00]));
        assert!(!offer_is_webrtc(b""));
    }

    // ---- Resolving a profile's `webrtc: auto` halves ----

    use crate::config::{MediaProfileConfig, NgFlagsConfig, WebrtcMode};
    use crate::rtpengine::ProfileRegistry;
    use std::collections::HashMap;

    /// A desk-phone profile: SDES toward the callee, plain toward the caller,
    /// and both halves `auto` so a browser on either side gets WebRTC.
    fn registry_with_auto(offer_auto: bool, answer_auto: bool) -> ProfileRegistry {
        let half = |protocol: &str, auto: bool| NgFlagsConfig {
            transport_protocol: Some(protocol.into()),
            ice: Some("remove".into()),
            dtls: Some("off".into()),
            rtcp_mux: vec!["demux".into()],
            replace: vec!["origin".into()],
            flags: vec!["symmetric".into()],
            webrtc: auto.then_some(WebrtcMode::Auto),
            ..NgFlagsConfig::default()
        };
        let mut custom = HashMap::new();
        custom.insert(
            "extension".to_string(),
            MediaProfileConfig {
                offer: half("RTP/SAVP", offer_auto),
                answer: half("RTP/AVP", answer_auto),
            },
        );
        ProfileRegistry::from_config(&custom)
    }

    #[test]
    fn a_profile_without_auto_halves_resolves_to_itself() {
        let registry = ProfileRegistry::new();
        for (offer, answer) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(
                registry.resolve_webrtc("wss_to_rtp", offer, answer),
                "wss_to_rtp"
            );
        }
    }

    #[test]
    fn an_auto_profile_toward_ordinary_peers_applies_as_written() {
        let registry = registry_with_auto(true, true);
        assert_eq!(
            registry.resolve_webrtc("extension", false, false),
            "extension"
        );
        let entry = registry.get("extension").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.offer.rtcp_mux, vec!["demux"]);
    }

    #[test]
    fn a_webrtc_contact_makes_the_offer_half_webrtc_and_leaves_the_answer_half() {
        let registry = registry_with_auto(true, true);
        let name = registry.resolve_webrtc("extension", true, false);
        assert_ne!(name, "extension");
        let entry = registry
            .get(&name)
            .expect("the resolved name is registered");
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some(WEBRTC_PROTOCOL)
        );
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
        assert_eq!(entry.offer.rtcp_mux, vec!["require"]);
        assert_ne!(entry.offer.dtls.as_deref(), Some("off"));
        // Everything else the half says survives.
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert_eq!(entry.offer.flags, vec!["symmetric"]);
        // The caller's half is as written.
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
    }

    #[test]
    fn a_webrtc_offer_makes_the_answer_half_webrtc_and_leaves_the_offer_half() {
        let registry = registry_with_auto(true, true);
        let name = registry.resolve_webrtc("extension", false, true);
        let entry = registry.get(&name).expect("registered");
        assert_eq!(
            entry.answer.transport_protocol.as_deref(),
            Some(WEBRTC_PROTOCOL)
        );
        assert_eq!(entry.answer.ice.as_deref(), Some("force"));
        assert_eq!(entry.answer.rtcp_mux, vec!["require"]);
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
    }

    #[test]
    fn both_halves_can_be_webrtc_and_each_combination_has_its_own_name() {
        let registry = registry_with_auto(true, true);
        let names = [
            registry.resolve_webrtc("extension", false, false),
            registry.resolve_webrtc("extension", true, false),
            registry.resolve_webrtc("extension", false, true),
            registry.resolve_webrtc("extension", true, true),
        ];
        for (index, name) in names.iter().enumerate() {
            assert!(registry.get(name).is_some(), "{name}");
            assert!(!names[..index].contains(name), "{name} repeats");
        }
        let both = registry.get(&names[3]).unwrap();
        assert_eq!(both.offer.ice.as_deref(), Some("force"));
        assert_eq!(both.answer.ice.as_deref(), Some("force"));
    }

    /// A WebRTC contact does nothing to a half that is not `auto`.
    #[test]
    fn a_half_not_marked_auto_ignores_a_webrtc_party() {
        let registry = registry_with_auto(false, true);
        assert_eq!(
            registry.resolve_webrtc("extension", true, false),
            "extension"
        );
        let name = registry.resolve_webrtc("extension", true, true);
        let entry = registry.get(&name).unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(
            entry.answer.transport_protocol.as_deref(),
            Some(WEBRTC_PROTOCOL)
        );
    }

    #[test]
    fn an_unknown_name_resolves_to_itself() {
        let registry = ProfileRegistry::new();
        assert_eq!(registry.resolve_webrtc("no_such", true, true), "no_such");
    }

    #[test]
    fn resolved_variants_are_not_listed_as_profiles() {
        let registry = registry_with_auto(true, true);
        assert!(!registry
            .profile_names()
            .iter()
            .any(|name| name.contains('#')));
        assert_eq!(registry.profile_names().len(), 9);
    }

    #[test]
    fn a_resolved_name_maps_back_to_its_base_profile() {
        let registry = registry_with_auto(true, true);
        let name = registry.resolve_webrtc("extension", true, true);
        assert_eq!(registry.base_name(&name), "extension");
        assert_eq!(registry.base_name("extension"), "extension");
    }

    /// An explicit `dtls: passive` role is the operator's and survives; only
    /// the `off` that contradicts a DTLS transport is dropped.
    #[test]
    fn webrtc_keeps_an_explicit_dtls_role() {
        let mut custom = HashMap::new();
        custom.insert(
            "extension".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    dtls: Some("passive".into()),
                    webrtc: Some(WebrtcMode::Auto),
                    ..NgFlagsConfig::default()
                },
                answer: NgFlagsConfig::default(),
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let name = registry.resolve_webrtc("extension", true, false);
        assert_eq!(
            registry.get(&name).unwrap().offer.dtls.as_deref(),
            Some("passive")
        );
    }
}
