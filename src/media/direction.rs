//! Which way a session description lets media flow, and what an in-dialog
//! offer changes about it.
//!
//! A stream's direction is its attribute (RFC 3264 §5.1): at media level, else
//! at session level, else `sendrecv`. An offer whose connection address is
//! `0.0.0.0` asks for no media to be sent to it, the hold of RFC 2543 phones,
//! which RFC 3264 §8.4 still has an answerer honour: such a stream does not
//! receive whatever its attribute says.
//!
//! An in-dialog offer is a hold when the party stops receiving, and a resume
//! when it starts again (TS 24.610 §4.5.2 has the holding party offer
//! `sendonly` or `inactive`). It is compared with the description the party
//! last gave on the dialog, not read on its own: a session refresh
//! (RFC 4028 §10) repeats the session in force, and on a call already held
//! that is a `sendonly` offer that holds nothing new.

use super::sdp::{MediaLine, SdpBody};

/// The attributes that give a stream its direction (RFC 3264 §5.1).
pub const DIRECTION_ATTRIBUTES: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// Whether a stream may send and receive as its attribute states: at media
/// level, else at session level, else both.
pub fn stated_direction(session: &SdpBody, section: &MediaLine) -> (bool, bool) {
    let named = DIRECTION_ATTRIBUTES
        .iter()
        .find(|name| section.has_attr(name))
        .or_else(|| {
            DIRECTION_ATTRIBUTES
                .iter()
                .find(|name| session.session_has_attr(name))
        });
    match named.copied() {
        Some("sendonly") => (true, false),
        Some("recvonly") => (false, true),
        Some("inactive") => (false, false),
        _ => (true, true),
    }
}

/// The attribute that names a stream that sends when `send` and receives when
/// `receive`.
pub fn direction_attribute(send: bool, receive: bool) -> &'static str {
    match (send, receive) {
        (true, true) => "sendrecv",
        (true, false) => "sendonly",
        (false, true) => "recvonly",
        (false, false) => "inactive",
    }
}

/// Whether `section` asks for nothing to be sent to it by a connection
/// address of `0.0.0.0` (RFC 3264 §8.4), its own or the session's.
fn connection_is_unspecified(session: &SdpBody, section: &MediaLine) -> bool {
    section
        .connection()
        .or_else(|| session.connection())
        .and_then(|connection| connection.split_whitespace().nth(2))
        .is_some_and(|address| address == "0.0.0.0")
}

/// Whether a stream sends and receives, the `0.0.0.0` hold counted.
fn stream_direction(session: &SdpBody, section: &MediaLine) -> (bool, bool) {
    let (send, receive) = stated_direction(session, section);
    (
        send,
        receive && !connection_is_unspecified(session, section),
    )
}

/// The way media flows for the party `sdp` describes, over every stream it
/// has not rejected: it sends when any stream sends and receives when any
/// stream receives. `None` when it describes no stream at all, as a body that
/// is not SDP does not.
pub fn effective_direction(sdp: &SdpBody) -> Option<&'static str> {
    let mut active = sdp
        .media_sections
        .iter()
        .filter(|section| section.port != 0)
        .peekable();
    active.peek()?;
    let (send, receive) = active.fold((false, false), |(send, receive), section| {
        let (sends, receives) = stream_direction(sdp, section);
        (send || sends, receive || receives)
    });
    Some(direction_attribute(send, receive))
}

/// What an in-dialog offer does to the session in force on its dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReofferKind {
    /// Nothing changes: no offer, or the streams, their addresses and their
    /// directions as they are in force. A session refresh (RFC 4028 §10).
    Refresh,
    /// The party stops receiving (RFC 3264 §8.4, TS 24.610 §4.5.2).
    Hold,
    /// The party receives again.
    Resume,
    /// Anything else: a codec, an address, a stream added or removed.
    Change,
}

impl ReofferKind {
    /// The name a script sees.
    pub fn as_str(self) -> &'static str {
        match self {
            ReofferKind::Refresh => "refresh",
            ReofferKind::Hold => "hold",
            ReofferKind::Resume => "resume",
            ReofferKind::Change => "change",
        }
    }
}

/// What each stream of `sdp` is: its media, port, transport and formats, the
/// address it is reached at, and its direction.
type StreamShape = (
    String,
    u16,
    String,
    Vec<String>,
    Option<String>,
    (bool, bool),
);

fn streams(sdp: &SdpBody) -> Vec<StreamShape> {
    sdp.media_sections
        .iter()
        .map(|section| {
            (
                section.media_type.to_ascii_lowercase(),
                section.port,
                section.protocol.to_ascii_uppercase(),
                section.formats.clone(),
                section
                    .connection()
                    .or_else(|| sdp.connection())
                    .map(|connection| connection.trim().to_string()),
                stream_direction(sdp, section),
            )
        })
        .collect()
}

/// Attributes whose change renegotiates a stream rather than repeating it: a
/// key exchange (RFC 4568, RFC 8842), an ICE restart (RFC 8839 §4.4.1.1.1), a
/// grouping (RFC 9143). A candidate is not one: a trickled candidate adds to
/// the session without restarting it.
const RENEGOTIATING_ATTRIBUTES: [&str; 8] = [
    "crypto",
    "key-mgmt",
    "fingerprint",
    "setup",
    "ice-ufrag",
    "ice-pwd",
    "group",
    "mid",
];

/// Every renegotiating attribute line of `sdp`, session and media level, in
/// the order it carries them.
fn renegotiating(sdp: &SdpBody) -> Vec<&str> {
    let named = |line: &&str| {
        let name = line.split(':').next().unwrap_or(line).trim();
        RENEGOTIATING_ATTRIBUTES
            .iter()
            .any(|renegotiating| name.eq_ignore_ascii_case(renegotiating))
    };
    sdp.session_lines
        .iter()
        .chain(
            sdp.media_sections
                .iter()
                .flat_map(|section| section.other_attrs.iter()),
        )
        .filter_map(|line| line.strip_prefix("a="))
        .filter(named)
        .collect()
}

/// What `offer` does to `in_force`, the description its sender last gave on
/// the dialog. `None` for an offerless request (RFC 3261 §14.1), which is a
/// refresh whatever its 2xx brings. Without a description in force an offer
/// that receives nothing is a hold and any other a change. An offer that keeps
/// the streams but restarts ICE, re-keys or regroups them is a change: the
/// session in force is not an answer to it.
pub fn classify(offer: Option<&SdpBody>, in_force: Option<&SdpBody>) -> ReofferKind {
    let Some(offer) = offer else {
        return ReofferKind::Refresh;
    };
    let receives = |sdp: &SdpBody| {
        effective_direction(sdp).is_some_and(|direction| direction.ends_with("recv"))
    };
    let Some(in_force) = in_force else {
        return if receives(offer) {
            ReofferKind::Change
        } else {
            ReofferKind::Hold
        };
    };
    if streams(offer) == streams(in_force) && renegotiating(offer) == renegotiating(in_force) {
        return ReofferKind::Refresh;
    }
    match (receives(in_force), receives(offer)) {
        (true, false) => ReofferKind::Hold,
        (false, true) => ReofferKind::Resume,
        _ => ReofferKind::Change,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdp(connection: &str, media: &str) -> SdpBody {
        SdpBody::parse(&format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 {connection}\r\nt=0 0\r\n{media}"
        ))
    }

    fn audio(direction: &str) -> SdpBody {
        sdp(
            "192.0.2.10",
            &format!("m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n{direction}"),
        )
    }

    #[test]
    fn a_stream_takes_its_direction_from_its_attribute() {
        for (attribute, expected) in [
            ("", "sendrecv"),
            ("a=sendrecv\r\n", "sendrecv"),
            ("a=sendonly\r\n", "sendonly"),
            ("a=recvonly\r\n", "recvonly"),
            ("a=inactive\r\n", "inactive"),
        ] {
            assert_eq!(
                effective_direction(&audio(attribute)),
                Some(expected),
                "{attribute:?}"
            );
        }
    }

    #[test]
    fn a_media_level_attribute_overrides_the_session_level_one() {
        let body = SdpBody::parse(concat!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
            "a=sendonly\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        ));
        assert_eq!(effective_direction(&body), Some("sendrecv"));
        let body = SdpBody::parse(concat!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n",
            "a=inactive\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
        ));
        assert_eq!(effective_direction(&body), Some("inactive"));
    }

    /// RFC 3264 §8.4: `c=0.0.0.0` asks for nothing to be sent, the hold of a
    /// phone that predates the direction attributes.
    #[test]
    fn an_unspecified_connection_address_receives_nothing() {
        let held = sdp("0.0.0.0", "m=audio 40000 RTP/AVP 0\r\n");
        assert_eq!(effective_direction(&held), Some("sendonly"));
        let held = sdp("0.0.0.0", "m=audio 40000 RTP/AVP 0\r\na=recvonly\r\n");
        assert_eq!(effective_direction(&held), Some("inactive"));
        let media_level = sdp(
            "192.0.2.10",
            "m=audio 40000 RTP/AVP 0\r\nc=IN IP4 0.0.0.0\r\n",
        );
        assert_eq!(effective_direction(&media_level), Some("sendonly"));
    }

    #[test]
    fn rejected_streams_do_not_count_and_a_body_without_streams_has_no_direction() {
        let body = sdp(
            "192.0.2.10",
            "m=audio 40000 RTP/AVP 0\r\na=sendonly\r\nm=video 0 RTP/AVP 96\r\n",
        );
        assert_eq!(effective_direction(&body), Some("sendonly"));
        assert_eq!(effective_direction(&SdpBody::parse("v=0\r\n")), None);
        assert_eq!(
            effective_direction(&sdp("192.0.2.10", "m=audio 0 RTP/AVP 0\r\n")),
            None
        );
    }

    #[test]
    fn a_party_receives_when_any_stream_does() {
        let body = sdp(
            "192.0.2.10",
            "m=audio 40000 RTP/AVP 0\r\na=sendonly\r\nm=video 40002 RTP/AVP 96\r\na=recvonly\r\n",
        );
        assert_eq!(effective_direction(&body), Some("sendrecv"));
    }

    #[test]
    fn sendonly_and_inactive_put_a_call_on_hold_and_sendrecv_resumes_it() {
        let talking = audio("");
        assert_eq!(
            classify(Some(&audio("a=sendonly\r\n")), Some(&talking)),
            ReofferKind::Hold
        );
        assert_eq!(
            classify(Some(&audio("a=inactive\r\n")), Some(&talking)),
            ReofferKind::Hold
        );
        assert_eq!(
            classify(Some(&talking), Some(&audio("a=sendonly\r\n"))),
            ReofferKind::Resume
        );
        assert_eq!(
            classify(Some(&talking), Some(&audio("a=inactive\r\n"))),
            ReofferKind::Resume
        );
    }

    #[test]
    fn the_rfc_2543_hold_and_its_resume() {
        let talking = audio("");
        let held = sdp(
            "0.0.0.0",
            "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        );
        assert_eq!(classify(Some(&held), Some(&talking)), ReofferKind::Hold);
        assert_eq!(classify(Some(&talking), Some(&held)), ReofferKind::Resume);
    }

    /// RFC 4028: a refresh repeats the session in force, and on a held call
    /// that is a `sendonly` offer, which must not read as a second hold.
    #[test]
    fn a_refresh_repeats_the_session_in_force_and_is_not_a_hold() {
        let held = audio("a=sendonly\r\n");
        assert_eq!(classify(Some(&held), Some(&held)), ReofferKind::Refresh);
        let talking = audio("");
        assert_eq!(
            classify(Some(&talking), Some(&talking)),
            ReofferKind::Refresh
        );
        // The o= version moving on alone changes nothing about the media.
        let bumped = SdpBody::parse(
            &audio("a=sendonly\r\n")
                .to_string()
                .replace("o=- 1 1", "o=- 1 2"),
        );
        assert_eq!(classify(Some(&bumped), Some(&held)), ReofferKind::Refresh);
        assert_eq!(classify(None, Some(&held)), ReofferKind::Refresh);
        assert_eq!(classify(None, None), ReofferKind::Refresh);
    }

    fn webrtc(extra: &str) -> SdpBody {
        SdpBody::parse(&format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nt=0 0\r\n\
             a=group:BUNDLE 0\r\na=fingerprint:sha-256 AB:CD\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 192.0.2.10\r\n\
             a=mid:0\r\na=ice-ufrag:uf1\r\na=ice-pwd:pw1\r\na=setup:actpass\r\n\
             a=rtpmap:111 opus/48000/2\r\na=candidate:1 1 udp 1 192.0.2.10 40000 typ host\r\n\
             {extra}"
        ))
    }

    /// An attribute that renegotiates nothing (RFC 7866's `a=recordpref`, a
    /// trickled candidate) leaves a refresh a refresh; one that restarts ICE,
    /// re-keys or regroups makes it a change, so a session in force is never
    /// repeated as the answer to an offer that renegotiates it.
    #[test]
    fn a_restart_or_a_rekey_is_a_change_and_anything_else_stays_a_refresh() {
        let in_force = webrtc("");
        assert_eq!(
            classify(Some(&webrtc("a=recordpref:on\r\n")), Some(&in_force)),
            ReofferKind::Refresh
        );
        let trickled = webrtc("a=candidate:2 1 udp 1 192.0.2.10 40002 typ host\r\n");
        assert_eq!(
            classify(Some(&trickled), Some(&in_force)),
            ReofferKind::Refresh
        );
        for (from, to) in [
            ("a=ice-ufrag:uf1", "a=ice-ufrag:uf2"),
            ("a=ice-pwd:pw1", "a=ice-pwd:pw2"),
            ("a=fingerprint:sha-256 AB:CD", "a=fingerprint:sha-256 EF:01"),
            ("a=setup:actpass", "a=setup:active"),
            ("a=group:BUNDLE 0", "a=group:BUNDLE 0 1"),
        ] {
            let renegotiated = SdpBody::parse(&in_force.to_string().replace(from, to));
            assert_eq!(
                classify(Some(&renegotiated), Some(&in_force)),
                ReofferKind::Change,
                "{to}"
            );
        }
        let rekeyed_sdes = (
            audio("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAA\r\n"),
            audio("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BBBB\r\n"),
        );
        assert_eq!(
            classify(Some(&rekeyed_sdes.1), Some(&rekeyed_sdes.0)),
            ReofferKind::Change
        );
        // A hold that also restarts ICE is still read as the hold it is.
        let held = SdpBody::parse(
            &webrtc("a=sendonly\r\n")
                .to_string()
                .replace("a=ice-ufrag:uf1", "a=ice-ufrag:uf2"),
        );
        assert_eq!(classify(Some(&held), Some(&in_force)), ReofferKind::Hold);
    }

    #[test]
    fn a_new_codec_or_address_is_a_change() {
        let talking = audio("");
        let new_codec = sdp(
            "192.0.2.10",
            "m=audio 40000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
        );
        assert_eq!(
            classify(Some(&new_codec), Some(&talking)),
            ReofferKind::Change
        );
        let moved = sdp(
            "192.0.2.20",
            "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        );
        assert_eq!(classify(Some(&moved), Some(&talking)), ReofferKind::Change);
        // A held party moving address stays held: still a change, not a hold.
        let held_elsewhere = sdp(
            "192.0.2.20",
            "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n",
        );
        assert_eq!(
            classify(Some(&held_elsewhere), Some(&audio("a=sendonly\r\n"))),
            ReofferKind::Change
        );
    }

    #[test]
    fn without_a_session_in_force_the_offer_is_read_on_its_own() {
        assert_eq!(
            classify(Some(&audio("a=sendonly\r\n")), None),
            ReofferKind::Hold
        );
        assert_eq!(classify(Some(&audio("")), None), ReofferKind::Change);
    }

    #[test]
    fn kinds_have_the_names_a_script_sees() {
        assert_eq!(ReofferKind::Refresh.as_str(), "refresh");
        assert_eq!(ReofferKind::Hold.as_str(), "hold");
        assert_eq!(ReofferKind::Resume.as_str(), "resume");
        assert_eq!(ReofferKind::Change.as_str(), "change");
    }
}
