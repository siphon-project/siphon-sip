//! One party's session description as the answer to another's offer
//! (RFC 3264 §6, §8).
//!
//! A B2BUA that answers an offer on one leg without asking the other party has
//! that party's description and the offer, and owes the offerer an answer that
//! describes the party as it is. The answer keeps the party's own address,
//! ports and session-level lines, and for each stream of the offer, in the
//! offer's order (§6: "the answer MUST contain exactly the same number of m=
//! lines as the offer"):
//!
//! * the party's stream at the same position, when it is of the same media
//!   type and transport and neither side has it at port zero, with the formats
//!   both list, in the party's order. A payload type both list has to name the
//!   same codec where either gives it an `a=rtpmap:` (§8.3.2: a mapping holds
//!   for the session);
//! * the direction the party has it in, cut down to what the offer leaves
//!   (§6.1): a `sendonly` offer is answered `recvonly` or `inactive`;
//! * a rejected stream, port zero, for one the party has no such stream for or
//!   shares no format with (§6).
//!
//! What it cannot do is negotiate anything beyond formats and direction for a
//! party that is not there: a key exchange (`a=crypto:`, `a=fingerprint:`),
//! ICE, a grouping of streams. A description that needs one is refused rather
//! than answered wrongly, unless the offer renegotiates none of it: an offer
//! that repeats what the offerer already had agreed, give or take a direction,
//! is answered by the description that agreement produced
//! ([`answer_repeating`]).

use super::direction::{direction_attribute, stated_direction, DIRECTION_ATTRIBUTES};
use super::sdp::{MediaLine, SdpBody};

/// Attributes whose answer takes more than the two descriptions to work out.
const NEGOTIATED_ATTRIBUTES: [&str; 9] = [
    "crypto",
    "key-mgmt",
    "fingerprint",
    "setup",
    "ice-ufrag",
    "ice-pwd",
    "candidate",
    "group",
    "mid",
];

/// Whether `sdp` carries an attribute this module cannot answer for.
fn needs_more_than_formats(sdp: &SdpBody) -> bool {
    NEGOTIATED_ATTRIBUTES.iter().any(|name| {
        sdp.session_has_attr(name)
            || sdp
                .media_sections
                .iter()
                .any(|section| section.has_attr(name))
    })
}

/// The `a=rtpmap:` encoding of `format` in `section`, when it gives one.
fn encoding<'a>(section: &'a MediaLine, format: &str) -> Option<&'a str> {
    let payload_type = format.parse::<u16>().ok()?;
    section
        .rtpmap
        .iter()
        .find(|(mapped, _)| *mapped == payload_type)
        .map(|(_, encoding)| encoding.as_str())
}

/// Whether `offered` lists `format` of `own` as the same thing: the same
/// token, and under RTP the same codec. A dynamic payload type only one side
/// maps to a codec is not known to be the same.
fn is_offered(offered: &MediaLine, own: &MediaLine, format: &str) -> bool {
    if !offered.formats.iter().any(|listed| listed == format) {
        return false;
    }
    if !own.is_rtp() {
        return true;
    }
    match (encoding(own, format), encoding(offered, format)) {
        (Some(one), Some(other)) => one.eq_ignore_ascii_case(other),
        (None, None) => true,
        _ => format
            .parse::<u16>()
            .is_ok_and(|payload_type| payload_type < 96),
    }
}

/// The stream that turns `offered` down (RFC 3264 §6): port zero, and one of
/// the offer's formats, since an `m=` line needs one.
fn rejected(offered: &MediaLine) -> MediaLine {
    MediaLine {
        media_type: offered.media_type.clone(),
        port: 0,
        port_count: None,
        protocol: offered.protocol.clone(),
        formats: offered.formats.iter().take(1).cloned().collect(),
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        other_attrs: Vec::new(),
    }
}

/// `own`, the party's stream, as the answer to `offered`, or `None` when it
/// cannot answer it.
fn accepted(
    offer: &SdpBody,
    offered: &MediaLine,
    description: &SdpBody,
    own: &MediaLine,
) -> Option<MediaLine> {
    if offered.port == 0
        || own.port == 0
        || !own.media_type.eq_ignore_ascii_case(&offered.media_type)
        || !own.protocol.eq_ignore_ascii_case(&offered.protocol)
    {
        return None;
    }
    let mut answer = own.clone();
    answer
        .formats
        .retain(|format| is_offered(offered, own, format));
    if answer.formats.is_empty() {
        return None;
    }
    let formats = &answer.formats;
    let kept = |format: &str| formats.iter().any(|listed| listed == format);
    answer
        .rtpmap
        .retain(|(payload_type, _)| kept(&payload_type.to_string()));
    answer.fmtp.retain(|(format, _)| kept(format));
    // Feedback is per format, or `*` for all of them (RFC 4585 §4.2).
    answer.other_attrs.retain(|line| {
        line.strip_prefix("a=rtcp-fb:")
            .and_then(|value| value.split_whitespace().next())
            .is_none_or(|format| format == "*" || kept(format))
    });
    // Multiplexing RTCP on the RTP port is the offerer's to propose
    // (RFC 5761 §5.1.1).
    if !offered.has_attr("rtcp-mux") {
        answer.remove_attr("rtcp-mux");
    }

    answer_direction(&mut answer, offer, offered, description, own);
    Some(answer)
}

/// Give `answer`, a copy of the party's stream `own`, the direction the party
/// has it in cut down to what the offered stream leaves (RFC 3264 §6.1). The
/// attribute stays where the party had it, and a stream that runs both ways
/// and never said so still does not.
fn answer_direction(
    answer: &mut MediaLine,
    offer: &SdpBody,
    offered: &MediaLine,
    description: &SdpBody,
    own: &MediaLine,
) {
    let (may_send, may_receive) = stated_direction(description, own);
    let (offerer_sends, offerer_receives) = stated_direction(offer, offered);
    let answered = direction_attribute(may_send && offerer_receives, may_receive && offerer_sends);
    let stated = DIRECTION_ATTRIBUTES
        .iter()
        .any(|name| own.has_attr(name) || description.session_has_attr(name));
    let position = answer.other_attrs.iter().position(|line| {
        line.strip_prefix("a=")
            .is_some_and(|name| DIRECTION_ATTRIBUTES.contains(&name))
    });
    for name in DIRECTION_ATTRIBUTES {
        answer.remove_attr(name);
    }
    if stated || answered != "sendrecv" {
        let position = position
            .unwrap_or(answer.other_attrs.len())
            .min(answer.other_attrs.len());
        answer.other_attrs.insert(position, format!("a={answered}"));
    }
}

/// `description`, one party's session description, as the answer to `offer`.
/// `Err` says why it cannot be one.
pub fn answer_from(offer: &SdpBody, description: &SdpBody) -> Result<SdpBody, &'static str> {
    if needs_more_than_formats(offer) || needs_more_than_formats(description) {
        return Err(
            "a stream is keyed, uses ICE or is grouped, which takes the other party to answer",
        );
    }
    let mut any_accepted = false;
    let media_sections = offer
        .media_sections
        .iter()
        .enumerate()
        .map(|(index, offered)| {
            let answer = description
                .media_sections
                .get(index)
                .and_then(|own| accepted(offer, offered, description, own));
            any_accepted |= answer.is_some();
            answer.unwrap_or_else(|| rejected(offered))
        })
        .collect();
    if !any_accepted {
        return Err("the offer has no stream and format in common with the other party's session");
    }
    Ok(SdpBody {
        session_lines: description.session_lines.clone(),
        media_sections,
    })
}

/// The lines of a description, or of one stream of it, that an offer has to
/// carry unchanged to be a repeat of it: all but the `o=` line, whose version
/// moves on (RFC 3264 §8), the direction attributes, and ICE candidates, which
/// trickle in without restarting anything (RFC 8840 §4.4).
fn repeated_lines(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| {
            let attribute = line.strip_prefix("a=");
            !line.starts_with("o=")
                && !attribute.is_some_and(|name| {
                    DIRECTION_ATTRIBUTES.contains(&name)
                        || name.starts_with("candidate:")
                        || name == "end-of-candidates"
                })
        })
        .collect()
}

/// Whether `offered` is the stream `had` again, whatever its direction.
fn repeats_stream(offered: &MediaLine, had: &MediaLine) -> bool {
    offered.media_type.eq_ignore_ascii_case(&had.media_type)
        && offered.port == had.port
        && offered.port_count == had.port_count
        && offered.protocol.eq_ignore_ascii_case(&had.protocol)
        && offered.formats == had.formats
        && offered.rtpmap == had.rtpmap
        && offered.fmtp == had.fmtp
        && repeated_lines(&offered.other_attrs) == repeated_lines(&had.other_attrs)
}

/// `description`, the session in force toward a party, as the answer to an
/// `offer` from that party which renegotiates nothing but a direction.
///
/// `previous` is the description the party last gave, the one `description`
/// was agreed against by whoever could: the media engine holding the keys,
/// the ICE agent and the bundle. An offer that says what `previous` said,
/// line for line at the session level and in every stream, asks for none of
/// that again (RFC 8839 §4.4.1.1.1 restarts ICE only on new credentials,
/// RFC 8842 §5.5 keeps the DTLS association while fingerprint and transport
/// are unchanged, RFC 9143 §7.5 keeps the BUNDLE group), so the answer it
/// had still answers it, with each stream's direction cut down to what the
/// offer leaves (RFC 3264 §6.1, §8.4). Any other difference (a codec
/// parameter, `a=rtcp-mux` taken away, an attribute moved from one stream to
/// another) is a change the answer it had does not answer.
///
/// `Err` says why it is not such an offer.
pub fn answer_repeating(
    offer: &SdpBody,
    previous: &SdpBody,
    description: &SdpBody,
) -> Result<SdpBody, &'static str> {
    if offer.media_sections.len() != previous.media_sections.len()
        || offer.media_sections.len() != description.media_sections.len()
    {
        return Err("the offer adds or removes a stream, which takes the other party to answer");
    }
    let repeats = repeated_lines(&offer.session_lines) == repeated_lines(&previous.session_lines)
        && offer
            .media_sections
            .iter()
            .zip(&previous.media_sections)
            .all(|(offered, had)| repeats_stream(offered, had));
    if !repeats {
        return Err(
            "the offer changes more than a direction of a keyed, ICE or grouped session, which \
             takes the other party to answer",
        );
    }
    let media_sections = offer
        .media_sections
        .iter()
        .zip(&description.media_sections)
        .map(|(offered, own)| {
            let mut answer = own.clone();
            // A stream either side has at port zero has no direction to state.
            if offered.port != 0 && own.port != 0 {
                answer_direction(&mut answer, offer, offered, description, own);
            }
            answer
        })
        .collect();
    Ok(SdpBody {
        session_lines: description.session_lines.clone(),
        media_sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A participant's offer toward a media engine that keys with DTLS, runs
    /// ICE and bundles (RFC 8842, RFC 8839, RFC 9143).
    const KEYED_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 4 4 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0\r\n",
        "m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "a=mid:0\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "a=ice-ufrag:ofrg\r\n",
        "a=ice-pwd:offererpassword0000000000\r\n",
        "a=fingerprint:sha-256 AA:BB\r\n",
        "a=setup:actpass\r\n",
        "a=rtcp-mux\r\n",
    );

    /// The engine's answer to it: the session in force toward the participant.
    const KEYED_SESSION: &str = concat!(
        "v=0\r\n",
        "o=- 9 9 IN IP4 203.0.113.7\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "a=group:BUNDLE 0\r\n",
        "m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 203.0.113.7\r\n",
        "a=mid:0\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "a=ice-ufrag:efrg\r\n",
        "a=ice-pwd:enginepassword00000000000\r\n",
        "a=fingerprint:sha-256 CC:DD\r\n",
        "a=setup:passive\r\n",
        "a=rtcp-mux\r\n",
    );

    #[test]
    fn a_keyed_offer_that_repeats_itself_is_answered_with_the_session_in_force() {
        let offer = SdpBody::parse(&KEYED_OFFER.replace("o=- 4 4", "o=- 4 5"));
        let previous = SdpBody::parse(KEYED_OFFER);
        let session = SdpBody::parse(KEYED_SESSION);
        assert!(
            answer_from(&offer, &session).is_err(),
            "not answerable from formats alone"
        );
        let answer = answer_repeating(&offer, &previous, &session).expect("answered");
        assert_eq!(answer.to_string(), session.to_string());
    }

    #[test]
    fn a_keyed_hold_is_answered_with_the_session_in_force_receiving_only() {
        let held = SdpBody::parse(&format!("{KEYED_OFFER}a=sendonly\r\n"));
        let answer = answer_repeating(
            &held,
            &SdpBody::parse(KEYED_OFFER),
            &SdpBody::parse(KEYED_SESSION),
        )
        .expect("answered")
        .to_string();
        assert!(answer.contains("a=recvonly\r\n"), "{answer}");
        assert!(
            answer.contains("a=fingerprint:sha-256 CC:DD\r\n"),
            "{answer}"
        );
        assert!(answer.contains("a=setup:passive\r\n"), "{answer}");
        assert!(answer.contains("a=ice-ufrag:efrg\r\n"), "{answer}");
    }

    #[test]
    fn an_ice_restart_a_new_key_or_a_moved_stream_is_not_a_repeat() {
        let previous = SdpBody::parse(KEYED_OFFER);
        let session = SdpBody::parse(KEYED_SESSION);
        for (what, changed) in [
            (
                "ICE restart",
                KEYED_OFFER.replace("ice-ufrag:ofrg", "ice-ufrag:new1"),
            ),
            ("new key", KEYED_OFFER.replace("AA:BB", "EE:FF")),
            (
                "moved",
                KEYED_OFFER.replace("m=audio 50000", "m=audio 50002"),
            ),
            (
                "new address",
                KEYED_OFFER.replace("c=IN IP4 192.0.2.10", "c=IN IP4 192.0.2.99"),
            ),
            (
                "new format",
                KEYED_OFFER.replace("SAVPF 111", "SAVPF 111 0"),
            ),
            (
                "new stream",
                format!("{KEYED_OFFER}m=video 50004 UDP/TLS/RTP/SAVPF 96\r\n"),
            ),
            ("no rtcp-mux", KEYED_OFFER.replace("a=rtcp-mux\r\n", "")),
            (
                "codec parameters",
                format!("{KEYED_OFFER}a=fmtp:111 useinbandfec=1\r\n"),
            ),
            (
                "another clock rate",
                KEYED_OFFER.replace("opus/48000/2", "opus/16000"),
            ),
            (
                "session-level credential",
                KEYED_OFFER
                    .replace("a=ice-ufrag:ofrg\r\n", "")
                    .replace("t=0 0\r\n", "t=0 0\r\na=ice-ufrag:ofrg\r\n"),
            ),
        ] {
            assert!(
                answer_repeating(&SdpBody::parse(&changed), &previous, &session).is_err(),
                "{what}"
            );
        }
    }

    #[test]
    fn a_trickled_candidate_and_a_new_version_leave_a_repeat_a_repeat() {
        let offer = format!(
            "{}a=candidate:1 1 UDP 2122252543 192.0.2.10 50000 typ host\r\na=end-of-candidates\r\n",
            KEYED_OFFER.replace("o=- 4 4", "o=- 4 9")
        );
        assert!(answer_repeating(
            &SdpBody::parse(&offer),
            &SdpBody::parse(KEYED_OFFER),
            &SdpBody::parse(KEYED_SESSION),
        )
        .is_ok());
    }

    #[test]
    fn a_rejected_stream_of_a_repeat_stays_as_it_was() {
        let offer = format!("{KEYED_OFFER}m=video 0 UDP/TLS/RTP/SAVPF 96\r\n");
        let session = format!("{KEYED_SESSION}m=video 0 UDP/TLS/RTP/SAVPF 96\r\n");
        let answer = answer_repeating(
            &SdpBody::parse(&offer),
            &SdpBody::parse(&offer),
            &SdpBody::parse(&session),
        )
        .expect("answered")
        .to_string();
        assert!(
            answer.ends_with("m=video 0 UDP/TLS/RTP/SAVPF 96\r\n"),
            "{answer}"
        );
    }

    const PARTY: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0 8 96 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:96 AMR-WB/16000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=fmtp:96 mode-change-capability=2\r\n",
        "a=fmtp:101 0-15\r\n",
        "a=ptime:20\r\n",
    );

    fn offer(media: &str) -> SdpBody {
        SdpBody::parse(&format!(
            "v=0\r\no=- 2 3 IN IP4 198.51.100.7\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n{media}"
        ))
    }

    fn answer(media: &str) -> String {
        answer_from(&offer(media), &SdpBody::parse(PARTY))
            .expect("the offer is answered")
            .to_string()
    }

    #[test]
    fn the_answer_is_the_partys_own_description_with_the_formats_both_list() {
        let answer = answer(concat!(
            "m=audio 50002 RTP/AVP 8 101\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
        ));
        assert_eq!(
            answer,
            concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 192.0.2.10\r\n",
                "s=-\r\n",
                "c=IN IP4 192.0.2.10\r\n",
                "t=0 0\r\n",
                "m=audio 40000 RTP/AVP 8 101\r\n",
                "a=ptime:20\r\n",
                "a=rtpmap:8 PCMA/8000\r\n",
                "a=rtpmap:101 telephone-event/8000\r\n",
                "a=fmtp:101 0-15\r\n",
            )
        );
    }

    #[test]
    fn a_payload_type_that_names_another_codec_is_not_a_common_format() {
        let answer = answer(concat!(
            "m=audio 50002 RTP/AVP 0 96\r\n",
            "a=rtpmap:96 opus/48000/2\r\n",
        ));
        assert!(answer.contains("m=audio 40000 RTP/AVP 0\r\n"), "{answer}");
        assert!(!answer.contains("AMR-WB"), "{answer}");
        // A static payload type needs no mapping, a dynamic one does.
        let unmapped = super::answer_from(
            &offer("m=audio 50002 RTP/AVP 96\r\n"),
            &SdpBody::parse(PARTY),
        );
        assert!(unmapped.is_err());
    }

    #[test]
    fn the_direction_is_the_partys_cut_down_to_what_the_offer_leaves() {
        for (offered, answered) in [
            ("a=sendonly\r\n", Some("a=recvonly\r\n")),
            ("a=recvonly\r\n", Some("a=sendonly\r\n")),
            ("a=inactive\r\n", Some("a=inactive\r\n")),
            ("a=sendrecv\r\n", None),
            ("", None),
        ] {
            let answer = answer(&format!("m=audio 50002 RTP/AVP 0\r\n{offered}"));
            match answered {
                Some(line) => assert!(answer.contains(line), "{offered}: {answer}"),
                None => assert!(
                    DIRECTION_ATTRIBUTES
                        .iter()
                        .all(|name| !answer.contains(&format!("a={name}"))),
                    "{offered}: {answer}"
                ),
            }
        }
        // A party that only sends does not start receiving because it is asked.
        let held = SdpBody::parse(&format!("{PARTY}a=sendonly\r\n"));
        let answer = answer_from(&offer("m=audio 50002 RTP/AVP 0\r\n"), &held)
            .expect("the offer is answered")
            .to_string();
        assert!(answer.contains("a=sendonly\r\n"), "{answer}");
        let answer = answer_from(&offer("m=audio 50002 RTP/AVP 0\r\na=sendonly\r\n"), &held)
            .expect("the offer is answered")
            .to_string();
        assert!(answer.contains("a=inactive\r\n"), "{answer}");
    }

    #[test]
    fn a_session_level_direction_of_the_offer_counts() {
        let offer = SdpBody::parse(concat!(
            "v=0\r\n",
            "o=- 2 3 IN IP4 198.51.100.7\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "a=sendonly\r\n",
            "m=audio 50002 RTP/AVP 0\r\n",
        ));
        let answer = answer_from(&offer, &SdpBody::parse(PARTY))
            .expect("the offer is answered")
            .to_string();
        assert!(answer.contains("a=recvonly\r\n"), "{answer}");
    }

    #[test]
    fn a_stream_the_party_does_not_have_is_rejected_in_its_place() {
        let answer = answer(concat!(
            "m=audio 50002 RTP/AVP 0\r\n",
            "m=video 50004 RTP/AVP 97 98\r\n",
            "a=rtpmap:97 H264/90000\r\n",
        ));
        assert!(answer.contains("m=audio 40000 RTP/AVP 0\r\n"), "{answer}");
        assert!(answer.ends_with("m=video 0 RTP/AVP 97\r\n"), "{answer}");
    }

    #[test]
    fn a_stream_either_side_has_at_port_zero_or_on_another_transport_is_rejected() {
        let two_streams = concat!("m=audio 50002 RTP/AVP 0\r\n", "m=audio 50004 RTP/AVP 0\r\n",);
        let party = SdpBody::parse(&format!("{PARTY}m=audio 0 RTP/AVP 0\r\n"));
        let answer = answer_from(&offer(two_streams), &party)
            .expect("the offer is answered")
            .to_string();
        assert!(answer.ends_with("m=audio 0 RTP/AVP 0\r\n"), "{answer}");

        let refused = answer_from(&offer("m=audio 0 RTP/AVP 0\r\n"), &SdpBody::parse(PARTY));
        assert!(refused.is_err(), "nothing is left to answer with");
        let refused = answer_from(
            &offer("m=audio 50002 RTP/SAVP 0\r\n"),
            &SdpBody::parse(PARTY),
        );
        assert!(refused.is_err());
    }

    #[test]
    fn feedback_and_rtcp_multiplexing_follow_the_formats_and_the_offer() {
        let party = SdpBody::parse(concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.10\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.10\r\n",
            "t=0 0\r\n",
            "m=video 40002 RTP/AVPF 97 98\r\n",
            "a=rtpmap:97 H264/90000\r\n",
            "a=rtpmap:98 VP8/90000\r\n",
            "a=rtcp-fb:* nack\r\n",
            "a=rtcp-fb:97 ccm fir\r\n",
            "a=rtcp-fb:98 ccm fir\r\n",
            "a=rtcp-mux\r\n",
        ));
        let offered = offer("m=video 50004 RTP/AVPF 98\r\na=rtpmap:98 VP8/90000\r\n");
        let answer = answer_from(&offered, &party)
            .expect("the offer is answered")
            .to_string();
        assert!(answer.contains("a=rtcp-fb:* nack\r\n"), "{answer}");
        assert!(answer.contains("a=rtcp-fb:98 ccm fir\r\n"), "{answer}");
        assert!(!answer.contains("a=rtcp-fb:97"), "{answer}");
        assert!(!answer.contains("a=rtcp-mux"), "{answer}");
    }

    #[test]
    fn a_keyed_or_grouped_description_is_not_answered_for_the_party() {
        for line in [
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj\r\n",
            "a=fingerprint:sha-256 00:11\r\n",
            "a=ice-ufrag:abcd\r\n",
            "a=mid:0\r\n",
        ] {
            let offered = offer(&format!("m=audio 50002 RTP/AVP 0\r\n{line}"));
            assert!(
                answer_from(&offered, &SdpBody::parse(PARTY)).is_err(),
                "{line}"
            );
            let party = SdpBody::parse(&format!("{PARTY}{line}"));
            assert!(
                answer_from(&offer("m=audio 50002 RTP/AVP 0\r\n"), &party).is_err(),
                "{line}"
            );
        }
    }
}
