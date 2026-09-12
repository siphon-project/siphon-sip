//! Finding the SDP in a SIP message body.
//!
//! The body of a message that carries an offer or an answer is not always SDP
//! and nothing else. RFC 5621 §3 lets a UA carry the session description as one
//! part of a `multipart/*` body, alongside parts SIP itself does not interpret:
//! ISUP on a SIP-I trunk (RFC 3204), a PIDF-LO location object (RFC 6442), an
//! operator-specific XML document. The session description is still there, one
//! level down.
//!
//! Every surface that reaches for "the SDP" therefore has to ask the same
//! question of a body, and the answer has to be the same everywhere — which is
//! what this module is for.

use crate::siprec::multipart::parse_multipart;

/// The media type an SDP body is carried under.
const SDP_MEDIA_TYPE: &str = "application/sdp";

/// The bare media type of a `Content-Type` value: lowercased, with parameters
/// (`;charset=…`, `;boundary=…`) and surrounding whitespace removed.
///
/// RFC 3261 §7.3.1 makes the type and subtype case-insensitive, so a peer
/// spelling it `Application/SDP` means the same thing we do.
pub fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Whether a `Content-Type` names SDP.
pub fn is_sdp(content_type: &str) -> bool {
    media_type(content_type) == SDP_MEDIA_TYPE
}

/// Whether a `Content-Type` names a multipart body.
///
/// `multipart/mixed` is the one SIP uses in practice, but `multipart/related`
/// and `multipart/alternative` are equally legal and parse identically, so the
/// test is on the type rather than on one subtype.
pub fn is_multipart(content_type: &str) -> bool {
    media_type(content_type).starts_with("multipart/")
}

/// The SDP a body carries: the body itself when the `Content-Type` is
/// `application/sdp`, or the `application/sdp` part of a `multipart/*` body.
///
/// `Err` carries a human reason, and callers surface it verbatim — a content
/// type that is neither, a multipart body that does not parse, and a multipart
/// body with no SDP part in it are three different mistakes and the caller
/// should be told which one they made.
pub fn sdp_from_body(content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    if is_sdp(content_type) {
        return Ok(body.to_vec());
    }
    if !is_multipart(content_type) {
        return Err(format!(
            "Content-Type '{}' is neither {SDP_MEDIA_TYPE} nor a multipart body carrying one",
            content_type.trim()
        ));
    }
    let parts = parse_multipart(content_type, body)
        .map_err(|error| format!("multipart body does not parse: {error}"))?;
    parts
        .iter()
        .find(|part| is_sdp(&part.content_type))
        .map(|part| part.body.clone())
        .ok_or_else(|| format!("multipart body has no {SDP_MEDIA_TYPE} part"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-part body of the shape a SIP-I / PIDF-LO INVITE carries: the offer
    /// plus one part SIP does not interpret.
    fn multipart_body() -> &'static str {
        concat!(
            "--siphon-1\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "o=- 1 1 IN IP4 198.51.100.10\r\n",
            "s=-\r\n",
            "c=IN IP4 198.51.100.10\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "\r\n--siphon-1\r\n",
            "Content-Type: application/vnd.example+xml\r\n",
            "\r\n",
            "<additional-data/>\r\n",
            "--siphon-1--\r\n",
        )
    }

    #[test]
    fn media_type_drops_parameters_and_case() {
        assert_eq!(media_type("application/sdp"), "application/sdp");
        assert_eq!(media_type("Application/SDP"), "application/sdp");
        assert_eq!(
            media_type("application/sdp; charset=utf-8"),
            "application/sdp"
        );
        assert_eq!(
            media_type(" multipart/mixed;boundary=siphon-1"),
            "multipart/mixed"
        );
        assert_eq!(media_type(""), "");
    }

    #[test]
    fn is_sdp_matches_the_type_not_a_prefix_of_it() {
        assert!(is_sdp("application/sdp"));
        assert!(is_sdp("APPLICATION/SDP;charset=utf-8"));
        // A different type that merely starts the same way is not SDP.
        assert!(!is_sdp("application/sdp-ng"));
        assert!(!is_sdp("text/plain"));
        assert!(!is_sdp(""));
    }

    #[test]
    fn is_multipart_covers_every_multipart_subtype() {
        assert!(is_multipart("multipart/mixed;boundary=siphon-1"));
        assert!(is_multipart("MULTIPART/RELATED; boundary=\"x\""));
        assert!(is_multipart("multipart/alternative;boundary=x"));
        assert!(!is_multipart("application/sdp"));
        assert!(!is_multipart(""));
    }

    #[test]
    fn a_bare_sdp_body_is_its_own_sdp() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\n";
        assert_eq!(
            sdp_from_body("application/sdp", sdp).expect("plain SDP"),
            sdp.to_vec()
        );
    }

    #[test]
    fn a_multipart_body_yields_only_its_sdp_part() {
        let extracted = sdp_from_body(
            "multipart/mixed;boundary=siphon-1",
            multipart_body().as_bytes(),
        )
        .expect("the SDP part is found");
        let extracted = String::from_utf8(extracted).expect("SDP is text");

        assert!(extracted.starts_with("v=0\r\n"), "got: {extracted:?}");
        assert!(extracted.contains("m=audio 40000 RTP/AVP 0"));
        // The point of extracting: nothing from the other part comes along, and
        // neither does the MIME framing.
        assert!(!extracted.contains("additional-data"));
        assert!(!extracted.contains("--siphon-1"));
        assert!(!extracted.contains("Content-Type"));
    }

    #[test]
    fn the_sdp_part_is_found_wherever_it_sits_and_however_it_is_spelled() {
        // RFC 5621 fixes no part order, and RFC 3261 §7.3.1 makes the media type
        // case-insensitive — an SDP part that arrives second, spelled in caps,
        // is still the SDP part.
        let body = concat!(
            "--b\r\n",
            "Content-Type: application/vnd.example+xml\r\n",
            "\r\n",
            "<additional-data/>\r\n",
            "--b\r\n",
            "Content-Type: Application/SDP\r\n",
            "\r\n",
            "v=0\r\nm=audio 40000 RTP/AVP 0\r\n",
            "--b--\r\n",
        );
        let extracted =
            sdp_from_body("multipart/mixed;boundary=b", body.as_bytes()).expect("SDP part found");
        assert!(String::from_utf8_lossy(&extracted).starts_with("v=0"));
    }

    #[test]
    fn a_body_that_is_not_sdp_and_not_multipart_names_itself_in_the_error() {
        let error = sdp_from_body("text/plain", b"hello").expect_err("not an SDP body");
        assert!(error.contains("text/plain"), "message was: {error}");
        assert!(error.contains("application/sdp"), "message was: {error}");
    }

    #[test]
    fn a_multipart_body_with_no_sdp_part_is_distinct_from_one_that_does_not_parse() {
        let no_sdp = concat!(
            "--b\r\n",
            "Content-Type: application/vnd.example+xml\r\n",
            "\r\n",
            "<additional-data/>\r\n",
            "--b--\r\n",
        );
        let error =
            sdp_from_body("multipart/mixed;boundary=b", no_sdp.as_bytes()).expect_err("no SDP");
        assert!(error.contains("no application/sdp part"), "was: {error}");

        // No boundary parameter at all: the body cannot even be split.
        let error = sdp_from_body("multipart/mixed", no_sdp.as_bytes()).expect_err("unparseable");
        assert!(error.contains("does not parse"), "was: {error}");
    }
}
