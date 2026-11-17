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

use crate::media::sdp::{is_attribute_line_named, retain_lines, strip_attributes};
use crate::siprec::multipart::{extract_boundary, parse_multipart};

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

/// Remove the `a=` attributes named in `names` from the SDP a body carries,
/// returning whether anything was removed.
///
/// Scoped the way [`sdp_from_body`] finds the SDP: the whole body under
/// `application/sdp`, only the `application/sdp` parts of a `multipart/*` body,
/// and nothing under any other type. The other parts of a multipart body and its
/// MIME framing cross byte for byte: an ISUP part is binary, and a line in it
/// that happens to read like an attribute is not one.
pub fn strip_sdp_attributes(content_type: &str, body: &mut Vec<u8>, names: &[String]) -> bool {
    if names.is_empty() || body.is_empty() {
        return false;
    }
    if is_sdp(content_type) {
        return strip_attributes(body, names);
    }
    if !is_multipart(content_type) {
        return false;
    }
    let Ok(boundary) = extract_boundary(content_type) else {
        // No boundary, no parts: there is no SDP part to strip.
        return false;
    };
    let delimiter = format!("--{boundary}");
    let mut section = MultipartSection::Outside;
    retain_lines(body, |line| {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if let Some(after_delimiter) = content.strip_prefix(delimiter.as_bytes()) {
            // `--boundary` opens a part, `--boundary--` closes the body.
            section = if after_delimiter.starts_with(b"--") {
                MultipartSection::Outside
            } else {
                MultipartSection::PartHeaders { sdp: false }
            };
            return true;
        }
        match section {
            MultipartSection::PartHeaders { sdp } if content.is_empty() => {
                section = MultipartSection::PartBody { sdp };
                true
            }
            MultipartSection::PartHeaders { .. } => {
                if let Some(value) = part_content_type(content) {
                    section = MultipartSection::PartHeaders { sdp: is_sdp(value) };
                }
                true
            }
            MultipartSection::PartBody { sdp: true } => !is_attribute_line_named(line, names),
            MultipartSection::PartBody { sdp: false } | MultipartSection::Outside => true,
        }
    })
}

/// A body siphon sends carrying `sdp` beside what a script gave it to send:
/// the `Content-Type` and the bytes.
///
/// A session description rides with other content as one part of a
/// `multipart/*` body (RFC 5621 §3), whatever the other parts are: a
/// service's own XML document, a location object. What the script gave is
/// either such a body already or a single part:
///
/// * a `multipart/*` body with an `application/sdp` part: that part's content
///   becomes `sdp`, and every other part and the framing cross byte for byte;
/// * a `multipart/*` body without one: an `application/sdp` part is put first,
///   under the body's own boundary;
/// * any other type: a `multipart/mixed` body of the SDP part and then the
///   script's part, under a boundary that occurs in neither (RFC 2046 §5.1.1).
///
/// `Err` says why a `multipart/*` body cannot take the part: no `boundary`
/// parameter, or no delimiter line of that boundary in it.
pub fn with_sdp_part(
    content_type: &str,
    body: &[u8],
    sdp: &[u8],
) -> Result<(String, Vec<u8>), String> {
    if !is_multipart(content_type) {
        return Ok(mixed_of(sdp, content_type, body));
    }
    let boundary = extract_boundary(content_type)
        .map_err(|error| format!("multipart body cannot take the SDP: {error}"))?;
    let delimiter = format!("--{boundary}");
    let has_sdp_part = parse_multipart(content_type, body)
        .is_ok_and(|parts| parts.iter().any(|part| is_sdp(&part.content_type)));
    let mut composed = Vec::with_capacity(body.len() + sdp.len() + 64);
    let mut section = MultipartSection::Outside;
    let mut placed = false;
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if let Some(after_delimiter) = content.strip_prefix(delimiter.as_bytes()) {
            if !placed && !has_sdp_part {
                // The first delimiter: the SDP part goes ahead of it.
                composed.extend_from_slice(delimiter.as_bytes());
                composed.extend_from_slice(b"\r\nContent-Type: application/sdp\r\n\r\n");
                push_part_content(&mut composed, sdp);
                placed = true;
            } else if !placed && matches!(section, MultipartSection::PartBody { sdp: true }) {
                // The end of the part whose content `sdp` replaces.
                push_part_content(&mut composed, sdp);
                placed = true;
            }
            section = if after_delimiter.starts_with(b"--") {
                MultipartSection::Outside
            } else {
                MultipartSection::PartHeaders { sdp: false }
            };
            composed.extend_from_slice(line);
            continue;
        }
        match section {
            MultipartSection::PartHeaders { sdp: named } if content.is_empty() => {
                section = MultipartSection::PartBody { sdp: named };
            }
            MultipartSection::PartHeaders { .. } => {
                if let Some(value) = part_content_type(content) {
                    section = MultipartSection::PartHeaders { sdp: is_sdp(value) };
                }
            }
            // The content `sdp` replaces: only the first SDP part's.
            MultipartSection::PartBody { sdp: true } if !placed => continue,
            MultipartSection::PartBody { .. } | MultipartSection::Outside => {}
        }
        composed.extend_from_slice(line);
    }
    if !placed {
        return Err(format!(
            "multipart body cannot take the SDP: no part delimited by its boundary '{boundary}'"
        ));
    }
    Ok((content_type.trim().to_string(), composed))
}

/// The content of a part and the line break that belongs to the delimiter
/// after it (RFC 2046 §5.1.1), so an SDP whose last line ends in CRLF, as
/// RFC 8866 §5 has every line end, keeps that CRLF as its own.
fn push_part_content(composed: &mut Vec<u8>, content: &[u8]) {
    composed.extend_from_slice(content);
    if !content.ends_with(b"\n") {
        composed.extend_from_slice(b"\r\n");
    }
    composed.extend_from_slice(b"\r\n");
}

/// A `multipart/mixed` body of `sdp` and then `body` under `content_type`.
fn mixed_of(sdp: &[u8], content_type: &str, body: &[u8]) -> (String, Vec<u8>) {
    let contains = |haystack: &[u8], needle: &[u8]| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    };
    // A boundary must not occur in any part (RFC 2046 §5.1.1). A random one
    // does not, and is drawn again in the case it ever does.
    let boundary = loop {
        let candidate = format!("siphon-{}", uuid::Uuid::new_v4().as_simple());
        if !contains(sdp, candidate.as_bytes()) && !contains(body, candidate.as_bytes()) {
            break candidate;
        }
    };
    let mut composed = Vec::with_capacity(sdp.len() + body.len() + 256);
    composed.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    composed.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    push_part_content(&mut composed, sdp);
    composed.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    composed.extend_from_slice(format!("Content-Type: {}\r\n\r\n", content_type.trim()).as_bytes());
    composed.extend_from_slice(body);
    composed.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/mixed;boundary={boundary}"), composed)
}

/// Where a line of a multipart body sits, for [`strip_sdp_attributes`] and
/// [`with_sdp_part`].
#[derive(Clone, Copy)]
enum MultipartSection {
    /// The preamble before the first delimiter, or the epilogue after the last.
    Outside,
    /// A part's header block; `sdp` once its `Content-Type` has named SDP.
    PartHeaders { sdp: bool },
    /// A part's content, after the blank line that ends its headers.
    PartBody { sdp: bool },
}

/// The value of a part header line, when that header is `Content-Type`.
fn part_content_type(line: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(line).ok()?;
    let (name, value) = text.split_once(':')?;
    name.trim()
        .eq_ignore_ascii_case("content-type")
        .then_some(value.trim())
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

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn a_plain_sdp_body_loses_the_named_attributes() {
        let mut body = concat!(
            "v=0\r\n",
            "a=x-hidden\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=x-hidden:detail\r\n",
            "a=sendrecv\r\n",
        )
        .as_bytes()
        .to_vec();

        assert!(strip_sdp_attributes(
            "Application/SDP; charset=utf-8",
            &mut body,
            &names(&["x-hidden"])
        ));
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            "v=0\r\nm=audio 40000 RTP/AVP 0\r\na=sendrecv\r\n"
        );
    }

    #[test]
    fn only_the_sdp_part_of_a_multipart_body_is_stripped() {
        // The other part carries a line spelled like the attribute. It is not
        // SDP, so it has to cross byte for byte, and so do the preamble and the
        // MIME framing.
        let mut body = concat!(
            "a=x-hidden:preamble\r\n",
            "--siphon-1\r\n",
            "content-type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "a=x-hidden\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=X-Hidden:detail\r\n",
            "a=sendrecv\r\n",
            "\r\n--siphon-1\r\n",
            "Content-Type: application/vnd.example+xml\r\n",
            "\r\n",
            "a=x-hidden:not-sdp\r\n",
            "--siphon-1--\r\n",
        )
        .as_bytes()
        .to_vec();

        assert!(strip_sdp_attributes(
            "multipart/mixed;boundary=siphon-1",
            &mut body,
            &names(&["x-hidden"])
        ));
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            concat!(
                "a=x-hidden:preamble\r\n",
                "--siphon-1\r\n",
                "content-type: application/sdp\r\n",
                "\r\n",
                "v=0\r\n",
                "m=audio 40000 RTP/AVP 0\r\n",
                "a=sendrecv\r\n",
                "\r\n--siphon-1\r\n",
                "Content-Type: application/vnd.example+xml\r\n",
                "\r\n",
                "a=x-hidden:not-sdp\r\n",
                "--siphon-1--\r\n",
            )
        );
    }

    #[test]
    fn a_body_that_is_not_sdp_is_left_alone() {
        let original = b"a=x-hidden:detail\r\n".to_vec();
        for content_type in ["text/plain", "", "multipart/mixed"] {
            // A multipart type with no boundary cannot be split into parts, so
            // there is no SDP part to strip.
            let mut body = original.clone();
            assert!(
                !strip_sdp_attributes(content_type, &mut body, &names(&["x-hidden"])),
                "{content_type:?} was stripped"
            );
            assert_eq!(body, original, "{content_type:?} changed");
        }
    }

    #[test]
    fn a_multipart_body_whose_sdp_part_has_nothing_to_strip_is_untouched() {
        let original = concat!(
            "--b\r\n",
            "Content-Type: application/sdp\r\n",
            "\r\n",
            "v=0\r\n",
            "a=sendrecv\r\n",
            "--b--\r\n",
        )
        .as_bytes()
        .to_vec();
        let mut body = original.clone();

        assert!(!strip_sdp_attributes(
            "multipart/mixed;boundary=b",
            &mut body,
            &names(&["x-hidden"])
        ));
        assert_eq!(body, original);
    }

    const SEAT_SDP: &str = concat!(
        "v=0\r\n",
        "o=- 7 8 IN IP4 203.0.113.7\r\n",
        "s=-\r\n",
        "c=IN IP4 203.0.113.7\r\n",
        "t=0 0\r\n",
        "m=audio 40002 RTP/AVP 0\r\n",
    );

    #[test]
    fn a_single_part_is_wrapped_with_the_sdp_first_under_a_fresh_boundary() {
        let (content_type, body) = with_sdp_part(
            "application/vnd.example+xml",
            b"<additional-data/>",
            SEAT_SDP.as_bytes(),
        )
        .expect("composes");
        assert!(content_type.starts_with("multipart/mixed;boundary=siphon-"));
        let boundary = extract_boundary(&content_type).expect("a boundary");
        // RFC 2046 §5.1.1: at most 70 characters.
        assert!(boundary.len() <= 70, "{boundary}");
        let text = String::from_utf8(body.clone()).expect("text");
        assert_eq!(
            text,
            format!(
                "--{boundary}\r\nContent-Type: application/sdp\r\n\r\n{SEAT_SDP}\r\n\
                 --{boundary}\r\nContent-Type: application/vnd.example+xml\r\n\r\n\
                 <additional-data/>\r\n--{boundary}--\r\n"
            )
        );
        let parts = parse_multipart(&content_type, &body).expect("parses");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].content_type, "application/sdp");
        assert_eq!(parts[1].body, b"<additional-data/>");
        assert_eq!(
            sdp_from_body(&content_type, &body).expect("the SDP part"),
            SEAT_SDP.trim_end().as_bytes()
        );
    }

    #[test]
    fn two_wraps_draw_different_boundaries() {
        let one = with_sdp_part("text/plain", b"x", SEAT_SDP.as_bytes()).expect("composes");
        let other = with_sdp_part("text/plain", b"x", SEAT_SDP.as_bytes()).expect("composes");
        assert_ne!(one.0, other.0);
    }

    #[test]
    fn a_multipart_without_an_sdp_part_gets_one_first_under_its_own_boundary() {
        let given = concat!(
            "--b\r\n",
            "Content-Type: application/vnd.example+xml\r\n",
            "Content-Disposition: render\r\n",
            "\r\n",
            "<additional-data/>\r\n",
            "--b--\r\n",
        );
        let (content_type, body) = with_sdp_part(
            "multipart/mixed;boundary=b",
            given.as_bytes(),
            SEAT_SDP.as_bytes(),
        )
        .expect("composes");
        assert_eq!(content_type, "multipart/mixed;boundary=b");
        let text = String::from_utf8(body).expect("text");
        assert_eq!(
            text,
            format!("--b\r\nContent-Type: application/sdp\r\n\r\n{SEAT_SDP}\r\n{given}")
        );
    }

    #[test]
    fn the_sdp_part_of_a_multipart_is_replaced_and_the_rest_crosses_untouched() {
        let (content_type, body) = with_sdp_part(
            "multipart/mixed;boundary=siphon-1",
            multipart_body().as_bytes(),
            SEAT_SDP.as_bytes(),
        )
        .expect("composes");
        assert_eq!(content_type, "multipart/mixed;boundary=siphon-1");
        let text = String::from_utf8(body).expect("text");
        assert_eq!(
            text,
            format!(
                "--siphon-1\r\nContent-Type: application/sdp\r\n\r\n{SEAT_SDP}\r\n\
                 --siphon-1\r\nContent-Type: application/vnd.example+xml\r\n\r\n\
                 <additional-data/>\r\n--siphon-1--\r\n"
            )
        );
    }

    #[test]
    fn an_sdp_without_a_final_line_break_is_given_one() {
        let (_, body) = with_sdp_part("text/plain", b"x", b"v=0\r\ns=-").expect("composes");
        let text = String::from_utf8(body).expect("text");
        assert!(
            text.contains("\r\n\r\nv=0\r\ns=-\r\n\r\n--siphon-"),
            "{text}"
        );
    }

    #[test]
    fn a_multipart_that_cannot_take_the_part_says_why() {
        let error = with_sdp_part("multipart/mixed", b"--b\r\n", SEAT_SDP.as_bytes())
            .expect_err("no boundary");
        assert!(error.contains("boundary"), "{error}");
        let error = with_sdp_part(
            "multipart/mixed;boundary=b",
            b"no delimiter here\r\n",
            SEAT_SDP.as_bytes(),
        )
        .expect_err("no delimiter");
        assert!(error.contains("no part delimited"), "{error}");
    }
}
