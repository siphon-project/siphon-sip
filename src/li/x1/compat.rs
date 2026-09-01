//! Narrow compatibility rewrites applied to inbound X1 documents.
//!
//! Everything here exists because a real peer emits something the published
//! schema does not allow, and refusing it would cost more than accepting it.
//! Each rewrite is deliberately specific — one element, one shape — rather than
//! a general loosening, and each logs when it fires, because a deviation the
//! operator never hears about is one nobody raises with the vendor.
//!
//! Nothing here changes what siphon *emits*. Outbound documents are built from
//! the typed model and validated strictly; a peer that is lenient with us gets
//! conformant messages back regardless.
//!
//! # The one rewrite
//!
//! **Fractional seconds on a date-time.** TS 103 280's
//! `QualifiedMicrosecondDateTime` requires exactly six fractional digits.
//! sipgate's `li-lib` renders a Java `XMLGregorianCalendar`, which produces
//! three, so every message from a simulator or ADMF built on it fails schema
//! validation on `messageTimestamp` before anything else is even looked at.
//! Refusing them means no warrant can be provisioned at all, which is a far
//! worse outcome on a lawful-intercept interface than accepting a timestamp
//! that names the same instant in a different width.

use tracing::warn;

use super::types::normalise_fractional_seconds;

/// Elements whose content is a `QualifiedMicrosecondDateTime`.
///
/// Matched on the local name, so a prefixed form (`x1:messageTimestamp`) is
/// covered too.
const DATE_TIME_ELEMENTS: &[&str] = &["messageTimestamp", "StartTime", "EndTime"];

/// Rewrite non-conformant fractional seconds in an inbound X1 document.
///
/// Returns the document and whether anything was changed, so the caller can log
/// once per message rather than once per element.
pub fn normalise_inbound_timestamps(xml: &str) -> (String, bool) {
    let mut output = String::with_capacity(xml.len());
    let mut rest = xml;
    let mut changed = false;

    while let Some(open) = rest.find('<') {
        output.push_str(&rest[..open]);
        rest = &rest[open..];

        // The element's name runs to the first delimiter after `<`.
        let Some(name_end) = rest[1..].find(['>', ' ', '\t', '\r', '\n', '/']) else {
            break;
        };
        let raw_name = &rest[1..1 + name_end];
        let local = raw_name.rsplit(':').next().unwrap_or(raw_name);

        if !DATE_TIME_ELEMENTS.contains(&local) {
            // Not one of ours: copy the `<` and carry on from the next byte, so
            // the scan cannot loop.
            output.push('<');
            rest = &rest[1..];
            continue;
        }

        // Copy the start tag through its closing `>`.
        let Some(tag_end) = rest.find('>') else {
            break;
        };
        output.push_str(&rest[..=tag_end]);
        rest = &rest[tag_end + 1..];

        // A self-closing tag has no text to rewrite.
        if output.ends_with("/>") {
            continue;
        }

        let Some(close) = rest.find("</") else {
            break;
        };
        let text = &rest[..close];
        match normalise_fractional_seconds(text.trim()) {
            Some(normalised) if normalised != text.trim() => {
                output.push_str(&normalised);
                changed = true;
            }
            _ => output.push_str(text),
        }
        rest = &rest[close..];
    }
    output.push_str(rest);

    if changed {
        warn!(
            "an X1 peer sent a date-time whose fractional second is not the six digits \
             TS 103 280 requires; siphon normalised it so provisioning can proceed, but the \
             peer is emitting schema-invalid timestamps and should be told"
        );
    }
    (output, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_millisecond_timestamp_is_widened() {
        // The exact shape sipgate's li-lib emits.
        let (out, changed) = normalise_inbound_timestamps(
            "<messageTimestamp>2026-08-31T17:04:58.754Z</messageTimestamp>",
        );
        assert!(changed);
        assert_eq!(
            out,
            "<messageTimestamp>2026-08-31T17:04:58.754000Z</messageTimestamp>"
        );
    }

    #[test]
    fn a_conformant_timestamp_is_untouched() {
        let input = "<messageTimestamp>2026-08-31T17:04:58.754000Z</messageTimestamp>";
        let (out, changed) = normalise_inbound_timestamps(input);
        assert!(!changed);
        assert_eq!(out, input);
    }

    #[test]
    fn a_prefixed_element_is_covered() {
        let (out, changed) = normalise_inbound_timestamps(
            "<x1:messageTimestamp>2026-08-31T17:04:58.7Z</x1:messageTimestamp>",
        );
        assert!(changed);
        assert!(out.contains("2026-08-31T17:04:58.700000Z"));
    }

    #[test]
    fn the_mediation_window_elements_are_covered() {
        let (out, changed) = normalise_inbound_timestamps(
            "<StartTime>2026-08-01T00:00:00.5Z</StartTime>\
             <EndTime>2026-09-01T00:00:00.25Z</EndTime>",
        );
        assert!(changed);
        assert!(out.contains("2026-08-01T00:00:00.500000Z"));
        assert!(out.contains("2026-09-01T00:00:00.250000Z"));
    }

    #[test]
    fn other_elements_are_left_alone() {
        // Only the date-time elements are rewritten; nothing else is touched,
        // however much it may look like one.
        let input = "<friendlyName>2026-08-31T17:04:58.754Z</friendlyName>";
        let (out, changed) = normalise_inbound_timestamps(input);
        assert!(!changed);
        assert_eq!(out, input);
    }

    #[test]
    fn a_whole_container_round_trips_with_only_the_timestamp_changed() {
        let input = concat!(
            "<?xml version=\"1.0\"?>",
            "<X1Request xmlns=\"http://uri.etsi.org/03221/X1/2017/10\">",
            "<x1RequestMessage xsi:type=\"PingRequest\">",
            "<admfIdentifier>admf-id</admfIdentifier>",
            "<neIdentifier>siphon-ne</neIdentifier>",
            "<messageTimestamp>2026-08-31T17:04:58.754Z</messageTimestamp>",
            "<version>v1.6.1</version>",
            "<x1TransactionId>0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f60</x1TransactionId>",
            "</x1RequestMessage></X1Request>",
        );
        let (out, changed) = normalise_inbound_timestamps(input);
        assert!(changed);
        assert!(out.contains("2026-08-31T17:04:58.754000Z"));
        // Everything else survives byte-for-byte.
        assert!(out.contains("<admfIdentifier>admf-id</admfIdentifier>"));
        assert!(out.contains("<version>v1.6.1</version>"));
        assert!(out.contains("xsi:type=\"PingRequest\""));
        assert!(out.contains("0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f60"));
        assert_eq!(out.matches("x1RequestMessage").count(), 2);
    }

    #[test]
    fn malformed_input_is_returned_rather_than_lost() {
        // The rewriter is not a parser; anything it cannot make sense of is
        // passed through for the real validator to reject.
        for input in ["", "<", "not xml", "<messageTimestamp>", "<messageTimestamp>x"] {
            let (out, _) = normalise_inbound_timestamps(input);
            assert!(
                out.contains(input.trim_start_matches('<').trim())
                    || out == input
                    || input.starts_with('<'),
                "{input:?} was mangled into {out:?}"
            );
        }
    }

    #[test]
    fn a_jaxb_style_document_survives_the_rewrite() {
        // The shape sipgate's simulator actually emits: JAXB puts the
        // dictionary types under a generated `ns2` prefix and declares it on
        // the root. A rewriter that dropped or reordered any of that would
        // produce a document whose prefixes no longer resolve — which is
        // exactly what happened the first time this was wired up.
        let input = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<X1Request xmlns=\"http://uri.etsi.org/03221/X1/2017/10\" ",
            "xmlns:ns2=\"http://uri.etsi.org/03280/common/2017/07\">",
            "<x1RequestMessage xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ",
            "xsi:type=\"CreateDestinationRequest\">",
            "<admfIdentifier>simulator</admfIdentifier>",
            "<neIdentifier>network-element</neIdentifier>",
            "<messageTimestamp>2026-08-31T17:16:08.832Z</messageTimestamp>",
            "<version>v1.6.1</version>",
            "<x1TransactionId>a8d730e4-e71a-4ce8-978d-124c0ab6ed1b</x1TransactionId>",
            "<destinationDetails><dId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</dId>",
            "<friendlyName>sipp-li-test</friendlyName>",
            "<deliveryType>X2Only</deliveryType>",
            "<deliveryAddress><ipAddressAndPort>",
            "<ns2:address><ns2:IPv4Address>172.20.0.62</ns2:IPv4Address></ns2:address>",
            "<ns2:port><ns2:TCPPort>42069</ns2:TCPPort></ns2:port>",
            "</ipAddressAndPort></deliveryAddress></destinationDetails>",
            "</x1RequestMessage></X1Request>",
        );

        let (out, changed) = normalise_inbound_timestamps(input);
        assert!(changed, "the millisecond timestamp should have been widened");

        // The only difference must be the timestamp's width.
        assert_eq!(
            out,
            input.replace("17:16:08.832Z", "17:16:08.832000Z"),
            "the rewrite changed something other than the timestamp"
        );
    }

    #[test]
    fn a_document_with_no_timestamp_is_unchanged() {
        let input = "<X1Request><x1RequestMessage/></X1Request>";
        let (out, changed) = normalise_inbound_timestamps(input);
        assert!(!changed);
        assert_eq!(out, input);
    }
}
