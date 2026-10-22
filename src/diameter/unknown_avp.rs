//! AVPs the dictionary does not define, and the DIAMETER_AVP_UNSUPPORTED
//! (5001) answer an end server gives for the ones with the M bit.
//!
//! RFC 6733 section 4.1: "The receiving entity MUST return an appropriate
//! error message if it receives an AVP that has the M-bit set but does not
//! understand it", and "Diameter relay and redirect agents MUST NOT reject
//! messages with unrecognized AVPs". Section 7.1.5 makes that error 5001, with
//! "one or more Failed-AVP AVPs containing the AVPs that caused the failure".
//!
//! Whether a node understands an AVP is the application's to say, not the
//! dictionary's: a script can read an AVP the dictionary does not define by its
//! code, and the same `@diameter.on_request` path serves relays, which must let
//! unknown AVPs through. So siphon never answers 5001 on its own; the handler
//! of an end server asks for the answer, naming what it understands beyond the
//! dictionary.

use crate::diameter::codec::{Avp, AvpData, AVP_FLAG_MANDATORY};
use crate::diameter::dictionary;

fn known(avp: &Avp) -> bool {
    dictionary::lookup_avp(avp.code, avp.vendor).is_some()
}

/// Every AVP of `avps` the dictionary does not define, in wire order, at the
/// top level and inside the grouped AVPs it does define. An undefined grouped
/// AVP is one opaque AVP: its members cannot be told from its octets without
/// its definition.
pub fn unknown_avps(avps: &[Avp]) -> Vec<&Avp> {
    let mut found = Vec::new();
    collect_unknown(avps, &mut found);
    found
}

fn collect_unknown<'a>(avps: &'a [Avp], found: &mut Vec<&'a Avp>) {
    for avp in avps {
        match &avp.value {
            _ if !known(avp) => found.push(avp),
            AvpData::Grouped(members) => collect_unknown(members, found),
            AvpData::Raw(_) => {}
        }
    }
}

/// What goes in the Failed-AVP of a 5001 answer: each AVP of `avps` that
/// carries the M bit, that the dictionary does not define and that
/// `understood(code, vendor)` does not claim. One inside a grouped AVP comes
/// wrapped in that group, holding it alone, and so on up to the top level,
/// which RFC 6733 section 7.5 allows so that the peer can tell where it was.
///
/// An undefined AVP without the M bit is left out: section 4.1 lets the
/// receiver ignore it. So is everything inside an undefined group, which
/// section 4.4 lets the receiver ignore when the group has no M bit and which
/// is the group's own failure when it has.
pub fn unsupported_mandatory_avps(avps: &[Avp], understood: &dyn Fn(u32, u32) -> bool) -> Vec<Avp> {
    let mut failed = Vec::new();
    for avp in avps {
        if !known(avp) {
            if avp.flags & AVP_FLAG_MANDATORY != 0 && !understood(avp.code, avp.vendor) {
                failed.push(avp.clone());
            }
            continue;
        }
        if let AvpData::Grouped(members) = &avp.value {
            for member in unsupported_mandatory_avps(members, understood) {
                failed.push(Avp {
                    code: avp.code,
                    vendor: avp.vendor,
                    flags: avp.flags,
                    value: AvpData::Grouped(vec![member]),
                });
            }
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::AVP_FLAG_VENDOR;
    use crate::diameter::dictionary::{avp, VENDOR_3GPP};

    const MANDATORY_VENDOR: u8 = AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR;

    fn unknown(code: u32, flags: u8) -> Avp {
        Avp {
            code,
            vendor: VENDOR_3GPP,
            flags,
            value: AvpData::Raw(vec![0, 0, 0, 1]),
        }
    }

    fn nothing_more(_code: u32, _vendor: u32) -> bool {
        false
    }

    fn request_avps() -> Vec<Avp> {
        vec![
            Avp::utf8(avp::SESSION_ID, 0, "pgw.example.org;1;1"),
            unknown(64000, MANDATORY_VENDOR),
            unknown(64001, AVP_FLAG_VENDOR),
            Avp {
                code: avp::QOS_INFORMATION,
                vendor: VENDOR_3GPP,
                flags: MANDATORY_VENDOR,
                value: AvpData::Grouped(vec![
                    Avp::u32(avp::QOS_CLASS_IDENTIFIER, VENDOR_3GPP, 5),
                    unknown(64002, MANDATORY_VENDOR),
                ]),
            },
        ]
    }

    #[test]
    fn unknown_avps_are_listed_at_every_level_of_a_defined_group() {
        let avps = request_avps();
        let codes: Vec<u32> = unknown_avps(&avps).iter().map(|found| found.code).collect();
        assert_eq!(codes, [64000, 64001, 64002]);
    }

    #[test]
    fn only_the_m_bit_ones_fail_and_a_nested_one_keeps_its_group() {
        let failed = unsupported_mandatory_avps(&request_avps(), &nothing_more);
        assert_eq!(failed.len(), 2);
        assert_eq!(failed[0], unknown(64000, MANDATORY_VENDOR));
        assert_eq!(failed[1].code, avp::QOS_INFORMATION);
        assert_eq!(failed[1].flags, MANDATORY_VENDOR);
        assert_eq!(
            failed[1].value,
            AvpData::Grouped(vec![unknown(64002, MANDATORY_VENDOR)]),
            "the group holds the offending AVP alone"
        );
    }

    #[test]
    fn what_the_handler_understands_does_not_fail() {
        let understood = |code: u32, vendor: u32| (code, vendor) == (64000, VENDOR_3GPP);
        let failed = unsupported_mandatory_avps(&request_avps(), &understood);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].code, avp::QOS_INFORMATION);
    }

    #[test]
    fn a_request_of_defined_avps_has_nothing_to_fail() {
        let avps = vec![
            Avp::utf8(avp::SESSION_ID, 0, "pgw.example.org;1;1"),
            Avp::u32(avp::REVALIDATION_TIME, VENDOR_3GPP, 1),
        ];
        assert!(unknown_avps(&avps).is_empty());
        assert!(unsupported_mandatory_avps(&avps, &nothing_more).is_empty());
    }
}
