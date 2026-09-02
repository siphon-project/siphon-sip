//! Calling-party identity: presentation and restriction.
//!
//! Two operations a network element performs on the identity a call presents,
//! both of which have to preserve the dialog:
//!
//! - **Substitute** the presented number ([`set_calling_number`]) — the CLI a
//!   given carrier should see, which is a per-call, per-carrier decision.
//! - **Restrict** it ([`restrict_calling_identity`]) — CLIR, per RFC 3323 §4.1
//!   and 3GPP TS 24.607: the `From` is anonymised, `Privacy: id` is added, and
//!   `P-Asserted-Identity` keeps the real identity for the trusted next hop
//!   (RFC 3325 §7).
//!
//! Both go through [`NameAddr`], which round-trips the `tag` parameter, so
//! neither can break the dialog the way a raw `headers.set("From", …)` would —
//! a `From` written without its tag drops the mandatory dialog tag
//! (RFC 3261 §8.1.1.3) and the breakage only surfaces later, on the ACK.
//!
//! Sending `Privacy: id` while leaving the real number in the `From` is the
//! failure this module exists to prevent: it leaks the number to every carrier
//! that renders `From` rather than `P-Asserted-Identity`, which defeats CLIR
//! entirely while looking like it works.

use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::SipMessage;

/// RFC 3323 §4.1: the anonymous URI a restricted identity presents.
pub const ANONYMOUS_URI: &str = "sip:anonymous@anonymous.invalid";

/// RFC 3323 §4.1: the display name that accompanies it.
pub const ANONYMOUS_DISPLAY_NAME: &str = "Anonymous";

/// Whether the calling party's identity may be presented to the far end
/// (3GPP TS 24.607 — Originating Identification Restriction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerIdPresentation {
    /// Present the calling identity normally.
    Allowed,
    /// Withhold it: anonymise `From`, assert `Privacy: id`, keep the real
    /// identity in `P-Asserted-Identity` for the trusted next hop.
    Restricted,
}

impl CallerIdPresentation {
    /// Parse the wire/config spelling. Unrecognised values are `None` so the
    /// caller can complain rather than silently guessing at a privacy setting.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allowed" | "allow" | "present" | "presented" => Some(Self::Allowed),
            "restricted" | "restrict" | "private" | "anonymous" => Some(Self::Restricted),
            _ => None,
        }
    }
}

/// Rewrite the userpart of every `name-addr` on `header`, preserving the
/// display name, the tag and every other parameter.
///
/// Returns the number of values rewritten.
fn rewrite_userpart(message: &mut SipMessage, header: &str, user: &str) -> usize {
    let Some(values) = message.headers.get_all(header).cloned() else {
        return 0;
    };

    let mut rewritten = 0;
    let mut new_values = Vec::with_capacity(values.len());
    for value in values {
        match NameAddr::parse_multi(&value) {
            Ok(entries) if !entries.is_empty() => {
                let mut kept = Vec::with_capacity(entries.len());
                for mut entry in entries {
                    entry.uri.user = Some(user.to_string());
                    rewritten += 1;
                    kept.push(entry.to_string());
                }
                new_values.push(kept.join(", "));
            }
            // Unparseable — keep verbatim rather than corrupt it.
            _ => new_values.push(value),
        }
    }

    if rewritten > 0 {
        message.headers.remove(header);
        for value in new_values {
            message.headers.add(header, value);
        }
    }
    rewritten
}

/// Present `number` as the calling party on `From`, and on
/// `P-Asserted-Identity` / `P-Preferred-Identity` when the message carries
/// them.
///
/// The dialog tag on `From` is preserved, which is why this exists rather than
/// a `set_header("From", …)`: the B-leg's From tag is siphon's, and a header
/// written without it breaks every subsequent in-dialog request.
///
/// Returns `true` if anything was rewritten.
pub fn set_calling_number(message: &mut SipMessage, number: &str) -> bool {
    if number.is_empty() {
        return false;
    }
    let mut rewritten = rewrite_userpart(message, "From", number);
    rewritten += rewrite_userpart(message, "P-Asserted-Identity", number);
    rewritten += rewrite_userpart(message, "P-Preferred-Identity", number);
    rewritten > 0
}

/// Withhold the calling party's identity (CLIR), per RFC 3323 §4.1 and
/// TS 24.607.
///
/// - `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`, keeping
///   its tag so the dialog survives.
/// - `Privacy: id` is asserted (RFC 3325 §7), appended to any existing
///   `Privacy` value rather than replacing it.
/// - `P-Asserted-Identity` is left intact: it carries the real identity to the
///   trusted next hop, which is the entire mechanism by which the network can
///   still identify the caller for regulatory and emergency purposes.
/// - `P-Preferred-Identity` is removed. It is the UA's *request* for what to
///   assert (RFC 3325 §9.1) and has no meaning once the network has decided;
///   forwarding it past a privacy boundary re-leaks the number.
///
/// Do not call this and then reformat identity headers — anonymisation is the
/// last step, or a number policy will try to reshape `anonymous` as a number.
pub fn restrict_calling_identity(message: &mut SipMessage) {
    anonymize_from(message);

    message.headers.remove("P-Preferred-Identity");

    // RFC 3323 §4.2: Privacy is a list. Preserve anything already asserted.
    let existing = message.headers.get("Privacy").cloned().unwrap_or_default();
    let already_set = existing
        .split(';')
        .any(|token| token.trim().eq_ignore_ascii_case("id"));
    if !already_set {
        let value = if existing.trim().is_empty() {
            "id".to_string()
        } else {
            format!("{};id", existing.trim())
        };
        message.headers.set("Privacy", value);
    }
}

/// Replace `From` with the RFC 3323 anonymous name-addr, preserving the tag.
fn anonymize_from(message: &mut SipMessage) {
    let Some(value) = message.headers.get("From").cloned() else {
        return;
    };
    let tag = NameAddr::parse(&value).ok().and_then(|entry| entry.tag);

    let anonymous = match tag {
        Some(tag) => format!("\"{ANONYMOUS_DISPLAY_NAME}\" <{ANONYMOUS_URI}>;tag={tag}"),
        // No tag to preserve (a malformed From, or a non-dialog request).
        None => format!("\"{ANONYMOUS_DISPLAY_NAME}\" <{ANONYMOUS_URI}>"),
    };
    message.headers.set("From", anonymous);
}

/// Apply a presentation decision: substitute `number` when given, then restrict
/// if the presentation says so.
///
/// Ordering is load-bearing. The substitution runs first so that under
/// `Restricted` the real number reaches `P-Asserted-Identity` before `From` is
/// anonymised — otherwise the trusted next hop would be asserted an anonymous
/// identity, and the caller would be unidentifiable even inside the trust
/// domain.
pub fn apply_calling_identity(
    message: &mut SipMessage,
    number: Option<&str>,
    presentation: Option<CallerIdPresentation>,
) {
    if let Some(number) = number {
        set_calling_number(message, number);
    }
    if presentation == Some(CallerIdPresentation::Restricted) {
        restrict_calling_identity(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message;

    fn invite_with(extra: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "INVITE sip:+12025550199@carrier.example.net SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-privacy\r\n",
                "From: \"Alice\" <sip:+12025550100@siphon.example.com>;tag=a-tag\r\n",
                "To: <sip:+12025550199@carrier.example.net>\r\n",
                "Call-ID: privacy-1@host\r\n",
                "CSeq: 1 INVITE\r\n",
                "{}",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            extra
        );
        parse_sip_message(&raw).expect("fixture parses").1
    }

    fn header(message: &SipMessage, name: &str) -> Option<String> {
        message.headers.get(name).cloned()
    }

    #[test]
    fn presentation_parses_its_spellings() {
        assert_eq!(
            CallerIdPresentation::parse("allowed"),
            Some(CallerIdPresentation::Allowed)
        );
        assert_eq!(
            CallerIdPresentation::parse("RESTRICTED"),
            Some(CallerIdPresentation::Restricted)
        );
        assert_eq!(
            CallerIdPresentation::parse(" private "),
            Some(CallerIdPresentation::Restricted)
        );
        // Unrecognised is None, never a silent guess at a privacy setting.
        assert!(CallerIdPresentation::parse("maybe").is_none());
        assert!(CallerIdPresentation::parse("").is_none());
    }

    #[test]
    fn set_calling_number_rewrites_from_and_keeps_the_dialog_tag() {
        // The reason this exists rather than a set_header("From", …): a From
        // written without its tag drops the mandatory dialog tag and the
        // breakage only surfaces later, on the ACK.
        let mut message = invite_with("");
        assert!(set_calling_number(&mut message, "+12025550111"));

        let from = header(&message, "From").expect("From present");
        assert!(from.contains("+12025550111"), "{from}");
        assert!(!from.contains("+12025550100"), "{from}");
        assert!(
            from.contains("tag=a-tag"),
            "the dialog tag must survive: {from}"
        );
        assert!(from.contains("Alice"), "the display name survives: {from}");
    }

    #[test]
    fn set_calling_number_also_rewrites_asserted_identity_when_present() {
        let mut message =
            invite_with("P-Asserted-Identity: <sip:+12025550100@siphon.example.com>\r\n");
        set_calling_number(&mut message, "+12025550111");

        let pai = header(&message, "P-Asserted-Identity").expect("PAI present");
        assert!(pai.contains("+12025550111"), "{pai}");
    }

    #[test]
    fn set_calling_number_ignores_an_empty_number() {
        let mut message = invite_with("");
        assert!(!set_calling_number(&mut message, ""));
        assert!(header(&message, "From")
            .expect("From")
            .contains("+12025550100"));
    }

    #[test]
    fn restrict_anonymises_from_and_asserts_privacy_id() {
        let mut message = invite_with("");
        restrict_calling_identity(&mut message);

        let from = header(&message, "From").expect("From present");
        assert!(from.contains(ANONYMOUS_URI), "{from}");
        assert!(from.contains(ANONYMOUS_DISPLAY_NAME), "{from}");
        assert!(
            !from.contains("+12025550100"),
            "the real number must not survive in From: {from}",
        );
        assert!(
            from.contains("tag=a-tag"),
            "the dialog tag must survive: {from}"
        );
        assert_eq!(header(&message, "Privacy").as_deref(), Some("id"));
    }

    #[test]
    fn restrict_keeps_the_real_identity_in_p_asserted_identity() {
        // RFC 3325 §7: PAI carries the identity to the trusted next hop. That
        // is the mechanism by which the caller stays identifiable inside the
        // trust domain, for regulatory and emergency purposes.
        let mut message =
            invite_with("P-Asserted-Identity: <sip:+12025550100@siphon.example.com>\r\n");
        restrict_calling_identity(&mut message);

        let pai = header(&message, "P-Asserted-Identity").expect("PAI present");
        assert!(pai.contains("+12025550100"), "{pai}");
        assert!(header(&message, "From")
            .expect("From")
            .contains(ANONYMOUS_URI));
    }

    #[test]
    fn restrict_removes_p_preferred_identity() {
        // It is the UA's *request* for what to assert (RFC 3325 §9.1), with no
        // meaning once the network has decided — and forwarding it past a
        // privacy boundary re-leaks the number.
        let mut message =
            invite_with("P-Preferred-Identity: <sip:+12025550100@siphon.example.com>\r\n");
        restrict_calling_identity(&mut message);

        assert!(header(&message, "P-Preferred-Identity").is_none());
    }

    #[test]
    fn restrict_appends_to_an_existing_privacy_value() {
        let mut message = invite_with("Privacy: header\r\n");
        restrict_calling_identity(&mut message);

        let privacy = header(&message, "Privacy").expect("Privacy present");
        assert!(
            privacy.contains("header"),
            "existing tokens survive: {privacy}"
        );
        assert!(privacy.contains("id"), "{privacy}");
    }

    #[test]
    fn restrict_is_idempotent_on_privacy_id() {
        let mut message = invite_with("Privacy: id\r\n");
        restrict_calling_identity(&mut message);
        restrict_calling_identity(&mut message);

        assert_eq!(header(&message, "Privacy").as_deref(), Some("id"));
    }

    #[test]
    fn a_withheld_call_presents_an_anonymous_from_and_a_real_pai() {
        // The whole point, end to end: substitution runs before anonymisation,
        // so the trusted next hop is still asserted a real identity.
        let mut message =
            invite_with("P-Asserted-Identity: <sip:+12025550100@siphon.example.com>\r\n");
        apply_calling_identity(
            &mut message,
            Some("+12025550111"),
            Some(CallerIdPresentation::Restricted),
        );

        let from = header(&message, "From").expect("From");
        let pai = header(&message, "P-Asserted-Identity").expect("PAI");

        assert!(from.contains(ANONYMOUS_URI), "{from}");
        assert!(from.contains("tag=a-tag"), "{from}");
        assert!(
            pai.contains("+12025550111"),
            "the substituted number must reach the trusted hop: {pai}",
        );
        assert_eq!(header(&message, "Privacy").as_deref(), Some("id"));
    }

    #[test]
    fn presentation_allowed_leaves_the_identity_visible() {
        let mut message = invite_with("");
        apply_calling_identity(
            &mut message,
            Some("+12025550111"),
            Some(CallerIdPresentation::Allowed),
        );

        let from = header(&message, "From").expect("From");
        assert!(from.contains("+12025550111"), "{from}");
        assert!(header(&message, "Privacy").is_none(), "no privacy asserted");
    }

    #[test]
    fn no_number_and_no_presentation_changes_nothing() {
        let mut message = invite_with("");
        let before = header(&message, "From");
        apply_calling_identity(&mut message, None, None);

        assert_eq!(header(&message, "From"), before);
        assert!(header(&message, "Privacy").is_none());
    }
}
