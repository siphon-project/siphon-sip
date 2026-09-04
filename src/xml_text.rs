//! Shared XML text-content helpers for siphon's hand-rolled quick-xml parsers.
//!
//! quick-xml does not hand a parser one text node per element. An entity
//! reference inside text terminates the current [`Event::Text`] and arrives as
//! its own [`Event::GeneralRef`], with the text after it following as another
//! `Text`. A parser that accumulates only `Text` therefore drops every entity
//! silently — the characters simply vanish from the value, with no error.
//!
//! That is not academic for SIP: a contact URI legitimately carries `&` once it
//! has more than one header (`sip:a@b?X=1&Y=2`), and it must be escaped as
//! `&amp;` in XML. Dropping it rewrites the URI into a different, still
//! well-formed one.
//!
//! [`Event::Text`]: quick_xml::events::Event::Text
//! [`Event::GeneralRef`]: quick_xml::events::Event::GeneralRef

/// Resolve a general entity reference to its replacement text.
///
/// Takes the reference *body* as quick-xml reports it — no leading `&`, no
/// trailing `;` — and handles the two forms XML allows in content:
///
/// * the five predefined named entities (`amp`, `lt`, `gt`, `quot`, `apos`),
/// * numeric character references, decimal (`#38`) and hexadecimal (`#x26`).
///
/// Returns `None` for anything else, which is the honest answer: siphon parses
/// no DTD, so a document-defined entity has no replacement text available and
/// guessing one would invent content. Callers decide whether an unresolvable
/// reference is worth failing the parse over.
pub fn resolve_general_ref(reference: &str) -> Option<String> {
    if let Some(numeric) = reference.strip_prefix('#') {
        let code = match numeric.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => numeric.parse::<u32>().ok()?,
        };
        return char::from_u32(code).map(|character| character.to_string());
    }
    quick_xml::escape::resolve_xml_entity(reference).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_five_predefined_entities() {
        for (reference, expected) in [
            ("amp", "&"),
            ("lt", "<"),
            ("gt", ">"),
            ("quot", "\""),
            ("apos", "'"),
        ] {
            assert_eq!(resolve_general_ref(reference).as_deref(), Some(expected));
        }
    }

    #[test]
    fn resolves_numeric_references_in_both_bases() {
        assert_eq!(resolve_general_ref("#38").as_deref(), Some("&"));
        assert_eq!(resolve_general_ref("#x26").as_deref(), Some("&"));
        assert_eq!(resolve_general_ref("#X26").as_deref(), Some("&"));
        // Beyond the BMP — a decimal reference to an astral plane character.
        assert_eq!(resolve_general_ref("#128512").as_deref(), Some("\u{1F600}"));
    }

    #[test]
    fn refuses_to_invent_replacement_text() {
        // No DTD is parsed, so a document-defined entity has no expansion.
        assert_eq!(resolve_general_ref("mycompany"), None);
        // Not a character at all.
        assert_eq!(resolve_general_ref("#xD800"), None); // lone surrogate
        assert_eq!(resolve_general_ref("#99999999"), None);
        assert_eq!(resolve_general_ref("#xZZ"), None);
    }
}
