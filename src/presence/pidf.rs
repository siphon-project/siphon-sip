//! PIDF (Presence Information Data Format) per RFC 3863.
//!
//! Generates and parses `application/pidf+xml` documents without external XML
//! crates — PIDF is structurally simple enough for formatted-string generation
//! and basic tag-based extraction.

use std::fmt;

// ---------------------------------------------------------------------------
// BasicStatus
// ---------------------------------------------------------------------------

/// Basic presence status as defined in RFC 3863 §4.1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicStatus {
    Open,
    Closed,
}

impl BasicStatus {
    /// XML element content value (`"open"` or `"closed"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            BasicStatus::Open => "open",
            BasicStatus::Closed => "closed",
        }
    }

    /// Parse from the XML text content of a `<basic>` element.
    pub fn from_str_value(value: &str) -> Option<Self> {
        match value.trim() {
            "open" => Some(BasicStatus::Open),
            "closed" => Some(BasicStatus::Closed),
            _ => None,
        }
    }
}

impl fmt::Display for BasicStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Tuple
// ---------------------------------------------------------------------------

/// A single presence tuple (RFC 3863 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    /// Unique identifier for this tuple (e.g. `"t1"`).
    pub id: String,
    /// Basic status of the presentity in this tuple.
    pub status: BasicStatus,
    /// Optional contact URI.
    pub contact: Option<String>,
    /// Optional human-readable note.
    pub note: Option<String>,
    /// Optional ISO 8601 timestamp.
    pub timestamp: Option<String>,
}

// ---------------------------------------------------------------------------
// PresenceBody
// ---------------------------------------------------------------------------

/// A PIDF `<presence>` document (RFC 3863 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceBody {
    /// The presentity URI (the `entity` attribute), e.g. `"sip:alice@example.com"`.
    pub entity: String,
    /// Ordered list of presence tuples.
    pub tuples: Vec<Tuple>,
}

impl PresenceBody {
    /// Create a new empty presence document for the given entity URI.
    pub fn new(entity: String) -> Self {
        Self {
            entity,
            tuples: Vec::new(),
        }
    }

    /// Append a tuple to this document.
    pub fn add_tuple(&mut self, tuple: Tuple) {
        self.tuples.push(tuple);
    }

    /// Serialize to RFC 3863 PIDF XML.
    pub fn to_xml(&self) -> String {
        let mut output = String::with_capacity(512);
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str(&format!(
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"{}\">\n",
            xml_escape(&self.entity),
        ));

        for tuple in &self.tuples {
            output.push_str(&format!("  <tuple id=\"{}\">\n", xml_escape(&tuple.id)));
            output.push_str(&format!(
                "    <status><basic>{}</basic></status>\n",
                tuple.status.as_str(),
            ));
            if let Some(ref contact) = tuple.contact {
                output.push_str(&format!("    <contact>{}</contact>\n", xml_escape(contact),));
            }
            if let Some(ref note) = tuple.note {
                output.push_str(&format!("    <note>{}</note>\n", xml_escape(note)));
            }
            if let Some(ref timestamp) = tuple.timestamp {
                output.push_str(&format!(
                    "    <timestamp>{}</timestamp>\n",
                    xml_escape(timestamp),
                ));
            }
            output.push_str("  </tuple>\n");
        }

        output.push_str("</presence>\n");
        output
    }

    /// Parse a PIDF XML document using simple string matching.
    ///
    /// This is intentionally not a full XML parser — it handles the
    /// well-formed output that compliant PIDF producers generate.
    pub fn parse(xml: &str) -> Option<Self> {
        let entity = extract_attribute(xml, "presence", "entity")?;
        let mut tuples = Vec::new();

        let mut search_from = 0;
        while let Some(tuple_start) = xml[search_from..].find("<tuple") {
            let absolute_start = search_from + tuple_start;
            let tuple_end = match xml[absolute_start..].find("</tuple>") {
                Some(offset) => absolute_start + offset + "</tuple>".len(),
                None => break,
            };
            let tuple_fragment = &xml[absolute_start..tuple_end];

            let id = extract_attribute(tuple_fragment, "tuple", "id").unwrap_or_default();

            let status = extract_tag_content(tuple_fragment, "basic")
                .and_then(|value| BasicStatus::from_str_value(&value))
                .unwrap_or(BasicStatus::Closed);

            let contact = extract_tag_content(tuple_fragment, "contact");
            let note = extract_tag_content(tuple_fragment, "note");
            let timestamp = extract_tag_content(tuple_fragment, "timestamp");

            tuples.push(Tuple {
                id,
                status,
                contact,
                note,
                timestamp,
            });

            search_from = tuple_end;
        }

        Some(PresenceBody { entity, tuples })
    }

    /// The MIME content type for PIDF documents.
    pub fn content_type() -> &'static str {
        "application/pidf+xml"
    }
}

// ---------------------------------------------------------------------------
// compose
// ---------------------------------------------------------------------------

/// Merge multiple PIDF documents for the same presentity.
///
/// All tuples from every document are collected into a single
/// `PresenceBody`. The `entity` URI is taken from the first document.
pub fn compose(documents: &[PresenceBody]) -> PresenceBody {
    let entity = documents
        .first()
        .map(|document| document.entity.clone())
        .unwrap_or_default();

    let mut merged = PresenceBody::new(entity);
    for document in documents {
        for tuple in &document.tuples {
            merged.add_tuple(tuple.clone());
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal XML escaping for the five predefined XML entities.
fn xml_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

/// Reverse minimal XML unescaping.
fn xml_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Extract the text content between `<tag>` and `</tag>`.
fn extract_tag_content(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let open_position = xml.find(&open)?;
    // Advance past the `>` that closes the opening tag (handles attributes).
    let content_start = xml[open_position..].find('>')? + open_position + 1;
    let close_position = xml[content_start..].find(&close)? + content_start;

    let raw = xml[content_start..close_position].trim();
    if raw.is_empty() {
        return None;
    }
    Some(xml_unescape(raw))
}

/// Extract an attribute value from the first occurrence of `<tag ... attr="value"`.
fn extract_attribute(xml: &str, tag: &str, attribute: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let tag_position = xml.find(&open)?;
    // Find the closing `>` of this opening tag.
    let tag_end = xml[tag_position..].find('>')? + tag_position;
    let tag_fragment = &xml[tag_position..tag_end];

    let attr_needle = format!("{}=\"", attribute);
    let attr_position = tag_fragment.find(&attr_needle)?;
    let value_start = attr_position + attr_needle.len();
    let value_end = tag_fragment[value_start..].find('"')? + value_start;

    Some(xml_unescape(&tag_fragment[value_start..value_end]))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BasicStatus -------------------------------------------------------

    #[test]
    fn basic_status_display() {
        assert_eq!(BasicStatus::Open.to_string(), "open");
        assert_eq!(BasicStatus::Closed.to_string(), "closed");
    }

    #[test]
    fn basic_status_round_trip() {
        for status in [BasicStatus::Open, BasicStatus::Closed] {
            let parsed = BasicStatus::from_str_value(status.as_str()).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn basic_status_from_invalid() {
        assert_eq!(BasicStatus::from_str_value("unknown"), None);
        assert_eq!(BasicStatus::from_str_value(""), None);
    }

    #[test]
    fn basic_status_from_trimmed() {
        assert_eq!(
            BasicStatus::from_str_value("  open  "),
            Some(BasicStatus::Open)
        );
    }

    // -- Tuple creation ----------------------------------------------------

    #[test]
    fn tuple_with_all_fields() {
        let tuple = Tuple {
            id: "t1".into(),
            status: BasicStatus::Open,
            contact: Some("sip:alice@10.0.0.1".into()),
            note: Some("Online".into()),
            timestamp: Some("2024-01-01T00:00:00Z".into()),
        };
        assert_eq!(tuple.id, "t1");
        assert_eq!(tuple.status, BasicStatus::Open);
        assert_eq!(tuple.contact.as_deref(), Some("sip:alice@10.0.0.1"));
        assert_eq!(tuple.note.as_deref(), Some("Online"));
        assert_eq!(tuple.timestamp.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn tuple_with_minimal_fields() {
        let tuple = Tuple {
            id: "t0".into(),
            status: BasicStatus::Closed,
            contact: None,
            note: None,
            timestamp: None,
        };
        assert_eq!(tuple.status, BasicStatus::Closed);
        assert!(tuple.contact.is_none());
        assert!(tuple.note.is_none());
        assert!(tuple.timestamp.is_none());
    }

    // -- PresenceBody construction -----------------------------------------

    #[test]
    fn new_presence_body_is_empty() {
        let body = PresenceBody::new("sip:alice@example.com".into());
        assert_eq!(body.entity, "sip:alice@example.com");
        assert!(body.tuples.is_empty());
    }

    #[test]
    fn add_tuple_appends() {
        let mut body = PresenceBody::new("sip:bob@example.com".into());
        body.add_tuple(Tuple {
            id: "a".into(),
            status: BasicStatus::Open,
            contact: None,
            note: None,
            timestamp: None,
        });
        body.add_tuple(Tuple {
            id: "b".into(),
            status: BasicStatus::Closed,
            contact: None,
            note: None,
            timestamp: None,
        });
        assert_eq!(body.tuples.len(), 2);
        assert_eq!(body.tuples[0].id, "a");
        assert_eq!(body.tuples[1].id, "b");
    }

    // -- content_type ------------------------------------------------------

    #[test]
    fn content_type_is_correct() {
        assert_eq!(PresenceBody::content_type(), "application/pidf+xml");
    }

    // -- XML generation ----------------------------------------------------

    #[test]
    fn to_xml_full_tuple() {
        let mut body = PresenceBody::new("sip:alice@example.com".into());
        body.add_tuple(Tuple {
            id: "t1".into(),
            status: BasicStatus::Open,
            contact: Some("sip:alice@10.0.0.1".into()),
            note: Some("Online".into()),
            timestamp: Some("2024-01-01T00:00:00Z".into()),
        });

        let xml = body.to_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("entity=\"sip:alice@example.com\""));
        assert!(xml.contains("<tuple id=\"t1\">"));
        assert!(xml.contains("<status><basic>open</basic></status>"));
        assert!(xml.contains("<contact>sip:alice@10.0.0.1</contact>"));
        assert!(xml.contains("<note>Online</note>"));
        assert!(xml.contains("<timestamp>2024-01-01T00:00:00Z</timestamp>"));
        assert!(xml.contains("</tuple>"));
        assert!(xml.contains("</presence>"));
    }

    #[test]
    fn to_xml_minimal_tuple() {
        let mut body = PresenceBody::new("sip:bob@example.com".into());
        body.add_tuple(Tuple {
            id: "min".into(),
            status: BasicStatus::Closed,
            contact: None,
            note: None,
            timestamp: None,
        });

        let xml = body.to_xml();
        assert!(xml.contains("<status><basic>closed</basic></status>"));
        assert!(!xml.contains("<contact>"));
        assert!(!xml.contains("<note>"));
        assert!(!xml.contains("<timestamp>"));
    }

    #[test]
    fn to_xml_empty_tuples() {
        let body = PresenceBody::new("sip:nobody@example.com".into());
        let xml = body.to_xml();
        assert!(xml.contains("entity=\"sip:nobody@example.com\""));
        assert!(!xml.contains("<tuple"));
        assert!(xml.contains("</presence>"));
    }

    #[test]
    fn to_xml_multiple_tuples() {
        let mut body = PresenceBody::new("sip:multi@example.com".into());
        body.add_tuple(Tuple {
            id: "desk".into(),
            status: BasicStatus::Open,
            contact: Some("sip:multi@desk.example.com".into()),
            note: Some("At desk".into()),
            timestamp: None,
        });
        body.add_tuple(Tuple {
            id: "mobile".into(),
            status: BasicStatus::Closed,
            contact: Some("sip:multi@mobile.example.com".into()),
            note: None,
            timestamp: None,
        });

        let xml = body.to_xml();
        assert!(xml.contains("<tuple id=\"desk\">"));
        assert!(xml.contains("<tuple id=\"mobile\">"));

        // Verify ordering: desk appears before mobile.
        let desk_position = xml.find("id=\"desk\"").unwrap();
        let mobile_position = xml.find("id=\"mobile\"").unwrap();
        assert!(desk_position < mobile_position);
    }

    #[test]
    fn to_xml_escapes_special_characters() {
        let mut body = PresenceBody::new("sip:a&b@example.com".into());
        body.add_tuple(Tuple {
            id: "x\"y".into(),
            status: BasicStatus::Open,
            contact: Some("sip:<user>@host".into()),
            note: Some("it's a \"test\" & more".into()),
            timestamp: None,
        });

        let xml = body.to_xml();
        assert!(xml.contains("entity=\"sip:a&amp;b@example.com\""));
        assert!(xml.contains("id=\"x&quot;y\""));
        assert!(xml.contains("<contact>sip:&lt;user&gt;@host</contact>"));
        assert!(xml.contains("it&apos;s a &quot;test&quot; &amp; more"));
    }

    // -- XML parsing -------------------------------------------------------

    #[test]
    fn parse_full_document() {
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:alice@example.com\">\n",
            "  <tuple id=\"t1\">\n",
            "    <status><basic>open</basic></status>\n",
            "    <contact>sip:alice@10.0.0.1</contact>\n",
            "    <note>Online</note>\n",
            "    <timestamp>2024-01-01T00:00:00Z</timestamp>\n",
            "  </tuple>\n",
            "</presence>\n",
        );

        let body = PresenceBody::parse(xml).unwrap();
        assert_eq!(body.entity, "sip:alice@example.com");
        assert_eq!(body.tuples.len(), 1);

        let tuple = &body.tuples[0];
        assert_eq!(tuple.id, "t1");
        assert_eq!(tuple.status, BasicStatus::Open);
        assert_eq!(tuple.contact.as_deref(), Some("sip:alice@10.0.0.1"));
        assert_eq!(tuple.note.as_deref(), Some("Online"));
        assert_eq!(tuple.timestamp.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn parse_minimal_tuple() {
        let xml = concat!(
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:bob@example.com\">\n",
            "  <tuple id=\"t0\">\n",
            "    <status><basic>closed</basic></status>\n",
            "  </tuple>\n",
            "</presence>\n",
        );

        let body = PresenceBody::parse(xml).unwrap();
        assert_eq!(body.tuples.len(), 1);
        assert_eq!(body.tuples[0].status, BasicStatus::Closed);
        assert!(body.tuples[0].contact.is_none());
        assert!(body.tuples[0].note.is_none());
        assert!(body.tuples[0].timestamp.is_none());
    }

    #[test]
    fn parse_multiple_tuples() {
        let xml = concat!(
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:multi@example.com\">\n",
            "  <tuple id=\"a\">\n",
            "    <status><basic>open</basic></status>\n",
            "  </tuple>\n",
            "  <tuple id=\"b\">\n",
            "    <status><basic>closed</basic></status>\n",
            "    <contact>sip:multi@mobile</contact>\n",
            "  </tuple>\n",
            "</presence>\n",
        );

        let body = PresenceBody::parse(xml).unwrap();
        assert_eq!(body.tuples.len(), 2);
        assert_eq!(body.tuples[0].id, "a");
        assert_eq!(body.tuples[0].status, BasicStatus::Open);
        assert_eq!(body.tuples[1].id, "b");
        assert_eq!(body.tuples[1].status, BasicStatus::Closed);
        assert_eq!(body.tuples[1].contact.as_deref(), Some("sip:multi@mobile"));
    }

    #[test]
    fn parse_empty_presence() {
        let xml = concat!(
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:empty@example.com\">\n",
            "</presence>\n",
        );

        let body = PresenceBody::parse(xml).unwrap();
        assert_eq!(body.entity, "sip:empty@example.com");
        assert!(body.tuples.is_empty());
    }

    #[test]
    fn parse_returns_none_without_presence_tag() {
        assert!(PresenceBody::parse("<other>no presence here</other>").is_none());
        assert!(PresenceBody::parse("").is_none());
    }

    #[test]
    fn parse_handles_escaped_entities() {
        let xml = concat!(
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:a&amp;b@example.com\">\n",
            "  <tuple id=\"x&quot;y\">\n",
            "    <status><basic>open</basic></status>\n",
            "    <note>it&apos;s &amp; &lt;ok&gt;</note>\n",
            "  </tuple>\n",
            "</presence>\n",
        );

        let body = PresenceBody::parse(xml).unwrap();
        assert_eq!(body.entity, "sip:a&b@example.com");
        assert_eq!(body.tuples[0].id, "x\"y");
        assert_eq!(body.tuples[0].note.as_deref(), Some("it's & <ok>"));
    }

    // -- Roundtrip ---------------------------------------------------------

    #[test]
    fn xml_roundtrip() {
        let mut original = PresenceBody::new("sip:roundtrip@example.com".into());
        original.add_tuple(Tuple {
            id: "r1".into(),
            status: BasicStatus::Open,
            contact: Some("sip:roundtrip@192.168.1.1:5060".into()),
            note: Some("Available".into()),
            timestamp: Some("2025-06-15T12:30:00Z".into()),
        });
        original.add_tuple(Tuple {
            id: "r2".into(),
            status: BasicStatus::Closed,
            contact: None,
            note: None,
            timestamp: None,
        });

        let xml = original.to_xml();
        let parsed = PresenceBody::parse(&xml).unwrap();

        assert_eq!(parsed.entity, original.entity);
        assert_eq!(parsed.tuples.len(), original.tuples.len());
        for (parsed_tuple, original_tuple) in parsed.tuples.iter().zip(original.tuples.iter()) {
            assert_eq!(parsed_tuple.id, original_tuple.id);
            assert_eq!(parsed_tuple.status, original_tuple.status);
            assert_eq!(parsed_tuple.contact, original_tuple.contact);
            assert_eq!(parsed_tuple.note, original_tuple.note);
            assert_eq!(parsed_tuple.timestamp, original_tuple.timestamp);
        }
    }

    #[test]
    fn xml_roundtrip_with_special_characters() {
        let mut original = PresenceBody::new("sip:test&user@example.com".into());
        original.add_tuple(Tuple {
            id: "id\"1".into(),
            status: BasicStatus::Open,
            contact: Some("sip:<special>@host".into()),
            note: Some("it's a \"fancy\" note & more".into()),
            timestamp: None,
        });

        let xml = original.to_xml();
        let parsed = PresenceBody::parse(&xml).unwrap();
        assert_eq!(parsed, original);
    }

    // -- compose -----------------------------------------------------------

    #[test]
    fn compose_merges_tuples() {
        let mut document_a = PresenceBody::new("sip:alice@example.com".into());
        document_a.add_tuple(Tuple {
            id: "desk".into(),
            status: BasicStatus::Open,
            contact: Some("sip:alice@desk".into()),
            note: None,
            timestamp: None,
        });

        let mut document_b = PresenceBody::new("sip:alice@example.com".into());
        document_b.add_tuple(Tuple {
            id: "mobile".into(),
            status: BasicStatus::Closed,
            contact: Some("sip:alice@mobile".into()),
            note: None,
            timestamp: None,
        });

        let merged = compose(&[document_a, document_b]);
        assert_eq!(merged.entity, "sip:alice@example.com");
        assert_eq!(merged.tuples.len(), 2);
        assert_eq!(merged.tuples[0].id, "desk");
        assert_eq!(merged.tuples[1].id, "mobile");
    }

    #[test]
    fn compose_uses_first_entity() {
        let document_a = PresenceBody::new("sip:first@example.com".into());
        let document_b = PresenceBody::new("sip:second@example.com".into());

        let merged = compose(&[document_a, document_b]);
        assert_eq!(merged.entity, "sip:first@example.com");
    }

    #[test]
    fn compose_empty_slice() {
        let merged = compose(&[]);
        assert_eq!(merged.entity, "");
        assert!(merged.tuples.is_empty());
    }

    #[test]
    fn compose_single_document() {
        let mut document = PresenceBody::new("sip:solo@example.com".into());
        document.add_tuple(Tuple {
            id: "only".into(),
            status: BasicStatus::Open,
            contact: None,
            note: Some("Just me".into()),
            timestamp: None,
        });

        let merged = compose(&[document.clone()]);
        assert_eq!(merged, document);
    }

    #[test]
    fn compose_preserves_tuple_order() {
        let mut documents: Vec<PresenceBody> = Vec::new();
        for index in 0..3 {
            let mut document = PresenceBody::new("sip:order@example.com".into());
            document.add_tuple(Tuple {
                id: format!("t{}", index),
                status: BasicStatus::Open,
                contact: None,
                note: None,
                timestamp: None,
            });
            documents.push(document);
        }

        let merged = compose(&documents);
        assert_eq!(merged.tuples.len(), 3);
        for (index, tuple) in merged.tuples.iter().enumerate() {
            assert_eq!(tuple.id, format!("t{}", index));
        }
    }

    // -- xml_escape / xml_unescape helpers ---------------------------------

    #[test]
    fn escape_and_unescape_roundtrip() {
        let original = "a&b<c>d\"e'f";
        let escaped = xml_escape(original);
        assert_eq!(escaped, "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        let unescaped = xml_unescape(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn escape_leaves_plain_text_unchanged() {
        let plain = "hello world 123";
        assert_eq!(xml_escape(plain), plain);
    }
}
