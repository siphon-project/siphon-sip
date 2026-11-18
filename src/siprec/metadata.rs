//! RFC 7866 recording metadata XML generation and parsing.
//!
//! **Generation**: Builds the `application/rs-metadata+xml` body part for
//! SIPREC INVITE requests sent by the SRC.
//!
//! **Parsing**: Extracts session, participant, and stream information from
//! inbound SIPREC INVITEs received by the SRS.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use thiserror::Error;

/// quick-xml 0.41 (RUSTSEC-2026-0194/0195 fix) removed `BytesText::unescape()`;
/// restore its "decode encoding + resolve XML entities" behaviour.
trait BytesTextExt {
    fn unescape(&self) -> Result<std::borrow::Cow<'_, str>, String>;
}
impl BytesTextExt for quick_xml::events::BytesText<'_> {
    fn unescape(&self) -> Result<std::borrow::Cow<'_, str>, String> {
        // quick-xml 0.42 made `BytesText` `str`-backed, so decoding happens in
        // the reader and `decode()` is gone. `xml10_content()` is the
        // replacement for that half — it applies XML 1.0 end-of-line
        // normalisation (§2.11) and nothing else, so the entity resolution the
        // old `unescape()` did still has to be layered on top.
        let content = self.xml10_content();
        Ok(std::borrow::Cow::Owned(
            quick_xml::escape::unescape(&content)
                .map_err(|error| error.to_string())?
                .into_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("missing required element: {0}")]
    MissingElement(String),
}

impl From<quick_xml::Error> for MetadataError {
    fn from(error: quick_xml::Error) -> Self {
        Self::Xml(error.to_string())
    }
}

// ---------------------------------------------------------------------------
// Parsed metadata types
// ---------------------------------------------------------------------------

/// Whether a metadata document is a full snapshot or carries only what changed
/// (RFC 7865 §9.1, RFC 7866 §9.1). Absent, it is `complete`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DataMode {
    /// The whole recording session's metadata.
    #[default]
    Complete,
    /// Only the elements that changed since the last snapshot.
    Partial,
}

impl DataMode {
    /// The `<datamode>` value: `complete` or `partial`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

/// Which streams a participant sends and receives (RFC 7865 §8.4,
/// `<participantstreamassoc>`): what tells a stored recording which side is
/// the caller and which the callee.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParticipantStreamAssoc {
    /// The participant this association is for.
    pub participant_id: String,
    /// Stream ids the participant sends on.
    pub send: Vec<String>,
    /// Stream ids the participant receives.
    pub recv: Vec<String>,
}

/// Parsed RFC 7866 recording metadata from a SIPREC INVITE.
#[derive(Debug, Clone, Default)]
pub struct RecordingMetadata {
    /// Recording session ID (from `<session session_id="...">`). Empty only on
    /// a partial update, which need not repeat the session.
    pub session_id: String,
    /// `complete` or `partial` (RFC 7865 §9.1).
    pub datamode: DataMode,
    /// SIP Session-IDs from `<sipSessionID>` elements (RFC 7865 §8.1.1).
    /// These reference the original SIP dialog(s) being recorded.
    /// A session may have zero or more sipSessionID values.
    pub sip_session_ids: Vec<String>,
    /// Participants in the recorded call.
    pub participants: Vec<Participant>,
    /// Media streams being recorded.
    pub streams: Vec<StreamInfo>,
    /// Which participant sends and receives which stream.
    pub participant_streams: Vec<ParticipantStreamAssoc>,
}

impl RecordingMetadata {
    /// The participant that sends the stream labelled `label` (the SDP
    /// `a=label` of its m-line), when the metadata says.
    pub fn sender_of_label(&self, label: &str) -> Option<&str> {
        let stream = self.streams.iter().find(|stream| stream.label == label)?;
        self.participant_streams
            .iter()
            .find(|association| association.send.contains(&stream.stream_id))
            .map(|association| association.participant_id.as_str())
    }

    /// Fold an update into this snapshot. A `complete` update replaces it
    /// outright. A `partial` one (RFC 7865 §9.1) carries only what changed: each
    /// participant, stream or association it names replaces the one with the
    /// same id, or is added; Session-IDs are added; everything it leaves out is
    /// kept. The result is always a complete snapshot.
    pub fn merge(&mut self, update: RecordingMetadata) {
        if update.datamode == DataMode::Complete {
            *self = update;
            return;
        }
        if !update.session_id.is_empty() {
            self.session_id = update.session_id;
        }
        for sip_session_id in update.sip_session_ids {
            if !self.sip_session_ids.contains(&sip_session_id) {
                self.sip_session_ids.push(sip_session_id);
            }
        }
        for participant in update.participants {
            match self
                .participants
                .iter_mut()
                .find(|known| known.participant_id == participant.participant_id)
            {
                Some(known) => *known = participant,
                None => self.participants.push(participant),
            }
        }
        for stream in update.streams {
            match self
                .streams
                .iter_mut()
                .find(|known| known.stream_id == stream.stream_id)
            {
                Some(known) => *known = stream,
                None => self.streams.push(stream),
            }
        }
        for association in update.participant_streams {
            match self
                .participant_streams
                .iter_mut()
                .find(|known| known.participant_id == association.participant_id)
            {
                Some(known) => *known = association,
                None => self.participant_streams.push(association),
            }
        }
        self.datamode = DataMode::Complete;
    }
}

/// A participant in the recorded call.
#[derive(Debug, Clone)]
pub struct Participant {
    /// Participant ID attribute.
    pub participant_id: String,
    /// Address of Record (from `<nameID aor="...">`).
    pub aor: String,
    /// Optional display name.
    pub name: Option<String>,
}

/// A media stream being recorded.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID attribute.
    pub stream_id: String,
    /// Session ID this stream belongs to.
    pub session_id: String,
    /// Stream label (correlates with SDP `a=label`).
    pub label: String,
}

// ---------------------------------------------------------------------------
// Generation (SRC → SRS direction)
// ---------------------------------------------------------------------------

/// Build RFC 7866 recording metadata XML.
///
/// The metadata describes the participants and streams being recorded.
/// Per RFC 7866 §4.2, each participant's media direction gets its own
/// `<stream>` element, correlated to an SDP `a=label:N` via `<label>`.
/// The `<participantstreamassoc>` elements map which participant sends
/// on which stream and receives on the other.
pub fn build_recording_metadata(
    session_id: &str,
    caller_uri: &str,
    callee_uri: &str,
    original_call_id: Option<&str>,
) -> String {
    let caller_participant_id = format!("part-{}", &session_id[..8]);
    let callee_participant_id = format!("part-{}", &session_id[8..16.min(session_id.len())]);
    let stream_0_id = format!("stream-0-{}", &session_id[..8]);
    let stream_1_id = format!("stream-1-{}", &session_id[..8]);

    // RFC 7865 §8.1.1: <sipSessionID> references the original SIP dialog
    // being recorded, not the recording session itself. Omit if unknown.
    let sip_session_id_element = match original_call_id {
        Some(call_id) => format!("\n    <sipSessionID>{call_id}</sipSessionID>"),
        None => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns="urn:ietf:params:xml:ns:recording:1">
  <datamode>complete</datamode>
  <session session_id="{session_id}">{sip_session_id_element}
  </session>
  <participant participant_id="{caller_participant_id}">
    <nameID aor="{caller_uri}"/>
  </participant>
  <participant participant_id="{callee_participant_id}">
    <nameID aor="{callee_uri}"/>
  </participant>
  <stream stream_id="{stream_0_id}" session_id="{session_id}">
    <label>0</label>
  </stream>
  <stream stream_id="{stream_1_id}" session_id="{session_id}">
    <label>1</label>
  </stream>
  <participantstreamassoc participant_id="{caller_participant_id}">
    <send>{stream_0_id}</send>
    <recv>{stream_1_id}</recv>
  </participantstreamassoc>
  <participantstreamassoc participant_id="{callee_participant_id}">
    <send>{stream_1_id}</send>
    <recv>{stream_0_id}</recv>
  </participantstreamassoc>
</recording>"#
    )
}

// ---------------------------------------------------------------------------
// Parsing (SRS ← SRC direction)
// ---------------------------------------------------------------------------

/// Parse RFC 7866 recording metadata XML into structured data.
///
/// Extracts session ID, participants (with AoR), and stream labels from
/// the `application/rs-metadata+xml` body part of a SIPREC INVITE.
pub fn parse_recording_metadata(xml: &str) -> Result<RecordingMetadata, MetadataError> {
    let mut reader = Reader::from_str(xml);

    let mut session_id: Option<String> = None;
    let mut sip_session_ids = Vec::new();
    let mut participants = Vec::new();
    let mut streams = Vec::new();

    // Current parsing context.
    let mut current_participant_id: Option<String> = None;
    let mut current_participant_aor: Option<String> = None;
    let mut current_participant_name: Option<String> = None;
    let mut current_stream_id: Option<String> = None;
    let mut current_stream_session_id: Option<String> = None;
    let mut current_label: Option<String> = None;
    let mut current_sip_session_id: Option<String> = None;
    let mut inside_label = false;
    let mut inside_name = false;
    let mut inside_sip_session_id = false;
    let mut datamode = DataMode::Complete;
    let mut participant_streams: Vec<ParticipantStreamAssoc> = Vec::new();
    let mut current_association: Option<ParticipantStreamAssoc> = None;
    // The text element being read, for the ones read as a whole: `datamode`,
    // and an association's `send` / `recv`.
    let mut text_element: Option<&'static str> = None;
    let mut text_value = String::new();

    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(ref element)) | Ok(Event::Empty(ref element)) => {
                let local_name = element.local_name();
                let name = local_name.as_ref();

                match name {
                    "session" => {
                        if session_id.is_none() {
                            session_id = get_attribute(element, "session_id");
                        }
                    }
                    "participant" => {
                        current_participant_id = get_attribute(element, "participant_id");
                        current_participant_aor = None;
                        current_participant_name = None;
                    }
                    "nameID" | "nameId" => {
                        if let Some(aor) = get_attribute(element, "aor") {
                            current_participant_aor = Some(aor);
                        }
                    }
                    "name" => {
                        inside_name = true;
                    }
                    "sipSessionID" => {
                        inside_sip_session_id = true;
                    }
                    "stream" => {
                        current_stream_id = get_attribute(element, "stream_id");
                        current_stream_session_id = get_attribute(element, "session_id");
                        current_label = None;
                    }
                    "label" => {
                        inside_label = true;
                    }
                    "participantstreamassoc" => {
                        current_association = Some(ParticipantStreamAssoc {
                            participant_id: get_attribute(element, "participant_id")
                                .unwrap_or_default(),
                            ..ParticipantStreamAssoc::default()
                        });
                    }
                    "datamode" => {
                        text_element = Some("datamode");
                        text_value.clear();
                    }
                    "send" if current_association.is_some() => {
                        text_element = Some("send");
                        text_value.clear();
                    }
                    "recv" if current_association.is_some() => {
                        text_element = Some("recv");
                        text_value.clear();
                    }
                    _ => {}
                }
            }
            // An entity reference splits the text node, so a value has to be
            // accumulated across fragments rather than assigned from one — and
            // trimmed once at the end, not per fragment, or interior spacing is
            // eaten. Both `Text` and `GeneralRef` append here.
            Ok(Event::Text(ref text)) => {
                if let Ok(value) = text.unescape() {
                    if text_element.is_some() {
                        text_value.push_str(&value);
                    }
                    if inside_label {
                        current_label
                            .get_or_insert_with(String::new)
                            .push_str(&value);
                    }
                    if inside_name {
                        current_participant_name
                            .get_or_insert_with(String::new)
                            .push_str(&value);
                    }
                    if inside_sip_session_id {
                        current_sip_session_id
                            .get_or_insert_with(String::new)
                            .push_str(&value);
                    }
                }
            }
            Ok(Event::GeneralRef(ref reference)) => {
                if let Some(resolved) = crate::xml_text::resolve_general_ref(reference) {
                    if text_element.is_some() {
                        text_value.push_str(&resolved);
                    }
                    if inside_label {
                        current_label
                            .get_or_insert_with(String::new)
                            .push_str(&resolved);
                    }
                    if inside_name {
                        current_participant_name
                            .get_or_insert_with(String::new)
                            .push_str(&resolved);
                    }
                    if inside_sip_session_id {
                        current_sip_session_id
                            .get_or_insert_with(String::new)
                            .push_str(&resolved);
                    }
                }
            }
            Ok(Event::End(ref element)) => {
                let local_name = element.local_name();
                let name = local_name.as_ref();

                match name {
                    "participant" => {
                        if let (Some(participant_id), Some(aor)) = (
                            current_participant_id.take(),
                            current_participant_aor.take(),
                        ) {
                            participants.push(Participant {
                                participant_id,
                                aor,
                                name: current_participant_name
                                    .take()
                                    .map(|value| value.trim().to_string()),
                            });
                        }
                    }
                    "stream" => {
                        if let (Some(stream_id), Some(stream_session_id)) =
                            (current_stream_id.take(), current_stream_session_id.take())
                        {
                            streams.push(StreamInfo {
                                stream_id,
                                session_id: stream_session_id,
                                label: current_label.take().unwrap_or_default().trim().to_string(),
                            });
                        }
                    }
                    "sipSessionID" => {
                        inside_sip_session_id = false;
                        // Push once the whole value is in, so an entity split
                        // across fragments does not become several ids.
                        if let Some(value) = current_sip_session_id.take() {
                            let trimmed = value.trim();
                            if !trimmed.is_empty() {
                                sip_session_ids.push(trimmed.to_string());
                            }
                        }
                    }
                    "label" => inside_label = false,
                    "name" => inside_name = false,
                    "datamode" | "send" | "recv" => {
                        let value = text_value.trim().to_string();
                        match (text_element.take(), current_association.as_mut()) {
                            (Some("datamode"), _) => {
                                if value.eq_ignore_ascii_case("partial") {
                                    datamode = DataMode::Partial;
                                }
                            }
                            (Some("send"), Some(association)) if !value.is_empty() => {
                                association.send.push(value);
                            }
                            (Some("recv"), Some(association)) if !value.is_empty() => {
                                association.recv.push(value);
                            }
                            _ => {}
                        }
                    }
                    "participantstreamassoc" => {
                        if let Some(association) = current_association.take() {
                            if !association.participant_id.is_empty() {
                                participant_streams.push(association);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(MetadataError::Xml(error.to_string())),
            _ => {}
        }
        buffer.clear();
    }

    // A partial update carries only what changed, so it need not name the
    // session again; a complete snapshot must.
    let session_id = match (session_id, datamode) {
        (Some(session_id), _) => session_id,
        (None, DataMode::Partial) => String::new(),
        (None, DataMode::Complete) => {
            return Err(MetadataError::MissingElement("session".to_string()))
        }
    };

    Ok(RecordingMetadata {
        session_id,
        datamode,
        sip_session_ids,
        participants,
        streams,
        participant_streams,
    })
}

/// Extract an attribute value from an XML element.
fn get_attribute(element: &BytesStart, attribute_name: &str) -> Option<String> {
    for attribute in element.attributes().flatten() {
        // Attribute keys are `str` in quick-xml 0.42.
        let key = attribute.key.as_ref();
        if key == attribute_name {
            return attribute
                .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                .ok()
                .map(|value| value.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Generation tests (existing) ---

    #[test]
    fn metadata_contains_session_id() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
        );
        assert!(xml.contains("abc12345-6789-0000-0000-000000000000"));
        assert!(xml.contains("sip:alice@example.com"));
        assert!(xml.contains("sip:bob@example.com"));
        // No sipSessionID when original_call_id is None.
        assert!(!xml.contains("<sipSessionID>"));
    }

    #[test]
    fn metadata_with_original_call_id() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
            Some("original-call-id-from-invite@192.168.1.1"),
        );
        assert!(
            xml.contains("<sipSessionID>original-call-id-from-invite@192.168.1.1</sipSessionID>")
        );
        // session_id attribute should still be the recording session ID.
        assert!(xml.contains("session_id=\"abc12345-6789-0000-0000-000000000000\""));
    }

    #[test]
    fn metadata_is_valid_xml_structure() {
        let xml = build_recording_metadata(
            "test-session-id-0000-0000-000000000000",
            "sip:caller@host.com",
            "sip:callee@host.com",
            None,
        );
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<recording xmlns="));
        assert!(xml.contains("<participant"));
        assert!(xml.contains("<stream"));
        assert!(xml.contains("<datamode>complete</datamode>"));
        assert!(xml.contains("</recording>"));
    }

    #[test]
    fn metadata_has_two_participants_and_streams() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
        );
        assert_eq!(xml.matches("<participant ").count(), 2);
        assert_eq!(xml.matches("<stream ").count(), 2);
        assert_eq!(xml.matches("<participantstreamassoc ").count(), 2);
        assert!(xml.contains("<label>0</label>"));
        assert!(xml.contains("<label>1</label>"));
        assert!(xml.contains("<send>stream-0-aaaabbbb</send>"));
        assert!(xml.contains("<recv>stream-1-aaaabbbb</recv>"));
    }

    // --- Parsing tests ---

    /// A display name carrying entity references parses whole.
    ///
    /// The value arrives in fragments — text, reference, text — so the parser
    /// has to accumulate rather than assign, and trim only once at the end.
    /// Assigning per fragment silently kept whichever fragment came last.
    #[test]
    fn parse_accumulates_entity_references_in_participant_name() {
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <session session_id=\"s1\"/>\n",
            "  <participant participant_id=\"p1\">\n",
            "    <nameID aor=\"sip:alice@example.com\"/>\n",
            "    <name>Alice &amp; Bob &lt;Support&gt;</name>\n",
            "  </participant>\n",
            "</recording>\n",
        );
        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.participants.len(), 1);
        assert_eq!(
            metadata.participants[0].name.as_deref(),
            Some("Alice & Bob <Support>"),
            "fragments around each entity must be joined, not overwritten"
        );
    }

    #[test]
    fn parse_roundtrip_no_original_call_id() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
        );
        let metadata = parse_recording_metadata(&xml).unwrap();

        assert_eq!(metadata.session_id, "abc12345-6789-0000-0000-000000000000");
        assert!(metadata.sip_session_ids.is_empty());
        assert_eq!(metadata.participants.len(), 2);
        assert_eq!(metadata.participants[0].aor, "sip:alice@example.com");
        assert_eq!(metadata.participants[1].aor, "sip:bob@example.com");
        assert_eq!(metadata.streams.len(), 2);
        assert_eq!(metadata.streams[0].label, "0");
        assert_eq!(metadata.streams[1].label, "1");
    }

    #[test]
    fn parse_roundtrip_with_original_call_id() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
            Some("orig-call-id@10.0.0.1"),
        );
        let metadata = parse_recording_metadata(&xml).unwrap();

        assert_eq!(metadata.session_id, "abc12345-6789-0000-0000-000000000000");
        assert_eq!(metadata.sip_session_ids, vec!["orig-call-id@10.0.0.1"]);
    }

    #[test]
    fn parse_participant_ids() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:caller@host.com",
            "sip:callee@host.com",
            None,
        );
        let metadata = parse_recording_metadata(&xml).unwrap();

        assert_eq!(metadata.participants[0].participant_id, "part-aaaabbbb");
        assert_eq!(metadata.participants[1].participant_id, "part--cccc-dd");
    }

    #[test]
    fn parse_stream_session_id() {
        let xml = build_recording_metadata(
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            "sip:a@x.com",
            "sip:b@x.com",
            None,
        );
        let metadata = parse_recording_metadata(&xml).unwrap();
        assert_eq!(
            metadata.streams[0].session_id,
            "aaaabbbb-cccc-dddd-eeee-ffffffffffff"
        );
    }

    #[test]
    fn parse_missing_session_errors() {
        let xml = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>complete</datamode>\n",
            "</recording>",
        );
        let result = parse_recording_metadata(xml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("session"));
    }

    #[test]
    fn parse_external_metadata_with_sip_session_id() {
        // Metadata from a different SRC implementation with sipSessionID.
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>complete</datamode>\n",
            "  <session session_id=\"ext-sess-001\">\n",
            "    <sipSessionID>original-dialog-call-id@10.0.0.5</sipSessionID>\n",
            "  </session>\n",
            "  <participant participant_id=\"p1\">\n",
            "    <nameID aor=\"sip:external@vendor.com\"/>\n",
            "  </participant>\n",
            "  <participant participant_id=\"p2\">\n",
            "    <nameID aor=\"sip:customer@our.com\"/>\n",
            "  </participant>\n",
            "  <stream stream_id=\"s1\" session_id=\"ext-sess-001\">\n",
            "    <label>caller-audio</label>\n",
            "  </stream>\n",
            "  <stream stream_id=\"s2\" session_id=\"ext-sess-001\">\n",
            "    <label>callee-audio</label>\n",
            "  </stream>\n",
            "</recording>",
        );

        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.session_id, "ext-sess-001");
        assert_eq!(
            metadata.sip_session_ids,
            vec!["original-dialog-call-id@10.0.0.5"]
        );
        assert_eq!(metadata.participants.len(), 2);
        assert_eq!(metadata.participants[0].aor, "sip:external@vendor.com");
        assert_eq!(metadata.participants[1].aor, "sip:customer@our.com");
        assert_eq!(metadata.streams.len(), 2);
        assert_eq!(metadata.streams[0].label, "caller-audio");
        assert_eq!(metadata.streams[1].label, "callee-audio");
    }

    #[test]
    fn parse_multiple_sip_session_ids() {
        // RFC 7865 allows multiple sipSessionID elements per session.
        let xml = concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <session session_id=\"multi-sess\">\n",
            "    <sipSessionID>call-id-1@host1</sipSessionID>\n",
            "    <sipSessionID>call-id-2@host2</sipSessionID>\n",
            "  </session>\n",
            "</recording>",
        );
        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(
            metadata.sip_session_ids,
            vec!["call-id-1@host1", "call-id-2@host2"]
        );
    }

    #[test]
    fn parse_empty_xml_errors() {
        let result = parse_recording_metadata("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_no_participants_ok() {
        // Valid XML but no participants — still valid structure.
        let xml = concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <session session_id=\"sess-1\"/>\n",
            "</recording>",
        );
        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.session_id, "sess-1");
        assert!(metadata.sip_session_ids.is_empty());
        assert!(metadata.participants.is_empty());
    }

    // --- RFC 7865/7866: datamode, participantstreamassoc, partial updates ---

    /// A complete snapshot of a two-party call, as an external SRC sends it.
    const COMPLETE: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
        "  <datamode>complete</datamode>\n",
        "  <session session_id=\"rs-1\">\n",
        "    <sipSessionID>orig-call@example.com</sipSessionID>\n",
        "  </session>\n",
        "  <participant participant_id=\"p-a\"><nameID aor=\"sip:alice@example.com\"/></participant>\n",
        "  <participant participant_id=\"p-b\"><nameID aor=\"sip:bob@example.com\"/></participant>\n",
        "  <stream stream_id=\"s-0\" session_id=\"rs-1\"><label>1</label></stream>\n",
        "  <stream stream_id=\"s-1\" session_id=\"rs-1\"><label>2</label></stream>\n",
        "  <participantstreamassoc participant_id=\"p-a\">\n",
        "    <send>s-0</send>\n",
        "    <recv>s-1</recv>\n",
        "  </participantstreamassoc>\n",
        "  <participantstreamassoc participant_id=\"p-b\">\n",
        "    <send>s-1</send>\n",
        "    <recv>s-0</recv>\n",
        "  </participantstreamassoc>\n",
        "</recording>\n",
    );

    #[test]
    fn parse_reads_datamode() {
        let metadata = parse_recording_metadata(COMPLETE).unwrap();
        assert_eq!(metadata.datamode, DataMode::Complete);
        assert_eq!(metadata.datamode.as_str(), "complete");
    }

    #[test]
    fn parse_without_datamode_is_complete() {
        // RFC 7865 §9.1: absent, the metadata is a complete snapshot.
        let xml = COMPLETE.replace("  <datamode>complete</datamode>\n", "");
        let metadata = parse_recording_metadata(&xml).unwrap();
        assert_eq!(metadata.datamode, DataMode::Complete);
    }

    #[test]
    fn parse_reads_participantstreamassoc() {
        let metadata = parse_recording_metadata(COMPLETE).unwrap();
        assert_eq!(
            metadata.participant_streams,
            vec![
                ParticipantStreamAssoc {
                    participant_id: "p-a".to_string(),
                    send: vec!["s-0".to_string()],
                    recv: vec!["s-1".to_string()],
                },
                ParticipantStreamAssoc {
                    participant_id: "p-b".to_string(),
                    send: vec!["s-1".to_string()],
                    recv: vec!["s-0".to_string()],
                },
            ]
        );
    }

    #[test]
    fn generated_metadata_parses_back_with_its_associations() {
        let xml = build_recording_metadata(
            "abc12345-6789-0000-0000-000000000000",
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
        );
        let metadata = parse_recording_metadata(&xml).unwrap();
        assert_eq!(metadata.participant_streams.len(), 2);
        let caller = &metadata.participant_streams[0];
        assert_eq!(caller.send, vec![metadata.streams[0].stream_id.clone()]);
        assert_eq!(caller.recv, vec![metadata.streams[1].stream_id.clone()]);
    }

    #[test]
    fn participant_sending_a_stream_is_found_by_its_label() {
        let metadata = parse_recording_metadata(COMPLETE).unwrap();
        assert_eq!(metadata.sender_of_label("1"), Some("p-a"));
        assert_eq!(metadata.sender_of_label("2"), Some("p-b"));
        assert_eq!(metadata.sender_of_label("9"), None);
    }

    #[test]
    fn parse_partial_without_session_is_accepted() {
        // A partial update carries only what changed (RFC 7865 §9.1).
        let xml = concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>partial</datamode>\n",
            "  <participant participant_id=\"p-c\"><nameID aor=\"sip:carol@example.com\"/></participant>\n",
            "</recording>\n",
        );
        let metadata = parse_recording_metadata(xml).unwrap();
        assert_eq!(metadata.datamode, DataMode::Partial);
        assert!(metadata.session_id.is_empty());
        assert_eq!(metadata.participants.len(), 1);
    }

    #[test]
    fn parse_complete_without_session_still_errors() {
        let xml = concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>complete</datamode>\n",
            "</recording>\n",
        );
        assert!(parse_recording_metadata(xml).is_err());
    }

    #[test]
    fn partial_update_merges_over_the_snapshot() {
        // The callee is transferred to carol: carol's participant and her
        // association arrive, bob's association is updated to send nothing.
        let mut snapshot = parse_recording_metadata(COMPLETE).unwrap();
        let update = parse_recording_metadata(concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>partial</datamode>\n",
            "  <participant participant_id=\"p-c\"><nameID aor=\"sip:carol@example.com\"/>",
            "<name>Carol</name></participant>\n",
            "  <participantstreamassoc participant_id=\"p-c\">\n",
            "    <send>s-1</send>\n",
            "    <recv>s-0</recv>\n",
            "  </participantstreamassoc>\n",
            "  <participantstreamassoc participant_id=\"p-b\">\n",
            "    <recv>s-0</recv>\n",
            "  </participantstreamassoc>\n",
            "</recording>\n",
        ))
        .unwrap();

        snapshot.merge(update);

        assert_eq!(
            snapshot.datamode,
            DataMode::Complete,
            "still a full snapshot"
        );
        assert_eq!(
            snapshot.session_id, "rs-1",
            "a partial update keeps the session"
        );
        assert_eq!(snapshot.sip_session_ids, vec!["orig-call@example.com"]);
        assert_eq!(snapshot.participants.len(), 3);
        assert_eq!(snapshot.participants[2].name.as_deref(), Some("Carol"));
        assert_eq!(snapshot.streams.len(), 2, "streams nobody touched stay");
        assert_eq!(snapshot.sender_of_label("2"), Some("p-c"));
        let bob = snapshot
            .participant_streams
            .iter()
            .find(|association| association.participant_id == "p-b")
            .unwrap();
        assert!(bob.send.is_empty(), "bob's association was replaced");
    }

    #[test]
    fn partial_update_replaces_an_element_by_id() {
        let mut snapshot = parse_recording_metadata(COMPLETE).unwrap();
        let update = parse_recording_metadata(concat!(
            "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n",
            "  <datamode>partial</datamode>\n",
            "  <participant participant_id=\"p-a\"><nameID aor=\"sip:alice@example.com\"/>",
            "<name>Alice</name></participant>\n",
            "  <stream stream_id=\"s-1\" session_id=\"rs-1\"><label>3</label></stream>\n",
            "</recording>\n",
        ))
        .unwrap();

        snapshot.merge(update);

        assert_eq!(snapshot.participants.len(), 2);
        assert_eq!(snapshot.participants[0].name.as_deref(), Some("Alice"));
        assert_eq!(snapshot.streams.len(), 2);
        assert_eq!(snapshot.streams[1].label, "3");
    }

    #[test]
    fn complete_update_replaces_the_snapshot() {
        let mut snapshot = parse_recording_metadata(COMPLETE).unwrap();
        let replacement = parse_recording_metadata(&COMPLETE.replace(
            "  <participant participant_id=\"p-b\"><nameID aor=\"sip:bob@example.com\"/></participant>\n",
            "",
        ))
        .unwrap();

        snapshot.merge(replacement);

        assert_eq!(snapshot.participants.len(), 1);
    }
}
