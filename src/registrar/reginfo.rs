//! RFC 3680 Registration Event — `application/reginfo+xml` body generation.
//!
//! Generates registration information documents for the `reg` event package.
//! Used by the S-CSCF to notify Application Servers about registration state
//! changes via SUBSCRIBE/NOTIFY (3GPP TS 24.229).
//!
//! XML is generated as formatted strings following the same pattern as
//! `presence/pidf.rs` — no external XML crate needed.

use std::fmt;

use super::{Contact, ContactKind};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Document state: `"full"` (complete snapshot) or `"partial"` (delta update).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReginfoState {
    Full,
    Partial,
}

impl fmt::Display for ReginfoState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReginfoState::Full => write!(formatter, "full"),
            ReginfoState::Partial => write!(formatter, "partial"),
        }
    }
}

/// Per-AoR registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Initial registration (not yet confirmed).
    Init,
    /// At least one active contact binding.
    Active,
    /// All contacts expired or deregistered.
    Terminated,
}

impl fmt::Display for RegistrationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationState::Init => write!(formatter, "init"),
            RegistrationState::Active => write!(formatter, "active"),
            RegistrationState::Terminated => write!(formatter, "terminated"),
        }
    }
}

/// Per-contact binding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    Active,
    Terminated,
}

impl fmt::Display for ContactState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactState::Active => write!(formatter, "active"),
            ContactState::Terminated => write!(formatter, "terminated"),
        }
    }
}

/// What happened to the contact (RFC 3680 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactEvent {
    Registered,
    Created,
    Refreshed,
    Shortened,
    Deactivated,
    Expired,
    Unregistered,
    Rejected,
    Probation,
}

impl fmt::Display for ContactEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ContactEvent::Registered => "registered",
            ContactEvent::Created => "created",
            ContactEvent::Refreshed => "refreshed",
            ContactEvent::Shortened => "shortened",
            ContactEvent::Deactivated => "deactivated",
            ContactEvent::Expired => "expired",
            ContactEvent::Unregistered => "unregistered",
            ContactEvent::Rejected => "rejected",
            ContactEvent::Probation => "probation",
        };
        write!(formatter, "{}", label)
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A single contact binding within a registration.
#[derive(Debug, Clone)]
pub struct ReginfoContact {
    /// Contact URI (e.g. `sip:alice@10.0.0.1:5060`).
    pub uri: String,
    /// Binding state.
    pub state: ContactState,
    /// What event triggered this state.
    pub event: ContactEvent,
    /// Remaining expires in seconds (None for terminated contacts).
    pub expires: Option<u64>,
    /// Quality value (0.0–1.0).
    pub q: Option<f32>,
    /// Additional Contact-header parameters (RFC 3840 feature tags etc.)
    /// preserved from the originating REGISTER or 3PR 200 OK.  Emitted as
    /// `<unknown-param name="…">value</unknown-param>` children per
    /// RFC 3680 §5.3.2 so watchers see the same capability advertisement
    /// the registrar received.  Empty `Vec` when there is nothing to emit.
    pub params: Vec<(String, Option<String>)>,
}

/// A single AoR registration entry.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Address of Record (e.g. `sip:alice@ims.example.com`).
    pub aor: String,
    /// Unique registration ID (stable across NOTIFYs for the same AoR).
    pub id: String,
    /// Registration state.
    pub state: RegistrationState,
    /// Contact bindings.
    pub contacts: Vec<ReginfoContact>,
}

/// A complete reginfo document (RFC 3680 §5).
#[derive(Debug, Clone)]
pub struct ReginfoBody {
    /// Monotonically increasing document version.
    pub version: u32,
    /// `"full"` (complete snapshot) or `"partial"` (delta).
    pub state: ReginfoState,
    /// Registrations in this document.
    pub registrations: Vec<Registration>,
}

impl ReginfoBody {
    /// MIME content type for this document.
    pub fn content_type() -> &'static str {
        "application/reginfo+xml"
    }

    /// Serialize to RFC 3680 reginfo XML.
    pub fn to_xml(&self) -> String {
        let mut output = String::with_capacity(512);
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str(&format!(
            "<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"{}\" state=\"{}\">\n",
            self.version, self.state,
        ));

        for registration in &self.registrations {
            output.push_str(&format!(
                "  <registration aor=\"{}\" id=\"{}\" state=\"{}\">\n",
                xml_escape(&registration.aor),
                xml_escape(&registration.id),
                registration.state,
            ));

            for contact in &registration.contacts {
                output.push_str(&format!(
                    "    <contact id=\"c-{}\" state=\"{}\" event=\"{}\"",
                    xml_escape(&contact.uri),
                    contact.state,
                    contact.event,
                ));
                if let Some(expires) = contact.expires {
                    output.push_str(&format!(" expires=\"{expires}\""));
                }
                if let Some(q) = contact.q {
                    output.push_str(&format!(" q=\"{q:.1}\""));
                }
                output.push_str(">\n");
                output.push_str(&format!(
                    "      <uri>{}</uri>\n",
                    xml_escape(&contact.uri),
                ));
                // RFC 3680 §5.3.2 — surface RFC 3840 feature tags and
                // other Contact-header parameters as <unknown-param>
                // children.  Flag params (`+g.3gpp.smsip`) become
                // self-closing; valued params (`+g.3gpp.icsi-ref="urn:…"`)
                // carry the value as text content with XML-escaping.
                for (name, value) in &contact.params {
                    match value {
                        Some(v) => output.push_str(&format!(
                            "      <unknown-param name=\"{}\">{}</unknown-param>\n",
                            xml_escape(name),
                            xml_escape(v),
                        )),
                        None => output.push_str(&format!(
                            "      <unknown-param name=\"{}\"/>\n",
                            xml_escape(name),
                        )),
                    }
                }
                output.push_str("    </contact>\n");
            }

            output.push_str("  </registration>\n");
        }

        output.push_str("</reginfo>\n");
        output
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a full-state reginfo document from current registrar contacts.
///
/// `contacts` should be the merged view (UE + AS) from `Registrar::lookup_all`
/// so watchers see iFC-matched AS feature tags (`+g.3gpp.smsip`,
/// `+g.3gpp.icsi-ref`, …) alongside the UE's own bindings per
/// TS 24.229 §5.4.2.1.2.
///
/// Registration state is `Active` when there is at least one non-expired
/// UE-side contact, otherwise `Terminated` — an AoR populated only by AS
/// capability records is treated as terminated (the user is not registered).
pub fn build_full_reginfo(aor: &str, contacts: &[Contact], version: u32) -> ReginfoBody {
    let has_ue = contacts
        .iter()
        .any(|c| !c.is_expired() && c.kind == ContactKind::Ue);
    let registration_state = if has_ue {
        RegistrationState::Active
    } else {
        RegistrationState::Terminated
    };

    let reginfo_contacts: Vec<ReginfoContact> = contacts
        .iter()
        .filter(|contact| !contact.is_expired())
        .map(|contact| ReginfoContact {
            uri: contact.uri.to_string(),
            state: ContactState::Active,
            event: ContactEvent::Registered,
            expires: Some(contact.remaining_seconds()),
            q: Some(contact.q),
            params: contact.params.clone(),
        })
        .collect();

    // Generate a stable registration ID from the AoR.
    let id = format!("reg-{:x}", hash_aor(aor));

    ReginfoBody {
        version,
        state: ReginfoState::Full,
        registrations: vec![Registration {
            aor: aor.to_string(),
            id,
            state: registration_state,
            contacts: reginfo_contacts,
        }],
    }
}

/// Simple hash for generating stable registration IDs.
fn hash_aor(aor: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in aor.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

// ---------------------------------------------------------------------------
// Parsing — RFC 3680 reginfo+xml → ReginfoBody
// ---------------------------------------------------------------------------

/// Errors produced by [`parse_reginfo`].
#[derive(Debug, thiserror::Error)]
pub enum ReginfoParseError {
    #[error("reginfo XML is malformed: {0}")]
    Xml(String),
    #[error("reginfo missing required attribute: {0}")]
    MissingAttr(&'static str),
    #[error("reginfo attribute has invalid value: {attr}={value:?}")]
    InvalidAttr { attr: &'static str, value: String },
    #[error("reginfo XML missing root <reginfo> element")]
    MissingRoot,
}

/// Parse an RFC 3680 `application/reginfo+xml` body into a structured
/// [`ReginfoBody`]. Tolerant of inbound NOTIFY bodies — accepts the
/// document with or without the optional XML declaration, ignores
/// unknown elements/attributes for forward compatibility, and treats
/// missing optional attributes (expires, q, contact event) as absent.
///
/// Used on the watcher side: a NOTIFY arrives via
/// `@proxy.on_request("NOTIFY")`, the script extracts the body, and
/// calls `presence.parse_reginfo(body)` to walk the registration data.
pub fn parse_reginfo(xml: &str) -> Result<ReginfoBody, ReginfoParseError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut body: Option<ReginfoBody> = None;
    let mut current_registration: Option<Registration> = None;
    let mut current_contact: Option<ReginfoContact> = None;
    // The <uri> child element wraps a text node; we accumulate text
    // events between <uri>...</uri> and apply on close so the contact's
    // declared URI matches the inner text rather than the contact id.
    let mut in_uri_text: bool = false;
    let mut uri_text_buffer = String::new();
    // <unknown-param> elements may be empty (flag form) or carry a value
    // as text content (RFC 3680 §5.3.2).  Track the param name on Start
    // and accumulate text until End.
    let mut pending_unknown_param_name: Option<String> = None;
    let mut unknown_param_text_buffer = String::new();

    let mut buf = Vec::new();
    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|error| ReginfoParseError::Xml(error.to_string()))?;
        let is_empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                let _ = is_empty; // captured above; used in branches below
                let local_name = element.local_name();
                let name_bytes = local_name.as_ref();
                match name_bytes {
                    b"reginfo" => {
                        let version = attr_required_u32(&element, "version")?;
                        let state = attr_required_str(&element, "state")?;
                        let parsed_state = match state.as_str() {
                            "full" => ReginfoState::Full,
                            "partial" => ReginfoState::Partial,
                            _ => {
                                return Err(ReginfoParseError::InvalidAttr {
                                    attr: "state",
                                    value: state,
                                });
                            }
                        };
                        body = Some(ReginfoBody {
                            version,
                            state: parsed_state,
                            registrations: Vec::new(),
                        });
                    }
                    b"registration" => {
                        if body.is_none() {
                            return Err(ReginfoParseError::MissingRoot);
                        }
                        let aor = attr_required_str(&element, "aor")?;
                        let id = attr_optional_str(&element, "id")?
                            .unwrap_or_else(|| format!("reg-{:x}", hash_aor(&aor)));
                        let state = attr_required_str(&element, "state")?;
                        let parsed_state = match state.as_str() {
                            "init" => RegistrationState::Init,
                            "active" => RegistrationState::Active,
                            "terminated" => RegistrationState::Terminated,
                            _ => {
                                return Err(ReginfoParseError::InvalidAttr {
                                    attr: "state",
                                    value: state,
                                });
                            }
                        };
                        current_registration = Some(Registration {
                            aor,
                            id,
                            state: parsed_state,
                            contacts: Vec::new(),
                        });
                        if is_empty {
                            if let Some(reg) = current_registration.take() {
                                if let Some(reginfo) = body.as_mut() {
                                    reginfo.registrations.push(reg);
                                }
                            }
                        }
                    }
                    b"contact" => {
                        if current_registration.is_none() {
                            // Stray <contact> outside <registration> — skip.
                            continue;
                        }
                        let state = attr_required_str(&element, "state")?;
                        let parsed_state = match state.as_str() {
                            "active" => ContactState::Active,
                            "terminated" => ContactState::Terminated,
                            _ => {
                                return Err(ReginfoParseError::InvalidAttr {
                                    attr: "state",
                                    value: state,
                                });
                            }
                        };
                        let event_attr = attr_optional_str(&element, "event")?;
                        let parsed_event = match event_attr.as_deref() {
                            Some("registered") | None => ContactEvent::Registered,
                            Some("created") => ContactEvent::Created,
                            Some("refreshed") => ContactEvent::Refreshed,
                            Some("shortened") => ContactEvent::Shortened,
                            Some("deactivated") => ContactEvent::Deactivated,
                            Some("expired") => ContactEvent::Expired,
                            Some("unregistered") => ContactEvent::Unregistered,
                            Some("rejected") => ContactEvent::Rejected,
                            Some("probation") => ContactEvent::Probation,
                            Some(other) => {
                                return Err(ReginfoParseError::InvalidAttr {
                                    attr: "event",
                                    value: other.to_string(),
                                });
                            }
                        };
                        let expires = attr_optional_u64(&element, "expires")?;
                        let q = attr_optional_f32(&element, "q")?;
                        // The contact's URI may live as an attribute on
                        // <contact> directly (some implementations emit
                        // it that way) or as the inner <uri> element
                        // text — fall back to the id attribute, which
                        // siphon's own builder uses as `c-<uri>`.
                        let direct_uri = attr_optional_str(&element, "uri")?;
                        let placeholder_uri = direct_uri
                            .clone()
                            .or_else(|| {
                                attr_optional_str(&element, "id")
                                    .ok()
                                    .flatten()
                                    .and_then(|id| id.strip_prefix("c-").map(str::to_string))
                            })
                            .unwrap_or_default();
                        current_contact = Some(ReginfoContact {
                            uri: placeholder_uri,
                            state: parsed_state,
                            event: parsed_event,
                            expires,
                            q,
                            params: Vec::new(),
                        });
                        if is_empty {
                            if let Some(contact) = current_contact.take() {
                                if let Some(reg) = current_registration.as_mut() {
                                    reg.contacts.push(contact);
                                }
                            }
                        }
                    }
                    b"uri" => {
                        in_uri_text = true;
                        uri_text_buffer.clear();
                    }
                    b"unknown-param" => {
                        // RFC 3680 §5.3.2.  Flag form is self-closing
                        // (`<unknown-param name="…"/>`); valued form
                        // carries its value as inner text.  We stash the
                        // name and accumulate text until End — empty
                        // accumulator on End ⇒ flag param.
                        let name = attr_required_str(&element, "name")?;
                        unknown_param_text_buffer.clear();
                        if is_empty {
                            if let Some(contact) = current_contact.as_mut() {
                                contact.params.push((name, None));
                            }
                            pending_unknown_param_name = None;
                        } else {
                            pending_unknown_param_name = Some(name);
                        }
                    }
                    _ => {
                        // Unknown element — ignored for forward compat.
                    }
                }
            }
            Event::Text(text) => {
                if in_uri_text {
                    let s = text
                        .unescape()
                        .map_err(|error| ReginfoParseError::Xml(error.to_string()))?;
                    uri_text_buffer.push_str(s.as_ref());
                } else if pending_unknown_param_name.is_some() {
                    let s = text
                        .unescape()
                        .map_err(|error| ReginfoParseError::Xml(error.to_string()))?;
                    unknown_param_text_buffer.push_str(s.as_ref());
                }
            }
            Event::End(element) => {
                let local_name = element.local_name();
                let name_bytes = local_name.as_ref();
                match name_bytes {
                    b"uri" => {
                        if let Some(contact) = current_contact.as_mut() {
                            let trimmed = uri_text_buffer.trim();
                            if !trimmed.is_empty() {
                                contact.uri = trimmed.to_string();
                            }
                        }
                        in_uri_text = false;
                        uri_text_buffer.clear();
                    }
                    b"unknown-param" => {
                        if let Some(name) = pending_unknown_param_name.take() {
                            let trimmed = unknown_param_text_buffer.trim();
                            let value = if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            };
                            if let Some(contact) = current_contact.as_mut() {
                                contact.params.push((name, value));
                            }
                        }
                        unknown_param_text_buffer.clear();
                    }
                    b"contact" => {
                        if let Some(contact) = current_contact.take() {
                            if let Some(reg) = current_registration.as_mut() {
                                reg.contacts.push(contact);
                            }
                        }
                    }
                    b"registration" => {
                        if let Some(reg) = current_registration.take() {
                            if let Some(reginfo) = body.as_mut() {
                                reginfo.registrations.push(reg);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    body.ok_or(ReginfoParseError::MissingRoot)
}

fn attr_required_str(
    element: &quick_xml::events::BytesStart<'_>,
    name: &'static str,
) -> Result<String, ReginfoParseError> {
    attr_optional_str(element, name)?.ok_or(ReginfoParseError::MissingAttr(name))
}

fn attr_optional_str(
    element: &quick_xml::events::BytesStart<'_>,
    name: &str,
) -> Result<Option<String>, ReginfoParseError> {
    for attr in element.attributes().with_checks(false) {
        let attr = attr.map_err(|error| ReginfoParseError::Xml(error.to_string()))?;
        if attr.key.local_name().as_ref() == name.as_bytes() {
            let value = attr
                .unescape_value()
                .map_err(|error| ReginfoParseError::Xml(error.to_string()))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn attr_required_u32(
    element: &quick_xml::events::BytesStart<'_>,
    name: &'static str,
) -> Result<u32, ReginfoParseError> {
    let value = attr_required_str(element, name)?;
    value.parse::<u32>().map_err(|_| ReginfoParseError::InvalidAttr {
        attr: name,
        value,
    })
}

fn attr_optional_u64(
    element: &quick_xml::events::BytesStart<'_>,
    name: &'static str,
) -> Result<Option<u64>, ReginfoParseError> {
    match attr_optional_str(element, name)? {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ReginfoParseError::InvalidAttr {
                attr: name,
                value: raw,
            }),
    }
}

fn attr_optional_f32(
    element: &quick_xml::events::BytesStart<'_>,
    name: &'static str,
) -> Result<Option<f32>, ReginfoParseError> {
    match attr_optional_str(element, name)? {
        None => Ok(None),
        Some(raw) => raw
            .parse::<f32>()
            .map(Some)
            .map_err(|_| ReginfoParseError::InvalidAttr {
                attr: name,
                value: raw,
            }),
    }
}

/// Escape XML special characters.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::sip::uri::SipUri;

    fn make_contact(uri_str: &str, expires_secs: u64) -> Contact {
        let mut uri = SipUri::new("10.0.0.1".to_string());
        uri.user = Some("alice".to_string());
        uri.port = Some(5060);
        let _ = uri_str;
        Contact {
            uri,
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: Duration::from_secs(expires_secs),
            call_id: "test-call-id".to_string(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: Vec::new(),
            kind: ContactKind::Ue,
        }
    }

    #[test]
    fn content_type() {
        assert_eq!(ReginfoBody::content_type(), "application/reginfo+xml");
    }

    #[test]
    fn full_reginfo_with_active_contacts() {
        let contacts = vec![make_contact("sip:alice@10.0.0.1:5060", 3600)];
        let body = build_full_reginfo("sip:alice@ims.example.com", &contacts, 0);

        assert_eq!(body.version, 0);
        assert_eq!(body.state, ReginfoState::Full);
        assert_eq!(body.registrations.len(), 1);
        assert_eq!(body.registrations[0].state, RegistrationState::Active);
        assert_eq!(body.registrations[0].contacts.len(), 1);
        assert_eq!(body.registrations[0].contacts[0].state, ContactState::Active);
        assert_eq!(body.registrations[0].contacts[0].event, ContactEvent::Registered);

        let xml = body.to_xml();
        assert!(!xml.contains("application/reginfo+xml")); // content type is separate
        assert!(xml.contains("urn:ietf:params:xml:ns:reginfo"));
        assert!(xml.contains("version=\"0\""));
        assert!(xml.contains("state=\"full\""));
        assert!(xml.contains("sip:alice@ims.example.com"));
        assert!(xml.contains("state=\"active\""));
        assert!(xml.contains("event=\"registered\""));
        assert!(xml.contains("<uri>"));
    }

    #[test]
    fn full_reginfo_no_contacts_is_terminated() {
        let body = build_full_reginfo("sip:bob@ims.example.com", &[], 5);

        assert_eq!(body.registrations[0].state, RegistrationState::Terminated);
        assert!(body.registrations[0].contacts.is_empty());

        let xml = body.to_xml();
        assert!(xml.contains("state=\"terminated\""));
        assert!(xml.contains("version=\"5\""));
    }

    #[test]
    fn xml_escapes_special_characters() {
        let body = ReginfoBody {
            version: 0,
            state: ReginfoState::Full,
            registrations: vec![Registration {
                aor: "sip:alice&bob@example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![],
            }],
        };
        let xml = body.to_xml();
        assert!(xml.contains("alice&amp;bob"));
    }

    #[test]
    fn reginfo_states_display() {
        assert_eq!(ReginfoState::Full.to_string(), "full");
        assert_eq!(ReginfoState::Partial.to_string(), "partial");
        assert_eq!(RegistrationState::Active.to_string(), "active");
        assert_eq!(RegistrationState::Terminated.to_string(), "terminated");
        assert_eq!(RegistrationState::Init.to_string(), "init");
        assert_eq!(ContactState::Active.to_string(), "active");
        assert_eq!(ContactState::Terminated.to_string(), "terminated");
        assert_eq!(ContactEvent::Registered.to_string(), "registered");
        assert_eq!(ContactEvent::Expired.to_string(), "expired");
        assert_eq!(ContactEvent::Unregistered.to_string(), "unregistered");
    }

    #[test]
    fn stable_registration_id() {
        let body1 = build_full_reginfo("sip:alice@ims.example.com", &[], 0);
        let body2 = build_full_reginfo("sip:alice@ims.example.com", &[], 1);
        // Same AoR should produce same registration ID.
        assert_eq!(body1.registrations[0].id, body2.registrations[0].id);

        // Different AoR should produce different registration ID.
        let body3 = build_full_reginfo("sip:bob@ims.example.com", &[], 0);
        assert_ne!(body1.registrations[0].id, body3.registrations[0].id);
    }

    #[test]
    fn contact_with_q_and_expires() {
        let contact = ReginfoContact {
            uri: "sip:alice@10.0.0.1:5060".to_string(),
            state: ContactState::Active,
            event: ContactEvent::Refreshed,
            expires: Some(1800),
            q: Some(0.5),
            params: Vec::new(),
        };
        let body = ReginfoBody {
            version: 2,
            state: ReginfoState::Partial,
            registrations: vec![Registration {
                aor: "sip:alice@example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![contact],
            }],
        };
        let xml = body.to_xml();
        assert!(xml.contains("expires=\"1800\""));
        assert!(xml.contains("q=\"0.5\""));
        assert!(xml.contains("event=\"refreshed\""));
        assert!(xml.contains("state=\"partial\""));
    }

    // -----------------------------------------------------------------
    // Parser tests
    // -----------------------------------------------------------------

    #[test]
    fn parse_full_state_single_registration() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="full">
  <registration aor="sip:alice@ims.example.com" id="reg-1" state="active">
    <contact id="c-1" state="active" event="registered" expires="1800" q="1.0">
      <uri>sip:alice@10.0.0.1:5060</uri>
    </contact>
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        assert_eq!(body.version, 3);
        assert_eq!(body.state, ReginfoState::Full);
        assert_eq!(body.registrations.len(), 1);
        let reg = &body.registrations[0];
        assert_eq!(reg.aor, "sip:alice@ims.example.com");
        assert_eq!(reg.id, "reg-1");
        assert_eq!(reg.state, RegistrationState::Active);
        assert_eq!(reg.contacts.len(), 1);
        let contact = &reg.contacts[0];
        assert_eq!(contact.uri, "sip:alice@10.0.0.1:5060");
        assert_eq!(contact.state, ContactState::Active);
        assert_eq!(contact.event, ContactEvent::Registered);
        assert_eq!(contact.expires, Some(1800));
        assert_eq!(contact.q, Some(1.0));
    }

    #[test]
    fn parse_partial_state_terminated_contact() {
        let xml = r#"<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="7" state="partial">
  <registration aor="sip:bob@ims.example.com" id="reg-bob" state="terminated">
    <contact id="c-old" state="terminated" event="expired"><uri>sip:bob@10.0.0.2</uri></contact>
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        assert_eq!(body.state, ReginfoState::Partial);
        assert_eq!(body.registrations.len(), 1);
        assert_eq!(body.registrations[0].state, RegistrationState::Terminated);
        assert_eq!(body.registrations[0].contacts.len(), 1);
        assert_eq!(body.registrations[0].contacts[0].state, ContactState::Terminated);
        assert_eq!(body.registrations[0].contacts[0].event, ContactEvent::Expired);
        assert!(body.registrations[0].contacts[0].expires.is_none());
        assert!(body.registrations[0].contacts[0].q.is_none());
    }

    #[test]
    fn parse_multi_registration_multi_contact() {
        let xml = r#"<reginfo version="0" state="full">
  <registration aor="sip:a@ex" id="r-a" state="active">
    <contact id="c-a1" state="active" event="registered"><uri>sip:a@1.1.1.1</uri></contact>
    <contact id="c-a2" state="active" event="created"><uri>sip:a@2.2.2.2</uri></contact>
  </registration>
  <registration aor="sip:b@ex" id="r-b" state="init">
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        assert_eq!(body.registrations.len(), 2);
        assert_eq!(body.registrations[0].contacts.len(), 2);
        assert_eq!(body.registrations[0].contacts[0].uri, "sip:a@1.1.1.1");
        assert_eq!(body.registrations[0].contacts[1].uri, "sip:a@2.2.2.2");
        assert_eq!(body.registrations[1].state, RegistrationState::Init);
        assert!(body.registrations[1].contacts.is_empty());
    }

    #[test]
    fn parse_roundtrips_through_to_xml() {
        // Build a body, serialize it, parse it back, verify equivalence.
        let original = build_full_reginfo("sip:alice@ims.example.com", &[], 5);
        let xml = original.to_xml();
        let parsed = parse_reginfo(&xml).unwrap();
        assert_eq!(parsed.version, 5);
        assert_eq!(parsed.state, ReginfoState::Full);
        assert_eq!(parsed.registrations.len(), 1);
        assert_eq!(
            parsed.registrations[0].state,
            RegistrationState::Terminated
        );
    }

    #[test]
    fn parse_rejects_missing_root() {
        let result = parse_reginfo("<not-reginfo/>");
        assert!(matches!(result, Err(ReginfoParseError::MissingRoot)));
    }

    #[test]
    fn parse_rejects_invalid_state_attribute() {
        let xml = r#"<reginfo version="1" state="bogus"></reginfo>"#;
        let result = parse_reginfo(xml);
        assert!(matches!(
            result,
            Err(ReginfoParseError::InvalidAttr { attr: "state", .. })
        ));
    }

    #[test]
    fn parse_rejects_missing_required_attribute() {
        // Missing version on <reginfo>.
        let xml = r#"<reginfo state="full"></reginfo>"#;
        let result = parse_reginfo(xml);
        assert!(matches!(result, Err(ReginfoParseError::MissingAttr("version"))));
    }

    #[test]
    fn parse_ignores_unknown_elements() {
        // Forward-compat: unknown <foo> element under reginfo or
        // registration must not break parsing.
        let xml = r#"<reginfo version="1" state="full">
  <foo>bar</foo>
  <registration aor="sip:x@ex" id="rx" state="active">
    <baz/>
    <contact id="c-x" state="active"><uri>sip:x@1.1.1.1</uri></contact>
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        assert_eq!(body.registrations[0].contacts[0].uri, "sip:x@1.1.1.1");
    }

    #[test]
    fn parse_empty_contact_event_defaults_to_registered() {
        let xml = r#"<reginfo version="1" state="full">
  <registration aor="sip:x@ex" id="rx" state="active">
    <contact id="c-x" state="active"><uri>sip:x@1.1.1.1</uri></contact>
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        assert_eq!(body.registrations[0].contacts[0].event, ContactEvent::Registered);
    }

    // -----------------------------------------------------------------
    // RFC 3680 §5.3.2 — <unknown-param> emission + parser tolerance
    // -----------------------------------------------------------------

    #[test]
    fn to_xml_emits_unknown_param_for_flag_and_valued() {
        let body = ReginfoBody {
            version: 0,
            state: ReginfoState::Full,
            registrations: vec![Registration {
                aor: "sip:alice@ims.example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![ReginfoContact {
                    uri: "sip:alice@10.0.0.1".to_string(),
                    state: ContactState::Active,
                    event: ContactEvent::Registered,
                    expires: Some(3600),
                    q: Some(1.0),
                    params: vec![
                        ("+g.3gpp.smsip".to_string(), None),
                        (
                            "+g.3gpp.icsi-ref".to_string(),
                            Some(
                                "\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
                                    .to_string(),
                            ),
                        ),
                    ],
                }],
            }],
        };
        let xml = body.to_xml();
        // Flag form (self-closing).
        assert!(
            xml.contains("<unknown-param name=\"+g.3gpp.smsip\"/>"),
            "flag tag should be self-closing; got\n{xml}"
        );
        // Valued form with XML-escaped value.  Quotes round-trip
        // unchanged in value content because RFC 3680 §5.3.2 places the
        // value in element text, not an attribute — but our writer still
        // escapes them defensively (`&quot;`).
        assert!(
            xml.contains("<unknown-param name=\"+g.3gpp.icsi-ref\">"),
            "valued tag should open <unknown-param name=…>; got\n{xml}"
        );
        assert!(
            xml.contains("urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"),
            "valued tag should carry the percent-encoded URN; got\n{xml}"
        );
        assert!(
            xml.contains("</unknown-param>"),
            "valued tag should have an end tag; got\n{xml}"
        );
    }

    #[test]
    fn build_full_reginfo_terminated_when_only_as_contacts() {
        // An AoR populated with AS-only records (cascade-clear race)
        // must still emit a terminated registration — the user is not
        // registered, only the iFC chain knows about them.
        let as_only = Contact {
            uri: crate::sip::uri::SipUri::new("ims.example.com".to_string())
                .with_user("mmtel".into()),
            q: 1.0,
            registered_at: std::time::Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: String::new(),
            cseq: 0,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: vec![("+g.3gpp.smsip".to_string(), None)],
            kind: ContactKind::As,
        };
        let body = build_full_reginfo("sip:alice@ims.example.com", &[as_only], 0);
        assert_eq!(body.registrations[0].state, RegistrationState::Terminated);
    }

    #[test]
    fn parse_reginfo_accepts_unknown_param_children() {
        // Watcher-side: an inbound NOTIFY from another registrar
        // implementation (or a future siphon) must be parseable even
        // when it carries <unknown-param>.
        let xml = r#"<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" state="full">
  <registration aor="sip:alice@ims.example.com" id="r-1" state="active">
    <contact id="c-1" state="active" event="registered">
      <uri>sip:alice@10.0.0.1</uri>
      <unknown-param name="+g.3gpp.smsip"/>
      <unknown-param name="+g.3gpp.icsi-ref">urn:urn-7:3gpp-service.ims.icsi.mmtel</unknown-param>
    </contact>
  </registration>
</reginfo>"#;
        let body = parse_reginfo(xml).unwrap();
        let params = &body.registrations[0].contacts[0].params;
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("+g.3gpp.smsip".to_string(), None));
        assert_eq!(
            params[1],
            (
                "+g.3gpp.icsi-ref".to_string(),
                Some("urn:urn-7:3gpp-service.ims.icsi.mmtel".to_string()),
            ),
        );
    }

    #[test]
    fn build_to_xml_parse_roundtrip_preserves_params() {
        // End-to-end: write a body with params, serialize, reparse, and
        // verify every (name, value) pair survives.
        let contact = ReginfoContact {
            uri: "sip:alice@10.0.0.1".to_string(),
            state: ContactState::Active,
            event: ContactEvent::Registered,
            expires: Some(3600),
            q: Some(1.0),
            params: vec![
                ("+g.3gpp.smsip".to_string(), None),
                (
                    "+g.3gpp.icsi-ref".to_string(),
                    Some(
                        "urn:urn-7:3gpp-service.ims.icsi.mmtel".to_string(),
                    ),
                ),
                ("vendor.x".to_string(), Some("y".to_string())),
            ],
        };
        let body = ReginfoBody {
            version: 1,
            state: ReginfoState::Full,
            registrations: vec![Registration {
                aor: "sip:alice@ims.example.com".to_string(),
                id: "reg-1".to_string(),
                state: RegistrationState::Active,
                contacts: vec![contact.clone()],
            }],
        };
        let xml = body.to_xml();
        let reparsed = parse_reginfo(&xml).unwrap();
        assert_eq!(reparsed.registrations[0].contacts[0].params, contact.params);
    }
}
