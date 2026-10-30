//! Initial Filter Criteria (iFC) evaluation engine.
//!
//! Implements 3GPP TS 29.228 §6.6 iFC XML parsing and evaluation.
//! Used by the S-CSCF to determine which Application Servers a SIP
//! request must be routed through, based on the subscriber's service
//! profile received from the HSS via Diameter Cx SAA.
//!
//! Three parts of the user profile beyond plain iFCs:
//!
//! - **Shared iFC sets** (TS 29.228 Annex B.2, Annex E `tServiceProfileExtension`;
//!   TS 29.229 §7.1.1 feature `SiFC`): a service profile may carry
//!   `SharedIFCSetID`s instead of, or next to, its iFCs. Each names a set
//!   provisioned locally at the S-CSCF (`isc.shared_ifc_sets`), merged with the
//!   profile's own iFCs by Priority at evaluation.
//! - **Session case 4, ORIGINATING_CDIV** (Annex E `tDirectionOfRequest`): the
//!   originating services after retargeting that TS 24.229 §5.4.3.3 NOTE 4 has
//!   the S-CSCF evaluate for a diverted request.
//! - **SessionDescription SPTs** (Annex F): `Line` is a regular expression
//!   matched against the type of each SDP field, `Content` one matched against
//!   its value, and the SPT matches when one field matches both.

use std::collections::HashMap;
use std::fmt;
use std::sync::{OnceLock, RwLock};

use dashmap::DashMap;
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;

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
use tracing::warn;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from iFC parsing or evaluation.
#[derive(Debug)]
pub enum IfcError {
    /// XML is malformed or unreadable.
    XmlParse(String),
    /// XML is well-formed but violates the expected schema.
    InvalidFormat(String),
}

impl fmt::Display for IfcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IfcError::XmlParse(message) => write!(formatter, "iFC XML parse error: {message}"),
            IfcError::InvalidFormat(message) => write!(formatter, "iFC format error: {message}"),
        }
    }
}

impl std::error::Error for IfcError {}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Session case for iFC evaluation (originating vs terminating).
///
/// The integer codes are those of `tDirectionOfRequest` in 3GPP TS 29.228
/// Annex E, which allows 0 to 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCase {
    /// Originating, request from a registered user (code 0).
    Originating,
    /// Terminating, request to a registered user (code 1).
    Terminating,
    /// Originating on behalf of an unregistered user (code 3).
    OriginatingUnregistered,
    /// Terminating for an unregistered user (code 2).
    TerminatingUnregistered,
    /// Originating after call diversion, on behalf of the diverting user
    /// (code 4, ORIGINATING_CDIV): the originating services after retargeting
    /// of TS 24.229 §5.4.3.3 NOTE 4, signalled onward with
    /// `P-Served-User: ...;sescase=orig-cdiv` (RFC 8498, §5.4.3.2).
    OriginatingCdiv,
}

impl SessionCase {
    /// Parse from the 3GPP integer encoding (TS 29.228 Annex E,
    /// `tDirectionOfRequest`).
    fn from_code(code: u32) -> Option<SessionCase> {
        match code {
            0 => Some(SessionCase::Originating),
            1 => Some(SessionCase::Terminating),
            2 => Some(SessionCase::TerminatingUnregistered),
            3 => Some(SessionCase::OriginatingUnregistered),
            4 => Some(SessionCase::OriginatingCdiv),
            _ => None,
        }
    }
}

impl fmt::Display for SessionCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionCase::Originating => write!(formatter, "Originating"),
            SessionCase::Terminating => write!(formatter, "Terminating"),
            SessionCase::OriginatingUnregistered => write!(formatter, "OriginatingUnregistered"),
            SessionCase::TerminatingUnregistered => write!(formatter, "TerminatingUnregistered"),
            SessionCase::OriginatingCdiv => write!(formatter, "OriginatingCdiv"),
        }
    }
}

/// A single Initial Filter Criteria entry.
#[derive(Debug, Clone)]
pub struct InitialFilterCriteria {
    /// Priority (lower = evaluated first).
    pub priority: i32,
    /// Trigger point — conditions that must match.
    pub trigger_point: Option<TriggerPoint>,
    /// Application Server to route to if trigger matches.
    pub application_server: ApplicationServer,
    /// Default handling when AS is unreachable:
    /// 0 = SESSION_CONTINUED, 1 = SESSION_TERMINATED.
    pub default_handling: u32,
}

/// Trigger point — a set of conditions evaluated as CNF or DNF.
#[derive(Debug, Clone)]
pub struct TriggerPoint {
    /// Condition type: true = CNF (AND of OR groups), false = DNF (OR of AND groups).
    pub condition_type_cnf: bool,
    /// Service point triggers (the conditions).
    pub service_point_triggers: Vec<ServicePointTrigger>,
    /// Pre-computed method filter for the early-return fast path.
    ///
    /// Set at parse time when the trigger has exactly one non-negated SPT with
    /// a method criterion — the overwhelmingly common iFC shape ("trigger on
    /// INVITE", "trigger on REGISTER"). At evaluate time, a single
    /// case-insensitive compare lets us skip the full SPT walk + HashMap
    /// allocation for any request whose method doesn't match. `None` means
    /// "no fast-path filter — fall through to the full evaluator".
    pub method_fast_path: Option<String>,
}

/// A single condition within a trigger point.
#[derive(Debug, Clone)]
pub struct ServicePointTrigger {
    /// Whether this condition is negated.
    pub condition_negated: bool,
    /// Group index for CNF/DNF grouping.
    pub group: Vec<i32>,
    /// Match on SIP method (e.g., "INVITE", "REGISTER").
    pub method: Option<String>,
    /// Match on SIP header: (header_name, optional_content_regex).
    pub header: Option<(String, Option<String>)>,
    /// Match on Request-URI.
    pub request_uri: Option<String>,
    /// Match on session case.
    pub session_case: Option<SessionCase>,
    /// Match on the SDP of the request (TS 29.228 Annex F `SessionDescription`):
    /// (`Line`, a regular expression on the field type; `Content`, an optional
    /// one on the field value).
    pub sdp_line: Option<(String, Option<String>)>,
}

impl ServicePointTrigger {
    /// Whether this SPT carries any condition at all.
    fn has_condition(&self) -> bool {
        self.method.is_some()
            || self.header.is_some()
            || self.request_uri.is_some()
            || self.session_case.is_some()
            || self.sdp_line.is_some()
    }
}

/// What a user profile document holds: its iFCs and the shared iFC sets its
/// service profiles name (TS 29.228 Annex B.2: "A SharedIFCSetID attribute
/// points to a set of Initial Filter Criteria locally administered and
/// stored at the S-CSCF").
#[derive(Debug, Clone, Default)]
pub struct UserProfile {
    pub ifcs: Vec<InitialFilterCriteria>,
    /// In document order, duplicates removed.
    pub shared_ifc_set_ids: Vec<u32>,
}

/// Application Server to route to.
#[derive(Debug, Clone)]
pub struct ApplicationServer {
    /// SIP URI of the AS (e.g., "sip:as1.example.com").
    pub server_name: String,
    /// Whether to include the original REGISTER request.
    pub include_register_request: bool,
    /// Whether to include the original REGISTER response.
    pub include_register_response: bool,
    /// Service information (opaque string passed to AS).
    pub service_info: Option<String>,
}

// ---------------------------------------------------------------------------
// XML Parsing
// ---------------------------------------------------------------------------

/// Parse iFC XML from a ServiceProfile document.
///
/// Expects XML conforming to 3GPP TS 29.228 §6.6, with a root
/// `<ServiceProfile>` element containing one or more
/// `<InitialFilterCriteria>` children. The iFCs only: see
/// [`parse_user_profile`] for the shared iFC sets the profile names.
pub fn parse_service_profile(xml: &str) -> Result<Vec<InitialFilterCriteria>, IfcError> {
    parse_user_profile(xml).map(|profile| profile.ifcs)
}

/// Parse a user profile document (`<IMSSubscription>`, a `<ServiceProfile>`,
/// or bare `<InitialFilterCriteria>` elements): its iFCs and the
/// `SharedIFCSetID`s of its service profiles (TS 29.228 Annex E).
///
/// A `<SessionCase>` that is not a `tDirectionOfRequest` value (0 to 4) is an
/// error rather than an SPT with no condition, which would never match and
/// silently drop a service. So is a `SharedIFCSetID` that is not an integer
/// of at least 0.
pub fn parse_user_profile(xml: &str) -> Result<UserProfile, IfcError> {
    let mut reader = Reader::from_str(xml);

    let mut results: Vec<InitialFilterCriteria> = Vec::new();
    let mut shared_ifc_set_ids: Vec<u32> = Vec::new();
    let mut depth: Vec<String> = Vec::new();

    // State for building the current iFC.
    let mut current_ifc: Option<IfcBuilder> = None;
    let mut current_trigger: Option<TriggerPointBuilder> = None;
    let mut current_spt: Option<SptBuilder> = None;
    let mut current_app_server: Option<AppServerBuilder> = None;
    let mut current_text = String::new();

    // For header SPT sub-elements.
    let mut header_name: Option<String> = None;
    let mut header_content: Option<String> = None;
    // For SDP line SPT sub-elements.
    let mut sdp_line_type: Option<String> = None;
    let mut sdp_line_content: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let tag = local_name(&element, &reader);
                match tag.as_str() {
                    "InitialFilterCriteria" => {
                        current_ifc = Some(IfcBuilder::default());
                    }
                    "TriggerPoint" => {
                        current_trigger = Some(TriggerPointBuilder::default());
                    }
                    "SPT" => {
                        current_spt = Some(SptBuilder::default());
                        header_name = None;
                        header_content = None;
                        sdp_line_type = None;
                        sdp_line_content = None;
                    }
                    "ApplicationServer" => {
                        current_app_server = Some(AppServerBuilder::default());
                    }
                    _ => {}
                }
                depth.push(tag);
                current_text.clear();
            }
            Ok(Event::End(_element)) => {
                let tag = depth.pop().unwrap_or_default();
                let text = current_text.trim().to_string();

                match tag.as_str() {
                    // --- iFC-level fields ---
                    "Priority" => {
                        if let Some(ref mut ifc) = current_ifc {
                            ifc.priority = text.parse::<i32>().ok();
                        }
                    }
                    "DefaultHandling" => {
                        if let Some(ref mut app) = current_app_server {
                            app.default_handling = text.parse::<u32>().ok();
                        }
                    }

                    // --- TriggerPoint fields ---
                    "ConditionTypeCNF" => {
                        if let Some(ref mut trigger) = current_trigger {
                            trigger.condition_type_cnf =
                                Some(text == "1" || text.eq_ignore_ascii_case("true"));
                        }
                    }

                    // --- SPT fields ---
                    "ConditionNegated" => {
                        if let Some(ref mut spt) = current_spt {
                            spt.condition_negated =
                                text == "1" || text.eq_ignore_ascii_case("true");
                        }
                    }
                    "Group" => {
                        if let Some(ref mut spt) = current_spt {
                            if let Ok(group) = text.parse::<i32>() {
                                spt.groups.push(group);
                            }
                        }
                    }
                    "Method" => {
                        if current_spt.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.method = Some(text);
                            }
                        }
                    }
                    "Header" => {
                        if current_spt.is_some() {
                            if header_name.is_some() {
                                // Close of the <Header> container with <HeaderName> child.
                                if let Some(ref mut spt) = current_spt {
                                    spt.header = Some((
                                        header_name.take().unwrap_or_default(),
                                        header_content.take(),
                                    ));
                                }
                            } else if !text.is_empty() {
                                // <Header> used as leaf node: text is the header name.
                                // Common in 3GPP iFC XML: <SIPHeader><Header>X-Foo</Header></SIPHeader>
                                header_name = Some(text);
                            }
                        }
                    }
                    "HeaderName" => {
                        header_name = Some(text);
                    }
                    "Content" => {
                        // Content can appear under Header or SIPHeader.
                        if sdp_line_type.is_some() {
                            sdp_line_content = Some(text);
                        } else {
                            header_content = Some(text);
                        }
                    }
                    "RequestURI" => {
                        if let Some(ref mut spt) = current_spt {
                            spt.request_uri = Some(text);
                        }
                    }
                    "SessionCase" => {
                        if let Some(ref mut spt) = current_spt {
                            let case = text.parse::<u32>().ok().and_then(SessionCase::from_code);
                            match case {
                                Some(case) => spt.session_case = Some(case),
                                None => {
                                    return Err(IfcError::InvalidFormat(format!(
                                        "SessionCase {text:?} is not a tDirectionOfRequest value \
                                         (0 to 4, TS 29.228 Annex E)"
                                    )))
                                }
                            }
                        }
                    }
                    "SharedIFCSetID" => {
                        let id = text.parse::<u32>().map_err(|_| {
                            IfcError::InvalidFormat(format!(
                                "SharedIFCSetID {text:?} is not an integer of at least 0 \
                                 (TS 29.228 Annex E tSharedIFCSetID)"
                            ))
                        })?;
                        if !shared_ifc_set_ids.contains(&id) {
                            shared_ifc_set_ids.push(id);
                        }
                    }
                    "SIPHeader" => {
                        // Alternative element name used by some implementations.
                        if current_spt.is_some() && header_name.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.header = Some((
                                    header_name.take().unwrap_or_default(),
                                    header_content.take(),
                                ));
                            }
                        }
                    }
                    // `SessionDescription` is the TS 29.228 Annex E element;
                    // `SDPLine` is kept for profiles written to the older name.
                    "SessionDescription" | "SDPLine" => {
                        if current_spt.is_some() {
                            if let Some(ref mut spt) = current_spt {
                                spt.sdp_line = Some((
                                    sdp_line_type.take().unwrap_or_default(),
                                    sdp_line_content.take(),
                                ));
                            }
                        }
                    }
                    "Line" => {
                        sdp_line_type = Some(text);
                    }

                    // --- SPT close ---
                    "SPT" => {
                        if let (Some(spt), Some(ref mut trigger)) =
                            (current_spt.take(), &mut current_trigger)
                        {
                            let spt = spt.build();
                            if !spt.has_condition() {
                                warn!(
                                    "iFC SPT with no condition siphon reads (RequestURI, Method, \
                                     SIPHeader, SessionCase, SessionDescription); it never matches"
                                );
                            }
                            trigger.spts.push(spt);
                        }
                    }

                    // --- ApplicationServer fields ---
                    "ServerName" => {
                        if let Some(ref mut app) = current_app_server {
                            app.server_name = Some(text);
                        }
                    }
                    "IncludeRegisterRequest" => {
                        if let Some(ref mut app) = current_app_server {
                            app.include_register_request = include_flag_value(&text);
                        }
                    }
                    "IncludeRegisterResponse" => {
                        if let Some(ref mut app) = current_app_server {
                            app.include_register_response = include_flag_value(&text);
                        }
                    }
                    "ServiceInfo" => {
                        if let Some(ref mut app) = current_app_server {
                            app.service_info = Some(text);
                        }
                    }

                    // --- Container closes ---
                    "TriggerPoint" => {
                        if let Some(ref mut ifc) = current_ifc {
                            if let Some(trigger) = current_trigger.take() {
                                ifc.trigger_point = Some(trigger.build());
                            }
                        }
                    }
                    "ApplicationServer" => {
                        if let Some(ref mut ifc) = current_ifc {
                            if let Some(app) = current_app_server.take() {
                                let default_handling = app.default_handling.unwrap_or(0);
                                ifc.application_server = Some(app.build()?);
                                ifc.default_handling = default_handling;
                            }
                        }
                    }
                    "InitialFilterCriteria" => {
                        if let Some(ifc) = current_ifc.take() {
                            results.push(ifc.build()?);
                        }
                    }
                    _ => {}
                }
                current_text.clear();
            }
            // TS 29.228 Annex E types `IncludeRegisterRequest` and
            // `IncludeRegisterResponse` as empty complex types: the element
            // being present is the flag, so the self-closing form is the
            // normal one. An empty element never pushes onto `depth`.
            Ok(Event::Empty(element)) => {
                if let Some(ref mut app) = current_app_server {
                    match local_name(&element, &reader).as_str() {
                        "IncludeRegisterRequest" => app.include_register_request = true,
                        "IncludeRegisterResponse" => app.include_register_response = true,
                        _ => {}
                    }
                }
            }
            Ok(Event::Text(element)) => {
                current_text.push_str(
                    &element
                        .unescape()
                        .map_err(|error| IfcError::XmlParse(error.to_string()))?,
                );
            }
            // An entity reference arrives as its own event between two `Text`
            // fragments; without this it is dropped and the iFC value silently
            // loses characters (a ServiceInfo body or an SPT header value can
            // legitimately contain `&`).
            Ok(Event::GeneralRef(reference)) => {
                let resolved =
                    crate::xml_text::resolve_general_ref(&reference).ok_or_else(|| {
                        IfcError::XmlParse(format!(
                            "unresolvable entity reference &{};  (siphon parses no DTD)",
                            reference.as_ref() as &str
                        ))
                    })?;
                current_text.push_str(&resolved);
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(IfcError::XmlParse(error.to_string())),
            _ => {}
        }
    }

    Ok(UserProfile {
        ifcs: results,
        shared_ifc_set_ids,
    })
}

/// Value of an `IncludeRegisterRequest` / `IncludeRegisterResponse` element
/// that has a start and end tag. The schema type is empty, so an empty body
/// means set; `1` and `true` are read for profiles written with a value, and
/// `0` / `false` clear it.
fn include_flag_value(text: &str) -> bool {
    text.is_empty() || text == "1" || text.eq_ignore_ascii_case("true")
}

/// Extract the local name (without namespace prefix) from a tag.
fn local_name(element: &quick_xml::events::BytesStart, _reader: &Reader<&[u8]>) -> String {
    let full = element.name();
    let local = full.local_name();
    // quick-xml 0.42 yields `str` here, so there is nothing left to decode.
    local.as_ref().to_string()
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct IfcBuilder {
    priority: Option<i32>,
    trigger_point: Option<TriggerPoint>,
    application_server: Option<ApplicationServer>,
    default_handling: u32,
}

impl IfcBuilder {
    fn build(self) -> Result<InitialFilterCriteria, IfcError> {
        Ok(InitialFilterCriteria {
            priority: self
                .priority
                .ok_or_else(|| IfcError::InvalidFormat("missing Priority element".into()))?,
            trigger_point: self.trigger_point,
            application_server: self.application_server.ok_or_else(|| {
                IfcError::InvalidFormat("missing ApplicationServer element".into())
            })?,
            default_handling: self.default_handling,
        })
    }
}

#[derive(Default)]
struct TriggerPointBuilder {
    condition_type_cnf: Option<bool>,
    spts: Vec<ServicePointTrigger>,
}

impl TriggerPointBuilder {
    fn build(self) -> TriggerPoint {
        let condition_type_cnf = self.condition_type_cnf.unwrap_or(true);
        let method_fast_path = compute_method_fast_path(condition_type_cnf, &self.spts);
        TriggerPoint {
            condition_type_cnf,
            service_point_triggers: self.spts,
            method_fast_path,
        }
    }
}

/// Detect the common-case method-only iFC trigger and stash the required
/// method (lower-cased) for the eval-time fast path. Conservative: returns
/// `Some(method)` only when the trigger UNAMBIGUOUSLY requires that method —
/// so any iFC with negated conditions, multiple SPTs in a CNF group, or no
/// method criterion at all, falls through to the full evaluator.
fn compute_method_fast_path(
    condition_type_cnf: bool,
    spts: &[ServicePointTrigger],
) -> Option<String> {
    // Single-SPT triggers are by far the most common shape: "trigger on INVITE".
    if spts.len() == 1 {
        let spt = &spts[0];
        if !spt.condition_negated {
            if let Some(ref method) = spt.method {
                return Some(method.to_ascii_lowercase());
            }
        }
        return None;
    }
    // CNF (AND of OR groups): a non-negated method SPT alone in its own group
    // is a hard requirement on the method. Find one and use it.
    if condition_type_cnf {
        for spt in spts {
            if spt.condition_negated || spt.method.is_none() {
                continue;
            }
            // Alone in its group means: explicit group [n] not shared with any
            // other SPT, or empty group (default 0) with no other empty-group
            // SPT alongside.
            let group_alone = if spt.group.is_empty() {
                spts.iter().filter(|other| other.group.is_empty()).count() == 1
            } else {
                spt.group.iter().all(|index| {
                    spts.iter()
                        .filter(|other| other.group.contains(index))
                        .count()
                        == 1
                })
            };
            if group_alone {
                return spt
                    .method
                    .as_ref()
                    .map(|method| method.to_ascii_lowercase());
            }
        }
    }
    None
}

#[derive(Default)]
struct SptBuilder {
    condition_negated: bool,
    groups: Vec<i32>,
    method: Option<String>,
    header: Option<(String, Option<String>)>,
    request_uri: Option<String>,
    session_case: Option<SessionCase>,
    sdp_line: Option<(String, Option<String>)>,
}

impl SptBuilder {
    fn build(self) -> ServicePointTrigger {
        ServicePointTrigger {
            condition_negated: self.condition_negated,
            group: self.groups,
            method: self.method,
            header: self.header,
            request_uri: self.request_uri,
            session_case: self.session_case,
            sdp_line: self.sdp_line,
        }
    }
}

#[derive(Default)]
struct AppServerBuilder {
    server_name: Option<String>,
    default_handling: Option<u32>,
    include_register_request: bool,
    include_register_response: bool,
    service_info: Option<String>,
}

impl AppServerBuilder {
    fn build(self) -> Result<ApplicationServer, IfcError> {
        Ok(ApplicationServer {
            server_name: self
                .server_name
                .ok_or_else(|| IfcError::InvalidFormat("missing ServerName element".into()))?,
            include_register_request: self.include_register_request,
            include_register_response: self.include_register_response,
            service_info: self.service_info,
        })
    }
}

// ---------------------------------------------------------------------------
// Evaluation engine
// ---------------------------------------------------------------------------

/// The parts of a request iFC evaluation reads.
#[derive(Debug, Clone, Copy)]
pub struct IfcRequest<'a> {
    pub method: &'a str,
    pub request_uri: &'a str,
    pub headers: &'a [(String, String)],
    pub session_case: SessionCase,
    /// The SDP of the request, for SessionDescription SPTs. `None` when the
    /// request carries none: such an SPT then does not match.
    pub body: Option<&'a str>,
}

/// Evaluate iFC rules against a SIP request.
///
/// Returns the list of Application Servers to route through, ordered by
/// priority (ascending — lower priority value is evaluated first).
pub fn evaluate<'a>(
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
    ifcs: &'a [InitialFilterCriteria],
) -> Vec<&'a ApplicationServer> {
    evaluate_request(
        &IfcRequest {
            method,
            request_uri,
            headers,
            session_case,
            body: None,
        },
        ifcs,
    )
}

/// [`evaluate`] over a whole [`IfcRequest`], the body included.
pub fn evaluate_request<'a>(
    request: &IfcRequest<'_>,
    ifcs: &'a [InitialFilterCriteria],
) -> Vec<&'a ApplicationServer> {
    let mut sorted: Vec<&InitialFilterCriteria> = ifcs.iter().collect();
    sorted.sort_by_key(|ifc| ifc.priority);

    sorted
        .into_iter()
        .filter(|ifc| matches_ifc(ifc, request))
        .map(|ifc| &ifc.application_server)
        .collect()
}

/// Check whether a single iFC matches the given request parameters.
fn matches_ifc(ifc: &InitialFilterCriteria, request: &IfcRequest<'_>) -> bool {
    match &ifc.trigger_point {
        None => true, // No trigger point → always matches.
        Some(trigger) => evaluate_trigger_point(trigger, request),
    }
}

/// Evaluate a trigger point (CNF or DNF) against request parameters.
fn evaluate_trigger_point(trigger: &TriggerPoint, request: &IfcRequest<'_>) -> bool {
    if trigger.service_point_triggers.is_empty() {
        return true;
    }

    // Method-match early return — for the overwhelmingly common iFC shape
    // ("trigger on INVITE", "trigger on REGISTER") this skips the SPT walk
    // and the HashMap allocation below for any non-matching method.
    if let Some(ref required) = trigger.method_fast_path {
        if !request.method.eq_ignore_ascii_case(required) {
            return false;
        }
    }

    // Single-SPT triggers don't need group bookkeeping — most iFCs in real
    // deployments are single-SPT method filters that survived the fast-path
    // guard above; eval them directly.
    if trigger.service_point_triggers.len() == 1 {
        return evaluate_spt(&trigger.service_point_triggers[0], request);
    }

    // Group SPTs by their group indices.
    let mut groups: HashMap<i32, Vec<&ServicePointTrigger>> = HashMap::new();
    for spt in &trigger.service_point_triggers {
        if spt.group.is_empty() {
            // No group specified — treat as group 0.
            groups.entry(0).or_default().push(spt);
        } else {
            for &group_index in &spt.group {
                groups.entry(group_index).or_default().push(spt);
            }
        }
    }

    if trigger.condition_type_cnf {
        // CNF: AND of OR groups.
        // For each group, at least one SPT must match. All groups must pass.
        groups
            .values()
            .all(|spts| spts.iter().any(|spt| evaluate_spt(spt, request)))
    } else {
        // DNF: OR of AND groups.
        // For each group, all SPTs must match. At least one group must pass.
        groups
            .values()
            .any(|spts| spts.iter().all(|spt| evaluate_spt(spt, request)))
    }
}

/// Evaluate a single Service Point Trigger condition.
fn evaluate_spt(spt: &ServicePointTrigger, request: &IfcRequest<'_>) -> bool {
    let raw_result = evaluate_spt_condition(spt, request);

    if spt.condition_negated {
        !raw_result
    } else {
        raw_result
    }
}

/// Whether `text` matches `pattern`, a regular expression; a pattern that
/// does not compile is taken as a literal substring, as the header SPT has
/// always done.
fn pattern_matches(pattern: &str, text: &str) -> bool {
    match Regex::new(pattern) {
        Ok(regex) => regex.is_match(text),
        Err(_) => text.contains(pattern),
    }
}

/// The `<type>=<value>` fields of an SDP body (RFC 4566 §5: the type is
/// exactly one character). Anything else in the body, such as another part
/// of a multipart body, is not a field and is skipped.
fn sdp_fields(body: &str) -> impl Iterator<Item = (&str, &str)> {
    body.lines().filter_map(|line| {
        let line = line.trim_end_matches('\r');
        let (field_type, value) = line.split_once('=')?;
        (field_type.len() == 1).then_some((field_type, value))
    })
}

/// Evaluate the raw condition of an SPT (before negation).
fn evaluate_spt_condition(spt: &ServicePointTrigger, request: &IfcRequest<'_>) -> bool {
    // Method match.
    if let Some(ref expected_method) = spt.method {
        return request.method.eq_ignore_ascii_case(expected_method);
    }

    // Header match.
    if let Some((ref header_name, ref content_pattern)) = spt.header {
        let matching_headers: Vec<&str> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(header_name))
            .map(|(_, value)| value.as_str())
            .collect();

        if matching_headers.is_empty() {
            return false;
        }

        if let Some(pattern) = content_pattern {
            // Check if any matching header value matches the regex.
            if let Ok(regex) = Regex::new(pattern) {
                return matching_headers.iter().any(|value| regex.is_match(value));
            }
            // If regex is invalid, fall back to substring match.
            return matching_headers
                .iter()
                .any(|value| value.contains(pattern.as_str()));
        }

        // Header exists, no content check required.
        return true;
    }

    // Request-URI match.
    if let Some(ref uri_pattern) = spt.request_uri {
        if let Ok(regex) = Regex::new(uri_pattern) {
            return regex.is_match(request.request_uri);
        }
        return request.request_uri.contains(uri_pattern.as_str());
    }

    // Session case match.
    if let Some(ref expected_case) = spt.session_case {
        return request.session_case == *expected_case;
    }

    // SessionDescription match (TS 29.228 Annex F): "evaluated separately
    // against each SDP field instance within the SIP message", matching "if at
    // least one field occurrence matches". `Line` is matched against the field
    // type, `Content` against its value. A request without SDP has no field to
    // match.
    if let Some((ref line_pattern, ref content_pattern)) = spt.sdp_line {
        let Some(body) = request.body else {
            return false;
        };
        return sdp_fields(body).any(|(field_type, value)| {
            pattern_matches(line_pattern, field_type)
                && content_pattern
                    .as_deref()
                    .is_none_or(|pattern| pattern_matches(pattern, value))
        });
    }

    // No condition matched — should not happen for a well-formed SPT.
    false
}

// ---------------------------------------------------------------------------
// IfcStore — thread-safe per-user + global iFC store
// ---------------------------------------------------------------------------

/// Result of iFC evaluation — AS + metadata needed for ISC routing.
#[derive(Debug, Clone)]
pub struct MatchedApplicationServer {
    /// SIP URI of the Application Server.
    pub server_name: String,
    /// Default handling when AS is unreachable:
    /// 0 = SESSION_CONTINUED, 1 = SESSION_TERMINATED.
    pub default_handling: u32,
    /// Opaque service info passed to the AS.
    pub service_info: Option<String>,
    /// Priority (lower = evaluated first).
    pub priority: i32,
    /// Whether to include original REGISTER request body.
    pub include_register_request: bool,
    /// Whether to include original REGISTER response body.
    pub include_register_response: bool,
}

impl From<&InitialFilterCriteria> for MatchedApplicationServer {
    fn from(ifc: &InitialFilterCriteria) -> Self {
        Self {
            server_name: ifc.application_server.server_name.clone(),
            default_handling: ifc.default_handling,
            service_info: ifc.application_server.service_info.clone(),
            priority: ifc.priority,
            include_register_request: ifc.application_server.include_register_request,
            include_register_response: ifc.application_server.include_register_response,
        }
    }
}

// ---------------------------------------------------------------------------
// IfcBackendWriter — coalesced write-through of iFC profiles to Redis
// ---------------------------------------------------------------------------

mod writer;

#[cfg(test)]
pub(crate) use writer::spawn_ifc_writer;
#[cfg(feature = "redis-backend")]
#[allow(deprecated)]
pub use writer::{
    spawn_ifc_backend_writer, spawn_ifc_backend_writer_with_client,
    spawn_ifc_backend_writer_with_client_and_ttl, spawn_ifc_backend_writer_with_ttl,
};
pub use writer::{IfcBackendWriter, IfcWrite, DEFAULT_IFC_PROFILE_TTL_SECS};

/// Restore iFC profiles from Redis into an `IfcStore`.
///
/// Walks the keys with the given prefix by cursor `SCAN` (never `KEYS`, which
/// holds the server for the whole keyspace in one call), loads the raw XML,
/// parses it, and stores the parsed profiles in the store.
///
/// Returns `(profile_count, ifc_count)` — number of AoRs restored and total iFCs.
#[cfg(feature = "redis-backend")]
pub async fn restore_ifc_profiles(
    connection: &mut redis::aio::MultiplexedConnection,
    key_prefix: &str,
    store: &IfcStore,
) -> Result<(usize, usize), String> {
    use redis::AsyncCommands;

    let pattern = format!("{key_prefix}*");
    // A set, because SCAN may return a key more than once.
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(connection)
            .await
            .map_err(|error| format!("SCAN failed: {error}"))?;
        keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let mut profile_count = 0usize;
    let mut ifc_count = 0usize;

    for key in &keys {
        let xml: Option<String> = connection
            .get(key)
            .await
            .map_err(|error| format!("GET {key} failed: {error}"))?;

        if let Some(xml) = xml {
            let aor = key.strip_prefix(key_prefix).unwrap_or(key);
            match parse_user_profile(&xml) {
                Ok(profile) => {
                    ifc_count +=
                        profile.ifcs.len() + store.note_shared_ids(aor, profile.shared_ifc_set_ids);
                    profile_count += 1;
                    store.profiles.insert(aor.to_string(), profile.ifcs);
                    // Also store the raw XML for potential re-persistence.
                    store.raw_xml.insert(aor.to_string(), xml);
                }
                Err(error) => {
                    warn!(aor, %error, "skipping invalid iFC XML from Redis");
                }
            }
        }
    }

    Ok((profile_count, ifc_count))
}

// ---------------------------------------------------------------------------
// IfcStore — thread-safe per-user + global iFC store with optional persistence
// ---------------------------------------------------------------------------

/// Thread-safe store for per-user and global Initial Filter Criteria.
///
/// The S-CSCF stores per-user iFC profiles received from the HSS via Cx SAR,
/// and optionally a set of global/static iFCs loaded from config as a fallback.
///
/// Evaluation checks per-user profiles first, falling back to global rules.
///
/// When a backend writer is configured (via `set_backend_writer`), profile
/// changes are persisted to Redis asynchronously for crash recovery.
pub struct IfcStore {
    /// Per-user iFC profiles (AoR → parsed iFCs).
    profiles: DashMap<String, Vec<InitialFilterCriteria>>,
    /// The shared iFC sets each AoR's profile names, when it names any.
    shared_ids: DashMap<String, Vec<u32>>,
    /// Raw XML per AoR — kept for Redis persistence (we persist XML, not structs).
    raw_xml: DashMap<String, String>,
    /// Global/static iFCs from config (fallback when no per-user profile exists).
    global: Vec<InitialFilterCriteria>,
    /// The shared iFC sets provisioned at this S-CSCF (`isc.shared_ifc_sets`),
    /// by SharedIFCSetID. Replaced whole on a reload.
    shared_sets: RwLock<HashMap<u32, Vec<InitialFilterCriteria>>>,
    /// Optional backend writer for Redis persistence.
    backend_writer: OnceLock<IfcBackendWriter>,
}

impl IfcStore {
    /// Create a new store with optional global/static iFCs.
    pub fn new(global: Vec<InitialFilterCriteria>) -> Self {
        Self {
            profiles: DashMap::new(),
            shared_ids: DashMap::new(),
            raw_xml: DashMap::new(),
            global,
            shared_sets: RwLock::new(HashMap::new()),
            backend_writer: OnceLock::new(),
        }
    }

    /// Replace the shared iFC sets provisioned at this S-CSCF.
    pub fn set_shared_sets(&self, sets: HashMap<u32, Vec<InitialFilterCriteria>>) {
        match self.shared_sets.write() {
            Ok(mut current) => *current = sets,
            Err(poisoned) => *poisoned.into_inner() = sets,
        }
    }

    /// Whether any shared iFC set is provisioned: what the `SiFC` feature
    /// (TS 29.229 §7.1.1) the S-CSCF advertises on Cx depends on.
    pub fn has_shared_sets(&self) -> bool {
        self.read_shared_sets(|sets| !sets.is_empty())
    }

    /// The SharedIFCSetIDs the profile of `aor` names.
    pub fn shared_set_ids(&self, aor: &str) -> Vec<u32> {
        self.shared_ids
            .get(aor)
            .map(|ids| ids.clone())
            .unwrap_or_default()
    }

    fn read_shared_sets<T>(
        &self,
        read: impl FnOnce(&HashMap<u32, Vec<InitialFilterCriteria>>) -> T,
    ) -> T {
        match self.shared_sets.read() {
            Ok(sets) => read(&sets),
            Err(poisoned) => read(&poisoned.into_inner()),
        }
    }

    /// Record the shared iFC sets `aor`'s profile names, saying loudly which
    /// of them this S-CSCF does not have: dropping one silently would remove
    /// the subscriber's services. Returns how many iFCs the known ones hold.
    fn note_shared_ids(&self, aor: &str, ids: Vec<u32>) -> usize {
        let resolved = self.read_shared_sets(|sets| {
            ids.iter()
                .map(|id| match sets.get(id) {
                    Some(set) => set.len(),
                    None => {
                        warn!(
                            aor,
                            shared_ifc_set_id = id,
                            "iFC profile names a shared iFC set this S-CSCF has no local set for \
                             (isc.shared_ifc_sets); its services are not applied"
                        );
                        0
                    }
                })
                .sum()
        });
        if ids.is_empty() {
            self.shared_ids.remove(aor);
        } else {
            self.shared_ids.insert(aor.to_string(), ids);
        }
        resolved
    }

    /// Set the backend writer for Redis persistence.
    ///
    /// Must be called once at startup, before any user script runs.
    pub fn set_backend_writer(&self, writer: IfcBackendWriter) {
        let _ = self.backend_writer.set(writer);
    }

    /// Store a parsed iFC profile for an AoR (from Cx SAR user_data XML).
    ///
    /// Replaces any existing profile for that AoR.
    pub fn store_profile(&self, aor: &str, ifcs: Vec<InitialFilterCriteria>) {
        self.profiles.insert(aor.to_string(), ifcs);
    }

    /// Store raw iFC XML for an AoR — parses, stores, and persists to backend.
    ///
    /// Returns the number of iFCs the profile now applies: its own, and those
    /// of the shared iFC sets it names that this S-CSCF has. An error if the
    /// XML is invalid.
    pub fn store_profile_xml(&self, aor: &str, xml: &str) -> Result<usize, IfcError> {
        let profile = parse_user_profile(xml)?;
        let count = profile.ifcs.len() + self.note_shared_ids(aor, profile.shared_ifc_set_ids);
        self.profiles.insert(aor.to_string(), profile.ifcs);
        // The sequence is taken under the `raw_xml` entry (what is persisted),
        // so two stores of one AoR racing to the writer end as memory does.
        let sequence = {
            let _entry = self.raw_xml.entry(aor.to_string()).insert(xml.to_string());
            self.backend_writer.get().map(IfcBackendWriter::sequence)
        };

        // Persist to Redis (fire-and-forget).
        if let (Some(writer), Some(sequence)) = (self.backend_writer.get(), sequence) {
            writer.save_at(aor, xml, sequence);
        }

        Ok(count)
    }

    /// Remove the stored profile for an AoR.
    ///
    /// Returns `true` if a profile was actually removed.
    pub fn remove_profile(&self, aor: &str) -> bool {
        let removed = self.profiles.remove(aor).is_some();
        self.shared_ids.remove(aor);
        let sequence = match self.raw_xml.entry(aor.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                let sequence = self.backend_writer.get().map(IfcBackendWriter::sequence);
                entry.remove();
                sequence
            }
            dashmap::mapref::entry::Entry::Vacant(_vacant) => {
                self.backend_writer.get().map(IfcBackendWriter::sequence)
            }
        };

        // Remove from Redis (fire-and-forget).
        if removed {
            if let (Some(writer), Some(sequence)) = (self.backend_writer.get(), sequence) {
                writer.remove_at(aor, sequence);
            }
        }

        removed
    }

    /// Check whether a profile is stored for an AoR.
    pub fn has_profile(&self, aor: &str) -> bool {
        self.profiles.contains_key(aor)
    }

    /// Evaluate iFCs for a request, returning matching Application Servers.
    ///
    /// Checks per-user profile first; falls back to global rules if no
    /// per-user profile exists for the given AoR. A per-user profile's own
    /// iFCs and those of the shared iFC sets it names are merged by Priority.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        aor: &str,
        method: &str,
        request_uri: &str,
        headers: &[(String, String)],
        session_case: SessionCase,
        start_after_priority: Option<i32>,
        body: Option<&str>,
    ) -> Vec<MatchedApplicationServer> {
        let request = IfcRequest {
            method,
            request_uri,
            headers,
            session_case,
            body,
        };
        if let Some(user_ifcs) = self.profiles.get(aor) {
            let shared_ids = self.shared_ids.get(aor);
            self.read_shared_sets(|sets| {
                let shared = shared_ids
                    .iter()
                    .flat_map(|ids| ids.value().iter())
                    .filter_map(|id| sets.get(id))
                    .flatten();
                Self::evaluate_ifcs(
                    user_ifcs.iter().chain(shared),
                    &request,
                    start_after_priority,
                )
            })
        } else {
            Self::evaluate_ifcs(self.global.iter(), &request, start_after_priority)
        }
    }

    /// Number of stored per-user profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    fn evaluate_ifcs<'a>(
        ifcs: impl Iterator<Item = &'a InitialFilterCriteria>,
        request: &IfcRequest<'_>,
        start_after_priority: Option<i32>,
    ) -> Vec<MatchedApplicationServer> {
        let mut sorted: Vec<&InitialFilterCriteria> = ifcs.collect();
        // Stable: iFCs of equal Priority keep profile order, the profile's own
        // ahead of those of its shared sets.
        sorted.sort_by_key(|ifc| ifc.priority);

        sorted
            .into_iter()
            .filter(|ifc| {
                // Skip iFCs at or below the already-processed priority.
                if let Some(min) = start_after_priority {
                    if ifc.priority <= min {
                        return false;
                    }
                }
                matches_ifc(ifc, request)
            })
            .map(MatchedApplicationServer::from)
            .collect()
    }
}

/// Load the shared iFC sets `isc.shared_ifc_sets` names, each from its file
/// or its inline XML: `<InitialFilterCriteria>` elements in the TS 29.228
/// Annex E form, bare or inside any wrapper. A set that cannot be read, does
/// not parse or holds no iFC is left out, said at `error`; a set whose `file`
/// and `xml` are both missing too.
pub fn load_shared_ifc_sets(
    configured: &[crate::config::SharedIfcSetConfig],
) -> HashMap<u32, Vec<InitialFilterCriteria>> {
    let mut sets = HashMap::new();
    for set in configured {
        let xml = match (&set.file, &set.xml) {
            (Some(path), _) => match std::fs::read_to_string(path) {
                Ok(xml) => xml,
                Err(error) => {
                    tracing::error!(id = set.id, path, %error, "could not read the shared iFC set");
                    continue;
                }
            },
            (None, Some(xml)) => xml.clone(),
            (None, None) => {
                tracing::error!(id = set.id, "shared iFC set has neither file nor xml");
                continue;
            }
        };
        match parse_service_profile(&xml) {
            // A set exists to hold iFCs; one that parses to none is a file cut
            // short or the wrong file, not a set to apply.
            Ok(ifcs) if ifcs.is_empty() => {
                tracing::error!(id = set.id, "shared iFC set holds no InitialFilterCriteria");
            }
            Ok(ifcs) => {
                tracing::info!(id = set.id, count = ifcs.len(), "shared iFC set loaded");
                sets.insert(set.id, ifcs);
            }
            Err(error) => {
                tracing::error!(id = set.id, %error, "could not parse the shared iFC set");
            }
        }
    }
    sets
}

/// Reload the shared iFC sets on `SIGHUP`, for the life of the process. A set
/// that no longer loads keeps what it had, so a bad edit does not take a
/// subscriber's services away.
#[cfg(unix)]
pub fn spawn_shared_set_reloader(
    store: std::sync::Arc<IfcStore>,
    configured: Vec<crate::config::SharedIfcSetConfig>,
) {
    use tokio::signal::unix::{signal, SignalKind};

    if configured.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::error!(%error, "isc: failed to install the SIGHUP handler for shared iFC sets");
                return;
            }
        };
        while hangup.recv().await.is_some() {
            store.reload_shared_sets(&configured);
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_shared_set_reloader(
    _store: std::sync::Arc<IfcStore>,
    _configured: Vec<crate::config::SharedIfcSetConfig>,
) {
}

impl IfcStore {
    /// Read the shared iFC sets again: each that loads replaces its old self,
    /// each that does not keeps it.
    pub fn reload_shared_sets(&self, configured: &[crate::config::SharedIfcSetConfig]) {
        let loaded = load_shared_ifc_sets(configured);
        let mut merged = self.read_shared_sets(HashMap::clone);
        merged.retain(|id, _| configured.iter().any(|set| set.id == *id));
        merged.extend(loaded);
        self.set_shared_sets(merged);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod spec_tests;

#[cfg(all(test, feature = "redis-backend"))]
mod redis_tests;

#[cfg(test)]
mod writer_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn simple_ifc_xml() -> &'static str {
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mmtel@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        )
    }

    /// Entity references in element text survive the parse.
    ///
    /// An AS URI carries `&` as soon as it has two URI headers, and XML
    /// requires that be written `&amp;`. quick-xml delivers the reference as
    /// its own event between two text fragments, so a parser reading only
    /// `Event::Text` drops it and silently routes to a *different* AS.
    #[test]
    fn parse_resolves_entity_references_in_server_name() {
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>0</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as@example.com?P-A=1&amp;P-B=2&#38;P-C=3</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );
        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(
            ifcs[0].application_server.server_name, "sip:as@example.com?P-A=1&P-B=2&P-C=3",
            "named and numeric references must both resolve, and neither be dropped"
        );
    }

    #[test]
    fn parse_simple_ifc() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        assert_eq!(ifcs.len(), 1);

        let ifc = &ifcs[0];
        assert_eq!(ifc.priority, 0);
        assert_eq!(ifc.default_handling, 0);
        assert_eq!(ifc.application_server.server_name, "sip:mmtel@example.com");

        let trigger = ifc.trigger_point.as_ref().unwrap();
        assert!(trigger.condition_type_cnf);
        assert_eq!(trigger.service_point_triggers.len(), 1);

        let spt = &trigger.service_point_triggers[0];
        assert!(!spt.condition_negated);
        assert_eq!(spt.group, vec![0]);
        assert_eq!(spt.method.as_deref(), Some("INVITE"));
    }

    #[test]
    fn method_fast_path_set_for_simple_invite_ifc() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        let trigger = ifcs[0].trigger_point.as_ref().unwrap();
        assert_eq!(trigger.method_fast_path.as_deref(), Some("invite"));
    }

    #[test]
    fn method_fast_path_skips_non_matching_method_without_iter() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        // INVITE-only iFC: any non-INVITE request must early-return false.
        let matched = evaluate(
            "REGISTER",
            "sip:user@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(matched.is_empty());

        let matched = evaluate(
            "INVITE",
            "sip:user@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn method_fast_path_unset_for_negated_method() {
        let xml = concat!(
            "<?xml version=\"1.0\"?>\n",
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>1</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>REGISTER</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );
        let ifcs = parse_service_profile(xml).unwrap();
        let trigger = ifcs[0].trigger_point.as_ref().unwrap();
        // !REGISTER means "trigger on any method except REGISTER" — fast path
        // can't filter by method, so no shortcut.
        assert_eq!(trigger.method_fast_path, None);
    }

    #[test]
    fn parse_multiple_ifcs() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mmtel@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>1</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:voicemail@example.com</ServerName>\n",
            "      <DefaultHandling>1</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 2);
        assert_eq!(ifcs[0].priority, 0);
        assert_eq!(
            ifcs[0].application_server.server_name,
            "sip:mmtel@example.com"
        );
        assert_eq!(ifcs[1].priority, 1);
        assert_eq!(
            ifcs[1].application_server.server_name,
            "sip:voicemail@example.com"
        );
        assert_eq!(ifcs[1].default_handling, 1);
    }

    #[test]
    fn parse_ifc_no_trigger_point() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:always@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 1);
        assert!(ifcs[0].trigger_point.is_none());
        assert_eq!(
            ifcs[0].application_server.server_name,
            "sip:always@example.com"
        );
    }

    #[test]
    fn parse_ifc_with_header_condition() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SIPHeader>\n",
            "          <HeaderName>P-Asserted-Identity</HeaderName>\n",
            "          <Content>sip:.*@example\\.com</Content>\n",
            "        </SIPHeader>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:header-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        assert_eq!(ifcs.len(), 1);

        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        let (ref header_name, ref content) = spt.header.as_ref().unwrap();
        assert_eq!(header_name, "P-Asserted-Identity");
        assert_eq!(content.as_deref(), Some("sip:.*@example\\.com"));
    }

    #[test]
    fn parse_ifc_with_session_case() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SessionCase>1</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:term-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        assert_eq!(spt.session_case, Some(SessionCase::Terminating));
    }

    #[test]
    fn evaluate_method_match() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "sip:mmtel@example.com");
    }

    #[test]
    fn evaluate_method_no_match() {
        let ifcs = parse_service_profile(simple_ifc_xml()).unwrap();

        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_cnf_logic() {
        // CNF: AND of OR groups.
        // Group 0: Method=INVITE OR Method=UPDATE
        // Group 1: SessionCase=Originating
        // Both groups must pass.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>UPDATE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>1</Group>\n",
            "        <SessionCase>0</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:cnf-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE + Originating → match (group 0: INVITE matches, group 1: Originating matches)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // UPDATE + Originating → match (group 0: UPDATE matches, group 1: Originating matches)
        let results = evaluate(
            "UPDATE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // INVITE + Terminating → no match (group 1 fails)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Terminating,
            &ifcs,
        );
        assert!(results.is_empty());

        // REGISTER + Originating → no match (group 0 fails)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_dnf_logic() {
        // DNF: OR of AND groups.
        // Group 0: Method=INVITE (alone → must match INVITE)
        // Group 1: Method=REGISTER (alone → must match REGISTER)
        // Either group passing is sufficient.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>0</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>1</Group>\n",
            "        <Method>REGISTER</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:dnf-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE → match (group 0 passes)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // REGISTER → match (group 1 passes)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // OPTIONS → no match (neither group passes)
        let results = evaluate(
            "OPTIONS",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_condition_negated() {
        // Negated method match: NOT REGISTER → should match anything except REGISTER.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>1</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>REGISTER</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:neg-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // INVITE → match (NOT REGISTER is true)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // REGISTER → no match (NOT REGISTER is false)
        let results = evaluate(
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_negated_header_prevents_loop() {
        // TAS scenario: match INVITE only when X-TAS-Handled header is NOT present.
        // CNF with two SPTs in separate groups: Method=INVITE (group 0) AND
        // NOT Header=X-TAS-Handled (group 1).  CNF = AND of OR groups, so
        // both groups must pass.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "      <SPT>\n",
            "        <ConditionNegated>1</ConditionNegated>\n",
            "        <Group>1</Group>\n",
            "        <SIPHeader>\n",
            "          <Header>X-TAS-Handled</Header>\n",
            "        </SIPHeader>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:tas@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // First evaluation: INVITE without X-TAS-Handled → should match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[("From".into(), "sip:alice@example.com".into())],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(
            results.len(),
            1,
            "should match: INVITE without X-TAS-Handled"
        );

        // Second evaluation: INVITE with X-TAS-Handled → must NOT match (loop prevention)
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[
                ("From".into(), "sip:alice@example.com".into()),
                ("X-TAS-Handled".into(), "1".into()),
            ],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(
            results.is_empty(),
            "must not match: X-TAS-Handled present, negated condition should block"
        );
    }

    #[test]
    fn evaluate_no_trigger_always_matches() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:always@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Any method should match.
        for method in &["INVITE", "REGISTER", "OPTIONS", "BYE", "CANCEL"] {
            let results = evaluate(
                method,
                "sip:any@example.com",
                &[],
                SessionCase::Originating,
                &ifcs,
            );
            assert_eq!(results.len(), 1, "method {method} should match");
        }
    }

    #[test]
    fn evaluate_priority_ordering() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>10</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:low-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:high-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:mid-priority@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].server_name, "sip:high-priority@example.com");
        assert_eq!(results[1].server_name, "sip:mid-priority@example.com");
        assert_eq!(results[2].server_name, "sip:low-priority@example.com");
    }

    #[test]
    fn evaluate_session_case_originating() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SessionCase>0</SessionCase>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:orig-only@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Originating → match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // Terminating → no match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Terminating,
            &ifcs,
        );
        assert!(results.is_empty());

        // OriginatingUnregistered → no match
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::OriginatingUnregistered,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    /// Service profile with one iFC whose only SPT is the given
    /// `SessionCase` code.
    fn session_case_profile(code: u32) -> String {
        format!(
            concat!(
                "<ServiceProfile>\n",
                "  <InitialFilterCriteria>\n",
                "    <Priority>0</Priority>\n",
                "    <TriggerPoint>\n",
                "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
                "      <SPT>\n",
                "        <ConditionNegated>0</ConditionNegated>\n",
                "        <Group>0</Group>\n",
                "        <SessionCase>{}</SessionCase>\n",
                "      </SPT>\n",
                "    </TriggerPoint>\n",
                "    <ApplicationServer>\n",
                "      <ServerName>sip:as@example.com</ServerName>\n",
                "      <DefaultHandling>0</DefaultHandling>\n",
                "    </ApplicationServer>\n",
                "  </InitialFilterCriteria>\n",
                "</ServiceProfile>\n",
            ),
            code
        )
    }

    /// The session cases a profile carrying `code` matches, out of the four
    /// the engine evaluates.
    fn session_cases_matched_by(code: u32) -> Vec<SessionCase> {
        let ifcs = parse_service_profile(&session_case_profile(code)).unwrap();
        [
            SessionCase::Originating,
            SessionCase::Terminating,
            SessionCase::TerminatingUnregistered,
            SessionCase::OriginatingUnregistered,
        ]
        .into_iter()
        .filter(|case| !evaluate("INVITE", "sip:bob@example.com", &[], *case, &ifcs).is_empty())
        .collect()
    }

    // 3GPP TS 29.228 Annex E, tDirectionOfRequest: 0 originating
    // (registered), 1 TERMINATING_REGISTERED, 2 TERMINATING_UNREGISTERED,
    // 3 ORIGINATING_UNREGISTERED.
    #[test]
    fn session_case_code_2_is_terminating_unregistered() {
        let ifcs = parse_service_profile(&session_case_profile(2)).unwrap();
        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        assert_eq!(spt.session_case, Some(SessionCase::TerminatingUnregistered));
        assert_eq!(
            session_cases_matched_by(2),
            vec![SessionCase::TerminatingUnregistered]
        );
    }

    #[test]
    fn session_case_code_3_is_originating_unregistered() {
        let ifcs = parse_service_profile(&session_case_profile(3)).unwrap();
        let spt = &ifcs[0]
            .trigger_point
            .as_ref()
            .unwrap()
            .service_point_triggers[0];
        assert_eq!(spt.session_case, Some(SessionCase::OriginatingUnregistered));
        assert_eq!(
            session_cases_matched_by(3),
            vec![SessionCase::OriginatingUnregistered]
        );
    }

    #[test]
    fn session_case_codes_0_and_1_are_the_registered_cases() {
        assert_eq!(session_cases_matched_by(0), vec![SessionCase::Originating]);
        assert_eq!(session_cases_matched_by(1), vec![SessionCase::Terminating]);
    }

    #[test]
    fn session_case_display() {
        assert_eq!(SessionCase::Originating.to_string(), "Originating");
        assert_eq!(SessionCase::Terminating.to_string(), "Terminating");
        assert_eq!(
            SessionCase::OriginatingUnregistered.to_string(),
            "OriginatingUnregistered"
        );
        assert_eq!(
            SessionCase::TerminatingUnregistered.to_string(),
            "TerminatingUnregistered"
        );
    }

    #[test]
    fn evaluate_header_match_with_regex() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <SIPHeader>\n",
            "          <HeaderName>P-Asserted-Identity</HeaderName>\n",
            "          <Content>sip:.*@example\\.com</Content>\n",
            "        </SIPHeader>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:header-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        // Matching header value
        let headers = vec![(
            "P-Asserted-Identity".to_string(),
            "sip:alice@example.com".to_string(),
        )];
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &headers,
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        // Non-matching header value
        let headers = vec![(
            "P-Asserted-Identity".to_string(),
            "sip:alice@other.com".to_string(),
        )];
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &headers,
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());

        // Missing header entirely
        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn evaluate_request_uri_match() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <RequestURI>sip:.*@example\\.com</RequestURI>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:ruri-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();

        let results = evaluate(
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert_eq!(results.len(), 1);

        let results = evaluate(
            "INVITE",
            "sip:bob@other.com",
            &[],
            SessionCase::Originating,
            &ifcs,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn ifc_error_display() {
        let xml_err = IfcError::XmlParse("bad xml".into());
        assert!(xml_err.to_string().contains("bad xml"));

        let fmt_err = IfcError::InvalidFormat("missing field".into());
        assert!(fmt_err.to_string().contains("missing field"));
    }

    #[test]
    fn parse_ifc_missing_server_name() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let result = parse_service_profile(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ifc_missing_priority() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:test@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let result = parse_service_profile(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_service_info() {
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>0</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:info-as@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "      <ServiceInfo>mmtel;conference</ServiceInfo>\n",
            "      <Extension>\n",
            "        <IncludeRegisterRequest/>\n",
            "        <IncludeRegisterResponse/>\n",
            "      </Extension>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let ifcs = parse_service_profile(xml).unwrap();
        let app_server = &ifcs[0].application_server;
        assert_eq!(app_server.service_info.as_deref(), Some("mmtel;conference"));
        assert!(app_server.include_register_request);
        assert!(app_server.include_register_response);
    }

    // -----------------------------------------------------------------------
    // IfcStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_new_empty() {
        let store = IfcStore::new(vec![]);
        assert_eq!(store.profile_count(), 0);
        assert!(!store.has_profile("sip:alice@example.com"));
    }

    #[test]
    fn store_and_evaluate_per_user() {
        let store = IfcStore::new(vec![]);

        let xml = simple_ifc_xml();
        let count = store
            .store_profile_xml("sip:alice@example.com", xml)
            .unwrap();
        assert_eq!(count, 1);
        assert!(store.has_profile("sip:alice@example.com"));
        assert_eq!(store.profile_count(), 1);

        let results = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            None,
            None,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "sip:mmtel@example.com");
        assert_eq!(results[0].priority, 0);
        assert_eq!(results[0].default_handling, 0);
    }

    #[test]
    fn store_fallback_to_global() {
        let global_ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        let store = IfcStore::new(global_ifcs);

        // No per-user profile → should use global rules.
        let results = store.evaluate(
            "sip:unknown@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            None,
            None,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "sip:mmtel@example.com");
    }

    #[test]
    fn store_per_user_overrides_global() {
        let global_ifcs = parse_service_profile(simple_ifc_xml()).unwrap();
        let store = IfcStore::new(global_ifcs);

        // Store a different profile for alice.
        let custom_xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <TriggerPoint>\n",
            "      <ConditionTypeCNF>1</ConditionTypeCNF>\n",
            "      <SPT>\n",
            "        <ConditionNegated>0</ConditionNegated>\n",
            "        <Group>0</Group>\n",
            "        <Method>INVITE</Method>\n",
            "      </SPT>\n",
            "    </TriggerPoint>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:custom-as@alice.com</ServerName>\n",
            "      <DefaultHandling>1</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );
        store
            .store_profile_xml("sip:alice@example.com", custom_xml)
            .unwrap();

        let results = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            None,
            None,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server_name, "sip:custom-as@alice.com");
        assert_eq!(results[0].default_handling, 1);
        assert_eq!(results[0].priority, 5);
    }

    #[test]
    fn store_remove_profile() {
        let store = IfcStore::new(vec![]);

        store
            .store_profile_xml("sip:alice@example.com", simple_ifc_xml())
            .unwrap();
        assert!(store.has_profile("sip:alice@example.com"));

        assert!(store.remove_profile("sip:alice@example.com"));
        assert!(!store.has_profile("sip:alice@example.com"));

        // Removing non-existent profile returns false.
        assert!(!store.remove_profile("sip:alice@example.com"));
    }

    #[test]
    fn store_invalid_xml() {
        let store = IfcStore::new(vec![]);
        // Malformed XML that the parser cannot handle.
        let result = store.store_profile_xml("sip:alice@example.com", "<<<totally broken");
        assert!(result.is_err());
        assert!(!store.has_profile("sip:alice@example.com"));
    }

    #[test]
    fn store_empty_service_profile() {
        let store = IfcStore::new(vec![]);
        // Valid XML but no iFCs — should succeed with count 0.
        let result =
            store.store_profile_xml("sip:alice@example.com", "<ServiceProfile></ServiceProfile>");
        assert_eq!(result.unwrap(), 0);
        assert!(store.has_profile("sip:alice@example.com"));
    }

    #[test]
    fn store_evaluate_no_match() {
        let store = IfcStore::new(vec![]);
        store
            .store_profile_xml("sip:alice@example.com", simple_ifc_xml())
            .unwrap();

        // REGISTER doesn't match the INVITE-only trigger.
        let results = store.evaluate(
            "sip:alice@example.com",
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            None,
            None,
        );
        assert!(results.is_empty());
    }

    #[test]
    fn store_thread_safety() {
        let store = Arc::new(IfcStore::new(vec![]));
        let mut handles = vec![];

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let aor = format!("sip:user{}@example.com", i);
                store_clone
                    .store_profile_xml(&aor, simple_ifc_xml())
                    .unwrap();
                let results = store_clone.evaluate(
                    &aor,
                    "INVITE",
                    "sip:bob@example.com",
                    &[],
                    SessionCase::Originating,
                    None,
                    None,
                );
                assert_eq!(results.len(), 1);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(store.profile_count(), 10);
    }

    #[test]
    fn matched_application_server_from_ifc() {
        let ifcs = parse_service_profile(concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>3</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as@example.com</ServerName>\n",
            "      <DefaultHandling>1</DefaultHandling>\n",
            "      <ServiceInfo>mmtel</ServiceInfo>\n",
            "      <Extension>\n",
            "        <IncludeRegisterRequest/>\n",
            "      </Extension>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        ))
        .unwrap();

        let matched = MatchedApplicationServer::from(&ifcs[0]);
        assert_eq!(matched.server_name, "sip:as@example.com");
        assert_eq!(matched.default_handling, 1);
        assert_eq!(matched.service_info.as_deref(), Some("mmtel"));
        assert_eq!(matched.priority, 3);
        assert!(matched.include_register_request);
        assert!(!matched.include_register_response);
    }

    /// One ApplicationServer in the TS 29.228 Annex E shape: the include
    /// flags live under `ApplicationServer/Extension`.
    fn include_register_profile(extension_body: &str) -> String {
        format!(
            concat!(
                "<ServiceProfile>\n",
                "  <InitialFilterCriteria>\n",
                "    <Priority>0</Priority>\n",
                "    <ApplicationServer>\n",
                "      <ServerName>sip:as@example.com</ServerName>\n",
                "      <DefaultHandling>0</DefaultHandling>\n",
                "{}",
                "    </ApplicationServer>\n",
                "  </InitialFilterCriteria>\n",
                "</ServiceProfile>\n",
            ),
            extension_body
        )
    }

    fn include_flags(extension_body: &str) -> (bool, bool) {
        let ifcs = parse_service_profile(&include_register_profile(extension_body)).unwrap();
        let app_server = &ifcs[0].application_server;
        (
            app_server.include_register_request,
            app_server.include_register_response,
        )
    }

    #[test]
    fn include_register_request_empty_element_in_extension_is_true() {
        let flags = include_flags(concat!(
            "      <Extension>\n",
            "        <IncludeRegisterRequest/>\n",
            "      </Extension>\n",
        ));
        assert_eq!(flags, (true, false));
    }

    #[test]
    fn include_register_response_empty_element_in_extension_is_true() {
        let flags = include_flags(concat!(
            "      <Extension>\n",
            "        <IncludeRegisterResponse/>\n",
            "      </Extension>\n",
        ));
        assert_eq!(flags, (false, true));
    }

    #[test]
    fn include_register_both_empty_elements_are_true() {
        let flags = include_flags(concat!(
            "      <Extension>\n",
            "        <IncludeRegisterRequest/>\n",
            "        <IncludeRegisterResponse/>\n",
            "      </Extension>\n",
        ));
        assert_eq!(flags, (true, true));
    }

    #[test]
    fn include_register_absent_is_false() {
        assert_eq!(include_flags(""), (false, false));
        let flags = include_flags(concat!("      <Extension>\n", "      </Extension>\n"));
        assert_eq!(flags, (false, false));
    }

    #[test]
    fn include_register_start_end_empty_form_is_true() {
        let flags = include_flags(concat!(
            "      <Extension>\n",
            "        <IncludeRegisterRequest></IncludeRegisterRequest>\n",
            "        <IncludeRegisterResponse></IncludeRegisterResponse>\n",
            "      </Extension>\n",
        ));
        assert_eq!(flags, (true, true));
    }

    #[test]
    fn include_register_legacy_one_is_still_true() {
        let flags = include_flags(concat!(
            "      <IncludeRegisterRequest>1</IncludeRegisterRequest>\n",
            "      <IncludeRegisterResponse>true</IncludeRegisterResponse>\n",
        ));
        assert_eq!(flags, (true, true));
    }

    #[test]
    fn include_register_zero_and_false_are_false() {
        let flags = include_flags(concat!(
            "      <Extension>\n",
            "        <IncludeRegisterRequest>0</IncludeRegisterRequest>\n",
            "        <IncludeRegisterResponse>false</IncludeRegisterResponse>\n",
            "      </Extension>\n",
        ));
        assert_eq!(flags, (false, false));
    }

    #[test]
    fn include_register_empty_element_does_not_disturb_following_siblings() {
        let ifcs = parse_service_profile(concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>4</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as@example.com</ServerName>\n",
            "      <Extension><IncludeRegisterRequest/></Extension>\n",
            "      <ServiceInfo>after</ServiceInfo>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>5</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:other@example.com</ServerName>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        ))
        .unwrap();
        assert_eq!(ifcs.len(), 2);
        assert!(ifcs[0].application_server.include_register_request);
        assert_eq!(
            ifcs[0].application_server.service_info.as_deref(),
            Some("after")
        );
        assert!(!ifcs[1].application_server.include_register_request);
    }

    #[test]
    fn evaluate_start_after_priority_skips_processed() {
        // Simulate ISC chain: three ASes at priorities 10, 20, 30.
        // After AS at priority 10 processes and returns, re-evaluate
        // with start_after_priority=10 → only priorities 20 and 30.
        let xml = concat!(
            "<ServiceProfile>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>10</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as1@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>20</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as2@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "  <InitialFilterCriteria>\n",
            "    <Priority>30</Priority>\n",
            "    <ApplicationServer>\n",
            "      <ServerName>sip:as3@example.com</ServerName>\n",
            "      <DefaultHandling>0</DefaultHandling>\n",
            "    </ApplicationServer>\n",
            "  </InitialFilterCriteria>\n",
            "</ServiceProfile>\n",
        );

        let store = IfcStore::new(vec![]);
        store
            .store_profile_xml("sip:alice@example.com", xml)
            .unwrap();

        // Full evaluation: all three match
        let all = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            None,
            None,
        );
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].server_name, "sip:as1@example.com");

        // After AS1 (priority 10) returns: skip priority <= 10
        let remaining = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            Some(10),
            None,
        );
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].server_name, "sip:as2@example.com");
        assert_eq!(remaining[1].server_name, "sip:as3@example.com");

        // After AS2 (priority 20) returns: skip priority <= 20
        let remaining = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            Some(20),
            None,
        );
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].server_name, "sip:as3@example.com");

        // After AS3 (priority 30) returns: nothing left
        let remaining = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
            Some(30),
            None,
        );
        assert!(remaining.is_empty());
    }
}
