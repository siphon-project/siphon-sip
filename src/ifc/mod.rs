//! Initial Filter Criteria (iFC) evaluation engine.
//!
//! Implements 3GPP TS 29.228 §6.6 iFC XML parsing and evaluation.
//! Used by the S-CSCF to determine which Application Servers a SIP
//! request must be routed through, based on the subscriber's service
//! profile received from the HSS via Diameter Cx SAA.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

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
        let decoded = self.decode().map_err(|error| error.to_string())?;
        Ok(std::borrow::Cow::Owned(
            quick_xml::escape::unescape(&decoded)
                .map_err(|error| error.to_string())?
                .into_owned(),
        ))
    }
}
use tokio::sync::mpsc;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCase {
    /// Originating (request from registered user).
    Originating,
    /// Terminating (request to registered user).
    Terminating,
    /// Originating on behalf of unregistered user.
    OriginatingUnregistered,
    /// Terminating for unregistered user.
    TerminatingUnregistered,
}

impl SessionCase {
    /// Parse from the 3GPP integer encoding (TS 29.228).
    fn from_code(code: u32) -> Option<SessionCase> {
        match code {
            0 => Some(SessionCase::Originating),
            1 => Some(SessionCase::Terminating),
            2 => Some(SessionCase::OriginatingUnregistered),
            3 => Some(SessionCase::TerminatingUnregistered),
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
    /// Match on SDP line content: (sdp_line_type, optional_content_regex).
    pub sdp_line: Option<(String, Option<String>)>,
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
/// `<InitialFilterCriteria>` children.
pub fn parse_service_profile(xml: &str) -> Result<Vec<InitialFilterCriteria>, IfcError> {
    let mut reader = Reader::from_str(xml);

    let mut results: Vec<InitialFilterCriteria> = Vec::new();
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
                            trigger.condition_type_cnf = Some(text == "1" || text.eq_ignore_ascii_case("true"));
                        }
                    }

                    // --- SPT fields ---
                    "ConditionNegated" => {
                        if let Some(ref mut spt) = current_spt {
                            spt.condition_negated = text == "1" || text.eq_ignore_ascii_case("true");
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
                            if let Ok(code) = text.parse::<u32>() {
                                spt.session_case = SessionCase::from_code(code);
                            }
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
                    "SDPLine" => {
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
                            trigger.spts.push(spt.build());
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
                            app.include_register_request =
                                text == "1" || text.eq_ignore_ascii_case("true");
                        }
                    }
                    "IncludeRegisterResponse" => {
                        if let Some(ref mut app) = current_app_server {
                            app.include_register_response =
                                text == "1" || text.eq_ignore_ascii_case("true");
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
            Ok(Event::Text(element)) => {
                current_text.push_str(
                    &element
                        .unescape()
                        .map_err(|error| IfcError::XmlParse(error.to_string()))?
                );
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(IfcError::XmlParse(error.to_string())),
            _ => {}
        }
    }

    Ok(results)
}

/// Extract the local name (without namespace prefix) from a tag.
fn local_name(element: &quick_xml::events::BytesStart, _reader: &Reader<&[u8]>) -> String {
    let full = element.name();
    let local = full.local_name();
    String::from_utf8_lossy(local.as_ref()).to_string()
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
fn compute_method_fast_path(condition_type_cnf: bool, spts: &[ServicePointTrigger]) -> Option<String> {
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
                    spts.iter().filter(|other| other.group.contains(index)).count() == 1
                })
            };
            if group_alone {
                return spt.method.as_ref().map(|method| method.to_ascii_lowercase());
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
    let mut sorted: Vec<&InitialFilterCriteria> = ifcs.iter().collect();
    sorted.sort_by_key(|ifc| ifc.priority);

    sorted
        .into_iter()
        .filter(|ifc| matches_ifc(ifc, method, request_uri, headers, session_case))
        .map(|ifc| &ifc.application_server)
        .collect()
}

/// Check whether a single iFC matches the given request parameters.
fn matches_ifc(
    ifc: &InitialFilterCriteria,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    match &ifc.trigger_point {
        None => true, // No trigger point → always matches.
        Some(trigger) => evaluate_trigger_point(trigger, method, request_uri, headers, session_case),
    }
}

/// Evaluate a trigger point (CNF or DNF) against request parameters.
fn evaluate_trigger_point(
    trigger: &TriggerPoint,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    if trigger.service_point_triggers.is_empty() {
        return true;
    }

    // Method-match early return — for the overwhelmingly common iFC shape
    // ("trigger on INVITE", "trigger on REGISTER") this skips the SPT walk
    // and the HashMap allocation below for any non-matching method.
    if let Some(ref required) = trigger.method_fast_path {
        if !method.eq_ignore_ascii_case(required) {
            return false;
        }
    }

    // Single-SPT triggers don't need group bookkeeping — most iFCs in real
    // deployments are single-SPT method filters that survived the fast-path
    // guard above; eval them directly.
    if trigger.service_point_triggers.len() == 1 {
        return evaluate_spt(
            &trigger.service_point_triggers[0],
            method, request_uri, headers, session_case,
        );
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
        groups.values().all(|spts| {
            spts.iter()
                .any(|spt| evaluate_spt(spt, method, request_uri, headers, session_case))
        })
    } else {
        // DNF: OR of AND groups.
        // For each group, all SPTs must match. At least one group must pass.
        groups.values().any(|spts| {
            spts.iter()
                .all(|spt| evaluate_spt(spt, method, request_uri, headers, session_case))
        })
    }
}

/// Evaluate a single Service Point Trigger condition.
fn evaluate_spt(
    spt: &ServicePointTrigger,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    let raw_result = evaluate_spt_condition(spt, method, request_uri, headers, session_case);

    if spt.condition_negated {
        !raw_result
    } else {
        raw_result
    }
}

/// Evaluate the raw condition of an SPT (before negation).
fn evaluate_spt_condition(
    spt: &ServicePointTrigger,
    method: &str,
    request_uri: &str,
    headers: &[(String, String)],
    session_case: SessionCase,
) -> bool {
    // Method match.
    if let Some(ref expected_method) = spt.method {
        return method.eq_ignore_ascii_case(expected_method);
    }

    // Header match.
    if let Some((ref header_name, ref content_pattern)) = spt.header {
        let matching_headers: Vec<&str> = headers
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
            return regex.is_match(request_uri);
        }
        return request_uri.contains(uri_pattern.as_str());
    }

    // Session case match.
    if let Some(ref expected_case) = spt.session_case {
        return session_case == *expected_case;
    }

    // SDP line match (simplified — checks headers for Content-Type: application/sdp
    // and body content via headers list, since we don't have full body access here).
    if let Some((ref _line_type, ref _content_pattern)) = spt.sdp_line {
        // SDP matching requires body access which is not provided in the
        // evaluation interface. Return false for now; callers should
        // pre-filter or extend the API if SDP matching is needed.
        return false;
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
// IfcBackendWriter — fire-and-forget Redis persistence for iFC profiles
// ---------------------------------------------------------------------------

/// Commands sent to the iFC backend writer task.
enum IfcBackendCommand {
    Save { aor: String, xml: String },
    Remove { aor: String },
}

/// Handle for sending write-through commands to the iFC backend task.
///
/// Sends are fire-and-forget; failures are logged by the background task.
#[derive(Debug, Clone)]
pub struct IfcBackendWriter {
    sender: mpsc::UnboundedSender<IfcBackendCommand>,
}

impl IfcBackendWriter {
    /// Enqueue a save (raw XML for an AoR) to the backend.
    pub fn save(&self, aor: &str, xml: &str) {
        let _ = self.sender.send(IfcBackendCommand::Save {
            aor: aor.to_string(),
            xml: xml.to_string(),
        });
    }

    /// Enqueue a remove (iFC profile for an AoR) from the backend.
    pub fn remove(&self, aor: &str) {
        let _ = self.sender.send(IfcBackendCommand::Remove {
            aor: aor.to_string(),
        });
    }
}

/// Spawn the iFC backend writer task using a Redis connection.
///
/// Returns an [`IfcBackendWriter`] handle. The task runs until the sender
/// is dropped (i.e., until the `IfcStore` is dropped).
#[cfg(feature = "redis-backend")]
pub fn spawn_ifc_backend_writer(
    mut connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
) -> IfcBackendWriter {
    let (sender, mut receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        use redis::AsyncCommands;

        while let Some(command) = receiver.recv().await {
            match command {
                IfcBackendCommand::Save { aor, xml } => {
                    let key = format!("{key_prefix}{aor}");
                    let result: Result<(), redis::RedisError> =
                        connection.set(&key, xml.as_str()).await;
                    if let Err(error) = result {
                        warn!(aor, %error, "iFC backend write-through save failed");
                    }
                }
                IfcBackendCommand::Remove { aor } => {
                    let key = format!("{key_prefix}{aor}");
                    let result: Result<(), redis::RedisError> = connection.del(&key).await;
                    if let Err(error) = result {
                        warn!(aor, %error, "iFC backend write-through remove failed");
                    }
                }
            }
        }
    });

    IfcBackendWriter { sender }
}

/// Restore iFC profiles from Redis into an `IfcStore`.
///
/// Scans for all keys with the given prefix, loads the raw XML, parses it,
/// and stores the parsed profiles in the store.
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
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(&pattern)
        .query_async(connection)
        .await
        .map_err(|error| format!("KEYS scan failed: {error}"))?;

    let mut profile_count = 0usize;
    let mut ifc_count = 0usize;

    for key in &keys {
        let xml: Option<String> = connection.get(key).await.map_err(|error| {
            format!("GET {key} failed: {error}")
        })?;

        if let Some(xml) = xml {
            let aor = key.strip_prefix(key_prefix).unwrap_or(key);
            match parse_service_profile(&xml) {
                Ok(ifcs) => {
                    ifc_count += ifcs.len();
                    profile_count += 1;
                    store.profiles.insert(aor.to_string(), ifcs);
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
    /// Raw XML per AoR — kept for Redis persistence (we persist XML, not structs).
    raw_xml: DashMap<String, String>,
    /// Global/static iFCs from config (fallback when no per-user profile exists).
    global: Vec<InitialFilterCriteria>,
    /// Optional backend writer for Redis persistence.
    backend_writer: OnceLock<IfcBackendWriter>,
}

impl IfcStore {
    /// Create a new store with optional global/static iFCs.
    pub fn new(global: Vec<InitialFilterCriteria>) -> Self {
        Self {
            profiles: DashMap::new(),
            raw_xml: DashMap::new(),
            global,
            backend_writer: OnceLock::new(),
        }
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
    /// Returns the number of iFCs parsed, or an error if the XML is invalid.
    pub fn store_profile_xml(&self, aor: &str, xml: &str) -> Result<usize, IfcError> {
        let ifcs = parse_service_profile(xml)?;
        let count = ifcs.len();
        self.profiles.insert(aor.to_string(), ifcs);
        self.raw_xml.insert(aor.to_string(), xml.to_string());

        // Persist to Redis (fire-and-forget).
        if let Some(writer) = self.backend_writer.get() {
            writer.save(aor, xml);
        }

        Ok(count)
    }

    /// Remove the stored profile for an AoR.
    ///
    /// Returns `true` if a profile was actually removed.
    pub fn remove_profile(&self, aor: &str) -> bool {
        let removed = self.profiles.remove(aor).is_some();
        self.raw_xml.remove(aor);

        // Remove from Redis (fire-and-forget).
        if removed {
            if let Some(writer) = self.backend_writer.get() {
                writer.remove(aor);
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
    /// per-user profile exists for the given AoR.
    pub fn evaluate(
        &self,
        aor: &str,
        method: &str,
        request_uri: &str,
        headers: &[(String, String)],
        session_case: SessionCase,
        start_after_priority: Option<i32>,
    ) -> Vec<MatchedApplicationServer> {
        if let Some(user_ifcs) = self.profiles.get(aor) {
            Self::evaluate_ifcs(&user_ifcs, method, request_uri, headers, session_case, start_after_priority)
        } else {
            Self::evaluate_ifcs(&self.global, method, request_uri, headers, session_case, start_after_priority)
        }
    }

    /// Number of stored per-user profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    fn evaluate_ifcs(
        ifcs: &[InitialFilterCriteria],
        method: &str,
        request_uri: &str,
        headers: &[(String, String)],
        session_case: SessionCase,
        start_after_priority: Option<i32>,
    ) -> Vec<MatchedApplicationServer> {
        let mut sorted: Vec<&InitialFilterCriteria> = ifcs.iter().collect();
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
                matches_ifc(ifc, method, request_uri, headers, session_case)
            })
            .map(MatchedApplicationServer::from)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
            "REGISTER", "sip:user@example.com", &[],
            SessionCase::Originating, &ifcs,
        );
        assert!(matched.is_empty());

        let matched = evaluate(
            "INVITE", "sip:user@example.com", &[],
            SessionCase::Originating, &ifcs,
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
        assert_eq!(results.len(), 1, "should match: INVITE without X-TAS-Handled");

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
        assert!(results.is_empty(), "must not match: X-TAS-Handled present, negated condition should block");
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
            "      <IncludeRegisterRequest>1</IncludeRegisterRequest>\n",
            "      <IncludeRegisterResponse>1</IncludeRegisterResponse>\n",
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
        let count = store.store_profile_xml("sip:alice@example.com", xml).unwrap();
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
        store.store_profile_xml("sip:alice@example.com", custom_xml).unwrap();

        let results = store.evaluate(
            "sip:alice@example.com",
            "INVITE",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
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

        store.store_profile_xml("sip:alice@example.com", simple_ifc_xml()).unwrap();
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
        let result = store.store_profile_xml(
            "sip:alice@example.com",
            "<ServiceProfile></ServiceProfile>",
        );
        assert_eq!(result.unwrap(), 0);
        assert!(store.has_profile("sip:alice@example.com"));
    }

    #[test]
    fn store_evaluate_no_match() {
        let store = IfcStore::new(vec![]);
        store.store_profile_xml("sip:alice@example.com", simple_ifc_xml()).unwrap();

        // REGISTER doesn't match the INVITE-only trigger.
        let results = store.evaluate(
            "sip:alice@example.com",
            "REGISTER",
            "sip:bob@example.com",
            &[],
            SessionCase::Originating,
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
            "      <IncludeRegisterRequest>1</IncludeRegisterRequest>\n",
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
        store.store_profile_xml("sip:alice@example.com", xml).unwrap();

        // Full evaluation: all three match
        let all = store.evaluate(
            "sip:alice@example.com", "INVITE", "sip:bob@example.com",
            &[], SessionCase::Originating, None,
        );
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].server_name, "sip:as1@example.com");

        // After AS1 (priority 10) returns: skip priority <= 10
        let remaining = store.evaluate(
            "sip:alice@example.com", "INVITE", "sip:bob@example.com",
            &[], SessionCase::Originating, Some(10),
        );
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].server_name, "sip:as2@example.com");
        assert_eq!(remaining[1].server_name, "sip:as3@example.com");

        // After AS2 (priority 20) returns: skip priority <= 20
        let remaining = store.evaluate(
            "sip:alice@example.com", "INVITE", "sip:bob@example.com",
            &[], SessionCase::Originating, Some(20),
        );
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].server_name, "sip:as3@example.com");

        // After AS3 (priority 30) returns: nothing left
        let remaining = store.evaluate(
            "sip:alice@example.com", "INVITE", "sip:bob@example.com",
            &[], SessionCase::Originating, Some(30),
        );
        assert!(remaining.is_empty());
    }
}
