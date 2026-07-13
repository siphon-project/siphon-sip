//! Number-format policies and the identity-header walk.
//!
//! A [`NumberPolicy`] declares, per identity header, what E.164 shape the
//! number should end up in. [`apply`] walks those headers on a [`SipMessage`],
//! reformatting each dialable userpart in place and leaving everything else
//! (display names, tags, hosts, non-numbers) untouched. The same walk backs
//! both the proxy (`request.rewrite_identities`) and the B2BUA
//! (`call.rewrite_identities` / `call.dial(number_policy=…)`).
//!
//! # Two regimes
//!
//! - **The safe walk** — `From`, `To`, `P-Asserted-Identity`,
//!   `P-Preferred-Identity`, the Request-URI, and (opt-in) `Referred-By` /
//!   `Remote-Party-ID`. These carry a number in a plain userpart; the walk
//!   reformats it.
//! - **The diversion family** — `Diversion` (RFC 5806) and `History-Info`
//!   (RFC 7044). These are structured: multi-valued, ordered, indexed, and the
//!   History-Info URI embeds an escaped `cause`. They are handled by a
//!   separate, opt-in path ([`apply_diversion`]) that rewrites only the
//!   userpart of each entry and preserves index/reason/cause/ordering and
//!   privacy-restricted entries verbatim. Off unless a policy sets `diversion`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::numbers::{AssumeForm, Locale, Number, NumberFormat};
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::{SipMessage, StartLine};

// ---------------------------------------------------------------------------
// Identity headers
// ---------------------------------------------------------------------------

/// A single-URI identity header the safe walk can reformat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityHeader {
    /// The Request-URI on the start line.
    RequestUri,
    /// `To` (RFC 3261 §8.1.1.2).
    To,
    /// `From` (RFC 3261 §8.1.1.3).
    From,
    /// `P-Asserted-Identity` (RFC 3325).
    PAssertedIdentity,
    /// `P-Preferred-Identity` (RFC 3325).
    PPreferredIdentity,
    /// `Referred-By` (RFC 3892).
    ReferredBy,
    /// `Remote-Party-ID` (legacy pre-PAI).
    RemotePartyId,
}

impl IdentityHeader {
    /// On-the-wire header name (Request-URI has none — it is the start line).
    pub fn header_name(&self) -> Option<&'static str> {
        match self {
            IdentityHeader::RequestUri => None,
            IdentityHeader::To => Some("To"),
            IdentityHeader::From => Some("From"),
            IdentityHeader::PAssertedIdentity => Some("P-Asserted-Identity"),
            IdentityHeader::PPreferredIdentity => Some("P-Preferred-Identity"),
            IdentityHeader::ReferredBy => Some("Referred-By"),
            IdentityHeader::RemotePartyId => Some("Remote-Party-ID"),
        }
    }

    /// Whether an unparseable value in this header may be stripped. Mandatory
    /// headers (`From`, `To`) and the Request-URI are never removed — only the
    /// informational P-headers and legacy identity headers are strippable.
    pub fn is_strippable(&self) -> bool {
        matches!(
            self,
            IdentityHeader::PAssertedIdentity
                | IdentityHeader::PPreferredIdentity
                | IdentityHeader::ReferredBy
                | IdentityHeader::RemotePartyId
        )
    }

    /// Resolve a config/API header token to an [`IdentityHeader`].
    ///
    /// Accepts `request-uri` / `ruri` / `r-uri`, the header names (any case),
    /// and the `pai` / `ppi` shorthands.
    pub fn from_token(token: &str) -> Option<IdentityHeader> {
        match token.trim().to_ascii_lowercase().replace([' ', '_'], "-").as_str() {
            "request-uri" | "ruri" | "r-uri" | "uri" => Some(IdentityHeader::RequestUri),
            "to" => Some(IdentityHeader::To),
            "from" => Some(IdentityHeader::From),
            "p-asserted-identity" | "pai" => Some(IdentityHeader::PAssertedIdentity),
            "p-preferred-identity" | "ppi" => Some(IdentityHeader::PPreferredIdentity),
            "referred-by" => Some(IdentityHeader::ReferredBy),
            "remote-party-id" | "rpid" => Some(IdentityHeader::RemotePartyId),
            _ => None,
        }
    }
}

/// Default header set walked when a policy does not name one explicitly.
pub const DEFAULT_IDENTITY_HEADERS: &[IdentityHeader] = &[
    IdentityHeader::From,
    IdentityHeader::To,
    IdentityHeader::PAssertedIdentity,
    IdentityHeader::PPreferredIdentity,
    IdentityHeader::RequestUri,
];

/// A header in the diversion family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiversionHeader {
    /// `Diversion` (RFC 5806).
    Diversion,
    /// `History-Info` (RFC 7044).
    HistoryInfo,
}

impl DiversionHeader {
    pub fn header_name(&self) -> &'static str {
        match self {
            DiversionHeader::Diversion => "Diversion",
            DiversionHeader::HistoryInfo => "History-Info",
        }
    }

    pub fn from_token(token: &str) -> Option<DiversionHeader> {
        match token.trim().to_ascii_lowercase().as_str() {
            "diversion" => Some(DiversionHeader::Diversion),
            "history-info" | "history_info" | "historyinfo" => Some(DiversionHeader::HistoryInfo),
            _ => None,
        }
    }
}

/// What to do with an identity header whose userpart is not a dialable number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnparseableAction {
    /// Leave the header exactly as it arrived (default).
    #[default]
    Keep,
    /// Remove the header (strippable headers only; `From`/`To`/R-URI are always
    /// kept regardless).
    Strip,
}

// ---------------------------------------------------------------------------
// Runtime policy
// ---------------------------------------------------------------------------

/// Structured rewrite of the diversion family. Opt-in.
#[derive(Debug, Clone, PartialEq)]
pub struct DiversionPolicy {
    /// Target format for the diverting-party number in each entry.
    pub format: NumberFormat,
    /// Which diversion-family headers to walk.
    pub apply_to: Vec<DiversionHeader>,
    /// Skip entries marked privacy-restricted rather than reformatting them.
    pub respect_privacy: bool,
}

/// A resolved, ready-to-apply number policy.
#[derive(Debug, Clone, PartialEq)]
pub struct NumberPolicy {
    /// Qualified name (`"teams-outbound@2026"`) or `"(inline)"`.
    pub name: String,
    /// Home numbering plan used to parse and format.
    pub locale: Locale,
    /// Format applied to any walked header without an explicit per-header rule.
    pub default_format: NumberFormat,
    /// Per-header target format overrides.
    pub header_formats: HashMap<IdentityHeader, NumberFormat>,
    /// Headers walked, in order.
    pub headers: Vec<IdentityHeader>,
    /// What to do with an unparseable userpart.
    pub on_unparseable: UnparseableAction,
    /// Glob patterns (`0800*`, `*`) whose matching userparts are never touched.
    pub preserve_users: Vec<String>,
    /// Opt-in diversion-family handling.
    pub diversion: Option<DiversionPolicy>,
}

impl NumberPolicy {
    /// Build a simple policy that applies one format to a set of headers.
    ///
    /// Used for the inline (`request.rewrite_identities(format=…)`) case.
    pub fn uniform(
        locale: Locale,
        format: NumberFormat,
        headers: Vec<IdentityHeader>,
    ) -> Self {
        Self {
            name: "(inline)".to_string(),
            locale,
            default_format: format,
            header_formats: HashMap::new(),
            headers,
            on_unparseable: UnparseableAction::Keep,
            preserve_users: Vec::new(),
            diversion: None,
        }
    }

    /// Target format for a header — its per-header override, else the default.
    pub fn format_for(&self, header: IdentityHeader) -> NumberFormat {
        self.header_formats
            .get(&header)
            .copied()
            .unwrap_or(self.default_format)
    }
}

/// Counts from an [`apply`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewriteReport {
    /// Userparts reformatted.
    pub rewritten: usize,
    /// Userparts left as-is (preserved, non-number, or empty).
    pub skipped: usize,
    /// Headers/entries removed under [`UnparseableAction::Strip`].
    pub stripped: usize,
}

impl RewriteReport {
    /// Total headers/entries the pass changed (rewrote or stripped).
    pub fn changed(&self) -> usize {
        self.rewritten + self.stripped
    }
}

/// Outcome of reformatting a single userpart.
enum Outcome {
    /// Replace the userpart with this new value.
    Rewrite(String),
    /// Leave it (preserved by glob, empty, or intentionally untouched).
    Skip,
    /// Not a dialable number — caller decides keep vs strip.
    Unparseable,
}

fn glob_match(pattern: &str, subject: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        subject.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        subject.ends_with(suffix)
    } else {
        pattern == subject
    }
}

fn reformat(user: &str, target: NumberFormat, policy: &NumberPolicy) -> Outcome {
    if user.is_empty() {
        return Outcome::Skip;
    }
    if policy
        .preserve_users
        .iter()
        .any(|pattern| glob_match(pattern, user))
    {
        return Outcome::Skip;
    }
    match Number::parse(user, &policy.locale) {
        Ok(number) => Outcome::Rewrite(number.format(target)),
        Err(_) => Outcome::Unparseable,
    }
}

/// Apply a policy to a message, rewriting identity-header userparts in place.
///
/// Walks the Request-URI too — for the proxy path, where the R-URI is the
/// routing target that must be normalized.
pub fn apply(message: &mut SipMessage, policy: &NumberPolicy) -> RewriteReport {
    apply_inner(message, policy, true)
}

/// Like [`apply`] but skips the Request-URI. For the B2BUA `dial()` path, where
/// the outbound target is supplied as a separate argument (normalized via
/// [`reformat_target`]) and the message's own R-URI is the inbound A-leg one.
pub fn apply_headers_only(message: &mut SipMessage, policy: &NumberPolicy) -> RewriteReport {
    apply_inner(message, policy, false)
}

fn apply_inner(
    message: &mut SipMessage,
    policy: &NumberPolicy,
    include_request_uri: bool,
) -> RewriteReport {
    let mut report = RewriteReport::default();

    for header in &policy.headers {
        let target = policy.format_for(*header);
        match header {
            IdentityHeader::RequestUri => {
                if include_request_uri {
                    rewrite_request_uri(message, target, policy, &mut report);
                }
            }
            other => rewrite_nameaddr_header(message, *other, target, policy, &mut report),
        }
    }

    if let Some(diversion) = &policy.diversion {
        apply_diversion(message, diversion, policy, &mut report);
    }

    report
}

/// Reformat a standalone URI string's userpart under a policy — for the B2BUA
/// dial/fork target. Returns the (possibly unchanged) URI string; a non-number
/// or unparseable URI is returned verbatim.
pub fn reformat_target(uri: &str, target: NumberFormat, policy: &NumberPolicy) -> String {
    let Ok(mut parsed) = crate::sip::parser::parse_uri_standalone(uri) else {
        return uri.to_string();
    };
    let Some(user) = parsed.user.clone() else {
        return uri.to_string();
    };
    if let Outcome::Rewrite(new_user) = reformat(&user, target, policy) {
        parsed.user = Some(new_user);
        parsed.to_string()
    } else {
        uri.to_string()
    }
}

fn rewrite_request_uri(
    message: &mut SipMessage,
    target: NumberFormat,
    policy: &NumberPolicy,
    report: &mut RewriteReport,
) {
    let StartLine::Request(request_line) = &mut message.start_line else {
        return;
    };
    let Some(user) = request_line.request_uri.user.clone() else {
        return;
    };
    match reformat(&user, target, policy) {
        Outcome::Rewrite(value) => {
            request_line.request_uri.user = Some(value);
            report.rewritten += 1;
        }
        // The Request-URI is never stripped, even when unparseable.
        Outcome::Skip | Outcome::Unparseable => report.skipped += 1,
    }
}

fn rewrite_nameaddr_header(
    message: &mut SipMessage,
    header: IdentityHeader,
    target: NumberFormat,
    policy: &NumberPolicy,
    report: &mut RewriteReport,
) {
    let Some(name) = header.header_name() else {
        return;
    };
    let Some(values) = message.headers.get_all(name).cloned() else {
        return;
    };
    let strippable = header.is_strippable();

    let mut new_values: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        // A header line may carry several comma-separated name-addr values
        // (e.g. two P-Asserted-Identity URIs, tel + sip).
        let entries = match NameAddr::parse_multi(&value) {
            Ok(entries) if !entries.is_empty() => entries,
            // Unparseable header line, or wildcard/empty — keep verbatim.
            _ => {
                new_values.push(value);
                continue;
            }
        };

        let mut kept: Vec<String> = Vec::with_capacity(entries.len());
        for mut entry in entries {
            let user = entry.uri.user.clone().unwrap_or_default();
            match reformat(&user, target, policy) {
                Outcome::Rewrite(new_user) => {
                    entry.uri.user = Some(new_user);
                    report.rewritten += 1;
                    kept.push(entry.to_string());
                }
                Outcome::Skip => {
                    report.skipped += 1;
                    kept.push(entry.to_string());
                }
                Outcome::Unparseable => {
                    if strippable && policy.on_unparseable == UnparseableAction::Strip {
                        report.stripped += 1; // drop this entry
                    } else {
                        report.skipped += 1;
                        kept.push(entry.to_string());
                    }
                }
            }
        }

        if !kept.is_empty() {
            new_values.push(kept.join(", "));
        }
    }

    if new_values.is_empty() {
        // Every entry was stripped — remove the header entirely.
        message.headers.remove(name);
    } else {
        message.headers.set_all(name, new_values);
    }
}

// ---------------------------------------------------------------------------
// Diversion family (RFC 5806 / RFC 7044)
// ---------------------------------------------------------------------------

/// True when a diversion entry is marked privacy-restricted and must not be
/// normalized into a cleaner, more-leakable form.
///
/// Checks a `privacy` parameter on the entry (`;privacy=full`), on the URI, or
/// among the URI's embedded headers. A bare `privacy` with no value is treated
/// as restricted (conservative).
fn entry_privacy_restricted(entry: &NameAddr) -> bool {
    let restricted = |value: &Option<String>| match value {
        Some(v) => {
            let v = v.trim().to_ascii_lowercase();
            v != "off" && v != "none"
        }
        None => true,
    };
    entry
        .other_params
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("privacy") && restricted(value))
        || entry
            .uri
            .params
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("privacy") && restricted(value))
        || entry
            .uri
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("privacy") && restricted(value))
}

/// Rewrite the diverting-party number in each diversion-family entry, in place.
///
/// Only the userpart changes. `index`, `reason`, `counter`, the embedded
/// History-Info `cause`, entry ordering, and privacy-restricted entries are all
/// preserved verbatim. Diversion entries are never stripped.
pub fn apply_diversion(
    message: &mut SipMessage,
    diversion: &DiversionPolicy,
    policy: &NumberPolicy,
    report: &mut RewriteReport,
) {
    for header in &diversion.apply_to {
        let name = header.header_name();
        let Some(values) = message.headers.get_all(name).cloned() else {
            continue;
        };

        let mut new_values: Vec<String> = Vec::with_capacity(values.len());
        for value in values {
            let entries = match NameAddr::parse_multi(&value) {
                Ok(entries) if !entries.is_empty() => entries,
                // Keep an unparseable / empty line verbatim — never corrupt it.
                _ => {
                    new_values.push(value);
                    continue;
                }
            };

            let mut rebuilt: Vec<String> = Vec::with_capacity(entries.len());
            for mut entry in entries {
                if diversion.respect_privacy && entry_privacy_restricted(&entry) {
                    report.skipped += 1;
                    rebuilt.push(entry.to_string());
                    continue;
                }
                let user = entry.uri.user.clone().unwrap_or_default();
                match reformat(&user, diversion.format, policy) {
                    Outcome::Rewrite(new_user) => {
                        entry.uri.user = Some(new_user);
                        report.rewritten += 1;
                    }
                    // Diversion entries are informational history — never
                    // dropped, only rewritten when the number is dialable.
                    Outcome::Skip | Outcome::Unparseable => report.skipped += 1,
                }
                rebuilt.push(entry.to_string());
            }
            new_values.push(rebuilt.join(", "));
        }

        message.headers.set_all(name, new_values);
    }
}

// ---------------------------------------------------------------------------
// Config (serde) — the YAML shape, resolved into runtime policies at startup
// ---------------------------------------------------------------------------

/// `numbering:` — the home numbering plan.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumberingConfig {
    /// Home country calling code, digits only (e.g. `"31"`). May be written
    /// with a leading `+`, which is stripped.
    #[serde(default)]
    pub country_code: String,
    #[serde(default = "default_trunk_prefix")]
    pub trunk_prefix: String,
    #[serde(default = "default_international_prefix")]
    pub international_prefix: String,
    #[serde(default)]
    pub assume: AssumeForm,
    #[serde(default = "default_min_national_digits")]
    pub min_national_digits: usize,
}

fn default_trunk_prefix() -> String {
    "0".to_string()
}
fn default_international_prefix() -> String {
    "00".to_string()
}
fn default_min_national_digits() -> usize {
    5
}

impl Default for NumberingConfig {
    fn default() -> Self {
        Self {
            country_code: String::new(),
            trunk_prefix: default_trunk_prefix(),
            international_prefix: default_international_prefix(),
            assume: AssumeForm::default(),
            min_national_digits: default_min_national_digits(),
        }
    }
}

impl NumberingConfig {
    /// Build the runtime [`Locale`].
    pub fn locale(&self) -> Locale {
        Locale {
            country_code: self
                .country_code
                .trim()
                .strip_prefix('+')
                .unwrap_or(self.country_code.trim())
                .to_string(),
            trunk_prefix: self.trunk_prefix.clone(),
            international_prefix: self.international_prefix.clone(),
            assume: self.assume,
            min_national_digits: self.min_national_digits,
        }
    }
}

/// A single `number_policies:` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumberPolicyConfig {
    /// Fallback format for any walked header without an explicit rule.
    #[serde(default = "default_policy_format")]
    pub default: NumberFormat,
    /// Per-header format overrides, keyed by header token.
    #[serde(default)]
    pub headers: HashMap<String, NumberFormat>,
    /// Explicit walk set (header tokens). When absent, the default set plus any
    /// header named in `headers` is walked.
    #[serde(default)]
    pub walk: Option<Vec<String>>,
    #[serde(default)]
    pub on_unparseable: UnparseableAction,
    #[serde(default)]
    pub preserve_users: Vec<String>,
    #[serde(default)]
    pub diversion: Option<DiversionConfig>,
    // Optional per-policy locale overrides (multi-country edges).
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub trunk_prefix: Option<String>,
    #[serde(default)]
    pub international_prefix: Option<String>,
    #[serde(default)]
    pub assume: Option<AssumeForm>,
}

fn default_policy_format() -> NumberFormat {
    NumberFormat::E164
}

/// The `diversion:` sub-block of a policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiversionConfig {
    #[serde(default = "default_policy_format")]
    pub format: NumberFormat,
    #[serde(default)]
    pub apply_to: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub respect_privacy: bool,
}

fn default_true() -> bool {
    true
}

impl NumberPolicyConfig {
    /// Resolve into a runtime [`NumberPolicy`]. Unknown header tokens are
    /// dropped (the caller should have logged them); `warnings` collects them
    /// so startup can surface a single message.
    pub fn resolve(&self, name: &str, base: &Locale, warnings: &mut Vec<String>) -> NumberPolicy {
        let locale = self.locale(base);

        let mut header_formats: HashMap<IdentityHeader, NumberFormat> = HashMap::new();
        for (token, format) in &self.headers {
            match IdentityHeader::from_token(token) {
                Some(header) => {
                    header_formats.insert(header, *format);
                }
                None => warnings.push(format!("{name}: unknown identity header {token:?}")),
            }
        }

        let mut headers: Vec<IdentityHeader> = match &self.walk {
            Some(tokens) => {
                let mut walk = Vec::new();
                for token in tokens {
                    match IdentityHeader::from_token(token) {
                        Some(header) if !walk.contains(&header) => walk.push(header),
                        Some(_) => {}
                        None => warnings.push(format!("{name}: unknown walk header {token:?}")),
                    }
                }
                walk
            }
            None => DEFAULT_IDENTITY_HEADERS.to_vec(),
        };
        // Any header given an explicit format is implicitly walked.
        for header in header_formats.keys() {
            if !headers.contains(header) {
                headers.push(*header);
            }
        }

        NumberPolicy {
            name: name.to_string(),
            locale,
            default_format: self.default,
            header_formats,
            headers,
            on_unparseable: self.on_unparseable,
            preserve_users: self.preserve_users.clone(),
            diversion: self.diversion.as_ref().map(|d| d.resolve(name, warnings)),
        }
    }

    fn locale(&self, base: &Locale) -> Locale {
        let mut locale = base.clone();
        if let Some(country_code) = &self.country_code {
            locale.country_code = country_code
                .trim()
                .strip_prefix('+')
                .unwrap_or(country_code.trim())
                .to_string();
        }
        if let Some(trunk_prefix) = &self.trunk_prefix {
            locale.trunk_prefix = trunk_prefix.clone();
        }
        if let Some(international_prefix) = &self.international_prefix {
            locale.international_prefix = international_prefix.clone();
        }
        if let Some(assume) = self.assume {
            locale.assume = assume;
        }
        locale
    }
}

impl DiversionConfig {
    fn resolve(&self, name: &str, warnings: &mut Vec<String>) -> DiversionPolicy {
        let apply_to = match &self.apply_to {
            Some(tokens) => {
                let mut headers = Vec::new();
                for token in tokens {
                    match DiversionHeader::from_token(token) {
                        Some(header) if !headers.contains(&header) => headers.push(header),
                        Some(_) => {}
                        None => {
                            warnings.push(format!("{name}: unknown diversion header {token:?}"))
                        }
                    }
                }
                headers
            }
            None => vec![DiversionHeader::Diversion, DiversionHeader::HistoryInfo],
        };
        DiversionPolicy {
            format: self.format,
            apply_to,
            respect_privacy: self.respect_privacy,
        }
    }
}

/// Resolved registry of named policies plus the default home locale, built once
/// at startup and shared read-only with the proxy and B2BUA paths.
#[derive(Debug, Clone, Default)]
pub struct NumberRegistry {
    pub default_locale: Locale,
    pub policies: HashMap<String, std::sync::Arc<NumberPolicy>>,
}

impl NumberRegistry {
    /// Build from the parsed config, returning any resolution warnings.
    pub fn build(
        numbering: &NumberingConfig,
        policies: &HashMap<String, NumberPolicyConfig>,
    ) -> (Self, Vec<String>) {
        let default_locale = numbering.locale();
        let mut warnings = Vec::new();
        let mut resolved = HashMap::new();
        for (name, config) in policies {
            let policy = config.resolve(name, &default_locale, &mut warnings);
            resolved.insert(name.clone(), std::sync::Arc::new(policy));
        }
        (
            Self {
                default_locale,
                policies: resolved,
            },
            warnings,
        )
    }

    pub fn get(&self, name: &str) -> Option<std::sync::Arc<NumberPolicy>> {
        self.policies.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message_bytes;

    fn nl_locale() -> Locale {
        Locale {
            country_code: "31".to_string(),
            trunk_prefix: "0".to_string(),
            international_prefix: "00".to_string(),
            assume: AssumeForm::National,
            min_national_digits: 5,
        }
    }

    fn parse(raw: &str) -> SipMessage {
        parse_sip_message_bytes(raw.as_bytes()).expect("valid SIP message")
    }

    fn e164_policy(headers: Vec<IdentityHeader>) -> NumberPolicy {
        NumberPolicy::uniform(nl_locale(), NumberFormat::E164, headers)
    }

    #[test]
    fn rewrites_from_to_and_ruri_to_e164() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc.example.com;branch=z9hG4bK1\r\n",
            "From: \"Alice\" <sip:0612345678@example.com>;tag=abc\r\n",
            "To: <sip:0201234567@example.com>\r\n",
            "Call-ID: call-1@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = e164_policy(vec![
            IdentityHeader::From,
            IdentityHeader::To,
            IdentityHeader::RequestUri,
        ]);
        let report = apply(&mut message, &policy);

        assert_eq!(report.rewritten, 3);
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("+31201234567")
        );
        let from = message.headers.from().unwrap();
        assert!(from.contains("+31612345678"), "from was {from}");
        // Display name and tag preserved.
        assert!(from.contains("\"Alice\""), "from was {from}");
        assert!(from.contains("tag=abc"), "from was {from}");
        let to = message.headers.to().unwrap();
        assert!(to.contains("+31201234567"), "to was {to}");
    }

    #[test]
    fn national_to_plain_headline_case() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "To: <sip:0201234567@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = NumberPolicy::uniform(
            nl_locale(),
            NumberFormat::Plain,
            vec![IdentityHeader::From, IdentityHeader::RequestUri],
        );
        apply(&mut message, &policy);
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("31201234567")
        );
        assert!(message.headers.from().unwrap().contains("31612345678"));
    }

    #[test]
    fn per_header_format_overrides() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "P-Asserted-Identity: <sip:0612345678@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let mut header_formats = HashMap::new();
        header_formats.insert(IdentityHeader::RequestUri, NumberFormat::National);
        header_formats.insert(IdentityHeader::PAssertedIdentity, NumberFormat::E164);
        let policy = NumberPolicy {
            name: "mixed".to_string(),
            locale: nl_locale(),
            default_format: NumberFormat::International,
            header_formats,
            headers: vec![
                IdentityHeader::RequestUri,
                IdentityHeader::From,
                IdentityHeader::PAssertedIdentity,
            ],
            on_unparseable: UnparseableAction::Keep,
            preserve_users: Vec::new(),
            diversion: None,
        };
        apply(&mut message, &policy);
        // R-URI national, From uses default (international 00), PAI e164.
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("0201234567")
        );
        assert!(message.headers.from().unwrap().contains("0031612345678"));
        assert!(message
            .headers
            .get("P-Asserted-Identity")
            .unwrap()
            .contains("+31612345678"));
    }

    #[test]
    fn non_number_user_is_left_untouched() {
        let raw = concat!(
            "INVITE sip:alice@example.com SIP/2.0\r\n",
            "From: \"Alice\" <sip:alice@example.com>;tag=x\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = e164_policy(vec![
            IdentityHeader::From,
            IdentityHeader::To,
            IdentityHeader::RequestUri,
        ]);
        let report = apply(&mut message, &policy);
        assert_eq!(report.rewritten, 0);
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("alice")
        );
        assert!(message.headers.from().unwrap().contains("alice"));
    }

    #[test]
    fn preserve_user_glob_skips_service_code() {
        let raw = concat!(
            "INVITE sip:0800123@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let mut policy = e164_policy(vec![IdentityHeader::RequestUri, IdentityHeader::From]);
        policy.preserve_users = vec!["0800*".to_string()];
        apply(&mut message, &policy);
        // R-URI preserved (0800 service code), From still rewritten.
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("0800123")
        );
        assert!(message.headers.from().unwrap().contains("+31612345678"));
    }

    #[test]
    fn strip_removes_unparseable_pai_but_keeps_from() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "From: <sip:alice@example.com>;tag=x\r\n",
            "P-Asserted-Identity: <sip:alice@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let mut policy = e164_policy(vec![
            IdentityHeader::From,
            IdentityHeader::PAssertedIdentity,
        ]);
        policy.on_unparseable = UnparseableAction::Strip;
        let report = apply(&mut message, &policy);
        // PAI (alice, not a number) stripped; From (mandatory) kept.
        assert!(!message.headers.has("P-Asserted-Identity"));
        assert!(message.headers.has("From"));
        assert_eq!(report.stripped, 1);
    }

    #[test]
    fn multi_value_pai_tel_and_sip() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "P-Asserted-Identity: <tel:0612345678>, <sip:0612345678@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = e164_policy(vec![IdentityHeader::PAssertedIdentity]);
        apply(&mut message, &policy);
        let pai = message.headers.get("P-Asserted-Identity").unwrap();
        // Both entries rewritten, tel scheme preserved.
        assert!(pai.contains("tel:+31612345678"), "pai was {pai}");
        assert!(pai.contains("sip:+31612345678@example.com"), "pai was {pai}");
    }

    // ---- Diversion family --------------------------------------------------

    fn diversion_policy(format: NumberFormat) -> NumberPolicy {
        NumberPolicy {
            name: "div".to_string(),
            locale: nl_locale(),
            default_format: format,
            header_formats: HashMap::new(),
            headers: Vec::new(), // safe walk empty; only diversion runs
            on_unparseable: UnparseableAction::Keep,
            preserve_users: Vec::new(),
            diversion: Some(DiversionPolicy {
                format,
                apply_to: vec![DiversionHeader::Diversion, DiversionHeader::HistoryInfo],
                respect_privacy: true,
            }),
        }
    }

    #[test]
    fn diversion_rewrites_number_keeps_reason_and_counter() {
        let raw = concat!(
            "INVITE sip:0301234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "Diversion: <sip:0201234567@example.com>;reason=unconditional;counter=1\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = diversion_policy(NumberFormat::E164);
        apply(&mut message, &policy);
        let diversion = message.headers.get("Diversion").unwrap();
        assert!(diversion.contains("+31201234567"), "diversion was {diversion}");
        assert!(diversion.contains("reason=unconditional"), "was {diversion}");
        assert!(diversion.contains("counter=1"), "was {diversion}");
    }

    #[test]
    fn history_info_preserves_escaped_cause_and_index() {
        // The critical round-trip: the escaped `cause` embedded in the URI and
        // the `index` param must survive a userpart rewrite untouched.
        let raw = concat!(
            "INVITE sip:0301234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "History-Info: <sip:0201234567@example.com?Reason=SIP%3Bcause%3D302>;index=1\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = diversion_policy(NumberFormat::E164);
        apply(&mut message, &policy);
        let history = message.headers.get("History-Info").unwrap();
        assert!(history.contains("+31201234567"), "history was {history}");
        assert!(
            history.contains("Reason=SIP%3Bcause%3D302"),
            "escaped cause lost: {history}"
        );
        assert!(history.contains("index=1"), "index lost: {history}");
    }

    #[test]
    fn history_info_index_tree_order_preserved() {
        let raw = concat!(
            "INVITE sip:0301234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "History-Info: <sip:0201234567@example.com>;index=1, ",
            "<sip:0612345678@example.com>;index=1.1\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = diversion_policy(NumberFormat::E164);
        apply(&mut message, &policy);
        let history = message.headers.get("History-Info").unwrap();
        let first = history.find("index=1").unwrap();
        let second = history.find("index=1.1").unwrap();
        assert!(first < second, "index order changed: {history}");
        assert!(history.contains("+31201234567"));
        assert!(history.contains("+31612345678"));
    }

    #[test]
    fn diversion_privacy_restricted_entry_is_skipped() {
        let raw = concat!(
            "INVITE sip:0301234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "Diversion: <sip:0201234567@example.com>;reason=unconditional;privacy=full\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = diversion_policy(NumberFormat::E164);
        let report = apply(&mut message, &policy);
        let diversion = message.headers.get("Diversion").unwrap();
        // Privacy-restricted diverting identity NOT normalized.
        assert!(diversion.contains("0201234567"), "was {diversion}");
        assert!(!diversion.contains("+31201234567"), "leaked: {diversion}");
        assert_eq!(report.rewritten, 0);
    }

    #[test]
    fn diversion_off_by_default() {
        let raw = concat!(
            "INVITE sip:0301234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "Diversion: <sip:0201234567@example.com>;reason=unconditional\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        // Safe-walk-only policy (no diversion): Diversion header untouched.
        let policy = e164_policy(vec![IdentityHeader::From]);
        apply(&mut message, &policy);
        assert!(message
            .headers
            .get("Diversion")
            .unwrap()
            .contains("0201234567"));
    }

    // ---- Config resolution -------------------------------------------------

    #[test]
    fn config_resolves_headers_and_walk() {
        let yaml = r#"
default: e164
headers:
  request-uri: national
  P-Asserted-Identity: e164
on_unparseable: strip
preserve_users:
  - "0800*"
"#;
        let config: NumberPolicyConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let mut warnings = Vec::new();
        let policy = config.resolve("test@2026", &nl_locale(), &mut warnings);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(policy.default_format, NumberFormat::E164);
        assert_eq!(
            policy.header_formats.get(&IdentityHeader::RequestUri),
            Some(&NumberFormat::National)
        );
        assert_eq!(policy.on_unparseable, UnparseableAction::Strip);
        // Default walk set plus the explicitly-formatted headers.
        assert!(policy.headers.contains(&IdentityHeader::RequestUri));
        assert!(policy.headers.contains(&IdentityHeader::PAssertedIdentity));
    }

    #[test]
    fn config_unknown_header_token_warns_not_panics() {
        let yaml = r#"
default: e164
headers:
  Bogus-Header: e164
"#;
        let config: NumberPolicyConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let mut warnings = Vec::new();
        let policy = config.resolve("test@2026", &nl_locale(), &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(policy.header_formats.is_empty());
    }

    #[test]
    fn config_per_policy_locale_override() {
        let yaml = r#"
default: national
country_code: "44"
"#;
        let config: NumberPolicyConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let mut warnings = Vec::new();
        let policy = config.resolve("uk@2026", &nl_locale(), &mut warnings);
        assert_eq!(policy.locale.country_code, "44");
        // A +44 number now nationalises under the overridden locale.
        let number = Number::parse("+441614960000", &policy.locale).unwrap();
        assert_eq!(number.format(NumberFormat::National), "01614960000");
    }

    #[test]
    fn reformat_target_normalizes_dial_uri() {
        let policy = e164_policy(vec![IdentityHeader::RequestUri]);
        assert_eq!(
            reformat_target("sip:0201234567@ims.example.com", NumberFormat::E164, &policy),
            "sip:+31201234567@ims.example.com"
        );
        // Non-number target returned verbatim.
        assert_eq!(
            reformat_target("sip:alice@ims.example.com", NumberFormat::E164, &policy),
            "sip:alice@ims.example.com"
        );
    }

    #[test]
    fn apply_headers_only_leaves_request_uri() {
        let raw = concat!(
            "INVITE sip:0201234567@example.com SIP/2.0\r\n",
            "From: <sip:0612345678@example.com>;tag=x\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let mut message = parse(raw);
        let policy = e164_policy(vec![IdentityHeader::From, IdentityHeader::RequestUri]);
        apply_headers_only(&mut message, &policy);
        // From rewritten, A-leg R-URI untouched (B-leg target handled separately).
        assert!(message.headers.from().unwrap().contains("+31612345678"));
        assert_eq!(
            message.request_uri().unwrap().user.as_deref(),
            Some("0201234567")
        );
    }

    #[test]
    fn registry_build_from_config() {
        let numbering = NumberingConfig {
            country_code: "31".to_string(),
            ..Default::default()
        };
        let mut policies = HashMap::new();
        let config: NumberPolicyConfig =
            serde_yaml_ng::from_str("default: e164\n").unwrap();
        policies.insert("teams-outbound@2026".to_string(), config);
        let (registry, warnings) = NumberRegistry::build(&numbering, &policies);
        assert!(warnings.is_empty());
        assert_eq!(registry.default_locale.country_code, "31");
        assert!(registry.get("teams-outbound@2026").is_some());
        assert!(registry.get("nope").is_none());
    }
}
