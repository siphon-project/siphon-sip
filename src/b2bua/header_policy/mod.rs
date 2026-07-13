//! B2BUA header-policy engine.
//!
//! A B2BUA, by definition, terminates a SIP dialog on one leg and originates
//! a new one on the other.  The two legs are independent dialogs with their
//! own Via, Call-ID, CSeq, From/To-tag, Contact, Record-Route, and Route
//! sets — that part is always handled by the framework and is not
//! policy-managed.
//!
//! Everything else — `Allow`, `Supported`, `Require`, `P-Asserted-Identity`,
//! `Alert-Info`, `Diversion`, `User-Agent`, `X-*`, vendor headers — sits in
//! "what should cross the trust boundary" territory and is policy-managed.
//!
//! Scripts pick a versioned preset at `call.dial(header_policy="…")` time,
//! optionally layered with per-call `copy=` / `strip=` / `translate=` deltas.
//! The preset library defines the four canonical postures
//! (`transparent-b2bua@2026`, `ims-intra-trust-domain@2026`,
//! `ims-trust-domain-boundary@2026`, `sip-trunk-edge@2026`).
//!
//! The engine is pure-functional: `apply_to_request` and `apply_to_response`
//! operate on a [`SipMessage`] in place given a [`ResolvedPolicy`] and a
//! [`PolicyContext`].  Both are cheap to construct in tests.

use std::collections::HashMap;
use std::sync::Arc;

use crate::sip::message::SipMessage;

// ---------------------------------------------------------------------------
// Verbs
// ---------------------------------------------------------------------------

/// What to do with a header during the A→B (request) or B→A (response) copy.
#[derive(Debug, Clone, PartialEq)]
pub enum Verb {
    /// Pass the header from inbound to outbound verbatim.
    Copy,
    /// Drop the header.
    Strip,
    /// Pass the header but with field-level edits.
    Rewrite(RewriteOp),
    /// Replace the header with a different header per a named transform.
    Translate(TranslateOp),
}

/// Field-level edit operations for the [`Verb::Rewrite`] verb.
#[derive(Debug, Clone, PartialEq)]
pub enum RewriteOp {
    /// Rewrite the host portion of a URI-bearing header to the B2BUA's
    /// advertised address — topology hiding for `P-Asserted-Identity` and
    /// similar.  Reuses [`crate::b2bua::actor::rewrite_uri_host`].
    HostToAdvertised,
    /// Replace the header value with [`PolicyContext::server_header`] — for
    /// the response-side `Server` topology-hiding rewrite.  No-op when
    /// `server_header` is unset.
    ReplaceWithServerHeader,
    /// Replace the header value with [`PolicyContext::user_agent_header`] —
    /// for the request-side `User-Agent` topology-hiding rewrite.  No-op
    /// when `user_agent_header` is unset.
    ReplaceWithUserAgentHeader,
}

/// Named cross-header transforms for the [`Verb::Translate`] verb.
#[derive(Debug, Clone, PartialEq)]
pub enum TranslateOp {
    /// Translate `Diversion` (RFC 5806) into `History-Info` (RFC 7044).
    /// Single-divert minimal mapping; full RFC 7044 chained-index carriage
    /// is out of scope for v1.
    DiversionToHistoryInfo,
}

// ---------------------------------------------------------------------------
// Header pattern matching
// ---------------------------------------------------------------------------

/// Match expression for a header name pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderPattern {
    /// Exact name match (case-insensitive).
    Exact(String),
    /// Prefix match (case-insensitive).  `Prefix("P-")` matches every header
    /// whose name starts with `P-` (or `p-`).  Used for `P-*` / `X-*`
    /// defensive strips.
    Prefix(String),
}

impl HeaderPattern {
    pub fn matches(&self, header_name: &str) -> bool {
        match self {
            HeaderPattern::Exact(name) => name.eq_ignore_ascii_case(header_name),
            HeaderPattern::Prefix(prefix) => {
                header_name.len() >= prefix.len()
                    && header_name[..prefix.len()].eq_ignore_ascii_case(prefix)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Direction policy + Preset
// ---------------------------------------------------------------------------

/// Policy for one direction (request or response).  The first matching
/// override wins; if nothing matches, `default` applies.
#[derive(Debug, Clone)]
pub struct DirectionPolicy {
    pub default: Verb,
    pub overrides: Vec<(HeaderPattern, Verb)>,
}

impl DirectionPolicy {
    pub fn verb_for(&self, header_name: &str) -> &Verb {
        for (pattern, verb) in &self.overrides {
            if pattern.matches(header_name) {
                return verb;
            }
        }
        &self.default
    }
}

/// A named, versioned header policy preset.
///
/// The qualified name is `"{name}@{version}"` and is the string scripts pass
/// to `call.dial(header_policy=…)`.  Versioning is mandatory — operator code
/// pins a specific version so siphon upgrades don't silently change the set
/// of headers crossing a trust boundary.
#[derive(Debug, Clone)]
pub struct Preset {
    pub name: String,
    pub version: String,
    pub request: DirectionPolicy,
    pub response: DirectionPolicy,
}

impl Preset {
    pub fn qualified_name(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

// ---------------------------------------------------------------------------
// Per-call resolved policy (preset + dial-time deltas)
// ---------------------------------------------------------------------------

/// The policy attached to a single B2BUA call at `dial()` time.  Combines a
/// chosen [`Preset`] with per-call deltas (the `copy=` / `strip=` /
/// `translate=` kwargs on [`Call.dial`](crate::script::api::call)).
///
/// Precedence (highest first) inside [`Self::verb_for_request`] /
/// [`Self::verb_for_response`]:
/// 1. delta strip (always wins over copy and translate)
/// 2. delta copy
/// 3. delta translate
/// 4. preset override
/// 5. preset default
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub preset: Arc<Preset>,
    pub deltas_copy: Vec<String>,
    pub deltas_strip: Vec<String>,
    pub deltas_translate: Vec<(String, TranslateOp)>,
}

impl ResolvedPolicy {
    pub fn from_preset(preset: Arc<Preset>) -> Self {
        Self {
            preset,
            deltas_copy: Vec::new(),
            deltas_strip: Vec::new(),
            deltas_translate: Vec::new(),
        }
    }

    fn delta_verb(&self, header_name: &str) -> Option<Verb> {
        for h in &self.deltas_strip {
            if h.eq_ignore_ascii_case(header_name) {
                return Some(Verb::Strip);
            }
        }
        for h in &self.deltas_copy {
            if h.eq_ignore_ascii_case(header_name) {
                return Some(Verb::Copy);
            }
        }
        for (h, op) in &self.deltas_translate {
            if h.eq_ignore_ascii_case(header_name) {
                return Some(Verb::Translate(op.clone()));
            }
        }
        None
    }

    pub fn verb_for_request(&self, header_name: &str) -> Verb {
        if let Some(v) = self.delta_verb(header_name) {
            return v;
        }
        self.preset.request.verb_for(header_name).clone()
    }

    pub fn verb_for_response(&self, header_name: &str) -> Verb {
        if let Some(v) = self.delta_verb(header_name) {
            return v;
        }
        self.preset.response.verb_for(header_name).clone()
    }
}

// ---------------------------------------------------------------------------
// PolicyContext — the slice of dispatcher state the engine needs
// ---------------------------------------------------------------------------

/// Subset of `DispatcherState` that the policy engine needs.  Constructed
/// cheaply in tests; constructed at call time in the dispatcher.
pub struct PolicyContext<'a> {
    pub b2bua_host: &'a str,
    pub b2bua_port: u16,
    pub user_agent_header: Option<&'a str>,
    pub server_header: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Application: apply_to_request / apply_to_response
// ---------------------------------------------------------------------------

/// Headers that are NEVER policy-managed.  These are dialog/transport/routing
/// invariants enforced by the framework regardless of preset.  No preset can
/// opt them in or out.
///
/// - `Via`, `Call-ID`, `CSeq`, `Max-Forwards`, `Content-Length`: transport /
///   per-leg dialog state.
/// - `From`, `To`, `Contact`: per-leg dialog identity rewritten by the
///   framework on every B-leg construction.
/// - `Record-Route`, `Route`: per-leg routing — A-leg's set must not leak
///   into the B-leg as content (RFC 3261 §16, topology hiding).
///
/// `Proxy-Authorization` / `Proxy-Authenticate` are NOT in this list, even
/// though RFC 3261 §22.3 makes them hop-by-hop.  Every built-in preset
/// strips them by default (the spec-correct posture), but a script can
/// opt in via `call.dial(copy=["Proxy-Authenticate"])` for the rare
/// transparent-proxy B2BUA case.
fn is_framework_auto(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "via"
            | "call-id"
            | "cseq"
            | "max-forwards"
            | "content-length"
            | "from"
            | "to"
            | "contact"
            | "record-route"
            | "route"
    )
}

/// Apply the policy to a freshly-cloned B-leg request.  Operates on
/// `outbound` in place.  Framework-auto headers are short-circuited; every
/// other header is passed to the resolved verb (Copy/Strip/Rewrite/Translate).
///
/// Called from `b2bua_send_b_leg_invite` after Record-Route/Route/etc. have
/// been stripped, and before Via/Call-ID/From/To/Contact framework rewrites.
pub fn apply_to_request(
    outbound: &mut SipMessage,
    policy: &ResolvedPolicy,
    ctx: &PolicyContext,
) {
    apply(outbound, policy, ctx, /*is_request=*/ true);
}

/// Apply the policy to a B-leg → A-leg response that is being forwarded back
/// to the inbound leg.  Operates on `response` in place.
///
/// Called from `sanitize_b2bua_response` in place of the previous hardcoded
/// `Allow` / `Supported` / `Require` / etc. strips.
pub fn apply_to_response(
    response: &mut SipMessage,
    policy: &ResolvedPolicy,
    ctx: &PolicyContext,
) {
    apply(response, policy, ctx, /*is_request=*/ false);
}

fn apply(message: &mut SipMessage, policy: &ResolvedPolicy, ctx: &PolicyContext, is_request: bool) {
    let header_names: Vec<String> = message
        .headers
        .names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    for name in header_names {
        if is_framework_auto(&name) {
            continue;
        }
        let verb = if is_request {
            policy.verb_for_request(&name)
        } else {
            policy.verb_for_response(&name)
        };
        apply_verb(message, &name, &verb, ctx);
    }
}

fn apply_verb(message: &mut SipMessage, name: &str, verb: &Verb, ctx: &PolicyContext) {
    match verb {
        Verb::Copy => {}
        Verb::Strip => {
            message.headers.remove(name);
        }
        Verb::Rewrite(op) => {
            if let Some(value) = message.headers.get(name).cloned() {
                if let Some(new_value) = apply_rewrite(&value, op, ctx) {
                    message.headers.set(name, new_value);
                } else {
                    message.headers.remove(name);
                }
            }
        }
        Verb::Translate(op) => {
            if let Some(value) = message.headers.get(name).cloned() {
                message.headers.remove(name);
                if let Some((new_name, new_value)) = apply_translate(&value, op) {
                    message.headers.set(&new_name, new_value);
                }
            }
        }
    }
}

fn apply_rewrite(value: &str, op: &RewriteOp, ctx: &PolicyContext) -> Option<String> {
    match op {
        RewriteOp::HostToAdvertised => {
            Some(crate::b2bua::actor::rewrite_uri_host(value, ctx.b2bua_host))
        }
        RewriteOp::ReplaceWithServerHeader => ctx.server_header.map(|s| s.to_string()),
        RewriteOp::ReplaceWithUserAgentHeader => ctx.user_agent_header.map(|s| s.to_string()),
    }
}

fn apply_translate(value: &str, op: &TranslateOp) -> Option<(String, String)> {
    match op {
        TranslateOp::DiversionToHistoryInfo => Some((
            "History-Info".to_string(),
            translate_diversion_to_history_info(value),
        )),
    }
}

/// Minimal RFC 5806 → RFC 7044 mapping for the single-divert case.
///
/// `Diversion: <sip:+3197010267609@sip.didww.com>;reason=unconditional;counter=1`
/// →
/// `History-Info: <sip:+3197010267609@sip.didww.com?Reason=SIP%3Bcause%3D302>;index=1`
///
/// Full RFC 7044 chained carriage (multiple `History-Info` entries with
/// hierarchical index `1.1`, `1.1.1`) is out of scope for v1 — the BGCF use
/// case that motivates this verb only sees one divert at the trust boundary.
fn translate_diversion_to_history_info(diversion: &str) -> String {
    let uri_end = diversion.find('>').map(|i| i + 1).unwrap_or(diversion.len());
    let uri_part = diversion[..uri_end].trim_end_matches('>').trim_start_matches('<');
    let params_part = if uri_end < diversion.len() {
        &diversion[uri_end..]
    } else {
        ""
    };
    let reason = params_part.split(';').find_map(|p| {
        let p = p.trim();
        p.strip_prefix("reason=").map(|v| v.trim_matches('"').to_string())
    });
    let cause = reason.as_deref().map(reason_to_sip_cause).unwrap_or(302);
    format!("<{}?Reason=SIP%3Bcause%3D{}>;index=1", uri_part, cause)
}

fn reason_to_sip_cause(reason: &str) -> u16 {
    match reason.to_ascii_lowercase().as_str() {
        "unconditional" | "follow-me" => 302,
        "user-busy" => 486,
        "no-answer" | "deflection" | "do-not-disturb" | "away" => 480,
        "unavailable" | "time-of-day" | "out-of-service" => 503,
        _ => 302,
    }
}

// ---------------------------------------------------------------------------
// Preset validation
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PresetError {
    #[error(
        "preset {0} has copy:[Authorization] but also a rewrite directive on a \
         Digest-protected field (R-URI host, To URI host, P-Asserted-Identity host) — \
         Digest hash would break.  Either remove Authorization from copy, or pick a \
         preset without those rewrites (e.g. ims-intra-trust-domain or \
         transparent-b2bua + per-call copy=[Authorization])."
    )]
    AuthorizationCopyWithDigestProtectedRewrite(String),

    #[error("preset {0} has empty version — versioning is mandatory")]
    MissingVersion(String),
}

/// Reject preset configurations that would silently break Digest auth.
///
/// Run at preset construction; built-in presets are validated at startup.
pub fn validate_preset(preset: &Preset) -> Result<(), PresetError> {
    if preset.version.is_empty() {
        return Err(PresetError::MissingVersion(preset.name.clone()));
    }
    let copies_authorization = matches!(preset.request.verb_for("Authorization"), Verb::Copy);
    if copies_authorization {
        let mutates_digest_field = preset.request.overrides.iter().any(|(p, v)| {
            matches!(v, Verb::Rewrite(_))
                && (p.matches("P-Asserted-Identity") || p.matches("To") || p.matches("Request-URI"))
        });
        if mutates_digest_field {
            return Err(PresetError::AuthorizationCopyWithDigestProtectedRewrite(
                preset.qualified_name(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Built-in preset library
// ---------------------------------------------------------------------------

/// All four built-in presets indexed by qualified name.  Built once at startup;
/// validated at construction.
pub fn builtin_presets() -> HashMap<String, Arc<Preset>> {
    let mut presets = HashMap::new();
    for preset in [
        transparent_b2bua_2026(),
        ims_intra_trust_domain_2026(),
        ims_trust_domain_boundary_2026(),
        sip_trunk_edge_2026(),
    ] {
        validate_preset(&preset).expect("built-in preset must validate");
        presets.insert(preset.qualified_name(), Arc::new(preset));
    }
    presets
}

/// Default preset: behaviour-equivalent to siphon's pre-policy B2BUA.
///
/// Reproduces every hardcoded strip and rewrite from
/// [`crate::dispatcher::sanitize_b2bua_response`] and the B-leg INVITE
/// construction so the migration to policy-driven dispatch produces
/// byte-identical wire output for any deployment that doesn't opt into a
/// different preset — with one intentional exception:
/// **`Proxy-Authenticate` is `Strip` in this preset** even though
/// pre-migration siphon passed it through.  Pre-migration behaviour was a
/// latent bug (RFC 3261 §22.3 hop-by-hop semantics).  See `is_framework_auto`
/// — `Proxy-Authenticate` is in the framework-auto strip list, not in this
/// preset's overrides, because no preset should be able to opt in.
fn transparent_b2bua_2026() -> Preset {
    Preset {
        name: "transparent-b2bua".to_string(),
        version: "2026".to_string(),
        request: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Exact("Authorization".to_string()), Verb::Strip),
                // RFC 3261 §22.3: Proxy-Authorization is hop-by-hop —
                // forwarding it across a B2BUA hop would target the wrong
                // realm.  Scripts can opt in via dial(copy=[…]) for the
                // rare transparent-proxy case.
                (HeaderPattern::Exact("Proxy-Authorization".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("User-Agent".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithUserAgentHeader),
                ),
                (
                    HeaderPattern::Exact("P-Asserted-Identity".to_string()),
                    Verb::Rewrite(RewriteOp::HostToAdvertised),
                ),
            ],
        },
        response: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Exact("Allow".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Allow-Events".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Supported".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Content-Disposition".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Require".to_string()), Verb::Strip),
                (HeaderPattern::Exact("RSeq".to_string()), Verb::Strip),
                (HeaderPattern::Exact("User-Agent".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("Server".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithServerHeader),
                ),
                // RFC 3261 §22.3: Proxy-Authenticate is hop-by-hop —
                // forwarding the upstream's challenge to A makes A
                // compute Proxy-Authorization against the wrong realm.
                // **Intentional behaviour change vs pre-policy siphon**,
                // which passed this header through (latent bug).
                (HeaderPattern::Exact("Proxy-Authenticate".to_string()), Verb::Strip),
            ],
        },
    }
}

/// S-CSCF ↔ AS, intra-trust IMS hop.  P-* flows through (RFC 3325 trust
/// domain).  Capability headers (`Allow`/`Supported`/`Require`/`RSeq`) flow
/// end-to-end so PRACK (RFC 3262 §6) and IMS preconditions (RFC 3312 / 4032)
/// negotiate correctly across the hop.  `X-*` stripped defensively.
fn ims_intra_trust_domain_2026() -> Preset {
    Preset {
        name: "ims-intra-trust-domain".to_string(),
        version: "2026".to_string(),
        request: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Exact("Authorization".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Proxy-Authorization".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("User-Agent".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithUserAgentHeader),
                ),
                (HeaderPattern::Prefix("X-".to_string()), Verb::Strip),
            ],
        },
        response: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (
                    HeaderPattern::Exact("Server".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithServerHeader),
                ),
                (HeaderPattern::Exact("User-Agent".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Proxy-Authenticate".to_string()), Verb::Strip),
                (HeaderPattern::Prefix("X-".to_string()), Verb::Strip),
            ],
        },
    }
}

/// P-CSCF / IBCF / BGCF edge.  Strict trust-boundary hygiene: default-strip,
/// with an explicit safe-set of UE-facing headers copied through.
/// `Diversion` translated to `History-Info`.  `P-Asserted-Identity` host
/// masked for topology hiding (legal under RFC 3325 — the host part is the
/// trust-domain identifier, not the asserted identity).
fn ims_trust_domain_boundary_2026() -> Preset {
    Preset {
        name: "ims-trust-domain-boundary".to_string(),
        version: "2026".to_string(),
        request: DirectionPolicy {
            default: Verb::Strip,
            overrides: vec![
                (HeaderPattern::Exact("Accept".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Accept-Encoding".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Accept-Language".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Allow".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Supported".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Require".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Min-SE".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Session-Expires".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Reason".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Refer-To".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Referred-By".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Replaces".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Subject".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Priority".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Date".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Timestamp".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Expires".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Type".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Encoding".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Language".to_string()), Verb::Copy),
                (HeaderPattern::Exact("MIME-Version".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Organization".to_string()), Verb::Copy),
                (
                    HeaderPattern::Exact("P-Asserted-Identity".to_string()),
                    Verb::Rewrite(RewriteOp::HostToAdvertised),
                ),
                (
                    HeaderPattern::Exact("Diversion".to_string()),
                    Verb::Translate(TranslateOp::DiversionToHistoryInfo),
                ),
                (
                    HeaderPattern::Exact("User-Agent".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithUserAgentHeader),
                ),
            ],
        },
        response: DirectionPolicy {
            default: Verb::Strip,
            overrides: vec![
                (HeaderPattern::Exact("Allow".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Supported".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Require".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Min-SE".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Session-Expires".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Reason".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Date".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Expires".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Type".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Encoding".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Language".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Retry-After".to_string()), Verb::Copy),
                (
                    HeaderPattern::Exact("Server".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithServerHeader),
                ),
            ],
        },
    }
}

/// Plain SIP trunk B2BUA, no IMS assumptions.  Strips `P-*` / `X-*`
/// defensively (no trust domain), passes capability negotiation through.
fn sip_trunk_edge_2026() -> Preset {
    Preset {
        name: "sip-trunk-edge".to_string(),
        version: "2026".to_string(),
        request: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Exact("Authorization".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Proxy-Authorization".to_string()), Verb::Strip),
                (HeaderPattern::Prefix("P-".to_string()), Verb::Strip),
                (HeaderPattern::Prefix("X-".to_string()), Verb::Strip),
                (HeaderPattern::Exact("History-Info".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Diversion".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Allow-Events".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("User-Agent".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithUserAgentHeader),
                ),
            ],
        },
        response: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Prefix("P-".to_string()), Verb::Strip),
                (HeaderPattern::Prefix("X-".to_string()), Verb::Strip),
                (HeaderPattern::Exact("User-Agent".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Allow-Events".to_string()), Verb::Strip),
                (HeaderPattern::Exact("Proxy-Authenticate".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("Server".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithServerHeader),
                ),
            ],
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message;

    fn ctx() -> PolicyContext<'static> {
        PolicyContext {
            b2bua_host: "192.0.2.1",
            b2bua_port: 5060,
            user_agent_header: Some("siphon-test/1.0"),
            server_header: Some("siphon-test/1.0"),
        }
    }

    fn transparent() -> Arc<Preset> {
        builtin_presets().get("transparent-b2bua@2026").unwrap().clone()
    }

    fn intra_trust() -> Arc<Preset> {
        builtin_presets()
            .get("ims-intra-trust-domain@2026")
            .unwrap()
            .clone()
    }

    fn trust_boundary() -> Arc<Preset> {
        builtin_presets()
            .get("ims-trust-domain-boundary@2026")
            .unwrap()
            .clone()
    }

    fn trunk_edge() -> Arc<Preset> {
        builtin_presets().get("sip-trunk-edge@2026").unwrap().clone()
    }

    fn parse(raw: &str) -> SipMessage {
        parse_sip_message(raw)
            .expect("test fixture must parse")
            .1
    }

    fn invite_with(extras: &[(&str, &str)]) -> SipMessage {
        let mut raw = String::from("INVITE sip:bob@biloxi.com SIP/2.0\r\n");
        raw.push_str("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n");
        raw.push_str("From: <sip:alice@atlanta.com>;tag=a\r\n");
        raw.push_str("To: <sip:bob@biloxi.com>\r\n");
        raw.push_str("Call-ID: test@example.com\r\n");
        raw.push_str("CSeq: 1 INVITE\r\n");
        raw.push_str("Max-Forwards: 70\r\n");
        for (n, v) in extras {
            raw.push_str(&format!("{}: {}\r\n", n, v));
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        parse(&raw)
    }

    fn ok_with(extras: &[(&str, &str)]) -> SipMessage {
        let mut raw = String::from("SIP/2.0 200 OK\r\n");
        raw.push_str("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n");
        raw.push_str("From: <sip:alice@atlanta.com>;tag=a\r\n");
        raw.push_str("To: <sip:bob@biloxi.com>;tag=b\r\n");
        raw.push_str("Call-ID: test@example.com\r\n");
        raw.push_str("CSeq: 1 INVITE\r\n");
        for (n, v) in extras {
            raw.push_str(&format!("{}: {}\r\n", n, v));
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        parse(&raw)
    }

    // ----- HeaderPattern matching -----

    #[test]
    fn header_pattern_exact_is_case_insensitive() {
        let p = HeaderPattern::Exact("Allow".to_string());
        assert!(p.matches("Allow"));
        assert!(p.matches("allow"));
        assert!(p.matches("ALLOW"));
        assert!(!p.matches("Allow-Events"));
    }

    #[test]
    fn header_pattern_prefix_is_case_insensitive_and_exact_prefix() {
        let p = HeaderPattern::Prefix("P-".to_string());
        assert!(p.matches("P-Asserted-Identity"));
        assert!(p.matches("p-charging-vector"));
        assert!(!p.matches("Privacy"), "single P with no dash must not match P-");
        assert!(!p.matches("Allow"));
    }

    // ----- is_framework_auto -----

    #[test]
    fn framework_auto_headers_recognised() {
        for name in &[
            "Via",
            "via",
            "Call-ID",
            "CSeq",
            "Max-Forwards",
            "Content-Length",
            "From",
            "To",
            "Contact",
            "Record-Route",
            "Route",
        ] {
            assert!(
                is_framework_auto(name),
                "{name} should be framework-auto"
            );
        }
    }

    #[test]
    fn non_framework_auto_headers_not_recognised() {
        for name in &[
            "Allow",
            "Supported",
            "Require",
            "Authorization",
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "WWW-Authenticate",
            "Authentication-Info",
            "P-Asserted-Identity",
            "Diversion",
            "Alert-Info",
            "X-Customer-Tier",
        ] {
            assert!(
                !is_framework_auto(name),
                "{name} should NOT be framework-auto (policy-managed)"
            );
        }
    }

    #[test]
    fn every_builtin_preset_strips_proxy_authenticate_on_response() {
        // RFC 3261 §22.3 — hop-by-hop, must not cross B2BUA hop.
        // Every shipped preset must include this strip.
        for qn in &[
            "transparent-b2bua@2026",
            "ims-intra-trust-domain@2026",
            "ims-trust-domain-boundary@2026",
            "sip-trunk-edge@2026",
        ] {
            let preset = builtin_presets().get(*qn).unwrap().clone();
            let policy = ResolvedPolicy::from_preset(preset);
            let mut msg = ok_with(&[("Proxy-Authenticate", "Digest realm=\"c\"")]);
            apply_to_response(&mut msg, &policy, &ctx());
            assert!(
                !msg.headers.has("Proxy-Authenticate"),
                "preset {qn} must strip Proxy-Authenticate on responses"
            );
        }
    }

    #[test]
    fn every_builtin_preset_strips_proxy_authorization_on_request() {
        for qn in &[
            "transparent-b2bua@2026",
            "ims-intra-trust-domain@2026",
            "ims-trust-domain-boundary@2026",
            "sip-trunk-edge@2026",
        ] {
            let preset = builtin_presets().get(*qn).unwrap().clone();
            let policy = ResolvedPolicy::from_preset(preset);
            let mut msg = invite_with(&[("Proxy-Authorization", "Digest username=\"a\"")]);
            apply_to_request(&mut msg, &policy, &ctx());
            assert!(
                !msg.headers.has("Proxy-Authorization"),
                "preset {qn} must strip Proxy-Authorization on requests"
            );
        }
    }

    #[test]
    fn transparent_proxy_can_opt_in_to_proxy_authenticate_passthrough() {
        // Rare transparent-proxy B2BUA case — script needs the upstream's
        // challenge to reach A.  Per-call delta overrides the preset strip.
        let mut policy = ResolvedPolicy::from_preset(transparent());
        policy.deltas_copy.push("Proxy-Authenticate".to_string());
        let mut msg = ok_with(&[("Proxy-Authenticate", "Digest realm=\"c\"")]);
        apply_to_response(&mut msg, &policy, &ctx());
        assert!(msg.headers.has("Proxy-Authenticate"), "delta copy should override preset strip");
    }

    #[test]
    fn transparent_proxy_can_opt_in_to_proxy_authorization_passthrough() {
        // The A→B (request) half of device-driven auth (auth_passthrough): the
        // caller's re-INVITE carries Proxy-Authorization, which must survive to
        // the challenging B-leg.  The preset strips it by default; a per-call
        // copy delta (what call.dial(auth_passthrough=True) injects) overrides that.
        let mut policy = ResolvedPolicy::from_preset(transparent());
        policy.deltas_copy.push("Proxy-Authorization".to_string());
        let mut msg = invite_with(&[("Proxy-Authorization", "Digest username=\"a\"")]);
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(
            msg.headers.has("Proxy-Authorization"),
            "delta copy should override preset strip on the request"
        );
    }

    // ----- transparent-b2bua@2026: behaviour equivalence with pre-migration -----

    #[test]
    fn transparent_strips_authorization_on_request() {
        let mut msg = invite_with(&[("Authorization", "Digest username=\"alice\"")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert!(!msg.headers.has("Authorization"));
    }

    #[test]
    fn transparent_strips_allow_on_response() {
        let mut msg = ok_with(&[("Allow", "INVITE, ACK, BYE")]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert!(!msg.headers.has("Allow"));
    }

    #[test]
    fn transparent_strips_allow_events_supported_require_rseq_on_response() {
        let mut msg = ok_with(&[
            ("Allow-Events", "presence"),
            ("Supported", "100rel, timer"),
            ("Require", "100rel"),
            ("RSeq", "1"),
            ("Content-Disposition", "session"),
        ]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert!(!msg.headers.has("Allow-Events"));
        assert!(!msg.headers.has("Supported"));
        assert!(!msg.headers.has("Require"));
        assert!(!msg.headers.has("RSeq"));
        assert!(!msg.headers.has("Content-Disposition"));
    }

    #[test]
    fn transparent_strips_user_agent_on_response() {
        let mut msg = ok_with(&[("User-Agent", "SomeVendor/9.9")]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert!(!msg.headers.has("User-Agent"));
    }

    #[test]
    fn transparent_rewrites_server_on_response() {
        let mut msg = ok_with(&[("Server", "BadActor/1.0")]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert_eq!(msg.headers.get("Server").map(|s| s.as_str()), Some("siphon-test/1.0"));
    }

    #[test]
    fn transparent_rewrites_user_agent_on_request() {
        let mut msg = invite_with(&[("User-Agent", "SomeVendor/9.9")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert_eq!(msg.headers.get("User-Agent").map(|s| s.as_str()), Some("siphon-test/1.0"));
    }

    #[test]
    fn transparent_rewrites_pai_host_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@private.internal>")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        // host rewritten to b2bua_host
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert!(pai.contains("192.0.2.1"), "PAI host should be rewritten: {pai}");
        assert!(pai.contains("alice"), "PAI user must be preserved: {pai}");
    }

    #[test]
    fn transparent_passes_arbitrary_headers_on_request() {
        let mut msg = invite_with(&[
            ("Alert-Info", "<urn:alert:service:normal>"),
            ("Subject", "Hi"),
            ("X-Custom", "value"),
        ]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        // transparent preset default=Copy, so unfamiliar headers pass through
        assert!(msg.headers.has("Alert-Info"));
        assert!(msg.headers.has("Subject"));
        assert!(msg.headers.has("X-Custom"));
    }

    #[test]
    fn transparent_passes_www_authenticate_on_response() {
        let mut msg = ok_with(&[("WWW-Authenticate", "Digest realm=\"c.example.com\"")]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        // matches today's pass-through behaviour
        assert!(msg.headers.has("WWW-Authenticate"));
    }

    #[test]
    fn transparent_passes_authentication_info_on_response() {
        let mut msg = ok_with(&[("Authentication-Info", "nextnonce=\"xyz\"")]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(transparent()), &ctx());
        assert!(msg.headers.has("Authentication-Info"));
    }

    // ----- Framework-auto headers are never touched by any preset -----

    #[test]
    fn framework_auto_headers_survive_strict_preset() {
        // ims-trust-domain-boundary has default=Strip, which would strip
        // everything not in the safe-set.  Framework-auto headers must
        // survive regardless.
        let mut msg = invite_with(&[("X-Should-Be-Stripped", "yes")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trust_boundary()), &ctx());
        assert!(msg.headers.has("Via"));
        assert!(msg.headers.has("From"));
        assert!(msg.headers.has("To"));
        assert!(msg.headers.has("Call-ID"));
        assert!(msg.headers.has("CSeq"));
        assert!(msg.headers.has("Max-Forwards"));
        assert!(!msg.headers.has("X-Should-Be-Stripped"));
    }

    // ----- ims-trust-domain-boundary@2026 -----

    #[test]
    fn trust_boundary_strips_leaky_headers_on_request() {
        let mut msg = invite_with(&[
            ("Alert-Info", "<urn:alert:service:call-waiting>"),
            ("P-Hint", "inbound"),
            ("X-FS-Support", "update_display"),
            ("P-Visited-Network-ID", "foo.example.com"),
        ]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trust_boundary()), &ctx());
        // these are the four headers from the BGCF MTC trace that leaked
        // through to the IMS side and confused the Samsung S21
        assert!(!msg.headers.has("Alert-Info"));
        assert!(!msg.headers.has("P-Hint"));
        assert!(!msg.headers.has("X-FS-Support"));
        assert!(!msg.headers.has("P-Visited-Network-ID"));
    }

    #[test]
    fn trust_boundary_preserves_safe_set_on_request() {
        let mut msg = invite_with(&[
            ("Allow", "INVITE, ACK, BYE"),
            ("Supported", "timer"),
            ("Min-SE", "90"),
            ("Refer-To", "<sip:target@example.com>"),
            ("Subject", "Important"),
        ]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trust_boundary()), &ctx());
        assert!(msg.headers.has("Allow"));
        assert!(msg.headers.has("Supported"));
        assert!(msg.headers.has("Min-SE"));
        assert!(msg.headers.has("Refer-To"));
        assert!(msg.headers.has("Subject"));
    }

    #[test]
    fn trust_boundary_translates_diversion_to_history_info() {
        let mut msg = invite_with(&[(
            "Diversion",
            "<sip:+3197010267609@sip.didww.com>;reason=unconditional",
        )]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trust_boundary()), &ctx());
        assert!(!msg.headers.has("Diversion"));
        let hi = msg
            .headers
            .get("History-Info")
            .expect("History-Info should be present");
        assert!(hi.contains("+3197010267609@sip.didww.com"), "URI preserved: {hi}");
        assert!(hi.contains("cause%3D302"), "unconditional → 302: {hi}");
        assert!(hi.contains("index=1"), "single-divert index: {hi}");
    }

    #[test]
    fn trust_boundary_rewrites_pai_host_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@private.internal>")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trust_boundary()), &ctx());
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert!(pai.contains("192.0.2.1"), "PAI host masked: {pai}");
        assert!(!pai.contains("private.internal"), "internal host gone: {pai}");
    }

    // ----- ims-intra-trust-domain@2026: PRACK/preconditions flow through -----

    #[test]
    fn intra_trust_flows_require_rseq_on_response() {
        let mut msg = ok_with(&[
            ("Require", "100rel"),
            ("RSeq", "1"),
            ("Supported", "100rel, precondition"),
        ]);
        apply_to_response(&mut msg, &ResolvedPolicy::from_preset(intra_trust()), &ctx());
        // intra-trust must pass these — RFC 3262 §6 + RFC 3312 / 4032
        assert!(msg.headers.has("Require"));
        assert!(msg.headers.has("RSeq"));
        assert!(msg.headers.has("Supported"));
    }

    #[test]
    fn intra_trust_flows_pai_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@trusted.internal>")]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(intra_trust()), &ctx());
        // intra-trust passes PAI verbatim — no host rewrite within trust domain
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert_eq!(pai, "<sip:alice@trusted.internal>");
    }

    #[test]
    fn intra_trust_strips_x_headers() {
        let mut msg = invite_with(&[
            ("X-Internal-Tag", "secret"),
            ("X-Customer-Tier", "gold"),
        ]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(intra_trust()), &ctx());
        assert!(!msg.headers.has("X-Internal-Tag"));
        assert!(!msg.headers.has("X-Customer-Tier"));
    }

    // ----- sip-trunk-edge@2026 -----

    #[test]
    fn trunk_edge_strips_p_and_x_headers_on_request() {
        let mut msg = invite_with(&[
            ("P-Asserted-Identity", "<sip:alice@host>"),
            ("P-Charging-Vector", "icid-value=foo"),
            ("X-Internal-Tag", "secret"),
        ]);
        apply_to_request(&mut msg, &ResolvedPolicy::from_preset(trunk_edge()), &ctx());
        assert!(!msg.headers.has("P-Asserted-Identity"));
        assert!(!msg.headers.has("P-Charging-Vector"));
        assert!(!msg.headers.has("X-Internal-Tag"));
    }

    // ----- Per-call deltas -----

    #[test]
    fn dial_time_strip_overrides_preset_copy() {
        let mut msg = invite_with(&[("Subject", "Test")]);
        let mut policy = ResolvedPolicy::from_preset(transparent()); // default=Copy
        policy.deltas_strip.push("Subject".to_string());
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(!msg.headers.has("Subject"));
    }

    #[test]
    fn dial_time_copy_overrides_preset_strip() {
        let mut msg = invite_with(&[("Alert-Info", "<urn:alert:service:normal>")]);
        let mut policy = ResolvedPolicy::from_preset(trust_boundary()); // strips Alert-Info
        policy.deltas_copy.push("Alert-Info".to_string());
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(msg.headers.has("Alert-Info"), "delta copy must override preset strip");
    }

    #[test]
    fn dial_time_strip_wins_over_dial_time_copy() {
        let mut msg = invite_with(&[("Subject", "Test")]);
        let mut policy = ResolvedPolicy::from_preset(transparent());
        policy.deltas_copy.push("Subject".to_string());
        policy.deltas_strip.push("Subject".to_string());
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(!msg.headers.has("Subject"), "strip wins on conflict");
    }

    // ----- Preset validation -----

    #[test]
    fn all_builtin_presets_validate() {
        let presets = builtin_presets();
        assert_eq!(presets.len(), 4);
        for (qn, p) in &presets {
            validate_preset(p).unwrap_or_else(|e| panic!("preset {qn} failed validation: {e}"));
        }
    }

    #[test]
    fn validate_rejects_empty_version() {
        let preset = Preset {
            name: "broken".to_string(),
            version: "".to_string(),
            request: DirectionPolicy {
                default: Verb::Copy,
                overrides: vec![],
            },
            response: DirectionPolicy {
                default: Verb::Copy,
                overrides: vec![],
            },
        };
        let err = validate_preset(&preset).unwrap_err();
        assert!(matches!(err, PresetError::MissingVersion(_)));
    }

    #[test]
    fn validate_rejects_authorization_copy_with_pai_rewrite() {
        let preset = Preset {
            name: "broken".to_string(),
            version: "test".to_string(),
            request: DirectionPolicy {
                default: Verb::Copy,
                overrides: vec![
                    (HeaderPattern::Exact("Authorization".to_string()), Verb::Copy),
                    (
                        HeaderPattern::Exact("P-Asserted-Identity".to_string()),
                        Verb::Rewrite(RewriteOp::HostToAdvertised),
                    ),
                ],
            },
            response: DirectionPolicy {
                default: Verb::Copy,
                overrides: vec![],
            },
        };
        let err = validate_preset(&preset).unwrap_err();
        assert!(matches!(
            err,
            PresetError::AuthorizationCopyWithDigestProtectedRewrite(_)
        ));
    }

    #[test]
    fn validate_accepts_authorization_copy_without_digest_protected_rewrite() {
        // intra-trust + per-call copy=[Authorization] is the supported case-c shape.
        // The preset itself must not have rewrites on Digest-protected fields.
        let mut preset = (*intra_trust()).clone();
        preset.request.overrides.insert(
            0,
            (HeaderPattern::Exact("Authorization".to_string()), Verb::Copy),
        );
        validate_preset(&preset).expect("intra-trust + Authorization Copy must validate");
    }

    // ----- Diversion → History-Info translation -----

    #[test]
    fn diversion_unconditional_becomes_history_info_302() {
        let h = translate_diversion_to_history_info(
            "<sip:+12025551212@example.com>;reason=unconditional",
        );
        assert!(h.contains("+12025551212@example.com"));
        assert!(h.contains("cause%3D302"));
        assert!(h.contains("index=1"));
    }

    #[test]
    fn diversion_user_busy_becomes_history_info_486() {
        let h = translate_diversion_to_history_info(
            "<sip:+12025551212@example.com>;reason=user-busy",
        );
        assert!(h.contains("cause%3D486"));
    }

    #[test]
    fn diversion_no_answer_becomes_history_info_480() {
        let h = translate_diversion_to_history_info(
            "<sip:+12025551212@example.com>;reason=no-answer",
        );
        assert!(h.contains("cause%3D480"));
    }

    #[test]
    fn diversion_unknown_reason_falls_back_to_302() {
        let h = translate_diversion_to_history_info(
            "<sip:+12025551212@example.com>;reason=unknown-rare-reason",
        );
        assert!(h.contains("cause%3D302"));
    }

    // ----- Preset library lookup -----

    #[test]
    fn builtin_presets_contains_four_postures() {
        let presets = builtin_presets();
        assert!(presets.contains_key("transparent-b2bua@2026"));
        assert!(presets.contains_key("ims-intra-trust-domain@2026"));
        assert!(presets.contains_key("ims-trust-domain-boundary@2026"));
        assert!(presets.contains_key("sip-trunk-edge@2026"));
    }
}
