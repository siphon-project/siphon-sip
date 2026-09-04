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

use serde::Deserialize;

use crate::sip::message::SipMessage;

/// Qualified name of the preset applied when nothing else resolves — an
/// unset `b2bua.default_header_policy`, or a name that could not be found.
pub const DEFAULT_PRESET_NAME: &str = "transparent-b2bua@2026";

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

impl RewriteOp {
    /// Resolve a config token (the value side of a `rewrite:` entry in
    /// `header_policies:`) to a rewrite op.  Returns `None` for an unknown
    /// token; the caller reports it with the offending policy name.
    pub fn from_token(token: &str) -> Option<RewriteOp> {
        match token.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "host-to-advertised" => Some(RewriteOp::HostToAdvertised),
            "replace-with-server-header" => Some(RewriteOp::ReplaceWithServerHeader),
            "replace-with-user-agent-header" => Some(RewriteOp::ReplaceWithUserAgentHeader),
            _ => None,
        }
    }

    /// Every token [`Self::from_token`] accepts, for error messages.
    pub fn tokens() -> &'static [&'static str] {
        &[
            "host-to-advertised",
            "replace-with-server-header",
            "replace-with-user-agent-header",
        ]
    }
}

/// Named cross-header transforms for the [`Verb::Translate`] verb.
#[derive(Debug, Clone, PartialEq)]
pub enum TranslateOp {
    /// Translate `Diversion` (RFC 5806) into `History-Info` (RFC 7044).
    /// Single-divert minimal mapping; full RFC 7044 chained-index carriage
    /// is out of scope for v1.
    DiversionToHistoryInfo,
}

impl TranslateOp {
    /// Resolve a translate-op token to an op.  Shared by the script-facing
    /// `call.dial(translate=[(…, "rfc7044")])` path and the `translate:` map
    /// of an operator-defined policy, so the two can never accept different
    /// spellings.  Returns `None` for an unknown token.
    pub fn from_token(token: &str) -> Option<TranslateOp> {
        match token.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "rfc7044" | "diversion-to-history-info" => Some(TranslateOp::DiversionToHistoryInfo),
            _ => None,
        }
    }

    /// Every token [`Self::from_token`] accepts, for error messages.
    pub fn tokens() -> &'static [&'static str] {
        &["rfc7044", "diversion-to-history-info"]
    }
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
    /// Parse a config token from a `copy:` / `strip:` list, or the key side of
    /// a `rewrite:` / `translate:` map.
    ///
    /// `"Alert-Info"` → [`Self::Exact`], `"X-*"` → [`Self::Prefix`].  The `*`
    /// is a trailing wildcard only — the engine matches on a name prefix, not
    /// a glob — and a bare `"*"` is refused because it silently duplicates the
    /// direction's `default:`.  Returns the reason on rejection so the caller
    /// can name the offending policy alongside it.
    pub fn from_token(token: &str) -> Result<HeaderPattern, String> {
        let token = token.trim();
        if token.is_empty() {
            return Err("empty header name".to_string());
        }
        if let Some(prefix) = token.strip_suffix('*') {
            if prefix.is_empty() {
                return Err(
                    "\"*\" would match every header — set the direction's `default:` instead"
                        .to_string(),
                );
            }
            if prefix.contains('*') {
                return Err(
                    "only one trailing \"*\" is supported — this is a prefix match, not a glob"
                        .to_string(),
                );
            }
            return Ok(HeaderPattern::Prefix(prefix.to_string()));
        }
        if token.contains('*') {
            return Err(
                "\"*\" is only supported as a trailing wildcard (e.g. \"X-*\")".to_string(),
            );
        }
        Ok(HeaderPattern::Exact(token.to_string()))
    }

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
pub(crate) const FRAMEWORK_AUTO_HEADERS: &[&str] = &[
    "Via",
    "Call-ID",
    "CSeq",
    "Max-Forwards",
    "Content-Length",
    "From",
    "To",
    "Contact",
    "Record-Route",
    "Route",
];

pub(crate) fn is_framework_auto(name: &str) -> bool {
    FRAMEWORK_AUTO_HEADERS
        .iter()
        .any(|header| header.eq_ignore_ascii_case(name))
}

/// Apply the policy to a freshly-cloned B-leg request.  Operates on
/// `outbound` in place.  Framework-auto headers are short-circuited; every
/// other header is passed to the resolved verb (Copy/Strip/Rewrite/Translate).
///
/// Called from `b2bua_send_b_leg_invite` after Record-Route/Route/etc. have
/// been stripped, and before Via/Call-ID/From/To/Contact framework rewrites.
pub fn apply_to_request(outbound: &mut SipMessage, policy: &ResolvedPolicy, ctx: &PolicyContext) {
    apply(outbound, policy, ctx, /*is_request=*/ true);
}

/// Apply the policy to a B-leg → A-leg response that is being forwarded back
/// to the inbound leg.  Operates on `response` in place.
///
/// Called from `sanitize_b2bua_response` in place of the previous hardcoded
/// `Allow` / `Supported` / `Require` / etc. strips.
pub fn apply_to_response(response: &mut SipMessage, policy: &ResolvedPolicy, ctx: &PolicyContext) {
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
/// `Diversion: <sip:+12025550123@example.com>;reason=unconditional;counter=1`
/// →
/// `History-Info: <sip:+12025550123@example.com?Reason=SIP%3Bcause%3D302>;index=1`
///
/// Full RFC 7044 chained carriage (multiple `History-Info` entries with
/// hierarchical index `1.1`, `1.1.1`) is out of scope for v1 — the BGCF use
/// case that motivates this verb only sees one divert at the trust boundary.
fn translate_diversion_to_history_info(diversion: &str) -> String {
    let uri_end = diversion
        .find('>')
        .map(|i| i + 1)
        .unwrap_or(diversion.len());
    let uri_part = diversion[..uri_end]
        .trim_end_matches('>')
        .trim_start_matches('<');
    let params_part = if uri_end < diversion.len() {
        &diversion[uri_end..]
    } else {
        ""
    };
    let reason = params_part.split(';').find_map(|p| {
        let p = p.trim();
        p.strip_prefix("reason=")
            .map(|v| v.trim_matches('"').to_string())
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

    #[error(
        "header policy {0:?} is not versioned — the map key is the name scripts pin, and it \
         must be \"<name>@<version>\" (e.g. {0:?}@1) so a later edit to this policy cannot \
         silently change what crosses the boundary for calls already pinning the old name"
    )]
    UnversionedName(String),

    #[error(
        "header policy {0:?} collides with a built-in preset of the same name — pick another \
         name (a built-in's behaviour is pinned by its version and must not be redefined); \
         to build on it, use `extends: {0:?}` under a name of your own"
    )]
    NameCollidesWithBuiltin(String),

    #[error(
        "header policy {policy:?} extends {base:?}, which is not a built-in preset — \
         `extends:` must name one of: {known}"
    )]
    UnknownBase {
        policy: String,
        base: String,
        known: String,
    },

    #[error("header policy {policy:?} ({direction}): {token:?} — {reason}")]
    InvalidPattern {
        policy: String,
        direction: String,
        token: String,
        reason: String,
    },

    #[error(
        "header policy {policy:?} ({direction}) names {token:?} more than once — one header \
         gets one verb; remove the duplicate"
    )]
    DuplicatePattern {
        policy: String,
        direction: String,
        token: String,
    },

    #[error(
        "header policy {policy:?} ({direction}) names {token:?}, which matches the \
         framework-managed header {header} — Via, Call-ID, CSeq, Max-Forwards, \
         Content-Length, From, To, Contact, Record-Route and Route are per-leg dialog and \
         routing state that no policy may touch, so this rule would never have taken effect"
    )]
    FrameworkAutoHeader {
        policy: String,
        direction: String,
        token: String,
        header: String,
    },

    #[error(
        "header policy {policy:?} ({direction}) sets `rewrite: {header}: {token:?}`, which is \
         not a rewrite op — expected one of: {known}"
    )]
    UnknownRewriteOp {
        policy: String,
        direction: String,
        header: String,
        token: String,
        known: String,
    },

    #[error(
        "header policy {policy:?} ({direction}) sets `translate: {header}: {token:?}`, which \
         is not a translate op — expected one of: {known}"
    )]
    UnknownTranslateOp {
        policy: String,
        direction: String,
        header: String,
        token: String,
        known: String,
    },

    #[error(
        "header policy {policy:?} ({direction}) has no `default:` — a policy without \
         `extends:` must say what happens to a header no rule matches (`default: copy` or \
         `default: strip`)"
    )]
    MissingDefault { policy: String, direction: String },

    #[error(
        "header policy {policy:?} ({direction}) sets both `extends:` and `default:` — the \
         base preset supplies the default; remove `default:`, or drop `extends:` and declare \
         the policy in full"
    )]
    DefaultWithExtends { policy: String, direction: String },

    #[error(
        "header policy {policy:?} has no `{direction}:` block and no `extends:` — declare \
         both directions, or extend a built-in preset to inherit them"
    )]
    MissingDirection { policy: String, direction: String },

    #[error(
        "header policy {0:?} is empty — declare `request:` / `response:` rules, or `extends:` \
         a built-in preset to alias it under a name of your own"
    )]
    EmptyPolicy(String),
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
                (
                    HeaderPattern::Exact("Authorization".to_string()),
                    Verb::Strip,
                ),
                // RFC 3261 §22.3: Proxy-Authorization is hop-by-hop —
                // forwarding it across a B2BUA hop would target the wrong
                // realm.  Scripts can opt in via dial(copy=[…]) for the
                // rare transparent-proxy case.
                (
                    HeaderPattern::Exact("Proxy-Authorization".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Allow-Events".to_string()),
                    Verb::Strip,
                ),
                (HeaderPattern::Exact("Supported".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("Content-Disposition".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Proxy-Authenticate".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Authorization".to_string()),
                    Verb::Strip,
                ),
                (
                    HeaderPattern::Exact("Proxy-Authorization".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Proxy-Authenticate".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Accept-Encoding".to_string()),
                    Verb::Copy,
                ),
                (
                    HeaderPattern::Exact("Accept-Language".to_string()),
                    Verb::Copy,
                ),
                (HeaderPattern::Exact("Allow".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Supported".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Require".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Min-SE".to_string()), Verb::Copy),
                (
                    HeaderPattern::Exact("Session-Expires".to_string()),
                    Verb::Copy,
                ),
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
                (
                    HeaderPattern::Exact("Content-Encoding".to_string()),
                    Verb::Copy,
                ),
                (
                    HeaderPattern::Exact("Content-Language".to_string()),
                    Verb::Copy,
                ),
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
                (
                    HeaderPattern::Exact("Session-Expires".to_string()),
                    Verb::Copy,
                ),
                (HeaderPattern::Exact("Reason".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Date".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Expires".to_string()), Verb::Copy),
                (HeaderPattern::Exact("Content-Type".to_string()), Verb::Copy),
                (
                    HeaderPattern::Exact("Content-Encoding".to_string()),
                    Verb::Copy,
                ),
                (
                    HeaderPattern::Exact("Content-Language".to_string()),
                    Verb::Copy,
                ),
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
                (
                    HeaderPattern::Exact("Authorization".to_string()),
                    Verb::Strip,
                ),
                (
                    HeaderPattern::Exact("Proxy-Authorization".to_string()),
                    Verb::Strip,
                ),
                (HeaderPattern::Prefix("P-".to_string()), Verb::Strip),
                (HeaderPattern::Prefix("X-".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("History-Info".to_string()),
                    Verb::Strip,
                ),
                (HeaderPattern::Exact("Diversion".to_string()), Verb::Strip),
                (
                    HeaderPattern::Exact("Allow-Events".to_string()),
                    Verb::Strip,
                ),
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
                (
                    HeaderPattern::Exact("Allow-Events".to_string()),
                    Verb::Strip,
                ),
                (
                    HeaderPattern::Exact("Proxy-Authenticate".to_string()),
                    Verb::Strip,
                ),
                (
                    HeaderPattern::Exact("Server".to_string()),
                    Verb::Rewrite(RewriteOp::ReplaceWithServerHeader),
                ),
            ],
        },
    }
}

/// The preset applied when no other name resolves — [`DEFAULT_PRESET_NAME`].
pub fn default_preset() -> Arc<Preset> {
    Arc::new(transparent_b2bua_2026())
}

// ---------------------------------------------------------------------------
// Operator-defined policies (`header_policies:` in siphon.yaml)
// ---------------------------------------------------------------------------

/// The catch-all verb of a direction block.
///
/// Only `copy` and `strip` are meaningful as a catch-all — `rewrite` and
/// `translate` are per-header operations and are declared in their own maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultVerb {
    Copy,
    Strip,
}

impl From<DefaultVerb> for Verb {
    fn from(value: DefaultVerb) -> Self {
        match value {
            DefaultVerb::Copy => Verb::Copy,
            DefaultVerb::Strip => Verb::Strip,
        }
    }
}

/// One direction (`request:` or `response:`) of an operator-defined policy.
///
/// Every key of `copy` / `strip` — and every key of `rewrite` / `translate` —
/// is a header name (exact, case-insensitive) or a `Prefix-*` trailing
/// wildcard; see [`HeaderPattern::from_token`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectionConfig {
    /// Catch-all verb for a header no rule matches.  Required when the policy
    /// has no `extends:`; rejected when it does, since the base supplies it.
    #[serde(default)]
    pub default: Option<DefaultVerb>,
    /// Header names to pass through.
    #[serde(default)]
    pub copy: Vec<String>,
    /// Header names to drop.
    #[serde(default)]
    pub strip: Vec<String>,
    /// Header name → rewrite-op token ([`RewriteOp::tokens`]).
    #[serde(default)]
    pub rewrite: HashMap<String, String>,
    /// Header name → translate-op token ([`TranslateOp::tokens`]).
    #[serde(default)]
    pub translate: HashMap<String, String>,
}

impl DirectionConfig {
    fn is_empty(&self) -> bool {
        self.default.is_none()
            && self.copy.is_empty()
            && self.strip.is_empty()
            && self.rewrite.is_empty()
            && self.translate.is_empty()
    }
}

/// One entry of the top-level `header_policies:` map.
///
/// The map key is the qualified name (`"<name>@<version>"`) that scripts pass
/// to `call.dial(header_policy=…)` and that `b2bua.default_header_policy`
/// pins — the same namespace as the built-in presets, which it may not
/// collide with.
///
/// ```yaml
/// header_policies:
///   "trunk-edge-plus@1":
///     extends: "sip-trunk-edge@2026"
///     request:
///       copy: ["X-Account-Ref"]
///     response:
///       strip: ["Server"]
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPolicyConfig {
    /// Qualified name of a built-in preset to inherit from.  The base supplies
    /// each direction's default and its rules; this policy's own rules are
    /// matched first, so they win.  Omit to declare the policy in full, in
    /// which case each direction needs an explicit `default:`.
    pub extends: Option<String>,
    /// A→B (request) direction.  Under `extends:`, omitting it inherits the
    /// base direction verbatim.
    pub request: Option<DirectionConfig>,
    /// B→A (response) direction.  Under `extends:`, omitting it inherits the
    /// base direction verbatim.
    pub response: Option<DirectionConfig>,
}

impl HeaderPolicyConfig {
    /// Compile into a [`Preset`], resolving `extends:` against `builtins`.
    ///
    /// `qualified_name` is the map key, which becomes the preset's
    /// `name@version` and must already carry a version.
    pub fn resolve(
        &self,
        qualified_name: &str,
        builtins: &HashMap<String, Arc<Preset>>,
    ) -> Result<Preset, PresetError> {
        let (name, version) = split_qualified_name(qualified_name)?;

        let base = match self.extends.as_deref().map(str::trim) {
            Some(base_name) => {
                let mut known: Vec<&str> = builtins.keys().map(String::as_str).collect();
                known.sort_unstable();
                Some(
                    builtins
                        .get(base_name)
                        .ok_or_else(|| PresetError::UnknownBase {
                            policy: qualified_name.to_string(),
                            base: base_name.to_string(),
                            known: known.join(", "),
                        })?,
                )
            }
            None => None,
        };

        let declares_nothing =
            declares_nothing(self.request.as_ref()) && declares_nothing(self.response.as_ref());
        if base.is_none() && declares_nothing {
            return Err(PresetError::EmptyPolicy(qualified_name.to_string()));
        }

        let request = build_direction(
            qualified_name,
            "request",
            self.request.as_ref(),
            base.map(|preset| &preset.request),
        )?;
        let response = build_direction(
            qualified_name,
            "response",
            self.response.as_ref(),
            base.map(|preset| &preset.response),
        )?;

        Ok(Preset {
            name,
            version,
            request,
            response,
        })
    }
}

/// Whether a direction block is absent or carries no rules at all.  Explicit
/// match rather than `is_none_or`, which is newer than the project MSRV.
fn declares_nothing(config: Option<&DirectionConfig>) -> bool {
    match config {
        Some(config) => config.is_empty(),
        None => true,
    }
}

/// Split a map key into `(name, version)`.  A key without a non-empty version
/// after the last `@` is refused — see [`PresetError::UnversionedName`].
fn split_qualified_name(qualified: &str) -> Result<(String, String), PresetError> {
    match qualified.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() && !version.is_empty() => {
            Ok((name.to_string(), version.to_string()))
        }
        _ => Err(PresetError::UnversionedName(qualified.to_string())),
    }
}

/// Compile one direction of an operator-defined policy.
///
/// Rule order in the resulting [`DirectionPolicy::overrides`] is what decides
/// behaviour, since [`DirectionPolicy::verb_for`] is first-match-wins:
///
/// 1. this policy's own rules, exact names before prefixes and longer prefixes
///    before shorter ones — so `strip: ["X-*"]` alongside
///    `copy: ["X-Account-Ref"]` in one block does the obvious thing;
/// 2. the base preset's rules, so a custom rule beats an inherited one;
/// 3. the base preset's `default` (or this policy's, when standalone).
fn build_direction(
    policy: &str,
    direction: &str,
    config: Option<&DirectionConfig>,
    base: Option<&DirectionPolicy>,
) -> Result<DirectionPolicy, PresetError> {
    let Some(config) = config else {
        return match base {
            Some(base) => Ok(base.clone()),
            None => Err(PresetError::MissingDirection {
                policy: policy.to_string(),
                direction: direction.to_string(),
            }),
        };
    };

    let default = match (config.default, base) {
        (Some(_), Some(_)) => {
            return Err(PresetError::DefaultWithExtends {
                policy: policy.to_string(),
                direction: direction.to_string(),
            });
        }
        (Some(verb), None) => Verb::from(verb),
        (None, Some(base)) => base.default.clone(),
        (None, None) => {
            return Err(PresetError::MissingDefault {
                policy: policy.to_string(),
                direction: direction.to_string(),
            });
        }
    };

    let mut overrides: Vec<(HeaderPattern, Verb)> = Vec::new();

    for token in &config.strip {
        push_rule(&mut overrides, policy, direction, token, Verb::Strip)?;
    }
    for token in &config.copy {
        push_rule(&mut overrides, policy, direction, token, Verb::Copy)?;
    }
    // Sorted so a bad entry is reported deterministically across runs, HashMap
    // iteration order being arbitrary.
    for (header, token) in sorted_pairs(&config.rewrite) {
        let operation =
            RewriteOp::from_token(token).ok_or_else(|| PresetError::UnknownRewriteOp {
                policy: policy.to_string(),
                direction: direction.to_string(),
                header: header.to_string(),
                token: token.to_string(),
                known: RewriteOp::tokens().join(", "),
            })?;
        push_rule(
            &mut overrides,
            policy,
            direction,
            header,
            Verb::Rewrite(operation),
        )?;
    }
    for (header, token) in sorted_pairs(&config.translate) {
        let operation =
            TranslateOp::from_token(token).ok_or_else(|| PresetError::UnknownTranslateOp {
                policy: policy.to_string(),
                direction: direction.to_string(),
                header: header.to_string(),
                token: token.to_string(),
                known: TranslateOp::tokens().join(", "),
            })?;
        push_rule(
            &mut overrides,
            policy,
            direction,
            header,
            Verb::Translate(operation),
        )?;
    }

    // Stable sort, so rules of equal specificity keep declaration order.
    overrides.sort_by_key(|(pattern, _)| specificity_key(pattern));

    if let Some(base) = base {
        overrides.extend(base.overrides.iter().cloned());
    }

    Ok(DirectionPolicy { default, overrides })
}

/// `(exact-before-prefix, longest-prefix-first)`.
fn specificity_key(pattern: &HeaderPattern) -> (u8, std::cmp::Reverse<usize>) {
    match pattern {
        HeaderPattern::Exact(_) => (0, std::cmp::Reverse(0)),
        HeaderPattern::Prefix(prefix) => (1, std::cmp::Reverse(prefix.len())),
    }
}

fn sorted_pairs(map: &HashMap<String, String>) -> Vec<(&str, &str)> {
    let mut pairs: Vec<(&str, &str)> = map
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    pairs.sort_unstable_by_key(|(key, _)| *key);
    pairs
}

/// Parse one rule token and append it, rejecting a pattern that is malformed,
/// already used in this direction, or aimed at a framework-managed header.
fn push_rule(
    overrides: &mut Vec<(HeaderPattern, Verb)>,
    policy: &str,
    direction: &str,
    token: &str,
    verb: Verb,
) -> Result<(), PresetError> {
    let pattern =
        HeaderPattern::from_token(token).map_err(|reason| PresetError::InvalidPattern {
            policy: policy.to_string(),
            direction: direction.to_string(),
            token: token.to_string(),
            reason,
        })?;

    if let Some(header) = FRAMEWORK_AUTO_HEADERS
        .iter()
        .find(|header| pattern.matches(header))
    {
        return Err(PresetError::FrameworkAutoHeader {
            policy: policy.to_string(),
            direction: direction.to_string(),
            token: token.to_string(),
            header: (*header).to_string(),
        });
    }

    if overrides.iter().any(|(existing, _)| *existing == pattern) {
        return Err(PresetError::DuplicatePattern {
            policy: policy.to_string(),
            direction: direction.to_string(),
            token: token.to_string(),
        });
    }

    overrides.push((pattern, verb));
    Ok(())
}

/// The full policy library: the built-in presets plus every operator-defined
/// policy from `header_policies:`.
///
/// Built once at startup and shared read-only with the B2BUA paths.  A custom
/// policy may not take a built-in's name, and `extends:` resolves against the
/// built-ins only — so the result does not depend on the order the map
/// happened to be iterated in.
pub fn build_registry(
    custom: &HashMap<String, HeaderPolicyConfig>,
) -> Result<HashMap<String, Arc<Preset>>, PresetError> {
    let builtins = builtin_presets();
    let mut registry = builtins.clone();

    // Sorted so a config with several bad policies always reports the same one.
    let mut names: Vec<&String> = custom.keys().collect();
    names.sort_unstable();

    for name in names {
        let Some(config) = custom.get(name) else {
            continue;
        };
        if builtins.contains_key(name.as_str()) {
            return Err(PresetError::NameCollidesWithBuiltin(name.to_string()));
        }
        let preset = config.resolve(name, &builtins)?;
        validate_preset(&preset)?;
        registry.insert(name.to_string(), Arc::new(preset));
    }

    Ok(registry)
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
        builtin_presets()
            .get("transparent-b2bua@2026")
            .unwrap()
            .clone()
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
        builtin_presets()
            .get("sip-trunk-edge@2026")
            .unwrap()
            .clone()
    }

    fn parse(raw: &str) -> SipMessage {
        parse_sip_message(raw).expect("test fixture must parse").1
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
        assert!(
            !p.matches("Privacy"),
            "single P with no dash must not match P-"
        );
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
            assert!(is_framework_auto(name), "{name} should be framework-auto");
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
        assert!(
            msg.headers.has("Proxy-Authenticate"),
            "delta copy should override preset strip"
        );
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
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert!(!msg.headers.has("Authorization"));
    }

    #[test]
    fn transparent_strips_allow_on_response() {
        let mut msg = ok_with(&[("Allow", "INVITE, ACK, BYE")]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
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
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert!(!msg.headers.has("Allow-Events"));
        assert!(!msg.headers.has("Supported"));
        assert!(!msg.headers.has("Require"));
        assert!(!msg.headers.has("RSeq"));
        assert!(!msg.headers.has("Content-Disposition"));
    }

    #[test]
    fn transparent_strips_user_agent_on_response() {
        let mut msg = ok_with(&[("User-Agent", "SomeVendor/9.9")]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert!(!msg.headers.has("User-Agent"));
    }

    #[test]
    fn transparent_rewrites_server_on_response() {
        let mut msg = ok_with(&[("Server", "BadActor/1.0")]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert_eq!(
            msg.headers.get("Server").map(|s| s.as_str()),
            Some("siphon-test/1.0")
        );
    }

    #[test]
    fn transparent_rewrites_user_agent_on_request() {
        let mut msg = invite_with(&[("User-Agent", "SomeVendor/9.9")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert_eq!(
            msg.headers.get("User-Agent").map(|s| s.as_str()),
            Some("siphon-test/1.0")
        );
    }

    #[test]
    fn transparent_rewrites_pai_host_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@private.internal>")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        // host rewritten to b2bua_host
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert!(
            pai.contains("192.0.2.1"),
            "PAI host should be rewritten: {pai}"
        );
        assert!(pai.contains("alice"), "PAI user must be preserved: {pai}");
    }

    #[test]
    fn transparent_passes_arbitrary_headers_on_request() {
        let mut msg = invite_with(&[
            ("Alert-Info", "<urn:alert:service:normal>"),
            ("Subject", "Hi"),
            ("X-Custom", "value"),
        ]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        // transparent preset default=Copy, so unfamiliar headers pass through
        assert!(msg.headers.has("Alert-Info"));
        assert!(msg.headers.has("Subject"));
        assert!(msg.headers.has("X-Custom"));
    }

    #[test]
    fn transparent_passes_www_authenticate_on_response() {
        let mut msg = ok_with(&[("WWW-Authenticate", "Digest realm=\"c.example.com\"")]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        // matches today's pass-through behaviour
        assert!(msg.headers.has("WWW-Authenticate"));
    }

    #[test]
    fn transparent_passes_authentication_info_on_response() {
        let mut msg = ok_with(&[("Authentication-Info", "nextnonce=\"xyz\"")]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(transparent()),
            &ctx(),
        );
        assert!(msg.headers.has("Authentication-Info"));
    }

    // ----- Framework-auto headers are never touched by any preset -----

    #[test]
    fn framework_auto_headers_survive_strict_preset() {
        // ims-trust-domain-boundary has default=Strip, which would strip
        // everything not in the safe-set.  Framework-auto headers must
        // survive regardless.
        let mut msg = invite_with(&[("X-Should-Be-Stripped", "yes")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(trust_boundary()),
            &ctx(),
        );
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
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(trust_boundary()),
            &ctx(),
        );
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
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(trust_boundary()),
            &ctx(),
        );
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
            "<sip:+12025550123@example.com>;reason=unconditional",
        )]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(trust_boundary()),
            &ctx(),
        );
        assert!(!msg.headers.has("Diversion"));
        let hi = msg
            .headers
            .get("History-Info")
            .expect("History-Info should be present");
        assert!(
            hi.contains("+12025550123@example.com"),
            "URI preserved: {hi}"
        );
        assert!(hi.contains("cause%3D302"), "unconditional → 302: {hi}");
        assert!(hi.contains("index=1"), "single-divert index: {hi}");
    }

    #[test]
    fn trust_boundary_rewrites_pai_host_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@private.internal>")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(trust_boundary()),
            &ctx(),
        );
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert!(pai.contains("192.0.2.1"), "PAI host masked: {pai}");
        assert!(
            !pai.contains("private.internal"),
            "internal host gone: {pai}"
        );
    }

    // ----- ims-intra-trust-domain@2026: PRACK/preconditions flow through -----

    #[test]
    fn intra_trust_flows_require_rseq_on_response() {
        let mut msg = ok_with(&[
            ("Require", "100rel"),
            ("RSeq", "1"),
            ("Supported", "100rel, precondition"),
        ]);
        apply_to_response(
            &mut msg,
            &ResolvedPolicy::from_preset(intra_trust()),
            &ctx(),
        );
        // intra-trust must pass these — RFC 3262 §6 + RFC 3312 / 4032
        assert!(msg.headers.has("Require"));
        assert!(msg.headers.has("RSeq"));
        assert!(msg.headers.has("Supported"));
    }

    #[test]
    fn intra_trust_flows_pai_on_request() {
        let mut msg = invite_with(&[("P-Asserted-Identity", "<sip:alice@trusted.internal>")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(intra_trust()),
            &ctx(),
        );
        // intra-trust passes PAI verbatim — no host rewrite within trust domain
        let pai = msg.headers.get("P-Asserted-Identity").unwrap();
        assert_eq!(pai, "<sip:alice@trusted.internal>");
    }

    #[test]
    fn intra_trust_strips_x_headers() {
        let mut msg = invite_with(&[("X-Internal-Tag", "secret"), ("X-Customer-Tier", "gold")]);
        apply_to_request(
            &mut msg,
            &ResolvedPolicy::from_preset(intra_trust()),
            &ctx(),
        );
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
        assert!(
            msg.headers.has("Alert-Info"),
            "delta copy must override preset strip"
        );
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
                    (
                        HeaderPattern::Exact("Authorization".to_string()),
                        Verb::Copy,
                    ),
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
            (
                HeaderPattern::Exact("Authorization".to_string()),
                Verb::Copy,
            ),
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
        let h =
            translate_diversion_to_history_info("<sip:+12025551212@example.com>;reason=user-busy");
        assert!(h.contains("cause%3D486"));
    }

    #[test]
    fn diversion_no_answer_becomes_history_info_480() {
        let h =
            translate_diversion_to_history_info("<sip:+12025551212@example.com>;reason=no-answer");
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

    // ----- Operator-defined policies (`header_policies:`) -----

    fn policies(yaml: &str) -> HashMap<String, HeaderPolicyConfig> {
        serde_yaml_ng::from_str(yaml).expect("valid header_policies YAML")
    }

    /// Parse one policy out of a `header_policies:`-shaped YAML fragment and
    /// resolve it against the built-in library.
    fn resolve_one(yaml: &str, name: &str) -> Result<Preset, PresetError> {
        let configs = policies(yaml);
        configs
            .get(name)
            .expect("policy present in fragment")
            .resolve(name, &builtin_presets())
    }

    fn resolved(yaml: &str, name: &str) -> ResolvedPolicy {
        ResolvedPolicy::from_preset(Arc::new(
            resolve_one(yaml, name).expect("policy should resolve"),
        ))
    }

    #[test]
    fn extends_lets_one_header_cross_and_leaves_the_rest_of_the_base_alone() {
        // The motivating shape: a trunk-edge posture that has to let exactly
        // one X- header through.  Everything else the base strips must still
        // be stripped, or the policy has quietly opened the boundary.
        let policy = resolved(
            concat!(
                "\"trunk-edge-plus@1\":\n",
                "  extends: \"sip-trunk-edge@2026\"\n",
                "  request:\n",
                "    copy: [\"X-Account-Ref\"]\n",
            ),
            "trunk-edge-plus@1",
        );

        let mut msg = invite_with(&[
            ("X-Account-Ref", "acct-1"),
            ("X-Internal-Tag", "secret"),
            ("P-Charging-Vector", "icid-value=foo"),
            ("Subject", "Test"),
        ]);
        apply_to_request(&mut msg, &policy, &ctx());

        assert!(
            msg.headers.has("X-Account-Ref"),
            "the opted-in header crosses"
        );
        assert!(
            !msg.headers.has("X-Internal-Tag"),
            "base X-* strip still applies"
        );
        assert!(
            !msg.headers.has("P-Charging-Vector"),
            "base P-* strip still applies"
        );
        assert!(
            msg.headers.has("Subject"),
            "base default (copy) still applies"
        );
    }

    #[test]
    fn custom_rule_beats_an_inherited_rule() {
        let policy = resolved(
            concat!(
                "\"quiet@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    strip: [\"Subject\"]\n",
            ),
            "quiet@1",
        );

        let mut msg = invite_with(&[("Subject", "Test")]);
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(
            !msg.headers.has("Subject"),
            "custom strip must beat the base default of copy"
        );
    }

    #[test]
    fn exact_rule_beats_prefix_rule_in_the_same_block() {
        // The ordering that makes "strip the family, keep this one" expressible
        // in a single block rather than needing two policies.
        let policy = resolved(
            concat!(
                "\"selective@1\":\n",
                "  request:\n",
                "    default: copy\n",
                "    strip: [\"X-*\"]\n",
                "    copy: [\"X-Account-Ref\"]\n",
                "  response:\n",
                "    default: copy\n",
            ),
            "selective@1",
        );

        let mut msg = invite_with(&[("X-Account-Ref", "acct-1"), ("X-Internal-Tag", "secret")]);
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(msg.headers.has("X-Account-Ref"));
        assert!(!msg.headers.has("X-Internal-Tag"));
    }

    #[test]
    fn longer_prefix_beats_shorter_prefix() {
        let policy = resolved(
            concat!(
                "\"selective@1\":\n",
                "  request:\n",
                "    default: copy\n",
                "    strip: [\"X-*\"]\n",
                "    copy: [\"X-Keep-*\"]\n",
                "  response:\n",
                "    default: copy\n",
            ),
            "selective@1",
        );

        let mut msg = invite_with(&[("X-Keep-This", "yes"), ("X-Drop-This", "no")]);
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(msg.headers.has("X-Keep-This"));
        assert!(!msg.headers.has("X-Drop-This"));
    }

    #[test]
    fn omitted_direction_inherits_the_base_verbatim() {
        let preset = resolve_one(
            concat!(
                "\"boundary-plus@1\":\n",
                "  extends: \"ims-trust-domain-boundary@2026\"\n",
                "  request:\n",
                "    copy: [\"X-Account-Ref\"]\n",
            ),
            "boundary-plus@1",
        )
        .expect("policy should resolve");

        let base = builtin_presets();
        let base = base
            .get("ims-trust-domain-boundary@2026")
            .expect("built-in present");
        assert_eq!(preset.response.default, base.response.default);
        assert_eq!(
            preset.response.overrides.len(),
            base.response.overrides.len()
        );

        // And it behaves like the base: default-strip with the safe set copied.
        let policy = ResolvedPolicy::from_preset(Arc::new(preset));
        let mut msg = ok_with(&[("Allow", "INVITE"), ("Organization", "Example")]);
        apply_to_response(&mut msg, &policy, &ctx());
        assert!(msg.headers.has("Allow"));
        assert!(!msg.headers.has("Organization"));
    }

    #[test]
    fn standalone_policy_declares_both_directions_in_full() {
        let policy = resolved(
            concat!(
                "\"locked-down@1\":\n",
                "  request:\n",
                "    default: strip\n",
                "    copy: [\"Allow\", \"Supported\"]\n",
                "  response:\n",
                "    default: copy\n",
                "    strip: [\"P-*\", \"Server\"]\n",
            ),
            "locked-down@1",
        );

        let mut request = invite_with(&[("Allow", "INVITE"), ("Subject", "Test")]);
        apply_to_request(&mut request, &policy, &ctx());
        assert!(request.headers.has("Allow"));
        assert!(!request.headers.has("Subject"), "default: strip applies");

        let mut response = ok_with(&[("P-Charging-Vector", "icid-value=foo"), ("Allow", "INVITE")]);
        apply_to_response(&mut response, &policy, &ctx());
        assert!(!response.headers.has("P-Charging-Vector"));
        assert!(response.headers.has("Allow"), "default: copy applies");
    }

    #[test]
    fn extends_alone_aliases_the_base_under_a_local_name() {
        // Legitimate: pin a stable local name so scripts don't carry the
        // built-in's version around.
        let preset = resolve_one(
            "\"our-trunk@1\":\n  extends: \"sip-trunk-edge@2026\"\n",
            "our-trunk@1",
        )
        .expect("alias should resolve");
        let policy = ResolvedPolicy::from_preset(Arc::new(preset));

        let mut msg = invite_with(&[("X-Internal-Tag", "secret"), ("Subject", "Test")]);
        apply_to_request(&mut msg, &policy, &ctx());
        assert!(!msg.headers.has("X-Internal-Tag"));
        assert!(msg.headers.has("Subject"));
    }

    #[test]
    fn config_rewrite_and_translate_ops_reach_the_engine() {
        let policy = resolved(
            concat!(
                "\"edge@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    rewrite:\n",
                "      P-Asserted-Identity: host-to-advertised\n",
                "    translate:\n",
                "      Diversion: diversion-to-history-info\n",
            ),
            "edge@1",
        );

        let mut msg = invite_with(&[
            ("P-Asserted-Identity", "<sip:alice@internal.example>"),
            (
                "Diversion",
                "<sip:+12025550123@example.com>;reason=user-busy",
            ),
        ]);
        apply_to_request(&mut msg, &policy, &ctx());

        let pai = msg
            .headers
            .get("P-Asserted-Identity")
            .expect("P-Asserted-Identity present");
        assert!(pai.contains("192.0.2.1"), "host rewritten: {pai}");
        assert!(!msg.headers.has("Diversion"));
        let history = msg
            .headers
            .get("History-Info")
            .expect("History-Info present");
        assert!(
            history.contains("cause%3D486"),
            "user-busy → 486: {history}"
        );
    }

    // ----- Rejections -----

    #[test]
    fn rejects_unversioned_name() {
        let error = resolve_one(
            "trunk-edge-plus:\n  extends: \"sip-trunk-edge@2026\"\n",
            "trunk-edge-plus",
        )
        .expect_err("an unversioned key must be refused");
        assert!(matches!(error, PresetError::UnversionedName(_)), "{error}");
    }

    #[test]
    fn rejects_empty_version() {
        let error = resolve_one(
            "\"trunk@\":\n  extends: \"sip-trunk-edge@2026\"\n",
            "trunk@",
        )
        .expect_err("an empty version must be refused");
        assert!(matches!(error, PresetError::UnversionedName(_)), "{error}");
    }

    #[test]
    fn rejects_a_name_that_collides_with_a_builtin() {
        let error = build_registry(&policies(
            "\"sip-trunk-edge@2026\":\n  extends: \"transparent-b2bua@2026\"\n",
        ))
        .expect_err("redefining a built-in must be refused");
        assert!(
            matches!(error, PresetError::NameCollidesWithBuiltin(_)),
            "{error}"
        );
    }

    #[test]
    fn rejects_unknown_extends_target() {
        let error = resolve_one("\"x@1\":\n  extends: \"no-such-preset@2026\"\n", "x@1")
            .expect_err("extending a non-existent preset must be refused");
        assert!(matches!(error, PresetError::UnknownBase { .. }), "{error}");
    }

    #[test]
    fn extends_cannot_name_another_custom_policy() {
        // Resolution is against the built-ins only, so the result never depends
        // on which order the map was iterated in.
        let error = build_registry(&policies(concat!(
            "\"a@1\":\n",
            "  extends: \"sip-trunk-edge@2026\"\n",
            "\"b@1\":\n",
            "  extends: \"a@1\"\n",
        )))
        .expect_err("extending a custom policy must be refused");
        assert!(matches!(error, PresetError::UnknownBase { .. }), "{error}");
    }

    #[test]
    fn rejects_unknown_rewrite_op() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    rewrite:\n",
                "      P-Asserted-Identity: make-it-nice\n",
            ),
            "x@1",
        )
        .expect_err("an unknown rewrite op must be refused");
        assert!(
            matches!(error, PresetError::UnknownRewriteOp { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_unknown_translate_op() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    translate:\n",
                "      Diversion: rfc9999\n",
            ),
            "x@1",
        )
        .expect_err("an unknown translate op must be refused");
        assert!(
            matches!(error, PresetError::UnknownTranslateOp { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_the_same_header_twice_in_one_direction() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    strip: [\"Alert-Info\"]\n",
                "    copy: [\"Alert-Info\"]\n",
            ),
            "x@1",
        )
        .expect_err("a header with two verbs must be refused");
        assert!(
            matches!(error, PresetError::DuplicatePattern { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_rule_aimed_at_a_framework_managed_header() {
        // Silently ignoring these is how someone concludes the feature is broken.
        for token in &["Via", "call-id", "Record-Route"] {
            let yaml = format!(
                concat!(
                    "\"x@1\":\n",
                    "  extends: \"transparent-b2bua@2026\"\n",
                    "  request:\n",
                    "    copy: [\"{}\"]\n",
                ),
                token
            );
            let error =
                resolve_one(&yaml, "x@1").expect_err("a framework-auto rule must be refused");
            assert!(
                matches!(error, PresetError::FrameworkAutoHeader { .. }),
                "{token}: {error}"
            );
        }
    }

    #[test]
    fn rejects_a_prefix_that_would_swallow_a_framework_managed_header() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    strip: [\"Co*\"]\n",
            ),
            "x@1",
        )
        .expect_err("a prefix matching Contact/Content-Length must be refused");
        assert!(
            matches!(error, PresetError::FrameworkAutoHeader { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_bare_wildcard() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    strip: [\"*\"]\n",
            ),
            "x@1",
        )
        .expect_err("a bare wildcard must be refused");
        assert!(
            matches!(error, PresetError::InvalidPattern { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_leading_wildcard() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    strip: [\"*-Info\"]\n",
            ),
            "x@1",
        )
        .expect_err("a non-trailing wildcard must be refused");
        assert!(
            matches!(error, PresetError::InvalidPattern { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_standalone_direction_without_a_default() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  request:\n",
                "    copy: [\"Allow\"]\n",
                "  response:\n",
                "    default: copy\n",
            ),
            "x@1",
        )
        .expect_err("a standalone direction needs a default");
        assert!(
            matches!(error, PresetError::MissingDefault { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_default_alongside_extends() {
        let error = resolve_one(
            concat!(
                "\"x@1\":\n",
                "  extends: \"transparent-b2bua@2026\"\n",
                "  request:\n",
                "    default: strip\n",
            ),
            "x@1",
        )
        .expect_err("extends supplies the default");
        assert!(
            matches!(error, PresetError::DefaultWithExtends { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_standalone_policy_missing_a_direction() {
        let error = resolve_one("\"x@1\":\n  request:\n    default: copy\n", "x@1")
            .expect_err("a standalone policy must declare both directions");
        assert!(
            matches!(error, PresetError::MissingDirection { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_an_empty_policy() {
        let error = resolve_one("\"x@1\": {}\n", "x@1").expect_err("an empty policy is a mistake");
        assert!(matches!(error, PresetError::EmptyPolicy(_)), "{error}");
    }

    #[test]
    fn rejects_an_unknown_field() {
        // `deny_unknown_fields` — a misspelled key must not be silently ignored.
        let yaml = "\"x@1\":\n  extends: \"transparent-b2bua@2026\"\n  requests:\n    copy: []\n";
        let parsed: std::result::Result<HashMap<String, HeaderPolicyConfig>, _> =
            serde_yaml_ng::from_str(yaml);
        assert!(parsed.is_err(), "misspelled `requests:` must not parse");
    }

    #[test]
    fn preset_validation_runs_on_custom_policies_too() {
        // Copying Authorization across a hop that rewrites a Digest-protected
        // field breaks the hash — the same guard the built-ins are held to.
        let error = build_registry(&policies(concat!(
            "\"broken@1\":\n",
            "  extends: \"transparent-b2bua@2026\"\n",
            "  request:\n",
            "    copy: [\"Authorization\"]\n",
        )))
        .expect_err("Authorization copy + inherited PAI rewrite must be refused");
        assert!(
            matches!(
                error,
                PresetError::AuthorizationCopyWithDigestProtectedRewrite(_)
            ),
            "{error}"
        );
    }

    // ----- Registry -----

    #[test]
    fn registry_carries_builtins_alongside_custom_policies() {
        let registry = build_registry(&policies(
            "\"trunk-edge-plus@1\":\n  extends: \"sip-trunk-edge@2026\"\n",
        ))
        .expect("registry should build");

        assert!(registry.contains_key("trunk-edge-plus@1"));
        for builtin in &[
            "transparent-b2bua@2026",
            "ims-intra-trust-domain@2026",
            "ims-trust-domain-boundary@2026",
            "sip-trunk-edge@2026",
        ] {
            assert!(registry.contains_key(*builtin), "{builtin} must survive");
        }
    }

    #[test]
    fn registry_with_no_custom_policies_is_exactly_the_builtins() {
        let registry = build_registry(&HashMap::new()).expect("registry should build");
        assert_eq!(registry.len(), builtin_presets().len());
    }

    #[test]
    fn custom_preset_reports_its_qualified_name_as_the_map_key() {
        let preset = resolve_one(
            "\"trunk-edge-plus@1\":\n  extends: \"sip-trunk-edge@2026\"\n",
            "trunk-edge-plus@1",
        )
        .expect("policy should resolve");
        assert_eq!(preset.qualified_name(), "trunk-edge-plus@1");
        assert_eq!(preset.name, "trunk-edge-plus");
        assert_eq!(preset.version, "1");
    }

    // ----- Op tokens -----

    #[test]
    fn translate_op_tokens_are_shared_with_the_dial_time_spelling() {
        // `call.dial(translate=[(…, "rfc7044")])` and `translate: rfc7044` in
        // config must never drift apart.
        assert_eq!(
            TranslateOp::from_token("rfc7044"),
            Some(TranslateOp::DiversionToHistoryInfo)
        );
        assert_eq!(
            TranslateOp::from_token("Diversion_To_History_Info"),
            Some(TranslateOp::DiversionToHistoryInfo)
        );
        assert_eq!(TranslateOp::from_token("rfc5806"), None);
    }

    #[test]
    fn rewrite_op_tokens_cover_every_op() {
        assert_eq!(
            RewriteOp::from_token("host-to-advertised"),
            Some(RewriteOp::HostToAdvertised)
        );
        assert_eq!(
            RewriteOp::from_token("replace-with-server-header"),
            Some(RewriteOp::ReplaceWithServerHeader)
        );
        assert_eq!(
            RewriteOp::from_token("replace-with-user-agent-header"),
            Some(RewriteOp::ReplaceWithUserAgentHeader)
        );
        assert_eq!(RewriteOp::from_token("nope"), None);
        assert_eq!(RewriteOp::tokens().len(), 3, "tokens() must list every op");
    }

    #[test]
    fn header_pattern_from_token_reads_the_two_forms() {
        assert_eq!(
            HeaderPattern::from_token("Alert-Info"),
            Ok(HeaderPattern::Exact("Alert-Info".to_string()))
        );
        assert_eq!(
            HeaderPattern::from_token("X-*"),
            Ok(HeaderPattern::Prefix("X-".to_string()))
        );
        assert!(HeaderPattern::from_token("  ").is_err());
    }
}
