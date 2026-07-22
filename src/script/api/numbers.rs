//! PyO3 wrapper for E.164 number normalization — the `numbers` namespace and
//! the shared policy resolver behind `request.rewrite_identities()` /
//! `call.rewrite_identities()` / `call.dial(number_policy=…)`.
//!
//! ```python
//! from siphon import numbers
//! n = numbers.parse("0031612345678")   # -> Number
//! n.e164                                  # "+31612345678"
//! n.national                             # "0612345678"
//! n.format("plain")                      # "31612345678"
//! ```

use std::sync::{Arc, OnceLock};

use pyo3::prelude::*;

use crate::numbers::policy::{
    apply, apply_headers_only, reformat_target, IdentityHeader, NumberPolicy, NumberRegistry,
    DEFAULT_IDENTITY_HEADERS,
};
use crate::numbers::{Number, NumberFormat};
use crate::sip::message::SipMessage;

// ---------------------------------------------------------------------------
// Global runtime — the resolved registry + the B2BUA default policy
// ---------------------------------------------------------------------------

/// Resolved number-policy state shared read-only with the proxy and B2BUA
/// paths. Installed once at startup from `numbering:` / `number_policies:` /
/// `b2bua.default_number_policy`.
#[derive(Debug, Default)]
pub struct NumberRuntime {
    pub registry: NumberRegistry,
    /// Policy applied to B2BUA calls that don't pass `number_policy=`.
    pub default_b2bua_policy: Option<Arc<NumberPolicy>>,
}

static NUMBER_RUNTIME: OnceLock<Arc<NumberRuntime>> = OnceLock::new();

/// Install the process-wide number runtime. Idempotent — the first install
/// wins (subsequent script reloads reuse it; policies are config, not script).
pub fn set_number_runtime(runtime: Arc<NumberRuntime>) {
    let _ = NUMBER_RUNTIME.set(runtime);
}

/// The installed runtime, or a default (empty registry, blank home locale) when
/// `numbering:` was absent from the config.
pub fn number_runtime() -> Arc<NumberRuntime> {
    NUMBER_RUNTIME
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(NumberRuntime::default()))
}

/// The B2BUA default policy, if `b2bua.default_number_policy` is set.
pub fn default_b2bua_policy() -> Option<Arc<NumberPolicy>> {
    number_runtime().default_b2bua_policy.clone()
}

// ---------------------------------------------------------------------------
// Shared policy resolution (named or inline)
// ---------------------------------------------------------------------------

/// Resolve the arguments of a `rewrite_identities()` call into a policy.
///
/// Exactly one of `policy` (a named registry entry) or `format` (an inline
/// single-format policy over `headers`, defaulting to the standard identity
/// set) must be supplied. `home` overrides the home country code inline.
pub fn resolve_rewrite_policy(
    policy: Option<&str>,
    format: Option<&str>,
    headers: Option<Vec<String>>,
    home: Option<&str>,
) -> PyResult<Arc<NumberPolicy>> {
    let runtime = number_runtime();

    if let Some(name) = policy {
        if format.is_some() || headers.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "rewrite_identities(): pass either policy= or format=, not both",
            ));
        }
        return runtime.registry.get(name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("unknown number policy {name:?}"))
        });
    }

    let Some(format) = format else {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rewrite_identities(): requires policy= (named) or format= (inline)",
        ));
    };

    let format: NumberFormat = format
        .parse()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))?;

    let walk = match headers {
        Some(tokens) => {
            let mut walk = Vec::with_capacity(tokens.len());
            for token in &tokens {
                let header = IdentityHeader::from_token(token).ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown identity header {token:?}"
                    ))
                })?;
                if !walk.contains(&header) {
                    walk.push(header);
                }
            }
            walk
        }
        None => DEFAULT_IDENTITY_HEADERS.to_vec(),
    };

    let mut locale = runtime.registry.default_locale.clone();
    if let Some(home) = home {
        locale.country_code = home.trim().strip_prefix('+').unwrap_or(home.trim()).to_string();
    }

    Ok(Arc::new(NumberPolicy::uniform(locale, format, walk)))
}

/// Apply a resolved policy to a locked message (proxy / `rewrite_identities`
/// path — includes the Request-URI). Returns the count of changed headers.
pub fn apply_to_message(message: &mut SipMessage, policy: &NumberPolicy) -> usize {
    apply(message, policy).changed()
}

/// Reshape only the identity headers (From / To / P-Asserted-Identity /
/// P-Preferred-Identity) of a message, leaving the Request-URI untouched. Used
/// by the LCR per-carrier `number_policy` so a carrier's From/To shape can
/// differ while `tech_prefix` / `ruri` own the R-URI.
pub fn apply_identity_headers(message: &mut SipMessage, policy: &NumberPolicy) {
    apply_headers_only(message, policy);
}

/// B2BUA dial path: normalize the header identities on the A-leg INVITE (which
/// flow to the B-leg) and return the normalized dial target. The A-leg
/// Request-URI is left alone; the dial `target` carries the B-leg R-URI.
pub fn apply_for_dial(message: &mut SipMessage, policy: &NumberPolicy, target: &str) -> String {
    apply_headers_only(message, policy);
    let format = policy.format_for(IdentityHeader::RequestUri);
    reformat_target(target, format, policy)
}

/// B2BUA fork path: normalize the A-leg header identities once, then normalize
/// each branch target in place.
pub fn apply_for_fork(message: &mut SipMessage, policy: &NumberPolicy, targets: &mut [String]) {
    apply_headers_only(message, policy);
    let format = policy.format_for(IdentityHeader::RequestUri);
    for target in targets.iter_mut() {
        *target = reformat_target(target, format, policy);
    }
}

/// Resolve a `number_policy=` argument for the B2BUA dial/fork path: an explicit
/// named policy, else the `b2bua.default_number_policy`, else `None`.
pub fn resolve_dial_policy(name: Option<&str>) -> PyResult<Option<Arc<NumberPolicy>>> {
    match name {
        Some(name) => number_runtime()
            .registry
            .get(name)
            .map(Some)
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!("unknown number policy {name:?}"))
            }),
        None => Ok(default_b2bua_policy()),
    }
}

// ---------------------------------------------------------------------------
// numbers namespace
// ---------------------------------------------------------------------------

/// Stateless number-parsing namespace, injected as `siphon.numbers`.
#[pyclass(name = "NumbersNamespace")]
pub struct PyNumbersNamespace;

impl Default for PyNumbersNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl PyNumbersNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyNumbersNamespace {
    /// Parse a raw number string into a [`PyNumber`] using the configured home
    /// numbering plan. `home` overrides the home country code (digits) for this
    /// call.
    ///
    /// Raises `ValueError` when the string is not a dialable number.
    #[pyo3(signature = (raw, home=None))]
    fn parse(&self, raw: &str, home: Option<&str>) -> PyResult<PyNumber> {
        let runtime = number_runtime();
        let mut locale = runtime.registry.default_locale.clone();
        if let Some(home) = home {
            locale.country_code =
                home.trim().strip_prefix('+').unwrap_or(home.trim()).to_string();
        }
        let number = Number::parse(raw, &locale)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))?;
        Ok(PyNumber { inner: number })
    }

    /// Names of the configured number policies.
    fn policy_names(&self) -> Vec<String> {
        let mut names: Vec<String> = number_runtime()
            .registry
            .policies
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }

    fn __repr__(&self) -> String {
        "<siphon.numbers>".to_string()
    }
}

/// A parsed telephone number. Format it into any E.164 shape.
#[pyclass(name = "Number")]
pub struct PyNumber {
    inner: Number,
}

#[pymethods]
impl PyNumber {
    /// Global E.164, `+CCNSN` (e.g. `+31612345678`).
    #[getter]
    fn e164(&self) -> String {
        self.inner.format(NumberFormat::E164)
    }

    /// E.164 digits, no `+` (e.g. `31612345678`).
    #[getter]
    fn plain(&self) -> String {
        self.inner.format(NumberFormat::Plain)
    }

    /// International access form (e.g. `0031612345678`).
    #[getter]
    fn international(&self) -> String {
        self.inner.format(NumberFormat::International)
    }

    /// National trunk form (e.g. `0612345678`); international form for a
    /// foreign number.
    #[getter]
    fn national(&self) -> String {
        self.inner.format(NumberFormat::National)
    }

    /// Country code, if it matched the configured home country, else `None`.
    #[getter]
    fn cc(&self) -> Option<String> {
        self.inner.country_code().map(str::to_string)
    }

    /// National significant number (digits after the country code).
    #[getter]
    fn nsn(&self) -> String {
        self.inner.nsn().to_string()
    }

    /// Format into a named shape: `"e164"`, `"plain"`, `"international"`,
    /// `"national"`.
    fn format(&self, format: &str) -> PyResult<String> {
        let format: NumberFormat = format
            .parse()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e}")))?;
        Ok(self.inner.format(format))
    }

    fn __str__(&self) -> String {
        self.inner.format(NumberFormat::E164)
    }

    fn __repr__(&self) -> String {
        format!("<Number {}>", self.inner.format(NumberFormat::E164))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_inline_format_default_headers() {
        let policy = resolve_rewrite_policy(None, Some("e164"), None, Some("31")).unwrap();
        assert_eq!(policy.default_format, NumberFormat::E164);
        assert_eq!(policy.locale.country_code, "31");
        assert_eq!(policy.headers, DEFAULT_IDENTITY_HEADERS.to_vec());
    }

    #[test]
    fn resolve_inline_rejects_both_policy_and_format() {
        let result = resolve_rewrite_policy(Some("x@2026"), Some("e164"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_requires_something() {
        assert!(resolve_rewrite_policy(None, None, None, None).is_err());
    }

    #[test]
    fn resolve_unknown_header_token_errors() {
        let result =
            resolve_rewrite_policy(None, Some("e164"), Some(vec!["bogus".to_string()]), None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_unknown_named_policy_errors() {
        // With no runtime installed the registry is empty.
        assert!(resolve_rewrite_policy(Some("nope@2026"), None, None, None).is_err());
    }
}
