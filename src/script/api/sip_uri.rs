//! PyO3 wrapper for [`SipUri`] — exposed to Python scripts as `SipUri`.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::sip::uri::SipUri;

/// Python-visible SIP URI object.
#[pyclass(name = "SipUri", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PySipUri {
    inner: SipUri,
    /// Local domains from config — used by `is_local` property.
    local_domains: Option<Arc<Vec<String>>>,
}

impl PySipUri {
    /// Create a new `PySipUri` wrapping a Rust `SipUri`.
    pub fn new(uri: SipUri) -> Self {
        Self {
            inner: uri,
            local_domains: None,
        }
    }

    /// Create a new `PySipUri` with local domain awareness.
    pub fn with_local_domains(uri: SipUri, local_domains: Arc<Vec<String>>) -> Self {
        Self {
            inner: uri,
            local_domains: Some(local_domains),
        }
    }

    /// Borrow the inner `SipUri`.
    pub fn inner(&self) -> &SipUri {
        &self.inner
    }
}

#[pymethods]
impl PySipUri {
    #[getter]
    fn scheme(&self) -> &str {
        &self.inner.scheme
    }

    #[getter]
    fn user(&self) -> Option<&str> {
        self.inner.user.as_deref()
    }

    #[setter]
    fn set_user(&mut self, value: Option<String>) {
        self.inner.user = value;
    }

    #[getter]
    fn host(&self) -> &str {
        &self.inner.host
    }

    #[setter]
    fn set_host(&mut self, value: String) {
        self.inner.host = value;
    }

    #[getter]
    fn port(&self) -> Option<u16> {
        self.inner.port
    }

    #[setter]
    fn set_port(&mut self, value: Option<u16>) {
        self.inner.port = value;
    }

    /// Whether this is a tel: URI (scheme == "tel").
    #[getter]
    fn is_tel(&self) -> bool {
        self.inner.scheme.eq_ignore_ascii_case("tel")
    }

    /// Whether the URI host matches one of the configured local domains.
    #[getter]
    fn is_local(&self) -> bool {
        match &self.local_domains {
            Some(domains) => domains
                .iter()
                .any(|domain| domain.eq_ignore_ascii_case(&self.inner.host)),
            None => false,
        }
    }

    /// URI parameters as a dict.  Flag parameters (no `=value`, e.g.
    /// `;lr` or `;ob`) appear with an empty-string value.  Useful for
    /// reading parameters off a Path/Route URI the script consumed —
    /// e.g. checking `;ob` on an RFC 5626 outbound flow token, or
    /// extracting custom params from a P-CSCF Path entry.
    #[getter]
    fn params(&self) -> std::collections::BTreeMap<String, String> {
        self.inner
            .params
            .iter()
            .map(|(name, value)| (name.clone(), value.clone().unwrap_or_default()))
            .collect()
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("SipUri({})", self.inner)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getters_return_uri_fields() {
        let uri = SipUri::new("example.com".to_string())
            .with_user("alice".to_string())
            .with_port(5060);
        let py_uri = PySipUri::new(uri);

        assert_eq!(py_uri.scheme(), "sip");
        assert_eq!(py_uri.user(), Some("alice"));
        assert_eq!(py_uri.host(), "example.com");
        assert_eq!(py_uri.port(), Some(5060));
    }

    #[test]
    fn str_and_repr() {
        let uri = SipUri::new("example.com".to_string()).with_user("bob".to_string());
        let py_uri = PySipUri::new(uri);

        assert_eq!(py_uri.__str__(), "sip:bob@example.com");
        assert_eq!(py_uri.__repr__(), "SipUri(sip:bob@example.com)");
    }

    #[test]
    fn uri_without_user() {
        let uri = SipUri::new("proxy.example.com".to_string());
        let py_uri = PySipUri::new(uri);

        assert_eq!(py_uri.user(), None);
        assert_eq!(py_uri.port(), None);
        assert_eq!(py_uri.__str__(), "sip:proxy.example.com");
    }

    #[test]
    fn is_local_without_domains() {
        let uri = SipUri::new("example.com".to_string());
        let py_uri = PySipUri::new(uri);
        assert!(!py_uri.is_local());
    }

    #[test]
    fn is_local_with_matching_domain() {
        let domains = Arc::new(vec!["example.com".to_string(), "127.0.0.1".to_string()]);
        let uri = SipUri::new("example.com".to_string());
        let py_uri = PySipUri::with_local_domains(uri, domains);
        assert!(py_uri.is_local());
    }

    #[test]
    fn is_local_with_non_matching_domain() {
        let domains = Arc::new(vec!["example.com".to_string()]);
        let uri = SipUri::new("other.com".to_string());
        let py_uri = PySipUri::with_local_domains(uri, domains);
        assert!(!py_uri.is_local());
    }

    #[test]
    fn is_local_case_insensitive() {
        let domains = Arc::new(vec!["Example.COM".to_string()]);
        let uri = SipUri::new("example.com".to_string());
        let py_uri = PySipUri::with_local_domains(uri, domains);
        assert!(py_uri.is_local());
    }

    #[test]
    fn set_user() {
        let uri = SipUri::new("example.com".to_string());
        let mut py_uri = PySipUri::new(uri);
        assert_eq!(py_uri.user(), None);

        py_uri.set_user(Some("alice".to_string()));
        assert_eq!(py_uri.user(), Some("alice"));
        assert_eq!(py_uri.__str__(), "sip:alice@example.com");

        py_uri.set_user(None);
        assert_eq!(py_uri.user(), None);
        assert_eq!(py_uri.__str__(), "sip:example.com");
    }

    #[test]
    fn set_host() {
        let uri = SipUri::new("example.com".to_string()).with_user("alice".to_string());
        let mut py_uri = PySipUri::new(uri);
        py_uri.set_host("other.com".to_string());
        assert_eq!(py_uri.host(), "other.com");
        assert_eq!(py_uri.__str__(), "sip:alice@other.com");
    }

    #[test]
    fn set_port() {
        let uri = SipUri::new("example.com".to_string());
        let mut py_uri = PySipUri::new(uri);
        assert_eq!(py_uri.port(), None);

        py_uri.set_port(Some(5080));
        assert_eq!(py_uri.port(), Some(5080));

        py_uri.set_port(None);
        assert_eq!(py_uri.port(), None);
    }

    #[test]
    fn is_tel_false_for_sip() {
        let uri = SipUri::new("example.com".to_string());
        let py_uri = PySipUri::new(uri);
        assert!(!py_uri.is_tel());
    }

    #[test]
    fn is_tel_true_for_tel_scheme() {
        let uri = SipUri {
            scheme: "tel".to_string(),
            user: Some("+12125551234".to_string()),
            host: String::new(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
            user_params: Vec::new(),
        };
        let py_uri = PySipUri::new(uri);
        assert!(py_uri.is_tel());
    }
}
