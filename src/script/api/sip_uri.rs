//! PyO3 wrapper for [`SipUri`] — exposed to Python scripts as `SipUri`.

use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::sip::message::{SipMessage, StartLine};
use crate::sip::parser::parse_uri_complete;
use crate::sip::uri::{format_sip_host, strip_ipv6_brackets, Scheme, SipUri};

/// Python-visible SIP URI object.
#[pyclass(name = "SipUri", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PySipUri {
    inner: SipUri,
    /// Local domains from config — used by `is_local` property.
    local_domains: Option<Arc<Vec<String>>>,
    /// Set on the object `request.ruri` hands out: the request whose
    /// Request-URI this is. Its setters then write through
    /// [`commit_request_uri`] instead of changing a copy nobody sends.
    request: Option<Arc<Mutex<SipMessage>>>,
}

impl PySipUri {
    /// Create a new `PySipUri` wrapping a Rust `SipUri`.
    pub fn new(uri: SipUri) -> Self {
        Self {
            inner: uri,
            local_domains: None,
            request: None,
        }
    }

    /// Create a new `PySipUri` with local domain awareness.
    pub fn with_local_domains(uri: SipUri, local_domains: Arc<Vec<String>>) -> Self {
        Self {
            inner: uri,
            local_domains: Some(local_domains),
            request: None,
        }
    }

    /// Bind this object to the Request-URI of `message`, so assigning to
    /// `user` / `host` / `port` rewrites the request rather than this copy.
    pub fn bound_to_request(mut self, message: Arc<Mutex<SipMessage>>) -> Self {
        self.request = Some(message);
        self
    }

    /// Apply one component change. A bound object re-reads the live
    /// Request-URI first, so a stale copy cannot put back a part another
    /// setter has changed since it was read.
    fn update(&mut self, change: impl FnOnce(&mut SipUri)) -> PyResult<()> {
        let mut candidate = match &self.request {
            Some(message) => current_request_uri(message)?,
            None => self.inner.clone(),
        };
        change(&mut candidate);
        self.inner = match &self.request {
            Some(message) => commit_request_uri(message, candidate)?,
            None => checked_uri(candidate)?,
        };
        Ok(())
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
        self.inner.scheme.as_str()
    }

    #[getter]
    fn user(&self) -> Option<&str> {
        self.inner.user.as_deref()
    }

    /// Assigning on `request.ruri` rewrites the Request-URI; same rules as
    /// `request.set_ruri_user()`.
    #[setter]
    fn set_user(&mut self, value: Option<String>) -> PyResult<()> {
        if let Some(user) = &value {
            check_user(user)?;
        }
        self.update(|uri| set_user_part(uri, value))
    }

    #[getter]
    fn host(&self) -> &str {
        &self.inner.host
    }

    /// Assigning on `request.ruri` rewrites the Request-URI; same rules as
    /// `request.set_ruri_host()`.
    #[setter]
    fn set_host(&mut self, value: String) -> PyResult<()> {
        let host = check_host(&value)?;
        self.update(|uri| uri.host = host)
    }

    #[getter]
    fn port(&self) -> Option<u16> {
        self.inner.port
    }

    #[setter]
    fn set_port(&mut self, value: Option<u16>) -> PyResult<()> {
        if value == Some(0) {
            return Err(PyValueError::new_err("URI port 0 is not a port"));
        }
        self.update(|uri| uri.port = value)
    }

    /// Whether this is a tel: URI (scheme == "tel").
    ///
    /// Case-insensitive on the token, not `Scheme::is_tel`. The parser only
    /// produces `Scheme::Tel` for a lowercase `tel:` (RFC 3966 §3); a
    /// differently-cased one is an `absoluteURI` and lands in `Scheme::Other`
    /// with its spelling intact. This property has always answered `True` for
    /// that shape and scripts branch on it, so it keeps doing so.
    #[getter]
    fn is_tel(&self) -> bool {
        self.inner.scheme.as_str().eq_ignore_ascii_case("tel")
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
// Validation: every write a script makes to a URI goes through here
// ---------------------------------------------------------------------------

fn invalid(message: String) -> PyErr {
    PyValueError::new_err(message)
}

/// The Request-URI of `message`, owned.
pub(crate) fn current_request_uri(message: &Mutex<SipMessage>) -> PyResult<SipUri> {
    let guard = lock(message)?;
    match &guard.start_line {
        StartLine::Request(request_line) => Ok(request_line.request_uri.clone()),
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err("not a request")),
    }
}

/// The one place a script's change to the Request-URI is written. Every path
/// ends here (`set_ruri`, the `ruri` property, `set_ruri_user` / `_host` /
/// `_param`, and assigning on `request.ruri`), so what goes on the wire has
/// always passed [`checked_uri`]. Returns what was stored.
pub(crate) fn commit_request_uri(
    message: &Mutex<SipMessage>,
    candidate: SipUri,
) -> PyResult<SipUri> {
    let checked = checked_uri(candidate)?;
    let mut guard = lock(message)?;
    match &mut guard.start_line {
        StartLine::Request(request_line) => {
            request_line.request_uri = checked.clone();
            Ok(checked)
        }
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err("not a request")),
    }
}

fn lock(message: &Mutex<SipMessage>) -> PyResult<std::sync::MutexGuard<'_, SipMessage>> {
    message.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
    })
}

/// Whole-URI check: the host is an address or a name, and the URI reads back
/// from its own wire form as exactly what was built. The round trip is what
/// catches a part that would change meaning once serialized, e.g. a `;` in a
/// user that the next parser splits into user parameters.
pub(crate) fn checked_uri(mut uri: SipUri) -> PyResult<SipUri> {
    if matches!(uri.scheme, Scheme::Sip | Scheme::Sips) {
        uri.host = checked_address(&uri.host)?;
    }
    // One shape for "no extras", so an equal URI compares equal.
    let (headers, user_params) = (uri.headers().to_vec(), uri.user_params().to_vec());
    uri.set_extras(headers, user_params);

    let wire = uri.to_string();
    let reparsed =
        parse_uri_complete(&wire).map_err(|error| invalid(format!("invalid URI: {error}")))?;
    if reparsed != uri {
        return Err(invalid(format!(
            "invalid URI {wire:?}: it does not read back as the URI that was set \
             (a user part holding ';' parameters belongs in set_ruri())"
        )));
    }
    Ok(uri)
}

/// Every component of a URI a script supplied whole (`set_ruri`).
pub(crate) fn check_components(uri: &SipUri) -> PyResult<()> {
    if matches!(uri.scheme, Scheme::Sip | Scheme::Sips) {
        if let Some(user) = &uri.user {
            check_user(user)?;
        }
        check_host(&uri.host)?;
    }
    for (name, value) in uri.params.iter().chain(uri.user_params()) {
        check_param(name, value.as_deref())?;
    }
    Ok(())
}

/// `sip:` user part. Refuses what would change the URI's structure; other
/// characters (a `*21#` service code) pass as they always have.
pub(crate) fn check_user(value: &str) -> PyResult<()> {
    if value.is_empty() {
        return Err(invalid(
            "empty URI user: pass None to remove the user part".to_string(),
        ));
    }
    if value.contains(';') {
        return Err(invalid(format!(
            "invalid URI user {value:?}: user parameters (e.g. RFC 4694 npdi/rn) \
             go in a full URI via set_ruri()"
        )));
    }
    if let Some(bad) = value.chars().find(|c| {
        matches!(c, '@' | ':' | '?' | '<' | '>' | '"') || c.is_whitespace() || c.is_control()
    }) {
        return Err(invalid(format!(
            "invalid URI user {value:?}: {bad:?} is not allowed (just the user, no scheme, host or port)"
        )));
    }
    Ok(())
}

/// A bare host: domain, IPv4 or IPv6 (brackets optional). Returns it in the
/// form the parser stores, with an IPv6 address bracketed.
pub(crate) fn check_host(value: &str) -> PyResult<String> {
    let refuse = || {
        invalid(format!(
            "invalid URI host {value:?}: expected a domain, IPv4 or IPv6 address with \
             no scheme, user or port (use set_ruri() to change the port)"
        ))
    };
    let hostname_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.';
    if !value.contains(['[', ':']) {
        if value.is_empty() || !value.chars().all(hostname_char) {
            return Err(refuse());
        }
        return Ok(value.to_string());
    }
    checked_address(value).map_err(|_| refuse())
}

/// Host shape the parser alone does not enforce: it takes anything between
/// brackets. Bracket an IPv6 address; refuse a colon that is not one.
fn checked_address(host: &str) -> PyResult<String> {
    if host.is_empty() {
        return Err(invalid("empty URI host".to_string()));
    }
    let unbracketed = strip_ipv6_brackets(host);
    let bracketed = unbracketed.len() != host.len();
    if bracketed || unbracketed.contains(':') {
        if unbracketed.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid(format!(
                "invalid URI host {host:?}: not an IPv6 address"
            )));
        }
        return Ok(format_sip_host(unbracketed));
    }
    Ok(host.to_string())
}

/// URI parameter: `token` name, `paramchar` value (RFC 3261 §25.1).
pub(crate) fn check_param(name: &str, value: Option<&str>) -> PyResult<()> {
    let token_char = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
            )
    };
    if name.is_empty() || !name.chars().all(token_char) {
        return Err(invalid(format!("invalid URI parameter name {name:?}")));
    }
    let param_char = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '_'
                    | '.'
                    | '!'
                    | '~'
                    | '*'
                    | '\''
                    | '('
                    | ')'
                    | '%'
                    | '['
                    | ']'
                    | '/'
                    | ':'
                    | '&'
                    | '+'
                    | '$'
            )
    };
    if let Some(value) = value {
        if value.is_empty() || !value.chars().all(param_char) {
            return Err(invalid(format!(
                "invalid value {value:?} for URI parameter {name:?} (pass None for a flag parameter)"
            )));
        }
    }
    Ok(())
}

/// Replace or clear the user; user parameters cannot outlive the user.
pub(crate) fn set_user_part(uri: &mut SipUri, user: Option<String>) {
    if user.is_none() {
        let headers = uri.headers().to_vec();
        uri.set_extras(headers, Vec::new());
    }
    uri.user = user;
}

/// A tel: URI keeps `phone-context` in `host` too (the parser's mapping), so
/// a parameter change has to refresh it or the URI no longer round-trips.
pub(crate) fn sync_tel_host(uri: &mut SipUri) {
    if uri.scheme.is_tel() {
        uri.host = uri
            .get_param("phone-context")
            .unwrap_or_default()
            .to_string();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::uri::Scheme;

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

        py_uri.set_user(Some("alice".to_string())).unwrap();
        assert_eq!(py_uri.user(), Some("alice"));
        assert_eq!(py_uri.__str__(), "sip:alice@example.com");

        py_uri.set_user(None).unwrap();
        assert_eq!(py_uri.user(), None);
        assert_eq!(py_uri.__str__(), "sip:example.com");
    }

    #[test]
    fn set_host() {
        let uri = SipUri::new("example.com".to_string()).with_user("alice".to_string());
        let mut py_uri = PySipUri::new(uri);
        py_uri.set_host("other.com".to_string()).unwrap();
        assert_eq!(py_uri.host(), "other.com");
        assert_eq!(py_uri.__str__(), "sip:alice@other.com");
    }

    #[test]
    fn set_port() {
        let uri = SipUri::new("example.com".to_string());
        let mut py_uri = PySipUri::new(uri);
        assert_eq!(py_uri.port(), None);

        py_uri.set_port(Some(5080)).unwrap();
        assert_eq!(py_uri.port(), Some(5080));

        py_uri.set_port(None).unwrap();
        assert_eq!(py_uri.port(), None);
    }

    /// A `TEL:` URI does not parse as RFC 3966 — it falls to the absoluteURI
    /// branch, so its userpart is not extracted — but the property has always
    /// reported it as a tel URI and a script's branch on it must not silently
    /// flip when the scheme becomes an enum.
    #[test]
    fn is_tel_is_case_insensitive_on_the_token() {
        let uri = SipUri {
            scheme: Scheme::from_token("TEL"),
            user: None,
            host: "+12125551234".to_string(),
            port: None,
            params: Vec::new(),
            extras: None,
        };
        assert!(PySipUri::new(uri).is_tel());
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
            scheme: Scheme::Tel,
            user: Some("+12125551234".to_string()),
            host: String::new(),
            port: None,
            params: Vec::new(),
            extras: None,
        };
        let py_uri = PySipUri::new(uri);
        assert!(py_uri.is_tel());
    }

    // --- validation ---

    fn parsed(input: &str) -> SipUri {
        parse_uri_complete(input).expect(input)
    }

    #[test]
    fn check_user_allows_service_codes_and_refuses_structure() {
        for user in [
            "alice",
            "+15551234567",
            "*21#",
            "#31#",
            "a.b-c_d!~*'()",
            "%41lice",
        ] {
            check_user(user).expect(user);
        }
        for user in [
            "",
            "bob@example.com",
            "sip:bob",
            "a b",
            "123;npdi",
            "a?b",
            "<a>",
        ] {
            assert!(check_user(user).is_err(), "{user:?} must be refused");
        }
    }

    #[test]
    fn check_host_normalises_ipv6_and_refuses_ports_and_uris() {
        assert_eq!(check_host("gw1.example.net").unwrap(), "gw1.example.net");
        assert_eq!(check_host("192.0.2.10").unwrap(), "192.0.2.10");
        assert_eq!(check_host("2001:db8::10").unwrap(), "[2001:db8::10]");
        assert_eq!(check_host("[2001:db8::10]").unwrap(), "[2001:db8::10]");
        for host in [
            "",
            "gw1.example.net:5080",
            "192.0.2.10:5060",
            "sip:gw1.example.net",
            "bob@gw1.example.net",
            "gw1.example.net;transport=tcp",
            "[gw1.example.net]",
            "[2001:db8::10]:5060",
            "gw_1.example.net",
        ] {
            assert!(check_host(host).is_err(), "{host:?} must be refused");
        }
    }

    #[test]
    fn check_param_takes_tokens_and_paramchars() {
        check_param("user", Some("phone")).unwrap();
        check_param("lr", None).unwrap();
        check_param("maddr", Some("[2001:db8::1]")).unwrap();
        check_param("x-tag", Some("a/b:c&d+e$f")).unwrap();
        for (name, value) in [
            ("", None),
            ("a b", None),
            ("a=b", None),
            ("user", Some("")),
            ("user", Some("a;b")),
            ("user", Some("a?b")),
            ("user", Some("a b")),
            ("user", Some("a=b")),
        ] {
            assert!(
                check_param(name, value).is_err(),
                "{name:?}={value:?} must be refused"
            );
        }
    }

    #[test]
    fn checked_uri_accepts_what_round_trips() {
        for input in [
            "sip:bob@example.com",
            "sips:bob@example.com:5061;transport=tcp",
            "sip:+15551234567;npdi;rn=+15559876543@carrier.example.net;user=phone",
            "sip:[2001:db8::10]:5060",
            "tel:+15551234567",
            "tel:1234;phone-context=example.com",
            "urn:service:sos",
        ] {
            assert_eq!(checked_uri(parsed(input)).expect(input).to_string(), input);
        }
    }

    #[test]
    fn checked_uri_refuses_a_bracketed_non_address() {
        // The parser takes anything between brackets; checked_uri does not.
        assert!(checked_uri(parsed("sip:bob@[gw1.example.net:5080]")).is_err());
    }

    #[test]
    fn checked_uri_refuses_a_user_that_the_wire_would_split() {
        let mut uri = parsed("sip:bob@example.com");
        uri.user = Some("123;npdi".to_string());
        assert!(checked_uri(uri).is_err());
    }

    #[test]
    fn clearing_the_user_drops_its_parameters() {
        let mut uri = parsed("sip:+15551234567;npdi;rn=+15559876543@carrier.example.net");
        set_user_part(&mut uri, None);
        assert_eq!(
            checked_uri(uri).unwrap().to_string(),
            "sip:carrier.example.net"
        );
    }

    #[test]
    fn detached_copy_setters_are_checked_too() {
        let mut py_uri = PySipUri::new(parsed("sip:bob@example.com"));
        assert!(py_uri.set_host("gw1.example.net:5080".to_string()).is_err());
        assert!(py_uri.set_user(Some("a@b".to_string())).is_err());
        assert!(py_uri.set_port(Some(0)).is_err());
        assert_eq!(
            py_uri.__str__(),
            "sip:bob@example.com",
            "a refused change leaves it alone"
        );
    }

    fn request_for(uri: &str) -> Arc<Mutex<SipMessage>> {
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        Arc::new(Mutex::new(
            SipMessageBuilder::new()
                .request(Method::Invite, parsed(uri))
                .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-uri".to_string())
                .to("<sip:bob@example.com>".to_string())
                .from("<sip:alice@example.com>;tag=1".to_string())
                .call_id("uri-test".to_string())
                .cseq("1 INVITE".to_string())
                .content_length(0)
                .build()
                .unwrap(),
        ))
    }

    #[test]
    fn bound_setters_write_the_request_uri() {
        let message = request_for("sip:bob@example.com");
        let mut py_uri =
            PySipUri::new(parsed("sip:bob@example.com")).bound_to_request(Arc::clone(&message));
        py_uri.set_user(Some("+15551234567".to_string())).unwrap();
        py_uri.set_host("2001:db8::10".to_string()).unwrap();
        py_uri.set_port(Some(5080)).unwrap();
        assert_eq!(
            current_request_uri(&message).unwrap().to_string(),
            "sip:+15551234567@[2001:db8::10]:5080"
        );
        assert_eq!(py_uri.__str__(), "sip:+15551234567@[2001:db8::10]:5080");
    }

    #[test]
    fn a_stale_bound_copy_does_not_put_back_an_older_part() {
        let message = request_for("sip:bob@example.com");
        let mut stale =
            PySipUri::new(parsed("sip:bob@example.com")).bound_to_request(Arc::clone(&message));
        // Something else rewrites the host after `stale` was read ...
        commit_request_uri(&message, parsed("sip:bob@gw1.example.net")).unwrap();
        // ... and changing only the user must keep that host.
        stale.set_user(Some("carol".to_string())).unwrap();
        assert_eq!(
            current_request_uri(&message).unwrap().to_string(),
            "sip:carol@gw1.example.net"
        );
    }

    #[test]
    fn a_refused_bound_change_leaves_the_request_alone() {
        let message = request_for("sip:bob@example.com");
        let mut py_uri =
            PySipUri::new(parsed("sip:bob@example.com")).bound_to_request(Arc::clone(&message));
        assert!(py_uri.set_host("gw1.example.net:5080".to_string()).is_err());
        assert_eq!(
            current_request_uri(&message).unwrap().to_string(),
            "sip:bob@example.com"
        );
    }
}
