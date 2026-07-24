use std::fmt;

/// Format an IP address or hostname for use in SIP URIs/headers.
/// Wraps IPv6 addresses in brackets per RFC 3261.
pub fn format_sip_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Strip brackets from an IPv6 host for use with standard parsers.
pub fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Split a SIP `host[:port]` authority into its host and optional port,
/// IPv6-bracket aware.  The returned host keeps its brackets for a v6 literal.
///
/// Handles `[2001:db8::1]:5060`, `[2001:db8::1]`, `host:5060`, `host`, and a
/// bare (unbracketed) IPv6 literal such as `2001:db8::1` — the last is returned
/// whole with no port, because a trailing `:port` cannot be disambiguated from
/// the address without brackets (RFC 3261 §19.1.2 / §25.1).
///
/// Lenient by contract: a malformed port yields `None` rather than an error.
/// This is the best-effort splitter for send-side overrides (e.g.
/// `force_send_via`); the strict, error-returning parse lives in
/// [`crate::sip::headers::via::Via::parse`].
pub fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    let authority = authority.trim();
    if authority.starts_with('[') {
        // Bracketed IPv6 literal, with an optional `:port` after the `]`.
        if let Some(bracket_end) = authority.find(']') {
            let host = &authority[..=bracket_end];
            let port = authority[bracket_end + 1..]
                .strip_prefix(':')
                .and_then(|port_str| port_str.parse::<u16>().ok());
            return (host, port);
        }
        // Unterminated bracket — hand it back untouched rather than mangle it.
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        // A colon still in the host portion means this is a bare, unbracketed
        // IPv6 literal (not host:port) — keep it whole.
        Some((host, _)) if host.contains(':') => (authority, None),
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    }
}

/// SIP URI as defined in RFC 3261
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    pub scheme: String, // "sip" or "sips"
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, Option<String>)>, // URI parameters (after hostport)
    pub headers: Vec<(String, Option<String>)>, // URI headers (after ?)
    /// User parameters (between user and @), e.g. ;phone-context=... (RFC 3966).
    pub user_params: Vec<(String, Option<String>)>,
}

impl SipUri {
    pub fn new(host: String) -> Self {
        Self {
            scheme: "sip".to_string(),
            user: None,
            host,
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
            user_params: Vec::new(),
        }
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_param(mut self, name: String, value: Option<String>) -> Self {
        self.params.push((name, value));
        self
    }

    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_deref().unwrap_or(""))
    }

}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;

        if self.scheme == "tel" {
            // tel: URI: tel:subscriber;params (no @host:port)
            if let Some(ref user) = self.user {
                write!(f, "{user}")?;
            }
        } else {
            // sip:/sips: URI: scheme:user[;user-params]@host:port
            if let Some(ref user) = self.user {
                write!(f, "{user}")?;
                for (name, value) in &self.user_params {
                    write!(f, ";{name}")?;
                    if let Some(ref v) = value {
                        write!(f, "={v}")?;
                    }
                }
                write!(f, "@")?;
            }

            write!(f, "{}", format_sip_host(&self.host))?;

            if let Some(port) = self.port {
                write!(f, ":{port}")?;
            }
        }

        for (name, value) in &self.params {
            write!(f, ";{name}")?;
            if let Some(ref v) = value {
                write!(f, "={v}")?;
            }
        }

        if !self.headers.is_empty() {
            write!(f, "?")?;
            let mut first = true;
            for (name, value) in &self.headers {
                if !first {
                    write!(f, "&")?;
                }
                first = false;
                write!(f, "{name}")?;
                if let Some(ref v) = value {
                    write!(f, "={v}")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_sip_host_ipv4() {
        assert_eq!(format_sip_host("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn format_sip_host_ipv6_bare() {
        assert_eq!(format_sip_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(format_sip_host("::1"), "[::1]");
        assert_eq!(format_sip_host("fe80::1%25eth0"), "[fe80::1%25eth0]");
    }

    #[test]
    fn format_sip_host_ipv6_already_bracketed() {
        assert_eq!(format_sip_host("[::1]"), "[::1]");
        assert_eq!(format_sip_host("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn format_sip_host_hostname() {
        assert_eq!(format_sip_host("example.com"), "example.com");
        assert_eq!(format_sip_host("proxy.atlanta.com"), "proxy.atlanta.com");
    }

    #[test]
    fn strip_ipv6_brackets_with_brackets() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn strip_ipv6_brackets_without_brackets() {
        assert_eq!(strip_ipv6_brackets("::1"), "::1");
        assert_eq!(strip_ipv6_brackets("example.com"), "example.com");
        assert_eq!(strip_ipv6_brackets("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn strip_ipv6_brackets_partial() {
        assert_eq!(strip_ipv6_brackets("[::1"), "[::1");
        assert_eq!(strip_ipv6_brackets("::1]"), "::1]");
    }

    #[test]
    fn split_host_port_ipv4() {
        assert_eq!(split_host_port("10.0.0.1:5060"), ("10.0.0.1", Some(5060)));
        assert_eq!(split_host_port("10.0.0.1"), ("10.0.0.1", None));
    }

    #[test]
    fn split_host_port_hostname() {
        assert_eq!(split_host_port("proxy.example.com:5061"), ("proxy.example.com", Some(5061)));
        assert_eq!(split_host_port("proxy.example.com"), ("proxy.example.com", None));
    }

    #[test]
    fn split_host_port_ipv6_bracketed_with_port() {
        assert_eq!(
            split_host_port("[2001:db8::1]:5060"),
            ("[2001:db8::1]", Some(5060))
        );
    }

    #[test]
    fn split_host_port_ipv6_bracketed_no_port() {
        // Regression: the old rsplit_once(':') truncated this to "[2001:db8:".
        assert_eq!(split_host_port("[2001:db8::1]"), ("[2001:db8::1]", None));
        assert_eq!(split_host_port("[::1]"), ("[::1]", None));
    }

    #[test]
    fn split_host_port_ipv6_bare_unbracketed() {
        // No brackets → can't disambiguate a port; whole thing is the host.
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(split_host_port("::1"), ("::1", None));
    }

    #[test]
    fn split_host_port_bad_port_is_all_host() {
        assert_eq!(split_host_port("host:notaport"), ("host:notaport", None));
    }

    #[test]
    fn sip_uri_to_string_ipv6_bare_host() {
        let uri = SipUri::new("2001:db8::1".to_string())
            .with_user("alice".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:alice@[2001:db8::1]:5060");
    }

    #[test]
    fn sip_uri_to_string_ipv6_bracketed_host() {
        let uri = SipUri::new("[::1]".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:[::1]:5060");
    }

    #[test]
    fn sip_uri_to_string_ipv4_unchanged() {
        let uri = SipUri::new("192.168.1.1".to_string())
            .with_user("bob".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:bob@192.168.1.1:5060");
    }

    #[test]
    fn sip_uri_to_string_hostname_unchanged() {
        let uri = SipUri::new("biloxi.com".to_string())
            .with_user("bob".to_string());
        assert_eq!(uri.to_string(), "sip:bob@biloxi.com");
    }

    #[test]
    fn tel_uri_display_global() {
        let uri = SipUri {
            scheme: "tel".to_string(),
            user: Some("+15551234567".to_string()),
            host: String::new(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
            user_params: Vec::new(),
        };
        assert_eq!(uri.to_string(), "tel:+15551234567");
    }

    #[test]
    fn tel_uri_display_with_phone_context() {
        let uri = SipUri {
            scheme: "tel".to_string(),
            user: Some("8367".to_string()),
            host: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            port: None,
            params: vec![("phone-context".to_string(), Some("ims.mnc001.mcc001.3gppnetwork.org".to_string()))],
            headers: Vec::new(),
            user_params: Vec::new(),
        };
        assert_eq!(uri.to_string(), "tel:8367;phone-context=ims.mnc001.mcc001.3gppnetwork.org");
    }
}

