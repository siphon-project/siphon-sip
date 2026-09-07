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

/// URI scheme (RFC 3261 §19.1.1, RFC 3966 §3).
///
/// An enum rather than a `String`, because `sip`, `sips` and `tel` cover every
/// URI siphon actually routes on: the common case becomes a discriminant
/// instead of a heap allocation, and a message carries several URIs (R-URI,
/// From, To, Contact, every Route and Record-Route), so the allocation is paid
/// per URI per message on the parse path and once per binding in the registrar.
///
/// [`Scheme::Other`] keeps the `absoluteURI` case: RFC 3261 §8.2.2 requires a
/// 416 Unsupported URI Scheme rather than a parse failure, which needs the
/// scheme preserved verbatim (RFC 4475 §3.3.2 / §3.3.3 exercise both the opaque
/// and the hierarchical shape). It holds a `Box<str>` rather than a `String`
/// because the capacity word is dead weight on a scheme nobody rewrites; the
/// enum still measures the same 24 bytes as the `String` it replaces, since a
/// `NonNull` niche has exactly one spare value and three unit variants do not
/// fit in it. The win is the allocation, not the width.
///
/// Recognition is exact-match lowercase, mirroring the parser's own
/// `starts_with("sip:")` / `strip_prefix("tel:")` dispatch. A scheme in any
/// other casing lands in `Other` and re-serialises with its original spelling,
/// which is what siphon has always done. (RFC 3261 §19.1.1 makes the scheme
/// case-insensitive, so `SIP:` *should* be recognised; that is a parser-level
/// change with routing consequences and is deliberately not made here.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `sip:` — RFC 3261 §19.1.
    Sip,
    /// `sips:` — RFC 3261 §19.1, TLS-secured.
    Sips,
    /// `tel:` — RFC 3966.
    Tel,
    /// Any other `absoluteURI` scheme, kept verbatim for the 416 path.
    ///
    /// Doubly boxed so the variant is a *thin* pointer: a `Box<str>` is a fat
    /// pointer and would make the enum 24 bytes, the same width as the `String`
    /// this replaced. The extra indirection is paid only on the 416 path, which
    /// no live network takes, and buys 8 bytes on every URI that is not on it.
    Other(Box<Box<str>>),
}

impl Scheme {
    /// The scheme token as it appears on the wire, without the `:`.
    pub fn as_str(&self) -> &str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
            Scheme::Tel => "tel",
            Scheme::Other(other) => other,
        }
    }

    /// Recognise a scheme token (no trailing `:`).
    pub fn from_token(token: &str) -> Self {
        match token {
            "sip" => Scheme::Sip,
            "sips" => Scheme::Sips,
            "tel" => Scheme::Tel,
            other => Scheme::Other(Box::new(other.into())),
        }
    }

    /// `sips:` — the secure SIP scheme (RFC 3261 §26.2.2).
    pub fn is_sips(&self) -> bool {
        matches!(self, Scheme::Sips)
    }

    /// `tel:` — RFC 3966, which has no host or port of its own.
    pub fn is_tel(&self) -> bool {
        matches!(self, Scheme::Tel)
    }

    /// `sip:` or `sips:` — the schemes siphon routes.
    pub fn is_sip_family(&self) -> bool {
        matches!(self, Scheme::Sip | Scheme::Sips)
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Scheme {
    fn from(token: &str) -> Self {
        Scheme::from_token(token)
    }
}

impl AsRef<str> for Scheme {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// Comparison against a bare token, so call sites and tests keep reading
// `uri.scheme == "sips"` the way `String == &str` does.
impl PartialEq<str> for Scheme {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Scheme {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Scheme> for str {
    fn eq(&self, other: &Scheme) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<Scheme> for &str {
    fn eq(&self, other: &Scheme) -> bool {
        *self == other.as_str()
    }
}

/// The two URI parts that are absent from essentially every URI on a live
/// network, held behind one pointer so they cost 8 bytes rather than 48.
///
/// `SipUri` is embedded in every `NameAddr`, so a message carries several and
/// the registrar carries one per binding; two `Vec` headers that are empty
/// every time are the kind of cost that only shows up at a million contacts.
/// Boxed together rather than separately because the URIs that have one
/// usually have neither and the ones that have either are rare enough that a
/// single allocation covering both is the right trade.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UriExtras {
    /// URI headers, after `?` (RFC 3261 §19.1.1).
    pub headers: Vec<(String, Option<String>)>,
    /// User parameters, between the user and `@` — e.g. `;phone-context=`
    /// (RFC 3966 §5.1.5).
    pub user_params: Vec<(String, Option<String>)>,
}

impl UriExtras {
    fn is_empty(&self) -> bool {
        self.headers.is_empty() && self.user_params.is_empty()
    }
}

/// SIP URI as defined in RFC 3261
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    pub scheme: Scheme,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, Option<String>)>, // URI parameters (after hostport)
    /// URI headers and user-params. `None` for the overwhelming majority of
    /// URIs — read through [`headers`](Self::headers) /
    /// [`user_params`](Self::user_params), which hand back an empty slice
    /// rather than making every caller unwrap.
    pub extras: Option<Box<UriExtras>>,
}

impl SipUri {
    pub fn new(host: String) -> Self {
        Self {
            scheme: Scheme::Sip,
            user: None,
            host,
            port: None,
            params: Vec::new(),
            extras: None,
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

    /// URI headers (after `?`). Empty slice when the URI has none, which is
    /// almost always.
    pub fn headers(&self) -> &[(String, Option<String>)] {
        self.extras.as_ref().map_or(&[], |e| e.headers.as_slice())
    }

    /// RFC 3966 user-params (between the user and `@`). Empty slice when the
    /// URI has none.
    pub fn user_params(&self) -> &[(String, Option<String>)] {
        self.extras
            .as_ref()
            .map_or(&[], |e| e.user_params.as_slice())
    }

    /// Mutable access to the rare parts, allocating the box on first use.
    /// Prefer [`set_extras`](Self::set_extras) when building a URI from parsed
    /// pieces — it skips the allocation entirely when both parts are empty.
    pub fn extras_mut(&mut self) -> &mut UriExtras {
        self.extras.get_or_insert_with(Box::default)
    }

    /// Attach headers and user-params, allocating only if at least one is
    /// non-empty. This is the constructor path: a URI with neither (which is
    /// nearly all of them) keeps `extras: None` and pays nothing.
    pub fn set_extras(
        &mut self,
        headers: Vec<(String, Option<String>)>,
        user_params: Vec<(String, Option<String>)>,
    ) {
        let extras = UriExtras {
            headers,
            user_params,
        };
        self.extras = if extras.is_empty() {
            None
        } else {
            Some(Box::new(extras))
        };
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

        if self.scheme.is_tel() {
            // tel: URI: tel:subscriber;params (no @host:port)
            if let Some(ref user) = self.user {
                write!(f, "{user}")?;
            }
        } else {
            // sip:/sips: URI: scheme:user[;user-params]@host:port
            if let Some(ref user) = self.user {
                write!(f, "{user}")?;
                for (name, value) in self.user_params() {
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

        if !self.headers().is_empty() {
            write!(f, "?")?;
            let mut first = true;
            for (name, value) in self.headers() {
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
        assert_eq!(
            split_host_port("proxy.example.com:5061"),
            ("proxy.example.com", Some(5061))
        );
        assert_eq!(
            split_host_port("proxy.example.com"),
            ("proxy.example.com", None)
        );
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
        let uri = SipUri::new("[::1]".to_string()).with_port(5060);
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
        let uri = SipUri::new("biloxi.com".to_string()).with_user("bob".to_string());
        assert_eq!(uri.to_string(), "sip:bob@biloxi.com");
    }

    #[test]
    fn tel_uri_display_global() {
        let uri = SipUri {
            scheme: Scheme::Tel,
            user: Some("+15551234567".to_string()),
            host: String::new(),
            port: None,
            params: Vec::new(),
            extras: None,
        };
        assert_eq!(uri.to_string(), "tel:+15551234567");
    }

    #[test]
    fn tel_uri_display_with_phone_context() {
        let uri = SipUri {
            scheme: Scheme::Tel,
            user: Some("8367".to_string()),
            host: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            port: None,
            params: vec![(
                "phone-context".to_string(),
                Some("ims.mnc001.mcc001.3gppnetwork.org".to_string()),
            )],
            extras: None,
        };
        assert_eq!(
            uri.to_string(),
            "tel:8367;phone-context=ims.mnc001.mcc001.3gppnetwork.org"
        );
    }
}

#[cfg(test)]
mod scheme_tests {
    use super::*;

    /// The enum is a substitute for the `String` it replaced, not an
    /// enlargement of it: `SipUri` is embedded in every `NameAddr` the parser
    /// builds, so a variant that widened this past a `String` would cost
    /// memory on every URI of every message and pay back nothing. Widening
    /// `Other` to a `String`, or adding a second payload variant, is silent
    /// without this.
    #[test]
    fn scheme_is_narrower_than_the_string_it_replaced() {
        // A thin pointer plus a tag: 16, against `String`'s 24. Pinned because
        // switching `Other` back to a bare `Box<str>` silently widens every
        // `SipUri` in the process by 8 bytes.
        assert_eq!(std::mem::size_of::<Scheme>(), 16);
        assert!(std::mem::size_of::<Scheme>() < std::mem::size_of::<String>());
    }

    /// The actual win: the three schemes siphon routes carry no pointer at
    /// all, so constructing one cannot allocate. Asserted structurally
    /// (`Other` is the only variant that owns heap) because a counting
    /// allocator would have to be global and would perturb every other test
    /// in the binary.
    #[test]
    fn the_routed_schemes_own_no_heap() {
        for scheme in [Scheme::Sip, Scheme::Sips, Scheme::Tel] {
            assert!(
                !matches!(scheme, Scheme::Other(_)),
                "a routed scheme must not be represented as an owned string"
            );
            // Same pointer for every construction of the same variant: the
            // token is a `&'static str` in the binary, not a fresh buffer.
            assert!(std::ptr::eq(
                scheme.as_str().as_ptr(),
                Scheme::from_token(scheme.as_str()).as_str().as_ptr()
            ));
        }
    }

    #[test]
    fn from_token_recognises_the_routed_schemes() {
        assert_eq!(Scheme::from_token("sip"), Scheme::Sip);
        assert_eq!(Scheme::from_token("sips"), Scheme::Sips);
        assert_eq!(Scheme::from_token("tel"), Scheme::Tel);
    }

    /// Recognition is exact-match, mirroring the parser's own dispatch: an
    /// oddly-cased scheme keeps its spelling so the URI re-serialises
    /// byte-for-byte, which is what the 416 path (RFC 3261 §8.2.2) hands back.
    #[test]
    fn from_token_keeps_an_unknown_scheme_verbatim() {
        assert_eq!(
            Scheme::from_token("nobodyKnowsThisScheme"),
            Scheme::Other(Box::new("nobodyKnowsThisScheme".into()))
        );
        assert_eq!(
            Scheme::from_token("SIP"),
            Scheme::Other(Box::new("SIP".into()))
        );
        assert_eq!(Scheme::from_token("SIP").as_str(), "SIP");
        assert_eq!(Scheme::from_token("soap.beep").to_string(), "soap.beep");
    }

    #[test]
    fn as_str_round_trips_every_variant() {
        for token in ["sip", "sips", "tel", "http", "urn", "mailto"] {
            assert_eq!(Scheme::from_token(token).as_str(), token);
            assert_eq!(Scheme::from_token(token).to_string(), token);
        }
    }

    #[test]
    fn predicates_partition_the_variants() {
        assert!(Scheme::Sips.is_sips());
        assert!(!Scheme::Sip.is_sips());
        assert!(Scheme::Tel.is_tel());
        assert!(!Scheme::Sip.is_tel());
        assert!(Scheme::Sip.is_sip_family());
        assert!(Scheme::Sips.is_sip_family());
        assert!(!Scheme::Tel.is_sip_family());
        assert!(!Scheme::from_token("http").is_sip_family());
    }

    #[test]
    fn compares_against_a_bare_token_in_both_directions() {
        assert_eq!(Scheme::Sips, "sips");
        assert_eq!("sips", Scheme::Sips);
        assert_ne!(Scheme::Sip, "sips");
        assert_eq!(Scheme::from_token("http"), "http");
        assert_eq!(Scheme::Sip.as_ref(), "sip");
    }
}
