//! RFC 4028 Session Timer header parsing.
//!
//! Parses `Session-Expires` and `Min-SE` headers for session timer negotiation.
//!
//! Format:
//!   Session-Expires: <delta-seconds> [;refresher={uac|uas}]
//!   Min-SE: <delta-seconds>

/// Parsed `Session-Expires` header.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionExpires {
    /// Session duration in seconds.
    pub delta_seconds: u32,
    /// Who refreshes: "uac" or "uas". None if not specified.
    pub refresher: Option<String>,
}

/// Parsed `Min-SE` header (minimum session interval).
#[derive(Debug, Clone, PartialEq)]
pub struct MinSe {
    pub delta_seconds: u32,
}

impl SessionExpires {
    /// Parse a `Session-Expires` header value.
    ///
    /// Examples:
    ///   "1800" → SessionExpires { delta_seconds: 1800, refresher: None }
    ///   "1800;refresher=uac" → SessionExpires { delta_seconds: 1800, refresher: Some("uac") }
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        let (seconds_part, params) = match trimmed.split_once(';') {
            Some((s, p)) => (s.trim(), Some(p)),
            None => (trimmed, None),
        };

        let delta_seconds = seconds_part.parse::<u32>().ok()?;

        let refresher = params.and_then(|param_str| {
            for param in param_str.split(';') {
                if let Some((key, value)) = param.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("refresher") {
                        let value = value.trim().to_lowercase();
                        if value == "uac" || value == "uas" {
                            return Some(value);
                        }
                    }
                }
            }
            None
        });

        Some(SessionExpires {
            delta_seconds,
            refresher,
        })
    }

    /// Format as a SIP header value.
    pub fn to_header_value(&self) -> String {
        match &self.refresher {
            Some(refresher) => format!("{};refresher={}", self.delta_seconds, refresher),
            None => self.delta_seconds.to_string(),
        }
    }
}

impl MinSe {
    /// Parse a `Min-SE` header value.
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        // Min-SE may have params too, but we only care about the delta-seconds
        let seconds_part = match trimmed.split_once(';') {
            Some((s, _)) => s.trim(),
            None => trimmed,
        };

        let delta_seconds = seconds_part.parse::<u32>().ok()?;
        Some(MinSe { delta_seconds })
    }

    /// Format as a SIP header value.
    pub fn to_header_value(&self) -> String {
        self.delta_seconds.to_string()
    }
}

/// Extract `Session-Expires` from SIP headers.
pub fn parse_session_expires(headers: &super::SipHeaders) -> Option<SessionExpires> {
    headers
        .get("Session-Expires")
        .and_then(|v| SessionExpires::parse(v))
}

/// Extract `Min-SE` from SIP headers.
pub fn parse_min_se(headers: &super::SipHeaders) -> Option<MinSe> {
    headers.get("Min-SE").and_then(|v| MinSe::parse(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SessionExpires parsing ---

    #[test]
    fn parse_session_expires_simple() {
        let result = SessionExpires::parse("1800").unwrap();
        assert_eq!(result.delta_seconds, 1800);
        assert_eq!(result.refresher, None);
    }

    #[test]
    fn parse_session_expires_with_refresher_uac() {
        let result = SessionExpires::parse("1800;refresher=uac").unwrap();
        assert_eq!(result.delta_seconds, 1800);
        assert_eq!(result.refresher, Some("uac".to_string()));
    }

    #[test]
    fn parse_session_expires_with_refresher_uas() {
        let result = SessionExpires::parse("3600;refresher=uas").unwrap();
        assert_eq!(result.delta_seconds, 3600);
        assert_eq!(result.refresher, Some("uas".to_string()));
    }

    #[test]
    fn parse_session_expires_with_whitespace() {
        let result = SessionExpires::parse("  1800 ; refresher = uac  ").unwrap();
        assert_eq!(result.delta_seconds, 1800);
        // refresher= with spaces should still parse
        assert_eq!(result.refresher, Some("uac".to_string()));
    }

    #[test]
    fn parse_session_expires_invalid_not_a_number() {
        assert!(SessionExpires::parse("abc").is_none());
    }

    #[test]
    fn parse_session_expires_invalid_refresher() {
        let result = SessionExpires::parse("1800;refresher=invalid").unwrap();
        assert_eq!(result.delta_seconds, 1800);
        assert_eq!(result.refresher, None); // invalid refresher ignored
    }

    #[test]
    fn parse_session_expires_zero() {
        let result = SessionExpires::parse("0").unwrap();
        assert_eq!(result.delta_seconds, 0);
    }

    #[test]
    fn session_expires_to_header_value() {
        let header = SessionExpires {
            delta_seconds: 1800,
            refresher: Some("uac".to_string()),
        };
        assert_eq!(header.to_header_value(), "1800;refresher=uac");
    }

    #[test]
    fn session_expires_to_header_value_no_refresher() {
        let header = SessionExpires {
            delta_seconds: 3600,
            refresher: None,
        };
        assert_eq!(header.to_header_value(), "3600");
    }

    // --- MinSe parsing ---

    #[test]
    fn parse_min_se_simple() {
        let result = MinSe::parse("90").unwrap();
        assert_eq!(result.delta_seconds, 90);
    }

    #[test]
    fn parse_min_se_with_whitespace() {
        let result = MinSe::parse("  120  ").unwrap();
        assert_eq!(result.delta_seconds, 120);
    }

    #[test]
    fn parse_min_se_with_params() {
        let result = MinSe::parse("90;some-ext=value").unwrap();
        assert_eq!(result.delta_seconds, 90);
    }

    #[test]
    fn parse_min_se_invalid() {
        assert!(MinSe::parse("abc").is_none());
    }

    // --- Header extraction ---

    #[test]
    fn extract_from_sip_headers() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Session-Expires", "1800;refresher=uac".to_string());
        headers.set("Min-SE", "90".to_string());

        let session_expires = parse_session_expires(&headers).unwrap();
        assert_eq!(session_expires.delta_seconds, 1800);
        assert_eq!(session_expires.refresher, Some("uac".to_string()));

        let min_se = parse_min_se(&headers).unwrap();
        assert_eq!(min_se.delta_seconds, 90);
    }

    #[test]
    fn extract_missing_headers() {
        let headers = super::super::SipHeaders::new();
        assert!(parse_session_expires(&headers).is_none());
        assert!(parse_min_se(&headers).is_none());
    }
}
