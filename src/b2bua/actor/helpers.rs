//! Small pure helpers over SIP header values and identifiers.
//!
//! Nothing here touches call or leg state: given a header value and a new host,
//! tag or authority, each returns the rewritten string. They live together
//! because the B-leg INVITE builder and the dialog rewrite path both reach for
//! the same handful, and because they are the easiest things in this module to
//! test in isolation.

use crate::sip::message::SipMessage;

/// Generate a fresh SDP `o=` session-id (RFC 4566 §5.2 — a numeric identifier).
///
/// Masked into the non-negative signed range: RFC 3264 §5 requires the `o=`
/// session-id and version to be "representable with a 64 bit signed integer",
/// and a full-range `u64` puts about half of all dialogs above [`i64::MAX`],
/// where a peer parsing the field with `strtoll` / `ParseInt` overflows on a
/// body that is otherwise fine.  Because the value is random per call, that
/// fails intermittently — the same route works, then does not, with nothing in
/// any log to separate the two calls.
///
/// 63 bits of a v4 UUID is far more collision resistance than the field needs;
/// it only has to be unique among the sessions one peer holds at once.  The
/// companion version starts at 0 and is only ever incremented, so it stays in
/// range without help.
pub fn generate_sdp_session_id() -> u64 {
    (uuid::Uuid::new_v4().as_u128() as u64) & (i64::MAX as u64)
}
/// Extract the bare SIP URI from a Contact header value.
///
/// Handles angle-bracket syntax: `<sip:user@host:5060;transport=tcp>;expires=3600`
/// → `sip:user@host:5060;transport=tcp`. Without brackets, returns the full value
/// trimmed of whitespace.
pub fn extract_contact_uri(header_value: &str) -> String {
    let trimmed = header_value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            return trimmed[start + 1..start + end].to_string();
        }
    }
    // No angle brackets — take the URI part (before any header params separated by ';'
    // that are NOT URI params). For bare URIs like "sip:user@host:5060;transport=tcp",
    // the entire value is the URI.
    trimmed.to_string()
}
/// Ensure a SIP From/To header value carries a `;tag=<tag>` parameter.
///
/// `local_from_uri` and `remote_to_uri` are captured from the outbound
/// INVITE before the dialog's far end answers, so they don't yet contain
/// the dialog tag. The tag arrives separately in the 2xx response and is
/// stored as `local_tag` / `remote_tag`. In-dialog request builders must
/// reunite them so peers can match the dialog (RFC 3261 §12.2).
///
/// Idempotent: if the value already contains `;tag=` it is returned
/// unchanged. If `tag` is `None` or empty (early-dialog requests, where
/// no remote tag is established yet — RFC 3311 §5.2), the value is also
/// unchanged.
pub fn ensure_tag(header_value: &str, tag: Option<&str>) -> String {
    if header_value.contains(";tag=") {
        return header_value.to_string();
    }
    match tag {
        Some(t) if !t.is_empty() => format!("{};tag={}", header_value.trim_end(), t),
        _ => header_value.to_string(),
    }
}
/// Rewrite the host part of a SIP URI in a From/To header value.
///
/// Given a header value like `<sip:user@old-host:5060;params>;tag=...`,
/// replaces `old-host` with `new_host`. Works for both From and To headers.
pub fn rewrite_uri_host(header_value: &str, new_host: &str) -> String {
    if let Some(at_pos) = header_value.find('@') {
        let after_at = &header_value[at_pos + 1..];
        let host_end = after_at.find(['>', ';', ':']).unwrap_or(after_at.len());
        let end_pos = at_pos + 1 + host_end;
        format!(
            "{}{}{}",
            &header_value[..at_pos + 1],
            new_host,
            &header_value[end_pos..],
        )
    } else {
        header_value.to_string()
    }
}
/// Rewrite the whole `host[:port]` authority of a SIP URI in a From/To header
/// value.
///
/// Unlike [`rewrite_uri_host`] — which replaces only the host token and leaves
/// any existing `:port` in place — this replaces the entire `host[:port]`
/// authority with `new_authority`. Use it when substituting a dial-target
/// authority that itself carries a port (e.g. topology-hiding the B-leg To to
/// the next-hop): replacing host-only there would splice the new `host:port` in
/// front of the retained old port and emit a malformed `host:newport:oldport`
/// (double port), which some SBCs reject as `400 Wrong URI`.
pub fn rewrite_uri_authority(header_value: &str, new_authority: &str) -> String {
    if let Some(at_pos) = header_value.find('@') {
        let after_at = &header_value[at_pos + 1..];
        // Split only on the URI-param / bracket terminators, NOT on ':', so the
        // original port is consumed along with the host.
        let authority_end = after_at.find(['>', ';']).unwrap_or(after_at.len());
        let end_pos = at_pos + 1 + authority_end;
        format!(
            "{}{}{}",
            &header_value[..at_pos + 1],
            new_authority,
            &header_value[end_pos..],
        )
    } else {
        header_value.to_string()
    }
}
/// Generate a fresh SIP tag.
pub fn generate_tag() -> String {
    format!("sb-{}", &uuid::Uuid::new_v4().as_simple().to_string()[..12])
}
/// Generate a fresh Call-ID for an outbound leg.
pub fn generate_call_id() -> String {
    format!("b2b-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Transport binding (owned by each leg)
/// Extract the To-tag from a SIP message.
pub fn extract_to_tag(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .and_then(|to| {
            to.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
}
