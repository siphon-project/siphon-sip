//! B2BUA call transfer — REFER handling (RFC 3515) and Replaces (RFC 3891).
//!
//! Supports two transfer modes:
//!
//! **Unattended (blind) transfer:**
//! 1. REFER arrives on an active call with `Refer-To: <target-uri>`
//! 2. B2BUA sends 202 Accepted + NOTIFY 100 Trying
//! 3. B2BUA sends new INVITE to the target URI
//! 4. On answer: bridge transferee ↔ target, BYE the old peer
//! 5. Send NOTIFY with final status (200 OK or error)
//!
//! **Attended transfer:**
//! 1. REFER arrives with `Refer-To: <uri?Replaces=call-id;from-tag=x;to-tag=y>`
//! 2. B2BUA looks up the target dialog by Replaces
//! 3. Bridges the two callers together, BYEs the old B-legs
//! 4. Send NOTIFY with result

use std::fmt;

use crate::sip::headers::refer::{ReferTo, Replaces};

/// Transfer state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// REFER received, waiting for script decision (accept/reject).
    Pending,
    /// Transfer accepted, INVITE to target in progress.
    Trying,
    /// Transfer succeeded — call bridged to new target.
    Succeeded,
    /// Transfer failed — original call maintained.
    Failed { code: u16, reason: String },
}

impl fmt::Display for TransferState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferState::Pending => write!(formatter, "pending"),
            TransferState::Trying => write!(formatter, "trying"),
            TransferState::Succeeded => write!(formatter, "succeeded"),
            TransferState::Failed { code, reason } => {
                write!(formatter, "failed ({code} {reason})")
            }
        }
    }
}

/// Context for an active transfer operation on a call.
#[derive(Debug, Clone)]
pub struct TransferContext {
    /// The parsed Refer-To header.
    pub refer_to: ReferTo,
    /// Which leg initiated the REFER ("a" or "b").
    pub initiated_by: TransferSide,
    /// Current transfer state.
    pub state: TransferState,
    /// CSeq for the NOTIFY subscription (incremented per NOTIFY).
    pub notify_cseq: u32,
    /// From-tag for the NOTIFY dialog (from the 202 response to REFER).
    pub notify_from_tag: String,
    /// To-tag from the REFER request.
    pub notify_to_tag: String,
    /// Call-ID for the NOTIFY dialog (same as the REFER's Call-ID).
    pub notify_call_id: String,
}

/// Which side of the B2BUA call initiated the transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferSide {
    /// Caller (A-leg) sent REFER.
    ALeg,
    /// Callee (B-leg) sent REFER.
    BLeg,
}

impl fmt::Display for TransferSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferSide::ALeg => write!(formatter, "a"),
            TransferSide::BLeg => write!(formatter, "b"),
        }
    }
}

/// Build a NOTIFY body with `message/sipfrag` content (RFC 3515 §2.4 / RFC
/// 3420).
///
/// The body is a SIP Status-Line, e.g. `SIP/2.0 200 OK`. Per RFC 3261 §25 the
/// Status-Line is CRLF-terminated, and message/sipfrag inherits that grammar
/// (RFC 3420), so the trailing CRLF is included.
pub fn build_sipfrag_body(status_code: u16, reason: &str) -> String {
    format!("SIP/2.0 {status_code} {reason}\r\n")
}

/// Parse the `message/sipfrag` body of a REFER-subscription NOTIFY into its
/// status code and reason phrase — the *outcome* of a transfer siphon
/// originated (RFC 3515 §2.4.4: the referee reports progress as a sipfrag
/// Status-Line; RFC 3420 defines the sipfrag body itself).
///
/// The inverse of [`build_sipfrag_body`]. Deliberately tolerant, because the
/// body comes off the wire from a peer:
///
/// * A sipfrag MAY carry headers after the Status-Line (RFC 3420 §2), so only
///   the first non-blank line is read.
/// * A sipfrag MAY omit the start line entirely and carry only headers
///   (RFC 3420 §2) — there is no status to report, so that yields `None`.
/// * The reason phrase is optional in the Status-Line grammar (RFC 3261 §25.1
///   allows an empty `Reason-Phrase`), so a bare `SIP/2.0 200` parses with an
///   empty reason.
///
/// Returns `None` when the body carries no usable Status-Line; the caller
/// treats that as "no outcome", never as success.
pub fn parse_sipfrag_status(body: &[u8]) -> Option<(u16, String)> {
    let text = std::str::from_utf8(body).ok()?;
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    // RFC 3261 §7.2: Status-Line = SIP-Version SP Status-Code SP Reason-Phrase.
    let (version, rest) = line.split_once(' ')?;
    if !version.eq_ignore_ascii_case("SIP/2.0") {
        return None;
    }
    let rest = rest.trim_start();
    let (code_text, reason) = match rest.split_once(' ') {
        Some((code_text, reason)) => (code_text, reason.trim()),
        None => (rest, ""),
    };
    let code: u16 = code_text.parse().ok()?;
    // RFC 3261 §21: a status code is 3 digits, 100..699.
    if !(100..700).contains(&code) {
        return None;
    }
    Some((code, reason.to_string()))
}

/// Build a `Subscription-State` header value for a REFER-subscription NOTIFY
/// (RFC 3515 §2.4.4 / RFC 6665 §4.1.3).
///
/// While the transfer is still pending or trying the subscription is
/// `active;expires=<n>`; once it reaches a final state (success or failure) the
/// implicit subscription is `terminated;reason=noresource` and the dialog is
/// torn down.
pub fn subscription_state_header(state: &TransferState, expires_secs: u32) -> String {
    match state {
        TransferState::Pending | TransferState::Trying => {
            format!("active;expires={expires_secs}")
        }
        TransferState::Succeeded | TransferState::Failed { .. } => {
            "terminated;reason=noresource".to_string()
        }
    }
}

/// Determine which NOTIFY status to send based on an INVITE response.
pub fn transfer_result_from_response(status_code: u16) -> TransferState {
    if (200..300).contains(&status_code) {
        TransferState::Succeeded
    } else if status_code >= 300 {
        let reason = match status_code {
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            408 => "Request Timeout",
            480 => "Temporarily Unavailable",
            486 => "Busy Here",
            487 => "Request Terminated",
            488 => "Not Acceptable Here",
            500 => "Server Internal Error",
            503 => "Service Unavailable",
            600 => "Busy Everywhere",
            603 => "Decline",
            _ => "Error",
        };
        TransferState::Failed {
            code: status_code,
            reason: reason.to_string(),
        }
    } else {
        // 1xx — still trying
        TransferState::Trying
    }
}

/// The `Referred-By` (RFC 3892) that the INVITE triggered by a
/// siphon-terminated transfer must carry, given the `Referred-By` on the REFER
/// that asked for it.
///
/// RFC 3892 §3: the referee SHOULD place the referrer's `Referred-By` on the
/// request the referral triggers, so the target can see on whose authority it
/// is being called. On a REFER without `Replaces` it is also the ONLY thing
/// tying the triggered INVITE back to the referral — a referrer that keeps the
/// consultation leg itself and expects the INVITE to come back to it has
/// nothing else to correlate on, and answers it as an unrelated new call.
///
/// `Some(value)` is set on the triggered INVITE; `None` means the triggered
/// INVITE must carry no `Referred-By` at all. `None` is not the same as "leave
/// whatever is there": the transfer INVITE is built from the referrer's own
/// INVITE as a template, so an A-leg that itself arrived as a transfer already
/// carries a `Referred-By` — the PREVIOUS referrer's. Left alone it would name
/// the wrong party on every transfer after the first in a chain, which is why
/// the absent case is explicit rather than a no-op.
///
/// Whitespace-only is treated as absent (RFC 3261 §7.3.1 allows the surrounding
/// LWS, and an empty value names nobody).
pub fn triggered_referred_by(refer_header: Option<&str>) -> Option<String> {
    let value = refer_header?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Validate that a Replaces header matches an existing call.
///
/// Returns `true` if the given call_id and tags match.
pub fn replaces_matches(
    replaces: &Replaces,
    call_id: &str,
    local_tag: &str,
    remote_tag: &str,
) -> bool {
    replaces.call_id == call_id && replaces.from_tag == remote_tag && replaces.to_tag == local_tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_state_display() {
        assert_eq!(TransferState::Pending.to_string(), "pending");
        assert_eq!(TransferState::Trying.to_string(), "trying");
        assert_eq!(TransferState::Succeeded.to_string(), "succeeded");
        assert_eq!(
            TransferState::Failed {
                code: 486,
                reason: "Busy Here".to_string()
            }
            .to_string(),
            "failed (486 Busy Here)"
        );
    }

    #[test]
    fn transfer_side_display() {
        assert_eq!(TransferSide::ALeg.to_string(), "a");
        assert_eq!(TransferSide::BLeg.to_string(), "b");
    }

    #[test]
    fn build_sipfrag_100_trying() {
        let body = build_sipfrag_body(100, "Trying");
        assert_eq!(body, "SIP/2.0 100 Trying\r\n");
    }

    #[test]
    fn build_sipfrag_200_ok() {
        let body = build_sipfrag_body(200, "OK");
        assert_eq!(body, "SIP/2.0 200 OK\r\n");
    }

    #[test]
    fn build_sipfrag_503() {
        let body = build_sipfrag_body(503, "Service Unavailable");
        assert_eq!(body, "SIP/2.0 503 Service Unavailable\r\n");
    }

    #[test]
    fn parse_sipfrag_round_trips_build() {
        // The inverse of build_sipfrag_body, on every status class it emits.
        for (code, reason) in [(100, "Trying"), (200, "OK"), (503, "Service Unavailable")] {
            let body = build_sipfrag_body(code, reason);
            assert_eq!(
                parse_sipfrag_status(body.as_bytes()),
                Some((code, reason.to_string()))
            );
        }
    }

    #[test]
    fn parse_sipfrag_ignores_trailing_headers() {
        // RFC 3420 §2: a sipfrag may carry headers after the Status-Line.
        let body = b"SIP/2.0 486 Busy Here
Contact: <sip:carol@example.com>
";
        assert_eq!(
            parse_sipfrag_status(body),
            Some((486, "Busy Here".to_string()))
        );
    }

    #[test]
    fn parse_sipfrag_accepts_missing_reason_phrase() {
        // RFC 3261 §25.1 allows an empty Reason-Phrase.
        assert_eq!(
            parse_sipfrag_status(
                b"SIP/2.0 200
"
            ),
            Some((200, String::new()))
        );
    }

    #[test]
    fn parse_sipfrag_multi_word_reason_is_kept_whole() {
        assert_eq!(
            parse_sipfrag_status(
                b"SIP/2.0 480 Temporarily Unavailable
"
            ),
            Some((480, "Temporarily Unavailable".to_string()))
        );
    }

    #[test]
    fn parse_sipfrag_without_status_line_is_none() {
        // RFC 3420 §2: a header-only fragment carries no outcome at all.
        assert_eq!(
            parse_sipfrag_status(
                b"Contact: <sip:carol@example.com>
"
            ),
            None
        );
        assert_eq!(parse_sipfrag_status(b""), None);
        assert_eq!(
            parse_sipfrag_status(
                b"

"
            ),
            None
        );
        assert_eq!(
            parse_sipfrag_status(
                b"SIP/2.0 not-a-code
"
            ),
            None
        );
        assert_eq!(
            parse_sipfrag_status(
                b"HTTP/1.1 200 OK
"
            ),
            None
        );
        // Out of the 100..699 status range (RFC 3261 §21).
        assert_eq!(
            parse_sipfrag_status(
                b"SIP/2.0 99 Nope
"
            ),
            None
        );
        assert_eq!(
            parse_sipfrag_status(
                b"SIP/2.0 700 Nope
"
            ),
            None
        );
        // Not UTF-8 at all.
        assert_eq!(parse_sipfrag_status(&[0xff, 0xfe, 0x00]), None);
    }

    #[test]
    fn parse_sipfrag_tolerates_leading_blank_lines() {
        assert_eq!(
            parse_sipfrag_status(
                b"
SIP/2.0 200 OK
"
            ),
            Some((200, "OK".to_string()))
        );
    }

    #[test]
    fn transfer_result_2xx() {
        assert_eq!(transfer_result_from_response(200), TransferState::Succeeded);
        assert_eq!(transfer_result_from_response(202), TransferState::Succeeded);
    }

    #[test]
    fn transfer_result_4xx() {
        match transfer_result_from_response(486) {
            TransferState::Failed { code, reason } => {
                assert_eq!(code, 486);
                assert_eq!(reason, "Busy Here");
            }
            other => panic!("Expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn transfer_result_5xx() {
        match transfer_result_from_response(503) {
            TransferState::Failed { code, reason } => {
                assert_eq!(code, 503);
                assert_eq!(reason, "Service Unavailable");
            }
            other => panic!("Expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn subscription_state_active_while_pending_or_trying() {
        assert_eq!(
            subscription_state_header(&TransferState::Pending, 60),
            "active;expires=60"
        );
        assert_eq!(
            subscription_state_header(&TransferState::Trying, 120),
            "active;expires=120"
        );
    }

    #[test]
    fn subscription_state_terminated_on_final() {
        assert_eq!(
            subscription_state_header(&TransferState::Succeeded, 60),
            "terminated;reason=noresource"
        );
        assert_eq!(
            subscription_state_header(
                &TransferState::Failed {
                    code: 486,
                    reason: "Busy Here".to_string()
                },
                60
            ),
            "terminated;reason=noresource"
        );
    }

    #[test]
    fn transfer_result_1xx_still_trying() {
        assert_eq!(transfer_result_from_response(180), TransferState::Trying);
        assert_eq!(transfer_result_from_response(183), TransferState::Trying);
    }

    #[test]
    fn transfer_result_unknown_error() {
        match transfer_result_from_response(499) {
            TransferState::Failed { code, reason } => {
                assert_eq!(code, 499);
                assert_eq!(reason, "Error");
            }
            other => panic!("Expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn replaces_matches_correct_dialog() {
        let replaces = Replaces {
            call_id: "call-1@host".to_string(),
            from_tag: "remote-tag".to_string(),
            to_tag: "local-tag".to_string(),
            early_only: false,
        };
        // Note: Replaces from-tag is the remote side's from-tag
        assert!(replaces_matches(
            &replaces,
            "call-1@host",
            "local-tag",
            "remote-tag"
        ));
    }

    #[test]
    fn replaces_no_match_wrong_call_id() {
        let replaces = Replaces {
            call_id: "call-1@host".to_string(),
            from_tag: "a".to_string(),
            to_tag: "b".to_string(),
            early_only: false,
        };
        assert!(!replaces_matches(&replaces, "call-2@host", "b", "a"));
    }

    #[test]
    fn replaces_no_match_wrong_tags() {
        let replaces = Replaces {
            call_id: "call-1@host".to_string(),
            from_tag: "a".to_string(),
            to_tag: "b".to_string(),
            early_only: false,
        };
        assert!(!replaces_matches(&replaces, "call-1@host", "a", "b"));
    }

    #[test]
    fn transfer_context_creation() {
        let context = TransferContext {
            refer_to: ReferTo {
                uri: "sip:carol@example.com".to_string(),
                replaces: None,
            },
            initiated_by: TransferSide::ALeg,
            state: TransferState::Pending,
            notify_cseq: 1,
            notify_from_tag: "our-tag".to_string(),
            notify_to_tag: "their-tag".to_string(),
            notify_call_id: "call-id-123".to_string(),
        };
        assert_eq!(context.state, TransferState::Pending);
        assert_eq!(context.initiated_by, TransferSide::ALeg);
        assert_eq!(context.refer_to.uri, "sip:carol@example.com");
        assert!(context.refer_to.replaces.is_none());
    }

    #[test]
    fn transfer_context_with_replaces() {
        let context = TransferContext {
            refer_to: ReferTo {
                uri: "sip:carol@example.com".to_string(),
                replaces: Some(Replaces {
                    call_id: "other-call@host".to_string(),
                    from_tag: "ft".to_string(),
                    to_tag: "tt".to_string(),
                    early_only: false,
                }),
            },
            initiated_by: TransferSide::BLeg,
            state: TransferState::Trying,
            notify_cseq: 2,
            notify_from_tag: "tag1".to_string(),
            notify_to_tag: "tag2".to_string(),
            notify_call_id: "call-99".to_string(),
        };
        assert!(context.refer_to.replaces.is_some());
        assert_eq!(context.initiated_by, TransferSide::BLeg);
    }

    // ----- Referred-By on the triggered INVITE (RFC 3892 §3) -----

    #[test]
    fn triggered_referred_by_carries_the_refers_value_verbatim() {
        // A referrer's Referred-By is opaque: it can carry URI parameters that
        // only the referrer understands, and they are exactly what a referrer
        // correlating the triggered INVITE back to its referral reads. Anything
        // less than verbatim breaks that.
        let value = "<sip:proxy.example.net:5061;x-ti=11111111-2222-3333-4444-555555555555>";
        assert_eq!(
            triggered_referred_by(Some(value)),
            Some(value.to_string()),
            "the referrer's Referred-By must reach the target unmodified"
        );
    }

    #[test]
    fn triggered_referred_by_trims_surrounding_whitespace() {
        // RFC 3261 §7.3.1 allows LWS around a header value; it is not part of it.
        assert_eq!(
            triggered_referred_by(Some("  <sip:alice@example.com>\t")),
            Some("<sip:alice@example.com>".to_string())
        );
    }

    #[test]
    fn triggered_referred_by_absent_when_the_refer_has_none() {
        assert_eq!(triggered_referred_by(None), None);
    }

    #[test]
    fn triggered_referred_by_treats_an_empty_value_as_absent() {
        // An empty Referred-By names nobody. Reporting it as present would put a
        // valueless header on the wire AND, worse, suppress the removal of a
        // stale one inherited from the dial template.
        assert_eq!(triggered_referred_by(Some("")), None);
        assert_eq!(triggered_referred_by(Some("   ")), None);
    }
}
