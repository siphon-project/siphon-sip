//! Transaction key — uniquely identifies a SIP transaction per RFC 3261 §17.1.3 / §17.2.3.
//!
//! A transaction is identified by:
//! - The **branch** parameter from the topmost Via header
//! - The **sent-by** value (host:port) from the topmost Via header
//! - The **method** (needed because ACK for non-2xx shares the INVITE transaction's branch)
//!
//! RFC 3261 §17.2.3 requires matching both branch AND sent-by for server transaction
//! identification. Without sent-by, two different UAs that generate the same branch
//! (e.g., SIPp's deterministic branches) would incorrectly collide.
//!
//! # RFC 2543 legacy matching is NOT implemented
//!
//! §17.2.3 also defines matching for a request whose topmost Via carries no
//! branch, or one without the `z9hG4bK` magic cookie: Request-URI, To tag,
//! From tag, Call-ID, CSeq and top Via, with ACK keyed on the To tag of the
//! *response* rather than the request. siphon does none of that — a request
//! with no branch parameter fails [`super::TransactionManager::key_from_message`]
//! and never gets a server transaction at all.
//!
//! (This module used to claim the fallback was implemented "as a simple hash
//! fallback". It never was, and the claim outlived several people reading it.)
//!
//! The consequence is not a rejection but a silent downgrade: the dispatcher
//! logs the failure at debug and processes the request anyway, statelessly. So
//! a legacy peer's retransmissions are not absorbed, and each one runs the
//! script again. `siphon_requests_without_branch_total` counts them, because
//! the alternative to counting is finding out from a duplicate-call report.
//!
//! Implementing §17.2.3 properly needs a second index (the ACK case keys on a
//! tag siphon only learns when it sends the response), which is why this is a
//! documented gap rather than a half-built one. Nothing in siphon's deployment
//! profile — IMS, WebRTC, modern trunks — speaks RFC 2543.

use std::fmt;
use std::hash::Hash;

use crate::sip::message::Method;

/// Identifies a SIP transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    /// The branch value from the topmost Via header (without `z9hG4bK` prefix check —
    /// that's the caller's responsibility).
    pub branch: String,
    /// The SIP method. ACK to a non-2xx INVITE shares the INVITE transaction,
    /// so we normalize ACK → INVITE for matching purposes.
    pub method: Method,
    /// The sent-by value (host:port) from the topmost Via header.
    /// Required by RFC 3261 §17.2.3 for correct server transaction matching.
    pub sent_by: String,
}

impl TransactionKey {
    /// Create a key from branch + method + sent-by.
    ///
    /// ACK is normalized to INVITE for transaction matching (RFC 3261 §17.1.1.2):
    /// the ACK for a non-2xx response is part of the INVITE transaction.
    pub fn new(branch: String, method: Method, sent_by: String) -> Self {
        let method = match method {
            Method::Ack => Method::Invite,
            other => other,
        };
        Self {
            branch,
            method,
            sent_by,
        }
    }

    /// Create a key from a raw Via branch, method string, and sent-by.
    pub fn from_parts(branch: &str, method: &str, sent_by: &str) -> Self {
        Self::new(
            branch.to_string(),
            Method::from_str(method),
            sent_by.to_string(),
        )
    }

    /// Check if a branch value follows the RFC 3261 magic cookie convention.
    pub fn is_rfc3261_branch(branch: &str) -> bool {
        branch.starts_with("z9hG4bK")
    }

    /// Generate a new unique branch value with the RFC 3261 magic cookie prefix.
    pub fn generate_branch() -> String {
        format!("z9hG4bK-{}", uuid::Uuid::new_v4().as_simple())
    }

    /// Format the sent-by from a Via header's host and optional port.
    pub fn format_sent_by(host: &str, port: Option<u16>) -> String {
        match port {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        }
    }
}

impl fmt::Display for TransactionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.branch,
            self.method.as_str(),
            self.sent_by
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sb() -> String {
        "10.0.0.1:5060".to_string()
    }

    #[test]
    fn same_branch_same_method_same_sent_by_matches() {
        let key1 = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        let key2 = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        assert_eq!(key1, key2);
    }

    #[test]
    fn same_branch_same_method_different_sent_by_does_not_match() {
        let key1 = TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Invite,
            "10.0.0.1:5060".to_string(),
        );
        let key2 = TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Invite,
            "10.0.0.2:5060".to_string(),
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn same_branch_different_method_does_not_match() {
        let key1 = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        let key2 = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Register, sb());
        assert_ne!(key1, key2);
    }

    #[test]
    fn different_branch_same_method_does_not_match() {
        let key1 = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        let key2 = TransactionKey::new("z9hG4bK-xyz".to_string(), Method::Invite, sb());
        assert_ne!(key1, key2);
    }

    #[test]
    fn ack_normalizes_to_invite() {
        let invite_key = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        let ack_key = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Ack, sb());
        assert_eq!(invite_key, ack_key);
    }

    #[test]
    fn cancel_has_own_transaction() {
        let invite_key = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Invite, sb());
        let cancel_key = TransactionKey::new("z9hG4bK-abc".to_string(), Method::Cancel, sb());
        // CANCEL creates its own transaction (same branch but different method)
        assert_ne!(invite_key, cancel_key);
    }

    #[test]
    fn from_parts_works() {
        let key = TransactionKey::from_parts("z9hG4bK-test", "REGISTER", "10.0.0.1:5060");
        assert_eq!(key.branch, "z9hG4bK-test");
        assert_eq!(key.method, Method::Register);
        assert_eq!(key.sent_by, "10.0.0.1:5060");
    }

    #[test]
    fn rfc3261_branch_detection() {
        assert!(TransactionKey::is_rfc3261_branch("z9hG4bK-abc123"));
        assert!(TransactionKey::is_rfc3261_branch("z9hG4bK776asdhds"));
        assert!(!TransactionKey::is_rfc3261_branch("abc123"));
        assert!(!TransactionKey::is_rfc3261_branch(""));
    }

    #[test]
    fn generate_branch_has_magic_cookie() {
        let branch = TransactionKey::generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        // Each call generates a unique branch
        let branch2 = TransactionKey::generate_branch();
        assert_ne!(branch, branch2);
    }

    #[test]
    fn display_format() {
        let key = TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Invite,
            "10.0.0.1:5060".to_string(),
        );
        assert_eq!(key.to_string(), "z9hG4bK-abc:INVITE:10.0.0.1:5060");
    }

    #[test]
    fn hash_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Invite,
            sb(),
        ));
        // ACK with same branch + sent_by should find the INVITE transaction
        assert!(set.contains(&TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Ack,
            sb()
        )));
        // Different method should not
        assert!(!set.contains(&TransactionKey::new(
            "z9hG4bK-abc".to_string(),
            Method::Bye,
            sb()
        )));
    }

    #[test]
    fn format_sent_by_with_port() {
        assert_eq!(
            TransactionKey::format_sent_by("10.0.0.1", Some(5060)),
            "10.0.0.1:5060"
        );
    }

    #[test]
    fn format_sent_by_without_port() {
        assert_eq!(TransactionKey::format_sent_by("10.0.0.1", None), "10.0.0.1");
    }
}
