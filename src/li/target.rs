//! The intercept matching index.
//!
//! This is the lookup that decides, for every SIP message, whether a
//! provisioned warrant applies to it. It is deliberately separate from the
//! provisioning store in [`crate::li::x1::store`]: that store owns *what* is
//! provisioned, this owns *how it is found*, and [`crate::li::x1::TaskStore`]
//! keeps the two in step so there is one source of truth.
//!
//! # What changed, and why
//!
//! The previous index keyed tasks on a free-text LIID and matched three
//! identifier kinds (`sip_uri`, `phone_number`, `ip_address`). Neither
//! survives contact with ETSI TS 103 221-1:
//!
//! * The task key is the **XID**, a UUID, because that same value goes into
//!   the 16-byte XID field of every X2 and X3 PDU delivered for the task. A
//!   LIID is a *mediation* attribute and lives in `mediationDetails`; several
//!   tasks can share one, and a task can have none.
//! * The identifier set is the dictionary's. An IMS keys on `impu` and `impi`
//!   as much as on `sipUri`, and neither existed here before.
//!
//! # Normalisation
//!
//! Every identifier is reduced to a canonical key before it is indexed or
//! looked up, so that `sip:Alice@Example.COM;transport=tcp` in a Request-URI
//! matches a warrant provisioned as `sip:alice@example.com`. Getting this
//! wrong makes a warrant silently match nothing, so each rule is tested.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;

use crate::li::x1::types::{TargetIdentifier, XId};

/// Reduce a target identifier to the key it is indexed under.
///
/// Returns `None` for an identifier siphon cannot match SIP traffic against,
/// which the provisioning layer has already refused.
fn index_key(identifier: &TargetIdentifier) -> Option<String> {
    match identifier {
        TargetIdentifier::SipUri(uri) | TargetIdentifier::Impu(uri) => Some(normalize_uri(uri)),
        TargetIdentifier::TelUri(uri) => Some(normalize_tel(uri)),
        TargetIdentifier::E164Number(number) => Some(normalize_digits(number)),
        TargetIdentifier::Impi(impi) => Some(impi.to_ascii_lowercase()),
        TargetIdentifier::Imsi(imsi) => Some(format!("imsi:{}", normalize_digits(imsi))),
        TargetIdentifier::Imei(imei) => Some(format!("imei:{}", normalize_digits(imei))),
        TargetIdentifier::Ipv4Address(address) => Some(IpAddr::V4(*address).to_string()),
        TargetIdentifier::Ipv6Address(address) => Some(IpAddr::V6(*address).to_string()),
        TargetIdentifier::Unsupported(_) => None,
    }
}

/// Canonicalise a SIP/SIPS URI for matching.
///
/// Lowercased, with URI parameters and any `<...>` / display name stripped.
/// Parameters carry transport and routing detail that has nothing to do with
/// who the party is, and a warrant provisioned without them must still match a
/// message that carries them.
pub fn normalize_uri(uri: &str) -> String {
    let trimmed = uri.trim();
    // Strip a display name and angle brackets: `"Alice" <sip:a@b>;tag=1`.
    let inner = match (trimmed.find('<'), trimmed.find('>')) {
        (Some(start), Some(end)) if end > start => &trimmed[start + 1..end],
        _ => trimmed,
    };
    // Drop URI parameters and headers.
    let without_params = inner
        .split(';')
        .next()
        .unwrap_or(inner)
        .split('?')
        .next()
        .unwrap_or(inner);
    without_params.trim().to_ascii_lowercase()
}

/// Canonicalise a `tel:` URI to `tel:` plus its digits.
fn normalize_tel(uri: &str) -> String {
    let normalized = normalize_uri(uri);
    let body = normalized.strip_prefix("tel:").unwrap_or(&normalized);
    format!("tel:{}", normalize_digits(body))
}

/// Keep only digits, dropping `+`, spaces and punctuation.
///
/// `+1-555-123-4567`, `+15551234567` and `15551234567` are the same subscriber,
/// and a warrant must match however the number was written. Note the
/// dictionary's `InternationalE164` is digits-only with no leading `+`, so the
/// canonical form drops it.
fn normalize_digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

/// Every key a SIP URI could match a warrant on.
///
/// One URI yields several candidates: the URI itself, and the user part as a
/// bare number (so a warrant on `e164Number` matches `sip:15551234567@carrier`)
/// and as a `tel:` URI.
fn candidate_keys(uri: &str) -> Vec<String> {
    let normalized = normalize_uri(uri);
    let mut keys = vec![normalized.clone()];

    // The user part, for number-shaped warrants.
    let scheme_stripped = normalized
        .strip_prefix("sip:")
        .or_else(|| normalized.strip_prefix("sips:"))
        .or_else(|| normalized.strip_prefix("tel:"))
        .unwrap_or(&normalized);
    if let Some(user) = scheme_stripped.split('@').next() {
        if !user.is_empty() {
            let digits = normalize_digits(user);
            if !digits.is_empty() {
                keys.push(digits.clone());
                keys.push(format!("tel:{digits}"));
            }
            // An IMPI is a bare user@realm with no scheme, so the
            // scheme-stripped form is itself a candidate.
            keys.push(scheme_stripped.to_string());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// Which party to a call a warrant matched.
///
/// Not a detail: ETSI TS 103 221-2 §5.2.6 defines a delivered packet's
/// direction *relative to the target*, so the delivery path has to know which
/// end of the call the warrant names. Getting it wrong inverts the direction on
/// every packet delivered for that intercept, which is worse than delivering
/// nothing — a mediation function would render the call backwards and nothing
/// would look broken.
///
/// Derived from the dialog's `From` and `To`, not from the direction of the
/// individual message, so it stays stable across requests and responses for the
/// life of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedParty {
    /// The warrant names the party that originated the dialog (the `From`).
    Originating,
    /// The warrant names the party the dialog is addressed to (the `To` or
    /// Request-URI).
    Terminating,
}

/// One warrant matching one message, and which party it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// The task whose warrant matched.
    pub x_id: XId,
    /// Which end of the call it names.
    pub party: MatchedParty,
}

/// The matching index: canonical identifier key to the tasks provisioned on it.
///
/// Several warrants may target the same identity, so a key maps to a list.
#[derive(Debug, Clone, Default)]
pub struct TargetStore {
    by_identity: Arc<DashMap<String, Vec<XId>>>,
    /// The keys each task was indexed under, so removal is exact.
    by_task: Arc<DashMap<XId, Vec<String>>>,
}

impl TargetStore {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a task's identifiers, replacing any previous entry for it.
    pub fn index(&self, x_id: XId, identifiers: &[TargetIdentifier]) {
        self.remove(x_id);

        let mut keys: Vec<String> = identifiers.iter().filter_map(index_key).collect();
        keys.sort();
        keys.dedup();

        for key in &keys {
            self.by_identity.entry(key.clone()).or_default().push(x_id);
        }
        if !keys.is_empty() {
            self.by_task.insert(x_id, keys);
        }
    }

    /// Drop a task from the index.
    pub fn remove(&self, x_id: XId) {
        let Some((_, keys)) = self.by_task.remove(&x_id) else {
            return;
        };
        for key in keys {
            let now_empty = match self.by_identity.get_mut(&key) {
                Some(mut tasks) => {
                    tasks.retain(|candidate| *candidate != x_id);
                    tasks.is_empty()
                }
                None => false,
            };
            if now_empty {
                self.by_identity.remove(&key);
            }
        }
    }

    /// Empty the index.
    pub fn clear(&self) {
        self.by_identity.clear();
        self.by_task.clear();
    }

    /// Tasks provisioned on an exact canonical key.
    fn tasks_for_key(&self, key: &str) -> Vec<XId> {
        self.by_identity
            .get(key)
            .map(|tasks| tasks.clone())
            .unwrap_or_default()
    }

    /// Tasks whose warrant matches a SIP URI.
    ///
    /// Deduplicated, because one URI yields several candidate keys and a single
    /// warrant can be indexed under more than one of them — an IMS subscriber
    /// provisioned by both IMPU and IMPI is the ordinary case. Returning it
    /// twice would mean two IRI records for one message.
    pub fn match_uri(&self, uri: &str) -> Vec<XId> {
        let mut seen = HashSet::new();
        let mut matched = Vec::new();
        for key in candidate_keys(uri) {
            for x_id in self.tasks_for_key(&key) {
                if seen.insert(x_id) {
                    matched.push(x_id);
                }
            }
        }
        matched
    }

    /// Tasks whose warrant matches a source address.
    pub fn match_ip(&self, address: IpAddr) -> Vec<XId> {
        self.tasks_for_key(&address.to_string())
    }

    /// Tasks whose warrant matches an IMSI.
    pub fn match_imsi(&self, imsi: &str) -> Vec<XId> {
        self.tasks_for_key(&format!("imsi:{}", normalize_digits(imsi)))
    }

    /// Tasks whose warrant matches an IMEI.
    pub fn match_imei(&self, imei: &str) -> Vec<XId> {
        self.tasks_for_key(&format!("imei:{}", normalize_digits(imei)))
    }

    /// Every task matching any identity carried by one SIP message, with the
    /// party each one matched.
    ///
    /// Deduplicated: a warrant matching both the From and the To of the same
    /// message is one intercept, not two. When a warrant matches both ends —
    /// a target calling themselves, or a forwarded leg where both parties are
    /// the same identity — the originating side wins, because that is the end
    /// the dialog is anchored on and it keeps the answer stable for the life of
    /// the call.
    pub fn match_message(
        &self,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<Match> {
        let mut seen = HashSet::new();
        let mut matched = Vec::new();

        // Ordered so the originating side is considered first and therefore
        // wins the deduplication.
        let candidates = [
            (from_uri, MatchedParty::Originating),
            (request_uri, MatchedParty::Terminating),
            (to_uri, MatchedParty::Terminating),
        ];
        for (uri, party) in candidates {
            let Some(uri) = uri else { continue };
            for x_id in self.match_uri(uri) {
                if seen.insert(x_id) {
                    matched.push(Match { x_id, party });
                }
            }
        }

        // A source address identifies the sender, which for a request is the
        // originating side.
        if let Some(address) = source_ip {
            for x_id in self.match_ip(address) {
                if seen.insert(x_id) {
                    matched.push(Match {
                        x_id,
                        party: MatchedParty::Originating,
                    });
                }
            }
        }
        matched
    }

    /// How many distinct tasks are indexed.
    pub fn len(&self) -> usize {
        self.by_task.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_task.is_empty()
    }

    /// How many distinct identifier keys are indexed.
    ///
    /// Used by the leak guard: this must drain to its baseline alongside
    /// [`Self::len`], because an orphaned key would grow without bound.
    pub fn key_count(&self) -> usize {
        self.by_identity.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sip(uri: &str) -> TargetIdentifier {
        TargetIdentifier::SipUri(uri.to_string())
    }

    // -- normalisation ---------------------------------------------------

    #[test]
    fn uri_normalisation_lowercases_and_strips_parameters() {
        assert_eq!(
            normalize_uri("sip:Alice@Example.COM;transport=tcp"),
            "sip:alice@example.com"
        );
        assert_eq!(normalize_uri("  sip:a@b.com  "), "sip:a@b.com");
        assert_eq!(normalize_uri("sip:a@b.com?subject=x"), "sip:a@b.com");
    }

    #[test]
    fn uri_normalisation_strips_display_names_and_angle_brackets() {
        assert_eq!(
            normalize_uri("\"Alice Smith\" <sip:alice@example.com>;tag=abc"),
            "sip:alice@example.com"
        );
        assert_eq!(normalize_uri("<sip:bob@example.com>"), "sip:bob@example.com");
    }

    #[test]
    fn digit_normalisation_drops_formatting_and_plus() {
        assert_eq!(normalize_digits("+1-555-123-4567"), "15551234567");
        assert_eq!(normalize_digits("+15551234567"), "15551234567");
        assert_eq!(normalize_digits("15551234567"), "15551234567");
        assert_eq!(normalize_digits("(555) 123 4567"), "5551234567");
    }

    #[test]
    fn tel_normalisation_is_scheme_plus_digits() {
        assert_eq!(normalize_tel("tel:+1-555-123-4567"), "tel:15551234567");
        assert_eq!(normalize_tel("TEL:+15551234567"), "tel:15551234567");
    }

    // -- indexing and matching --------------------------------------------

    #[test]
    fn a_sip_warrant_matches_its_uri() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);

        assert_eq!(store.match_uri("sip:alice@example.com"), vec![x_id]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn matching_is_case_and_parameter_insensitive() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);

        // All of these are the same subscriber on the wire.
        for candidate in [
            "sip:Alice@Example.COM",
            "sip:alice@example.com;transport=tls",
            "\"Alice\" <sip:alice@example.com>;tag=99",
        ] {
            assert_eq!(
                store.match_uri(candidate),
                vec![x_id],
                "{candidate} should match"
            );
        }
    }

    #[test]
    fn an_e164_warrant_matches_a_sip_uri_carrying_the_number() {
        // The common IMS case: the warrant names a number, the traffic names
        // sip:<number>@carrier.
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[TargetIdentifier::E164Number("15551234567".into())]);

        assert_eq!(store.match_uri("sip:15551234567@carrier.example"), vec![x_id]);
        assert_eq!(store.match_uri("sip:+15551234567@carrier.example"), vec![x_id]);
        assert_eq!(store.match_uri("tel:+1-555-123-4567"), vec![x_id]);
    }

    #[test]
    fn a_tel_warrant_matches_however_the_number_is_written() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[TargetIdentifier::TelUri("tel:+15551234567".into())]);

        assert_eq!(store.match_uri("tel:+15551234567"), vec![x_id]);
        assert_eq!(store.match_uri("sip:15551234567@carrier.example"), vec![x_id]);
    }

    #[test]
    fn an_impu_warrant_matches_like_a_sip_uri() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[TargetIdentifier::Impu("sip:alice@ims.example.com".into())],
        );
        assert_eq!(store.match_uri("sip:alice@ims.example.com"), vec![x_id]);
    }

    #[test]
    fn an_impi_warrant_matches_a_bare_user_at_realm() {
        // An IMPI has no scheme; the scheme-stripped form of the URI is the
        // candidate that matches it.
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[TargetIdentifier::Impi("alice@ims.example.com".into())],
        );
        assert_eq!(store.match_uri("sip:alice@ims.example.com"), vec![x_id]);
    }

    #[test]
    fn an_ip_warrant_matches_a_source_address() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[TargetIdentifier::Ipv4Address(Ipv4Addr::new(198, 51, 100, 7))],
        );
        assert_eq!(
            store.match_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            vec![x_id]
        );
        assert!(store
            .match_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)))
            .is_empty());
    }

    #[test]
    fn an_ipv6_warrant_matches_regardless_of_written_form() {
        // The warrant arrives expanded (the schema requires it); the message's
        // source address is a parsed Ipv6Addr. Both normalise through
        // Ipv6Addr's own Display, so they meet.
        let store = TargetStore::new();
        let x_id = XId::generate();
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
        store.index(x_id, &[TargetIdentifier::Ipv6Address(address)]);
        assert_eq!(store.match_ip(IpAddr::V6(address)), vec![x_id]);
    }

    #[test]
    fn imsi_and_imei_warrants_do_not_collide() {
        // Both are bare digit strings, so they are namespaced in the index.
        let store = TargetStore::new();
        let imsi_task = XId::generate();
        let imei_task = XId::generate();
        store.index(imsi_task, &[TargetIdentifier::Imsi("001010000000001".into())]);
        store.index(imei_task, &[TargetIdentifier::Imei("01234567890123".into())]);

        assert_eq!(store.match_imsi("001010000000001"), vec![imsi_task]);
        assert_eq!(store.match_imei("01234567890123"), vec![imei_task]);
        assert!(store.match_imsi("01234567890123").is_empty());
        // And neither is reachable through URI matching, which would be a
        // cross-namespace false positive.
        assert!(store.match_uri("sip:001010000000001@ims.example").is_empty());
    }

    #[test]
    fn an_unsupported_identifier_is_not_indexed() {
        let store = TargetStore::new();
        store.index(
            XId::generate(),
            &[TargetIdentifier::Unsupported("gtpuTunnelId".into())],
        );
        assert!(store.is_empty());
        assert_eq!(store.key_count(), 0);
    }

    // -- message matching --------------------------------------------------

    #[test]
    fn match_message_checks_every_identity_on_the_message() {
        let store = TargetStore::new();
        let ruri_task = XId::generate();
        let from_task = XId::generate();
        let to_task = XId::generate();
        store.index(ruri_task, &[sip("sip:target@example.com")]);
        store.index(from_task, &[sip("sip:caller@example.com")]);
        store.index(to_task, &[sip("sip:callee@example.com")]);

        let matched = store.match_message(
            Some("sip:target@example.com"),
            Some("sip:caller@example.com"),
            Some("sip:callee@example.com"),
            None,
        );
        assert_eq!(matched.len(), 3);
        let found = |x_id| matched.iter().find(|entry| entry.x_id == x_id);
        // Which party each warrant names follows from where it matched, and it
        // is what the delivered packets' direction is defined against.
        assert_eq!(
            found(from_task).map(|entry| entry.party),
            Some(MatchedParty::Originating)
        );
        assert_eq!(
            found(ruri_task).map(|entry| entry.party),
            Some(MatchedParty::Terminating)
        );
        assert_eq!(
            found(to_task).map(|entry| entry.party),
            Some(MatchedParty::Terminating)
        );
    }

    #[test]
    fn a_warrant_matching_both_ends_resolves_to_the_originating_side() {
        // A target calling themselves, or a leg where both parties are the
        // same identity. The answer has to be stable for the life of the call,
        // so the originating side wins rather than whichever field was read
        // first.
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);

        let matched = store.match_message(
            Some("sip:alice@example.com"),
            Some("sip:alice@example.com"),
            Some("sip:alice@example.com"),
            None,
        );
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].party, MatchedParty::Originating);
    }

    #[test]
    fn a_source_address_match_names_the_originating_side() {
        use std::net::Ipv4Addr;
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[TargetIdentifier::Ipv4Address(Ipv4Addr::new(198, 51, 100, 7))],
        );

        let matched = store.match_message(
            None,
            None,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        );
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].x_id, x_id);
        assert_eq!(matched[0].party, MatchedParty::Originating);
    }

    #[test]
    fn match_message_deduplicates_one_warrant_hit_twice() {
        // A warrant matching both From and To is one intercept.
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);

        let matched = store.match_message(
            Some("sip:alice@example.com"),
            Some("sip:alice@example.com"),
            Some("sip:alice@example.com"),
            None,
        );
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].x_id, x_id);
    }

    #[test]
    fn several_warrants_can_target_one_identity() {
        let store = TargetStore::new();
        let first = XId::generate();
        let second = XId::generate();
        store.index(first, &[sip("sip:alice@example.com")]);
        store.index(second, &[sip("sip:alice@example.com")]);

        let matched = store.match_uri("sip:alice@example.com");
        assert_eq!(matched.len(), 2);
        assert!(matched.contains(&first));
        assert!(matched.contains(&second));
    }

    #[test]
    fn a_warrant_with_several_identifiers_matches_on_any_of_them() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[
                sip("sip:alice@example.com"),
                TargetIdentifier::E164Number("15551234567".into()),
            ],
        );
        assert_eq!(store.match_uri("sip:alice@example.com"), vec![x_id]);
        assert_eq!(store.match_uri("sip:15551234567@carrier.example"), vec![x_id]);
    }

    #[test]
    fn an_unmatched_message_matches_nothing() {
        let store = TargetStore::new();
        store.index(XId::generate(), &[sip("sip:alice@example.com")]);
        assert!(store
            .match_message(
                Some("sip:bob@example.com"),
                Some("sip:carol@example.com"),
                None,
                None
            )
            .is_empty());
    }

    // -- every identifier type the profile supports -----------------------

    /// A realistic SIP message that each identifier type should match, so the
    /// table below is about *matching* rather than about parsing.
    struct Case {
        identifier: TargetIdentifier,
        /// Request-URI, From, To, source address.
        message: (Option<&'static str>, Option<&'static str>, Option<&'static str>, Option<IpAddr>),
        expect: MatchedParty,
    }

    /// Exhaustive over `TargetIdentifier`.
    ///
    /// The `match` is the point: adding a variant without deciding how it is
    /// indexed and matched breaks this build. Without it, a new identifier type
    /// would be accepted at `ActivateTask` and then silently match nothing —
    /// a warrant that reads as provisioned and intercepts no traffic, which is
    /// the failure mode this whole module exists to prevent.
    fn coverage_case(identifier: &TargetIdentifier) -> Option<Case> {
        use TargetIdentifier as T;
        let case = match identifier {
            T::SipUri(_) => Case {
                identifier: T::SipUri("sip:alice@example.com".into()),
                message: (
                    Some("sip:bob@example.com"),
                    Some("\"Alice\" <sip:Alice@Example.COM>;tag=1"),
                    Some("sip:bob@example.com"),
                    None,
                ),
                expect: MatchedParty::Originating,
            },
            T::TelUri(_) => Case {
                identifier: T::TelUri("tel:+15551234567".into()),
                message: (
                    Some("tel:+1-555-123-4567"),
                    Some("sip:carol@example.com"),
                    Some("tel:+1-555-123-4567"),
                    None,
                ),
                expect: MatchedParty::Terminating,
            },
            T::E164Number(_) => Case {
                identifier: T::E164Number("15551234567".into()),
                message: (
                    Some("sip:+15551234567@carrier.example;user=phone"),
                    Some("sip:carol@example.com"),
                    Some("sip:+15551234567@carrier.example"),
                    None,
                ),
                expect: MatchedParty::Terminating,
            },
            T::Impu(_) => Case {
                identifier: T::Impu("sip:alice@ims.example.com".into()),
                message: (
                    Some("sip:alice@ims.example.com"),
                    Some("sip:bob@ims.example.com"),
                    Some("sip:alice@ims.example.com"),
                    None,
                ),
                expect: MatchedParty::Terminating,
            },
            T::Impi(_) => Case {
                identifier: T::Impi("alice@ims.example.com".into()),
                message: (
                    None,
                    Some("<sip:alice@ims.example.com>;tag=9"),
                    Some("sip:bob@ims.example.com"),
                    None,
                ),
                expect: MatchedParty::Originating,
            },
            T::Imsi(_) => Case {
                // An IMSI never appears in a SIP header, so it is matched
                // through its own namespaced lookup rather than off a URI.
                identifier: T::Imsi("001010000000001".into()),
                message: (None, None, None, None),
                expect: MatchedParty::Originating,
            },
            T::Imei(_) => Case {
                identifier: T::Imei("01234567890123".into()),
                message: (None, None, None, None),
                expect: MatchedParty::Originating,
            },
            T::Ipv4Address(_) => Case {
                identifier: T::Ipv4Address(Ipv4Addr::new(198, 51, 100, 7)),
                message: (
                    Some("sip:bob@example.com"),
                    Some("sip:carol@example.com"),
                    Some("sip:bob@example.com"),
                    Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
                ),
                expect: MatchedParty::Originating,
            },
            T::Ipv6Address(_) => Case {
                identifier: T::Ipv6Address("2001:db8::1".parse().unwrap()),
                message: (
                    Some("sip:bob@example.com"),
                    Some("sip:carol@example.com"),
                    Some("sip:bob@example.com"),
                    Some(IpAddr::V6("2001:db8::1".parse().unwrap())),
                ),
                expect: MatchedParty::Originating,
            },
            // Not a target type — the provisioning layer refuses these by name
            // (error 3010) rather than indexing them, which
            // `an_unsupported_identifier_is_not_indexed` covers.
            T::Unsupported(_) => return None,
        };
        Some(case)
    }

    /// Every supported identifier type matches realistic SIP traffic.
    #[test]
    fn every_supported_identifier_type_matches_traffic() {
        // One representative of each variant, so `coverage_case`'s exhaustive
        // match is actually reached for all of them.
        let variants = [
            TargetIdentifier::SipUri(String::new()),
            TargetIdentifier::TelUri(String::new()),
            TargetIdentifier::E164Number(String::new()),
            TargetIdentifier::Impu(String::new()),
            TargetIdentifier::Impi(String::new()),
            TargetIdentifier::Imsi(String::new()),
            TargetIdentifier::Imei(String::new()),
            TargetIdentifier::Ipv4Address(Ipv4Addr::UNSPECIFIED),
            TargetIdentifier::Ipv6Address(Ipv6Addr::UNSPECIFIED),
            TargetIdentifier::Unsupported(String::new()),
        ];

        let mut covered = 0;
        for variant in &variants {
            let Some(case) = coverage_case(variant) else {
                continue;
            };
            covered += 1;

            let store = TargetStore::new();
            let x_id = XId::generate();
            store.index(x_id, std::slice::from_ref(&case.identifier));
            assert_eq!(
                store.len(),
                1,
                "{} was not indexed at all",
                case.identifier.element_name()
            );

            let (ruri, from, to, source) = case.message;
            let matched = match &case.identifier {
                // The two subscriber-equipment identifiers are looked up
                // directly; they are not carried in SIP headers.
                TargetIdentifier::Imsi(value) => store.match_imsi(value),
                TargetIdentifier::Imei(value) => store.match_imei(value),
                _ => store
                    .match_message(ruri, from, to, source)
                    .into_iter()
                    .map(|entry| entry.x_id)
                    .collect(),
            };
            assert_eq!(
                matched,
                vec![x_id],
                "{} did not match its own traffic",
                case.identifier.element_name()
            );

            // And the party, where the match came off a message.
            if !matches!(
                case.identifier,
                TargetIdentifier::Imsi(_) | TargetIdentifier::Imei(_)
            ) {
                let entries = store.match_message(ruri, from, to, source);
                assert_eq!(
                    entries[0].party,
                    case.expect,
                    "{} matched the wrong party",
                    case.identifier.element_name()
                );
            }
        }

        assert_eq!(
            covered, 9,
            "every supported identifier type must be exercised; add the new one to \
             `coverage_case` rather than letting it match nothing"
        );
    }

    /// One warrant naming several identifier kinds matches on any of them —
    /// the ordinary IMS case, where a subscriber has an IMPU, an IMPI and a
    /// number and traffic may carry whichever.
    #[test]
    fn a_multi_identifier_warrant_matches_on_every_one() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(
            x_id,
            &[
                TargetIdentifier::SipUri("sip:alice@example.com".into()),
                TargetIdentifier::Impu("sip:alice@ims.example.com".into()),
                TargetIdentifier::Impi("alice@ims.example.com".into()),
                TargetIdentifier::E164Number("15551234567".into()),
                TargetIdentifier::TelUri("tel:+15551234567".into()),
                TargetIdentifier::Ipv4Address(Ipv4Addr::new(198, 51, 100, 7)),
            ],
        );

        for uri in [
            "sip:alice@example.com",
            "sip:alice@ims.example.com",
            "sip:15551234567@carrier.example",
            "sip:+1-555-123-4567@carrier.example",
            "tel:+15551234567",
        ] {
            assert_eq!(store.match_uri(uri), vec![x_id], "{uri} should match");
        }
        assert_eq!(
            store.match_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            vec![x_id]
        );

        // And it is still one warrant, however many of its identifiers the
        // message happens to carry.
        let matched = store.match_message(
            Some("sip:alice@example.com"),
            Some("sip:15551234567@carrier.example"),
            Some("sip:alice@ims.example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        );
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].x_id, x_id);
    }

    // -- lifecycle ----------------------------------------------------------

    #[test]
    fn removing_a_task_stops_it_matching() {
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);
        assert!(!store.match_uri("sip:alice@example.com").is_empty());

        store.remove(x_id);
        assert!(store.match_uri("sip:alice@example.com").is_empty());
        assert!(store.is_empty());
        assert_eq!(store.key_count(), 0, "the identity key must be reclaimed");
    }

    #[test]
    fn removing_one_of_two_warrants_leaves_the_other_matching() {
        let store = TargetStore::new();
        let kept = XId::generate();
        let removed = XId::generate();
        store.index(kept, &[sip("sip:alice@example.com")]);
        store.index(removed, &[sip("sip:alice@example.com")]);

        store.remove(removed);
        assert_eq!(store.match_uri("sip:alice@example.com"), vec![kept]);
    }

    #[test]
    fn reindexing_replaces_the_previous_identifiers() {
        // A ModifyTask that changes the target must stop the old one matching.
        let store = TargetStore::new();
        let x_id = XId::generate();
        store.index(x_id, &[sip("sip:alice@example.com")]);
        store.index(x_id, &[sip("sip:bob@example.com")]);

        assert!(store.match_uri("sip:alice@example.com").is_empty());
        assert_eq!(store.match_uri("sip:bob@example.com"), vec![x_id]);
        assert_eq!(store.len(), 1);
        assert_eq!(store.key_count(), 1);
    }

    #[test]
    fn clear_empties_the_index() {
        let store = TargetStore::new();
        for _ in 0..10 {
            store.index(XId::generate(), &[sip("sip:alice@example.com")]);
        }
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.key_count(), 0);
    }

    #[test]
    fn removing_an_unknown_task_is_a_no_op() {
        let store = TargetStore::new();
        store.remove(XId::generate());
        assert!(store.is_empty());
    }

    #[test]
    fn index_drains_to_baseline_after_a_full_lifecycle() {
        // Per-module leak guard. Both maps must return to empty: an orphaned
        // identity key would grow without bound across warrant churn.
        let store = TargetStore::new();
        for _ in 0..1000 {
            let x_id = XId::generate();
            store.index(
                x_id,
                &[
                    sip("sip:alice@example.com"),
                    TargetIdentifier::E164Number("15551234567".into()),
                    TargetIdentifier::Ipv4Address(Ipv4Addr::new(198, 51, 100, 7)),
                ],
            );
            store.remove(x_id);
        }
        assert_eq!(store.len(), 0, "task index did not drain");
        assert_eq!(store.key_count(), 0, "identity index did not drain");
    }

    #[test]
    fn concurrent_indexing_is_safe() {
        use std::thread;

        let store = TargetStore::new();
        let mut handles = Vec::new();
        for index in 0..16 {
            let store = store.clone();
            handles.push(thread::spawn(move || {
                store.index(XId::generate(), &[sip(&format!("sip:user{index}@example.com"))]);
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(store.len(), 16);
    }
}
