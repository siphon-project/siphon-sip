//! INVITEs that have arrived and not yet become a call, and the CANCELs that
//! overtake them (RFC 3261 §9.1, §9.2).
//!
//! Requests reach a pool of workers in the order the dispatch loop receives
//! them, but a worker holding an INVITE still has to admit it, answer
//! `100 Trying` and create the call before anything can be matched to it, while
//! the worker holding the caller's CANCEL, taken a moment later, goes straight
//! to its lookup. A caller that cancels within a few milliseconds of its INVITE
//! therefore found no call and was answered `481`, and the INVITE went on to
//! ring a callee for a call the caller had abandoned.
//!
//! RFC 3261 §9.2 matches a CANCEL to the INVITE's *server transaction*, which
//! exists from the INVITE's arrival, not from the moment siphon has built its
//! call. This is that transaction's stand-in for the time between the two. The
//! INVITE is registered by the dispatch loop itself ([`initial_invite_key`]
//! reads its key from the raw bytes), before any worker is handed it, so
//! arrival order guarantees the registration precedes its CANCEL's lookup. A
//! CANCEL that matches nothing else but finds the registration is held
//! ([`InflightInvites::hold`]) and run once the call exists or the INVITE's
//! worker has finished ([`InflightInvites::release`]).
//!
//! The store is generic over what is held so that it knows nothing of the
//! dispatcher.

use dashmap::DashMap;

use crate::sip::message::Method;
use crate::transaction::key::TransactionKey;

/// How many CANCELs one INVITE holds. A caller retransmits its CANCEL on Timer
/// E, so a handful is every legitimate case; one past that is not held.
pub const HELD_CANCELS_PER_INVITE: usize = 8;

/// How many header lines of an INVITE [`initial_invite_key`] reads looking for
/// the topmost Via. It is the first header in practice.
const VIA_SEARCH_LINES: usize = 24;

struct Entry<H> {
    /// The call exists: a CANCEL finds it by its own lookup, and holding one
    /// here would strand it.
    call_exists: bool,
    held: Vec<H>,
}

/// INVITEs between their arrival and their call, keyed by the INVITE's server
/// transaction (top Via branch and sent-by).
pub struct InflightInvites<H> {
    entries: DashMap<TransactionKey, Entry<H>>,
}

impl<H> Default for InflightInvites<H> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<H> InflightInvites<H> {
    /// Register the INVITE `key`. `false` when it is already registered (a
    /// retransmission, which must not end the original's entry early).
    pub fn register(&self, key: TransactionKey) -> bool {
        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(Entry {
                    call_exists: false,
                    held: Vec::new(),
                });
                true
            }
        }
    }

    /// Hold `cancel` for the INVITE `key`, if that INVITE is registered and its
    /// call does not exist yet. Handed back when it is not, for the caller to
    /// answer.
    pub fn hold(&self, key: &TransactionKey, cancel: H) -> Result<(), Box<H>> {
        match self.entries.get_mut(key) {
            Some(mut entry) if !entry.call_exists && entry.held.len() < HELD_CANCELS_PER_INVITE => {
                entry.held.push(cancel);
                Ok(())
            }
            _ => Err(Box::new(cancel)),
        }
    }

    /// The call of the INVITE `key` now exists: take what was held for it, and
    /// hold nothing more (a later CANCEL finds the call itself).
    pub fn call_created(&self, key: &TransactionKey) -> Vec<H> {
        match self.entries.get_mut(key) {
            Some(mut entry) => {
                entry.call_exists = true;
                std::mem::take(&mut entry.held)
            }
            None => Vec::new(),
        }
    }

    /// The INVITE `key` is done with: drop its registration and return what was
    /// still held for it.
    pub fn release(&self, key: &TransactionKey) -> Vec<H> {
        self.entries
            .remove(key)
            .map(|(_, entry)| entry.held)
            .unwrap_or_default()
    }

    /// Number of INVITEs registered: back to zero once every INVITE's worker has
    /// finished.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no INVITE is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The INVITE server transaction key of `raw`, if it is an INVITE request with a
/// topmost Via that carries a branch.
///
/// Reads the request line's method and the first Via header only, by a bounded
/// scan of the bytes, without parsing the message: this runs in the dispatch
/// loop, for every message. A non-INVITE costs one prefix comparison. The key it
/// builds is the one the full parse yields (host and port as [`Via::parse`]
/// splits them, joined by [`TransactionKey::format_sent_by`]); an input it
/// cannot read gives `None`, which only leaves that INVITE unregistered, as
/// before.
///
/// [`Via::parse`]: crate::sip::headers::via::Via::parse
pub fn initial_invite_key(raw: &[u8]) -> Option<TransactionKey> {
    let mut lines = raw.strip_prefix(b"INVITE ")?.split(|&byte| byte == b'\n');
    // The rest of the request line.
    lines.next()?;
    for line in lines.take(VIA_SEARCH_LINES) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return None;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"via") || name.eq_ignore_ascii_case(b"v") {
            return key_from_via(&line[colon + 1..]);
        }
    }
    None
}

/// The key a Via header value names. Only the first of several comma-separated
/// Vias is read, as it is the topmost.
fn key_from_via(value: &[u8]) -> Option<TransactionKey> {
    let value = std::str::from_utf8(value).ok()?;
    let value = value.split(',').next()?.trim();
    let rest = value.strip_prefix("SIP/2.0/")?;
    let (_transport, rest) = rest.split_once(|c: char| c.is_ascii_whitespace())?;
    let rest = rest.trim_start();
    let (sent_by, params) = match rest.find(';') {
        Some(position) => (&rest[..position], &rest[position + 1..]),
        None => (rest, ""),
    };
    let sent_by = sent_by.trim();
    let sent_by = if sent_by.starts_with('[') {
        let end = sent_by.find(']')?;
        match sent_by[end + 1..].strip_prefix(':') {
            Some(port) => format!("{}:{}", &sent_by[..=end], port.parse::<u16>().ok()?),
            None => sent_by[..=end].to_string(),
        }
    } else {
        match sent_by.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) => format!("{host}:{port}"),
                Err(_) => sent_by.to_string(),
            },
            None => sent_by.to_string(),
        }
    };
    let branch = params.split(';').find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("branch")
            .then(|| value.trim().to_string())
    })?;
    Some(TransactionKey::new(branch, Method::Invite, sent_by))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::headers::via::Via;

    fn invite(via: &str) -> Vec<u8> {
        format!(
            concat!(
                "INVITE sip:bob@example.com SIP/2.0\r\n",
                "{via}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:alice@example.com>;tag=1\r\n",
                "To: <sip:bob@example.com>\r\n",
                "Call-ID: a84b4c76e66710\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            via = via
        )
        .into_bytes()
    }

    /// The key the full parse of the same Via yields, which is what the worker
    /// and the CANCEL path compute.
    fn parsed_key(via_value: &str) -> TransactionKey {
        let via = Via::parse_multi(via_value)
            .expect("the Via parses")
            .remove(0);
        TransactionKey::new(
            via.branch.expect("a branch"),
            Method::Invite,
            TransactionKey::format_sent_by(&via.host, via.port),
        )
    }

    #[test]
    fn the_scanned_key_is_the_parsed_key() {
        for value in [
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds",
            "SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK776asdhds",
            "SIP/2.0/UDP 192.0.2.10:05060;rport;branch=z9hG4bK776asdhds",
            "SIP/2.0/TCP [2001:db8::1]:5061;branch=z9hG4bKv6",
            "SIP/2.0/TLS [2001:db8::1];branch=z9hG4bKv6",
            "SIP/2.0/UDP proxy.example.com:notaport;branch=z9hG4bKodd",
            "SIP/2.0/UDP   host.example.com ;  Branch = z9hG4bKspaced ;rport",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKfirst, SIP/2.0/UDP 192.0.2.11;branch=z9hG4bKsecond",
        ] {
            for header in ["Via", "via", "VIA", "v", "Via "] {
                let raw = invite(&format!("{header}: {value}"));
                assert_eq!(
                    initial_invite_key(&raw),
                    Some(parsed_key(value)),
                    "{header}: {value}"
                );
            }
        }
    }

    #[test]
    fn anything_that_is_not_an_initial_invite_with_a_branch_has_no_key() {
        let via = "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1";
        let cancel = String::from_utf8(invite(via))
            .expect("text")
            .replace("INVITE sip", "CANCEL sip");
        assert_eq!(initial_invite_key(cancel.as_bytes()), None);
        assert_eq!(initial_invite_key(b"SIP/2.0 200 OK\r\n"), None);
        assert_eq!(initial_invite_key(b""), None);
        assert_eq!(initial_invite_key(b"INVITE "), None);
        assert_eq!(
            initial_invite_key(&invite("Via: SIP/2.0/UDP 192.0.2.10:5060")),
            None,
            "no branch"
        );
        assert_eq!(
            initial_invite_key(&invite("Via: SIP/2.0/UDP [::1:5060;branch=z9hG4bK1")),
            None,
            "unterminated bracket"
        );
        assert_eq!(
            initial_invite_key(&invite("Via: SIP/2.0/UDP 192.0.2.10:99999;branch=z9hG4bK1"))
                .map(|key| key.sent_by),
            Some("192.0.2.10:99999".to_string()),
            "an unparseable port stays in the host, as Via::parse has it"
        );
        // No Via before the end of the headers.
        assert_eq!(
            initial_invite_key(
                b"INVITE sip:a SIP/2.0\r\nTo: <sip:a>\r\n\r\nVia: SIP/2.0/UDP h;branch=z\r\n"
            ),
            None
        );
        // Binary garbage in a header is not an error, only no key.
        assert_eq!(
            initial_invite_key(b"INVITE sip:a SIP/2.0\r\nVia: \xff\xfe\r\n\r\n"),
            None
        );
    }

    #[test]
    fn a_via_far_down_the_headers_is_not_searched_for() {
        let mut raw = String::from("INVITE sip:a SIP/2.0\r\n");
        for index in 0..VIA_SEARCH_LINES {
            raw.push_str(&format!("X-Filler-{index}: x\r\n"));
        }
        raw.push_str("Via: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\r\n");
        assert_eq!(initial_invite_key(raw.as_bytes()), None);
    }

    fn key(branch: &str) -> TransactionKey {
        TransactionKey::new(branch.to_string(), Method::Invite, "192.0.2.10".into())
    }

    #[test]
    fn a_cancel_is_held_until_the_call_exists_and_then_not() {
        let store: InflightInvites<u32> = InflightInvites::default();
        assert!(store.register(key("a")));
        assert!(!store.register(key("a")), "a copy does not register again");
        assert!(store.hold(&key("a"), 1).is_ok());
        assert!(store.hold(&key("a"), 2).is_ok());
        assert_eq!(store.call_created(&key("a")), vec![1, 2]);
        assert!(store.hold(&key("a"), 3).is_err(), "the call exists now");
        assert!(store.hold(&key("unknown"), 4).is_err());
        assert!(store.release(&key("a")).is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn only_so_many_cancels_are_held_and_release_returns_them() {
        let store: InflightInvites<usize> = InflightInvites::default();
        store.register(key("a"));
        for index in 0..HELD_CANCELS_PER_INVITE {
            assert!(store.hold(&key("a"), index).is_ok());
        }
        assert!(store.hold(&key("a"), 99).is_err());
        assert_eq!(store.release(&key("a")).len(), HELD_CANCELS_PER_INVITE);
        assert_eq!(store.len(), 0);
    }
}
