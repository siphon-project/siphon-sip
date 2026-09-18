pub mod charging;
pub mod cseq;
pub mod nameaddr;
pub mod refer;
pub mod retry_after;
pub mod route;
pub mod rseq;
pub mod session_timer;
pub mod via;

use indexmap::IndexMap;
use std::sync::Arc;

/// SIP Headers container.
///
/// Internally uses a copy-on-write design — `Clone` is just an `Arc` bump
/// rather than a deep copy of every header value. The first mutating call
/// after a clone pays for `Arc::make_mut` (deep copy if shared, no-op
/// otherwise); subsequent mutations on the same instance are direct.
///
/// This matters because `SipMessage` is cloned heavily on the proxy hot
/// path (transaction caches, per-event copies, dispatched-to-handler
/// snapshots). Many of those clones are read-only — with COW they reduce
/// to a refcount bump.
#[derive(Debug, Clone)]
pub struct SipHeaders {
    inner: Arc<HeadersInner>,
}

#[derive(Debug, Clone)]
struct HeadersInner {
    // Lowercase field name -> (original-cased name, values), insertion-ordered.
    // One map, not two (a values map plus a separate lowercase->original-name
    // map): the original name lives next to its values, so a COW `make_mut`
    // clone copies each lowercase key once instead of twice, and `add` does one
    // entry lookup instead of two. RFC 3261 §7.3.1 makes field names
    // case-insensitive, so the lowercase form is the canonical key.
    headers: IndexMap<String, (String, Vec<String>)>,
}

impl HeadersInner {
    fn new() -> Self {
        Self {
            headers: IndexMap::new(),
        }
    }
}

/// Canonical lookup key for a header name.
///
/// RFC 3261 §7.3.3 defines single-letter *compact forms* that are exactly
/// equivalent to their long-form field names, and §7.3.1 makes field names
/// case-insensitive. A message may use either form (or mix them), so the
/// container must treat `v`/`Via`, `f`/`From`, `i`/`Call-ID`, etc. as the same
/// header — otherwise a response arriving with `v:` is invisible to
/// `get("Via")` and the transaction/response-routing layer drops it as
/// "no Via header".
///
/// This maps any name to a single canonical key: ASCII-lowercased, with the
/// registered compact single-letter forms expanded to their long name. The
/// on-the-wire name is stored separately and preserved verbatim for
/// serialization, so canonicalization only affects lookup, never output.
///
/// Compact-form set is the IANA "SIP Header Fields" registry (RFC 3261 §20 +
/// the extension registrations RFC 3515/3841/3892/4028/6665/8224).
fn canonical_key(name: &str) -> String {
    // Only a single-character token can be a compact form (§7.3.3); expand it.
    // Everything else is just lowercased.
    if name.len() == 1 {
        let full = match name.as_bytes()[0].to_ascii_lowercase() {
            b'a' => Some("accept-contact"),      // RFC 3841
            b'b' => Some("referred-by"),         // RFC 3892
            b'c' => Some("content-type"),        // RFC 3261
            b'd' => Some("request-disposition"), // RFC 3841
            b'e' => Some("content-encoding"),    // RFC 3261
            b'f' => Some("from"),                // RFC 3261
            b'i' => Some("call-id"),             // RFC 3261
            b'j' => Some("reject-contact"),      // RFC 3841
            b'k' => Some("supported"),           // RFC 3261
            b'l' => Some("content-length"),      // RFC 3261
            b'm' => Some("contact"),             // RFC 3261
            b'o' => Some("event"),               // RFC 6665 (orig RFC 3265)
            b'r' => Some("refer-to"),            // RFC 3515
            b's' => Some("subject"),             // RFC 3261
            b't' => Some("to"),                  // RFC 3261
            b'u' => Some("allow-events"),        // RFC 6665
            b'v' => Some("via"),                 // RFC 3261
            b'x' => Some("session-expires"),     // RFC 4028
            b'y' => Some("identity"),            // RFC 8224
            _ => None,
        };
        if let Some(full) = full {
            return full.to_string();
        }
    }
    name.to_ascii_lowercase()
}

/// Whether two header field names name the same header: case-insensitive
/// (RFC 3261 §7.3.1), with a compact form equal to its long name (§7.3.3), so
/// `k` is `Supported`.
pub fn same_header_name(first: &str, second: &str) -> bool {
    canonical_key(first) == canonical_key(second)
}

/// Rank shared by every header this module does not place explicitly. Sits
/// between the head group and the `Content-*` tail, so unranked headers keep the
/// relative order they were inserted in and only move as a block.
const MIDDLE_RANK: u8 = 128;

/// Canonical position on the wire for a header field name, keyed on the
/// canonical form from [`canonical_key`] — so a message carrying the compact
/// `l` ranks it as `Content-Length` and `v` as `Via`, while still going out
/// under the short name it arrived with.
///
/// RFC 3261 §7.3.1: "The relative order of header fields with different field
/// names is not significant. However, it is RECOMMENDED that header fields
/// which are needed for proxy processing (Via, Route, Record-Route,
/// Proxy-Require, Max-Forwards, and Proxy-Authorization, for example) appear
/// towards the top of the message to facilitate rapid parsing." Ranks 0–5 are
/// that set, ordered as the §24 call-flow examples lay them out (`Via` then
/// `Max-Forwards`); 6–10 are the dialog-identifying headers, the order
/// [`build_response_skeleton`](crate::sip::builder::build_response_skeleton)
/// already emits.
///
/// The `Content-*` group goes last, `Content-Length` at the very end. No RFC
/// requires that — §7.3.1 is explicit that it cannot matter — but it is what
/// every mainstream stack emits, and a header block whose tail moves depending
/// on which code path last touched the message is the thing this ordering
/// exists to stop.
fn wire_rank(canonical: &str) -> u8 {
    match canonical {
        // Needed for proxy processing (§7.3.1).
        "via" => 0,
        "max-forwards" => 1,
        "record-route" => 2,
        "route" => 3,
        "proxy-require" => 4,
        "proxy-authorization" => 5,
        // Dialog identification.
        "from" => 6,
        "to" => 7,
        "call-id" => 8,
        "cseq" => 9,
        "contact" => 10,
        // Body description, last, with the length at the very end.
        "content-disposition" => 250,
        "content-encoding" => 251,
        "content-language" => 252,
        "content-type" => 253,
        "content-length" => 254,
        _ => MIDDLE_RANK,
    }
}

/// Distinct field names whose ordering is worked out without touching the heap.
/// Real messages carry 10–25; the inbound cap is on header *fields*
/// (`MAX_HEADER_FIELDS` in [`validate`](crate::sip::validate), counting values,
/// not names), so more than this is legal and just falls back to a `Vec` for the
/// same ordering.
const INLINE_HEADERS: usize = 64;

/// Append one header's rows to `out`, one `Name: value\r\n` line per value.
fn push_header_rows(out: &mut Vec<u8>, name: &str, values: &[String]) {
    for value in values {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

impl SipHeaders {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HeadersInner::new()),
        }
    }

    fn make_mut(&mut self) -> &mut HeadersInner {
        Arc::make_mut(&mut self.inner)
    }

    // Keys are the canonical form (see `canonical_key`): ASCII-lowercased with
    // RFC 3261 §7.3.3 compact single-letter forms expanded to their long name,
    // so `v`/`Via`, `f`/`From`, `i`/`Call-ID`, … resolve to the same entry.
    // The original on-the-wire name is kept alongside for serialization.

    /// Add a header value (appends if header already exists)
    pub fn add(&mut self, name: &str, value: String) {
        let key = canonical_key(name);
        let inner = self.make_mut();
        inner
            .headers
            .entry(key)
            .or_insert_with(|| (name.to_string(), Vec::new()))
            .1
            .push(value);
    }

    /// Set a header value (replaces existing, preserves position in header order)
    pub fn set(&mut self, name: &str, value: String) {
        let key = canonical_key(name);
        let inner = self.make_mut();
        inner.headers.insert(key, (name.to_string(), vec![value]));
    }

    /// Set multiple values for a header (replaces existing, preserves position in header order).
    ///
    /// Use this when replacing a multi-value header like Via where you need to
    /// keep insertion ordering but supply more than one value.
    pub fn set_all(&mut self, name: &str, values: Vec<String>) {
        let key = canonical_key(name);
        let inner = self.make_mut();
        inner.headers.insert(key, (name.to_string(), values));
    }

    /// Get first value of a header
    pub fn get(&self, name: &str) -> Option<&String> {
        self.inner
            .headers
            .get(&canonical_key(name))
            .and_then(|(_, values)| values.first())
    }

    /// Get all values of a header
    pub fn get_all(&self, name: &str) -> Option<&Vec<String>> {
        self.inner
            .headers
            .get(&canonical_key(name))
            .map(|(_, values)| values)
    }

    /// Remove a header
    pub fn remove(&mut self, name: &str) {
        let key = canonical_key(name);
        let inner = self.make_mut();
        inner.headers.shift_remove(&key);
    }

    /// Check if header exists
    pub fn has(&self, name: &str) -> bool {
        self.inner.headers.contains_key(&canonical_key(name))
    }

    /// Get all header names (in original case)
    pub fn names(&self) -> Vec<&String> {
        self.inner.headers.values().map(|(name, _)| name).collect()
    }

    /// Iterate over headers — yields `(lowercase name, values)`.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.inner
            .headers
            .iter()
            .map(|(key, (_, values))| (key, values))
    }

    /// Iterate over headers yielding `(original-cased name, values)` in
    /// insertion order — for serialization, which needs the on-the-wire name
    /// without re-lowercasing and re-looking-up each header.
    pub fn iter_original(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.inner
            .headers
            .values()
            .map(|(name, values)| (name, values))
    }

    /// Append the header block to `out` in canonical wire order (see
    /// [`wire_rank`]), one `Name: value\r\n` row per value. The caller writes
    /// the blank line and the body.
    ///
    /// This is the one place header order is decided. Construction order is not
    /// it: `set`/`set_all` hold a header's slot but `remove` shifts the
    /// survivors up, so a remove-then-re-add moves a header to the tail, and
    /// anything injected after the body was set lands past `Content-Length`.
    /// Ordering here means no call site can move a header on the wire.
    ///
    /// **Rows sharing a field name keep their relative order** — the one
    /// ordering rule §7.3.1 does make significant ("The relative order of
    /// header field rows with the same field name is important"). They live in
    /// a single entry's value vector, and this only ever reorders whole
    /// entries, so `Via` and `Record-Route` stacking is untouched.
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        // Fast path: almost every message is already canonical, because parse
        // preserves the wire order it came in on and siphon's builders
        // construct in this order. One scan proves it, and then the emit is the
        // same straight walk it has always been.
        let mut previous = 0u8;
        let mut ordered = true;
        for key in self.inner.headers.keys() {
            let rank = wire_rank(key);
            if rank < previous {
                ordered = false;
                break;
            }
            previous = rank;
        }
        if ordered {
            for (name, values) in self.iter_original() {
                push_header_rows(out, name, values);
            }
            return;
        }

        let count = self.inner.headers.len();
        let mut inline_ranks = [0u8; INLINE_HEADERS];
        let mut inline_order = [0usize; INLINE_HEADERS];
        let mut heap_ranks;
        let mut heap_order;
        let (ranks, order) = if count <= INLINE_HEADERS {
            (&mut inline_ranks[..count], &mut inline_order[..count])
        } else {
            heap_ranks = vec![0u8; count];
            heap_order = vec![0usize; count];
            (&mut heap_ranks[..], &mut heap_order[..])
        };

        for (index, key) in self.inner.headers.keys().enumerate() {
            ranks[index] = wire_rank(key);
            order[index] = index;
        }

        // Stable insertion sort over the index permutation. The list is short
        // and nearly sorted — typically one header out of place, the one a
        // remove-then-re-add or a post-body injection pushed to the tail — so
        // this is effectively linear. Stability is what keeps every header
        // sharing `MIDDLE_RANK` in its insertion order.
        for position in 1..count {
            let mut cursor = position;
            while cursor > 0 && ranks[order[cursor - 1]] > ranks[order[cursor]] {
                order.swap(cursor - 1, cursor);
                cursor -= 1;
            }
        }

        for &index in order.iter() {
            // In range by construction: every index came from enumerating this
            // same map, which has not been touched since.
            if let Some((_, (name, values))) = self.inner.headers.get_index(index) {
                push_header_rows(out, name, values);
            }
        }
    }

    /// Convenience methods for common headers
    pub fn via(&self) -> Option<&String> {
        self.get("Via")
    }

    pub fn to(&self) -> Option<&String> {
        self.get("To")
    }

    pub fn from(&self) -> Option<&String> {
        self.get("From")
    }

    pub fn call_id(&self) -> Option<&String> {
        self.get("Call-ID")
    }

    pub fn cseq(&self) -> Option<&String> {
        self.get("CSeq")
    }

    pub fn contact(&self) -> Option<&String> {
        self.get("Contact")
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("Content-Length")
            .and_then(|s| s.trim().parse().ok())
    }

    pub fn content_type(&self) -> Option<&String> {
        self.get("Content-Type")
    }

    pub fn max_forwards(&self) -> Option<u8> {
        self.get("Max-Forwards").and_then(|s| s.trim().parse().ok())
    }
}

impl Default for SipHeaders {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3261 §7.3.3 — a header stored under its compact form must be
    /// retrievable by its long name. This is the exact failure behind a
    /// dropped 401: an upstream registrar answers with `v:` (compact Via)
    /// and the response-routing layer's `get("Via")` came back `None`.
    #[test]
    fn compact_via_found_by_long_name() {
        let mut headers = SipHeaders::new();
        headers.add(
            "v",
            "SIP/2.0/UDP siphon.example:5060;branch=z9hG4bK-abc".to_string(),
        );
        assert_eq!(
            headers.via().map(String::as_str),
            Some("SIP/2.0/UDP siphon.example:5060;branch=z9hG4bK-abc"),
        );
        assert!(headers.has("Via"));
        assert!(headers.has("v"));
    }

    /// All RFC 3261 §20 compact forms resolve to their long name, and the
    /// reverse (store long, read compact) works too.
    #[test]
    fn all_compact_forms_alias_long_names() {
        let cases = [
            ("v", "Via"),
            ("f", "From"),
            ("t", "To"),
            ("i", "Call-ID"),
            ("m", "Contact"),
            ("c", "Content-Type"),
            ("e", "Content-Encoding"),
            ("l", "Content-Length"),
            ("s", "Subject"),
            ("k", "Supported"),
            // Extension compact forms (RFC 3515/3841/3892/4028/6665/8224)
            ("o", "Event"),
            ("r", "Refer-To"),
            ("u", "Allow-Events"),
            ("x", "Session-Expires"),
            ("y", "Identity"),
            ("b", "Referred-By"),
            ("a", "Accept-Contact"),
            ("d", "Request-Disposition"),
            ("j", "Reject-Contact"),
        ];
        for (compact, long) in cases {
            let mut headers = SipHeaders::new();
            headers.add(compact, "value".to_string());
            assert_eq!(
                headers.get(long).map(String::as_str),
                Some("value"),
                "compact `{compact}` should be readable as `{long}`",
            );

            let mut headers = SipHeaders::new();
            headers.add(long, "value".to_string());
            assert_eq!(
                headers.get(compact).map(String::as_str),
                Some("value"),
                "long `{long}` should be readable as compact `{compact}`",
            );
        }
    }

    #[test]
    fn same_header_name_folds_case_and_compact_forms() {
        assert!(same_header_name("Supported", "supported"));
        assert!(same_header_name("k", "Supported"));
        assert!(same_header_name("ALLOW", "Allow"));
        assert!(!same_header_name("Supported", "Require"));
        // A single letter with no registered compact form is only itself.
        assert!(!same_header_name("q", "Supported"));
    }

    /// The on-the-wire name is preserved: canonicalization is lookup-only.
    /// A message received with `v:` is forwarded as `v:`, not rewritten.
    #[test]
    fn compact_form_preserved_in_names_for_serialization() {
        let mut headers = SipHeaders::new();
        headers.add("v", "SIP/2.0/UDP h:5060;branch=z9hG4bK1".to_string());
        assert_eq!(headers.names(), vec![&"v".to_string()]);
        let (name, values) = headers.iter_original().next().unwrap();
        assert_eq!(name, "v");
        assert_eq!(
            values,
            &vec!["SIP/2.0/UDP h:5060;branch=z9hG4bK1".to_string()]
        );
    }

    /// Compact and long form of the same header merge into one entry
    /// (multi-value), not two separate headers.
    #[test]
    fn compact_and_long_merge_into_one_entry() {
        let mut headers = SipHeaders::new();
        headers.add("Via", "SIP/2.0/UDP first:5060;branch=z9hG4bK1".to_string());
        headers.add("v", "SIP/2.0/UDP second:5060;branch=z9hG4bK2".to_string());
        let all = headers.get_all("Via").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], "SIP/2.0/UDP first:5060;branch=z9hG4bK1");
        assert_eq!(all[1], "SIP/2.0/UDP second:5060;branch=z9hG4bK2");
    }

    /// `set`/`remove` by long name affects a header stored compactly.
    #[test]
    fn set_and_remove_cross_form() {
        let mut headers = SipHeaders::new();
        headers.add("i", "call-abc@host".to_string());
        headers.set("Call-ID", "call-xyz@host".to_string());
        assert_eq!(headers.call_id().map(String::as_str), Some("call-xyz@host"));

        headers.remove("i");
        assert!(!headers.has("Call-ID"));
        assert!(headers.call_id().is_none());
    }

    /// An unknown single-letter header (not a registered compact form) is
    /// treated as an ordinary header, not silently aliased.
    #[test]
    fn unknown_single_letter_is_not_a_compact_form() {
        let mut headers = SipHeaders::new();
        headers.add("z", "opaque".to_string());
        assert_eq!(headers.get("z").map(String::as_str), Some("opaque"));
        // `z` has no long-form alias, so it stays distinct from any header.
        assert!(!headers.has("Via"));
    }

    /// Serialize the header block alone and split it into `Name: value` rows.
    fn wire_rows(headers: &SipHeaders) -> Vec<String> {
        let mut out = Vec::new();
        headers.write_wire(&mut out);
        String::from_utf8(out)
            .expect("header block is UTF-8")
            .split_terminator("\r\n")
            .map(str::to_string)
            .collect()
    }

    /// Just the field names, in the order they go out.
    fn wire_names(headers: &SipHeaders) -> Vec<String> {
        wire_rows(headers)
            .iter()
            .map(|row| {
                row.split_once(':')
                    .map(|(name, _)| name.to_string())
                    .unwrap_or_else(|| row.clone())
            })
            .collect()
    }

    /// `Content-Length` goes out last and `Content-Type` immediately before it,
    /// however late the other headers were added. This is the reported bug:
    /// headers injected after the body was set (per-carrier headers, charging
    /// headers) used to land past `Content-Length`.
    #[test]
    fn content_length_is_last_however_late_headers_arrive() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );
        headers.add("Content-Type", "application/sdp".to_string());
        headers.add("Content-Length", "328".to_string());
        // Everything below is injected after the body was accounted for.
        headers.add("P-Charging-Vector", "icid-value=abc".to_string());
        headers.add("Supported", "timer,replaces".to_string());
        headers.add("Privacy", "id".to_string());

        let names = wire_names(&headers);
        assert_eq!(
            names,
            vec![
                "Via",
                "P-Charging-Vector",
                "Supported",
                "Privacy",
                "Content-Type",
                "Content-Length",
            ]
        );
    }

    /// The 1.9.0 regression in its own right: `remove` + re-add moves a header
    /// to the end of the container, which used to put `Allow` and `Supported`
    /// on the wire *after* `Content-Length`. Container order still moves — that
    /// is what `remove` does — but the wire order no longer follows it.
    #[test]
    fn remove_and_re_add_does_not_move_a_header_past_content_length() {
        let mut headers = SipHeaders::new();
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );
        headers.add("Allow", "INVITE, ACK, BYE".to_string());
        headers.add("Content-Length", "0".to_string());

        // Exactly what `advertise_b_leg_capabilities` does.
        headers.remove("Allow");
        headers.add("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS".to_string());

        // Container order did move — this is the behaviour behind the bug.
        let container: Vec<&str> = headers.names().iter().map(|s| s.as_str()).collect();
        assert_eq!(container, vec!["Via", "Content-Length", "Allow"]);

        // The wire does not.
        assert_eq!(wire_names(&headers), vec!["Via", "Allow", "Content-Length"]);
    }

    /// RFC 3261 §7.3.1: "The relative order of header field rows with the same
    /// field name is important." Via stacking is topmost-first and load-bearing
    /// for response routing, so canonicalising entries must never touch it.
    #[test]
    fn rows_sharing_a_field_name_keep_their_order() {
        let mut headers = SipHeaders::new();
        headers.add("Content-Length", "0".to_string());
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK3".to_string(),
        );
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK2".to_string(),
        );
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK1".to_string(),
        );
        headers.add("Record-Route", "<sip:192.0.2.10;lr>".to_string());
        headers.add("Record-Route", "<sip:192.0.2.20;lr>".to_string());

        let rows = wire_rows(&headers);
        assert_eq!(
            rows,
            vec![
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK3",
                "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK2",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK1",
                "Record-Route: <sip:192.0.2.10;lr>",
                "Record-Route: <sip:192.0.2.20;lr>",
                "Content-Length: 0",
            ]
        );
    }

    /// Headers with no assigned rank share `MIDDLE_RANK` and keep the order
    /// they were inserted in — the sort is stable, so this is a targeted
    /// normalisation and not a reshuffle of the whole block.
    #[test]
    fn unranked_headers_keep_insertion_order() {
        let mut headers = SipHeaders::new();
        headers.add("Content-Length", "0".to_string());
        headers.add("User-Agent", "siphon".to_string());
        headers.add("P-Charging-Vector", "icid-value=abc".to_string());
        headers.add("X-Zulu", "1".to_string());
        headers.add("X-Alpha", "2".to_string());
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );

        assert_eq!(
            wire_names(&headers),
            vec![
                "Via",
                "User-Agent",
                "P-Charging-Vector",
                "X-Zulu",
                "X-Alpha",
                "Content-Length",
            ]
        );
    }

    /// A compact-form header ranks as its long name (RFC 3261 §7.3.3) but still
    /// goes out under the short name it arrived with: `l` is `Content-Length`,
    /// so it sorts last, and `v` is `Via`, so it sorts first.
    #[test]
    fn compact_forms_rank_as_their_long_name() {
        let mut headers = SipHeaders::new();
        headers.add("l", "0".to_string());
        headers.add("Subject", "test".to_string());
        headers.add(
            "v",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );

        assert_eq!(wire_names(&headers), vec!["v", "Subject", "l"]);
    }

    /// A block already in canonical order takes the fast path, and must come
    /// out byte-identical to the slow path's answer for the same headers.
    #[test]
    fn ordered_and_unordered_inputs_agree() {
        let rows = [
            ("Via", "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1"),
            ("Max-Forwards", "70"),
            ("From", "<sip:15550100001@example.com>;tag=a"),
            ("To", "<sip:15550100042@example.com>"),
            ("Call-ID", "call-1@192.0.2.10"),
            ("CSeq", "1 INVITE"),
            ("Contact", "<sip:192.0.2.10:5060>"),
            ("Supported", "timer,replaces"),
            ("Content-Type", "application/sdp"),
            ("Content-Length", "0"),
        ];

        let mut ordered = SipHeaders::new();
        for (name, value) in rows {
            ordered.add(name, value.to_string());
        }
        // Same headers, built back to front, so the fast path cannot trigger.
        let mut scrambled = SipHeaders::new();
        for (name, value) in rows.iter().rev() {
            scrambled.add(name, value.to_string());
        }

        assert_eq!(wire_rows(&ordered), wire_rows(&scrambled));
        assert_eq!(
            wire_names(&ordered),
            rows.iter().map(|(name, _)| *name).collect::<Vec<_>>()
        );
    }

    /// Ordering is idempotent: canonical output re-parsed and re-serialised is
    /// the same bytes. `tests/rfc4475` asserts this across the torture corpus;
    /// this pins it at the container, where the ordering actually happens.
    #[test]
    fn ordering_is_idempotent() {
        let mut headers = SipHeaders::new();
        headers.add("Content-Length", "0".to_string());
        headers.add("Allow", "INVITE, ACK, BYE".to_string());
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );
        headers.add("Content-Type", "application/sdp".to_string());

        let once = wire_rows(&headers);

        // Feed the canonical order back in, as a re-parse would.
        let mut reparsed = SipHeaders::new();
        for row in &once {
            let (name, value) = row.split_once(": ").expect("row is Name: value");
            reparsed.add(name, value.to_string());
        }

        assert_eq!(wire_rows(&reparsed), once);
    }

    /// More distinct field names than the inline budget still get ordered —
    /// the heap path is the same algorithm, not a bail-out to insertion order.
    #[test]
    fn heap_path_orders_too() {
        let mut headers = SipHeaders::new();
        headers.add("Content-Length", "0".to_string());
        for index in 0..INLINE_HEADERS + 8 {
            headers.add(&format!("X-Pad-{index}"), index.to_string());
        }
        headers.add(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1".to_string(),
        );

        let names = wire_names(&headers);
        assert!(names.len() > INLINE_HEADERS);
        assert_eq!(names.first().map(String::as_str), Some("Via"));
        assert_eq!(names.last().map(String::as_str), Some("Content-Length"));
    }
}
