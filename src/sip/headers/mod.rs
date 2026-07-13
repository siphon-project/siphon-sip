pub mod via;
pub mod nameaddr;
pub mod cseq;
pub mod refer;
pub mod route;
pub mod session_timer;
pub mod rseq;
pub mod charging;
pub mod retry_after;

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
            b'a' => Some("accept-contact"),   // RFC 3841
            b'b' => Some("referred-by"),       // RFC 3892
            b'c' => Some("content-type"),      // RFC 3261
            b'd' => Some("request-disposition"), // RFC 3841
            b'e' => Some("content-encoding"),  // RFC 3261
            b'f' => Some("from"),              // RFC 3261
            b'i' => Some("call-id"),           // RFC 3261
            b'j' => Some("reject-contact"),    // RFC 3841
            b'k' => Some("supported"),         // RFC 3261
            b'l' => Some("content-length"),    // RFC 3261
            b'm' => Some("contact"),           // RFC 3261
            b'o' => Some("event"),             // RFC 6665 (orig RFC 3265)
            b'r' => Some("refer-to"),          // RFC 3515
            b's' => Some("subject"),           // RFC 3261
            b't' => Some("to"),                // RFC 3261
            b'u' => Some("allow-events"),      // RFC 6665
            b'v' => Some("via"),               // RFC 3261
            b'x' => Some("session-expires"),   // RFC 4028
            b'y' => Some("identity"),          // RFC 8224
            _ => None,
        };
        if let Some(full) = full {
            return full.to_string();
        }
    }
    name.to_ascii_lowercase()
}

impl SipHeaders {
    pub fn new() -> Self {
        Self { inner: Arc::new(HeadersInner::new()) }
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
        self.inner
            .headers
            .values()
            .map(|(name, _)| name)
            .collect()
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
        self.inner.headers.values().map(|(name, values)| (name, values))
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
        self.get("Max-Forwards")
            .and_then(|s| s.trim().parse().ok())
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
        headers.add("v", "SIP/2.0/UDP siphon.example:5060;branch=z9hG4bK-abc".to_string());
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

    /// The on-the-wire name is preserved: canonicalization is lookup-only.
    /// A message received with `v:` is forwarded as `v:`, not rewritten.
    #[test]
    fn compact_form_preserved_in_names_for_serialization() {
        let mut headers = SipHeaders::new();
        headers.add("v", "SIP/2.0/UDP h:5060;branch=z9hG4bK1".to_string());
        assert_eq!(headers.names(), vec![&"v".to_string()]);
        let (name, values) = headers.iter_original().next().unwrap();
        assert_eq!(name, "v");
        assert_eq!(values, &vec!["SIP/2.0/UDP h:5060;branch=z9hG4bK1".to_string()]);
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
}



