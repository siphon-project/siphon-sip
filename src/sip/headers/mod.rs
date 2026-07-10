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

impl SipHeaders {
    pub fn new() -> Self {
        Self { inner: Arc::new(HeadersInner::new()) }
    }

    fn make_mut(&mut self) -> &mut HeadersInner {
        Arc::make_mut(&mut self.inner)
    }

    // Keys are lowercased ASCII: RFC 3261 §7.3.1 makes field names
    // case-insensitive tokens, and tokens are ASCII (§25.1), so
    // `to_ascii_lowercase` is the correct canonical key.

    /// Add a header value (appends if header already exists)
    pub fn add(&mut self, name: &str, value: String) {
        let key = name.to_ascii_lowercase();
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
        let key = name.to_ascii_lowercase();
        let inner = self.make_mut();
        inner.headers.insert(key, (name.to_string(), vec![value]));
    }

    /// Set multiple values for a header (replaces existing, preserves position in header order).
    ///
    /// Use this when replacing a multi-value header like Via where you need to
    /// keep insertion ordering but supply more than one value.
    pub fn set_all(&mut self, name: &str, values: Vec<String>) {
        let key = name.to_ascii_lowercase();
        let inner = self.make_mut();
        inner.headers.insert(key, (name.to_string(), values));
    }

    /// Get first value of a header
    pub fn get(&self, name: &str) -> Option<&String> {
        self.inner
            .headers
            .get(&name.to_ascii_lowercase())
            .and_then(|(_, values)| values.first())
    }

    /// Get all values of a header
    pub fn get_all(&self, name: &str) -> Option<&Vec<String>> {
        self.inner
            .headers
            .get(&name.to_ascii_lowercase())
            .map(|(_, values)| values)
    }

    /// Remove a header
    pub fn remove(&mut self, name: &str) {
        let key = name.to_ascii_lowercase();
        let inner = self.make_mut();
        inner.headers.shift_remove(&key);
    }

    /// Check if header exists
    pub fn has(&self, name: &str) -> bool {
        self.inner.headers.contains_key(&name.to_ascii_lowercase())
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



