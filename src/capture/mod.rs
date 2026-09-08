//! Bounded SIP message capture, indexed by Call-ID.
//!
//! The question an operator actually arrives with is "the call from +31… at
//! 14:02 failed, why?", and answering it means seeing the messages. Without
//! this they leave the dashboard for `sngrep` on the box, or for a packet
//! capture nobody started before the fault.
//!
//! # Cost
//!
//! Off by default. When on, capture is a `Bytes` refcount bump and a push: both
//! hook points already hold the wire bytes, so nothing is re-serialized and
//! nothing is formatted on the datapath. When off it is one relaxed atomic load
//! at each of the two points every message passes through.
//!
//! # Bounds
//!
//! Total bytes, call count, and messages per call, all capped. Eviction is
//! oldest-call-first, so a live call is never half-evicted: the unit of
//! retention is the call, because half a ladder answers nothing.
//!
//! # What this is not
//!
//! This is a debugging facility. It is **not** lawful intercept — `crate::li`
//! is that, with its own warrant handling, its own delivery, and its own
//! retention rules. Nothing here should ever be presented as satisfying an LI
//! obligation, and the retention here is a ring buffer measured in megabytes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use bytes::Bytes;
use serde::Serialize;

/// Direction of a captured frame, from this node's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// One captured SIP message.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
    pub timestamp_ms: u64,
    pub direction: Direction,
    pub peer: String,
    pub transport: &'static str,
    /// The wire bytes, shared with whatever produced them.
    pub raw: Bytes,
}

impl CapturedMessage {
    /// The first line, for a ladder label, without keeping a parsed copy.
    fn start_line(&self) -> String {
        let end = self
            .raw
            .iter()
            .position(|byte| *byte == b'\r' || *byte == b'\n')
            .unwrap_or(self.raw.len());
        String::from_utf8_lossy(&self.raw[..end]).into_owned()
    }

    fn to_json(&self, redact_bodies: bool) -> serde_json::Value {
        let text = String::from_utf8_lossy(&self.raw);
        let body = if redact_bodies {
            // Headers are the routing story; a body is where the SDP (and any
            // MESSAGE content) lives, which an operator debugging routing does
            // not need and a privacy-conscious deployment would rather not
            // retain in a browser tab.
            match text.find("\r\n\r\n") {
                Some(at) => {
                    let (headers, rest) = text.split_at(at + 4);
                    format!("{headers}[{} bytes redacted]", rest.len())
                }
                None => text.into_owned(),
            }
        } else {
            text.into_owned()
        };
        serde_json::json!({
            "timestamp_ms": self.timestamp_ms,
            "direction": self.direction.label(),
            "peer": self.peer,
            "transport": self.transport,
            "start_line": self.start_line(),
            "bytes": self.raw.len(),
            "raw": body,
        })
    }
}

/// Everything captured for one Call-ID.
#[derive(Debug, Default)]
struct CallCapture {
    messages: Vec<CapturedMessage>,
    bytes: usize,
}

/// Configuration and bounds.
#[derive(Debug, Clone, Copy)]
pub struct CaptureLimits {
    pub max_bytes: usize,
    pub max_calls: usize,
    pub max_messages_per_call: usize,
    pub redact_bodies: bool,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            max_calls: 500,
            max_messages_per_call: 256,
            redact_bodies: false,
        }
    }
}

/// The process-wide capture store.
#[derive(Debug)]
pub struct CaptureStore {
    enabled: AtomicBool,
    inner: Mutex<CaptureInner>,
    bytes: AtomicUsize,
    dropped: AtomicU64,
    limits: Mutex<CaptureLimits>,
}

#[derive(Debug, Default)]
struct CaptureInner {
    calls: std::collections::HashMap<String, CallCapture>,
    /// Insertion order, for oldest-first eviction.
    order: VecDeque<String>,
}

impl Default for CaptureStore {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            inner: Mutex::new(CaptureInner::default()),
            bytes: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
            limits: Mutex::new(CaptureLimits::default()),
        }
    }
}

impl CaptureStore {
    fn inner(&self) -> MutexGuard<'_, CaptureInner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn limits(&self) -> CaptureLimits {
        match self.limits.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Bytes currently retained.
    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Calls currently retained.
    pub fn call_count(&self) -> usize {
        self.inner().calls.len()
    }

    /// Messages dropped because a call hit its per-call cap.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Record one message. Cheap enough for the datapath: a refcount bump, a
    /// push, and the eviction check.
    pub fn record(
        &self,
        call_id: &str,
        direction: Direction,
        peer: String,
        transport: &'static str,
        raw: Bytes,
    ) {
        if !self.is_enabled() || call_id.is_empty() {
            return;
        }
        let limits = self.limits();
        let size = raw.len();
        let message = CapturedMessage {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis() as u64)
                .unwrap_or(0),
            direction,
            peer,
            transport,
            raw,
        };

        let mut inner = self.inner();
        let entry = inner.calls.entry(call_id.to_string());
        match entry {
            std::collections::hash_map::Entry::Occupied(mut occupied) => {
                let call = occupied.get_mut();
                if call.messages.len() >= limits.max_messages_per_call {
                    // A call that has already produced hundreds of messages is
                    // a retransmission storm or a very long dialog; keeping the
                    // first N tells the story of how it started, which is the
                    // part that explains a failure.
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    if let Some(metrics) = crate::metrics::try_metrics() {
                        metrics.capture_dropped_total.inc();
                    }
                    return;
                }
                call.bytes += size;
                call.messages.push(message);
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(CallCapture {
                    messages: vec![message],
                    bytes: size,
                });
                inner.order.push_back(call_id.to_string());
            }
        }
        self.bytes.fetch_add(size, Ordering::Relaxed);

        // Evict oldest calls until both bounds hold. Whole calls, never partial
        // ones: half a ladder answers nothing.
        while inner.calls.len() > limits.max_calls
            || self.bytes.load(Ordering::Relaxed) > limits.max_bytes
        {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(evicted) = inner.calls.remove(&oldest) {
                self.bytes.fetch_sub(evicted.bytes, Ordering::Relaxed);
            }
        }

        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.capture_messages_total.inc();
            metrics
                .capture_bytes
                .set(self.bytes.load(Ordering::Relaxed) as i64);
            metrics.capture_calls.set(inner.calls.len() as i64);
        }
    }

    /// Everything captured for one call, oldest first.
    pub fn get(&self, call_id: &str) -> Option<serde_json::Value> {
        let redact = self.limits().redact_bodies;
        let inner = self.inner();
        let call = inner.calls.get(call_id)?;
        Some(serde_json::json!({
            "call_id": call_id,
            "messages": call.messages.iter().map(|message| message.to_json(redact)).collect::<Vec<_>>(),
            "bytes": call.bytes,
        }))
    }

    /// Call-IDs whose captured text contains `needle` (case-insensitive).
    ///
    /// Scans retained messages, so it is a per-lookup cost bounded by the ring,
    /// never a per-packet one. This is what lets an operator find a call by the
    /// number that was dialled rather than by a Call-ID they do not have.
    pub fn search(&self, needle: &str, limit: usize) -> Vec<serde_json::Value> {
        let needle = needle.to_lowercase();
        let inner = self.inner();
        let mut hits = Vec::new();
        // Newest first: the call an operator is looking for is usually recent.
        for call_id in inner.order.iter().rev() {
            if hits.len() >= limit {
                break;
            }
            let Some(call) = inner.calls.get(call_id) else {
                continue;
            };
            let matched = call_id.to_lowercase().contains(&needle)
                || call.messages.iter().any(|message| {
                    String::from_utf8_lossy(&message.raw)
                        .to_lowercase()
                        .contains(&needle)
                });
            if matched {
                hits.push(serde_json::json!({
                    "call_id": call_id,
                    "messages": call.messages.len(),
                    "first_line": call.messages.first().map(|message| message.start_line()),
                    "started_ms": call.messages.first().map(|message| message.timestamp_ms),
                }));
            }
        }
        hits
    }

    /// Switch capture on with the given bounds.
    pub fn enable(&self, limits: CaptureLimits) {
        if let Ok(mut guard) = self.limits.lock() {
            *guard = limits;
        }
        self.enabled.store(true, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn clear(&self) {
        let mut inner = self.inner();
        inner.calls.clear();
        inner.order.clear();
        self.bytes.store(0, Ordering::Relaxed);
    }
}

static CAPTURE: OnceLock<Arc<CaptureStore>> = OnceLock::new();

/// The process-wide capture store. Inert until [`enable`].
pub fn capture() -> &'static Arc<CaptureStore> {
    CAPTURE.get_or_init(|| Arc::new(CaptureStore::default()))
}

/// Switch capture on.
pub fn enable(limits: CaptureLimits) {
    capture().enable(limits);
}

/// Whether capture is on — the gate both datapath hooks read.
#[inline]
pub fn is_enabled() -> bool {
    capture().is_enabled()
}

/// Extract a Call-ID from raw SIP bytes without parsing the message.
///
/// The outbound hook holds serialized bytes and no parsed message, and parsing
/// one just to index it would put a full parse on the send path. This is a
/// header scan that stops at the first match — and it only ever runs when
/// capture is enabled.
pub fn call_id_from_bytes(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.lines() {
        if line.is_empty() {
            break; // end of headers; a body cannot contain the Call-ID
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        // RFC 3261 §7.3.3 compact form `i`.
        if name.eq_ignore_ascii_case("Call-ID") || name.eq_ignore_ascii_case("i") {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:alice@example.com>;tag=a\r\n",
        "To: <sip:bob@example.com>\r\n",
        "Call-ID: call-one@192.0.2.1\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 11\r\n",
        "\r\n",
        "v=0\r\ns=hi\r\n",
    );

    fn store() -> CaptureStore {
        let store = CaptureStore::default();
        store.enable(CaptureLimits::default());
        store
    }

    fn record(store: &CaptureStore, call_id: &str, raw: &str) {
        store.record(
            call_id,
            Direction::In,
            "192.0.2.1:5060".to_string(),
            "udp",
            Bytes::from(raw.to_string()),
        );
    }

    #[test]
    fn call_id_is_found_without_parsing() {
        assert_eq!(
            call_id_from_bytes(INVITE.as_bytes()).as_deref(),
            Some("call-one@192.0.2.1")
        );
    }

    #[test]
    fn compact_call_id_form_is_understood() {
        let raw = "ACK sip:b@e SIP/2.0\r\ni: compact-id\r\n\r\n";
        assert_eq!(
            call_id_from_bytes(raw.as_bytes()).as_deref(),
            Some("compact-id")
        );
    }

    #[test]
    fn a_body_containing_call_id_is_not_mistaken_for_the_header() {
        let raw = "MESSAGE sip:b@e SIP/2.0\r\nCSeq: 1 MESSAGE\r\n\r\nCall-ID: not-a-header\r\n";
        assert_eq!(call_id_from_bytes(raw.as_bytes()), None);
    }

    #[test]
    fn a_disabled_store_records_nothing() {
        let store = CaptureStore::default();
        record(&store, "call-one", INVITE);
        assert_eq!(store.call_count(), 0);
        assert_eq!(store.bytes(), 0);
    }

    #[test]
    fn messages_are_grouped_by_call_id() {
        let store = store();
        record(&store, "call-one", INVITE);
        record(&store, "call-one", "SIP/2.0 200 OK\r\n\r\n");
        record(&store, "call-two", INVITE);

        assert_eq!(store.call_count(), 2);
        let one = store.get("call-one").expect("captured");
        assert_eq!(one["messages"].as_array().map(Vec::len), Some(2));
        assert!(store.get("call-three").is_none());
    }

    #[test]
    fn the_start_line_is_kept_for_the_ladder() {
        let store = store();
        record(&store, "call-one", INVITE);
        let captured = store.get("call-one").expect("captured");
        assert_eq!(
            captured["messages"][0]["start_line"],
            "INVITE sip:bob@example.com SIP/2.0"
        );
    }

    #[test]
    fn per_call_message_cap_drops_rather_than_grows() {
        let store = CaptureStore::default();
        store.enable(CaptureLimits {
            max_messages_per_call: 3,
            ..CaptureLimits::default()
        });
        for _ in 0..10 {
            record(&store, "loud-call", INVITE);
        }
        let captured = store.get("loud-call").expect("captured");
        assert_eq!(captured["messages"].as_array().map(Vec::len), Some(3));
        assert_eq!(store.dropped(), 7);
    }

    #[test]
    fn oldest_calls_are_evicted_whole() {
        let store = CaptureStore::default();
        store.enable(CaptureLimits {
            max_calls: 2,
            ..CaptureLimits::default()
        });
        record(&store, "call-one", INVITE);
        record(&store, "call-two", INVITE);
        record(&store, "call-three", INVITE);

        assert_eq!(store.call_count(), 2);
        // The oldest went entirely — not trimmed to a partial ladder.
        assert!(store.get("call-one").is_none());
        assert!(store.get("call-two").is_some());
        assert!(store.get("call-three").is_some());
    }

    #[test]
    fn byte_bound_evicts_and_accounting_returns_to_zero() {
        let store = CaptureStore::default();
        store.enable(CaptureLimits {
            max_bytes: INVITE.len() * 2,
            ..CaptureLimits::default()
        });
        for index in 0..8 {
            record(&store, &format!("call-{index}"), INVITE);
        }
        assert!(store.bytes() <= INVITE.len() * 2);
        assert!(store.call_count() <= 2);

        // Byte accounting must track eviction exactly, or the store silently
        // stops accepting messages once the counter drifts above the cap.
        let counted: usize = {
            let inner = store.inner();
            inner.calls.values().map(|call| call.bytes).sum()
        };
        assert_eq!(store.bytes(), counted);
    }

    #[test]
    fn search_matches_call_id_and_message_content() {
        let store = store();
        record(&store, "call-one", INVITE);

        assert_eq!(store.search("call-one", 10).len(), 1);
        // The point of the feature: find a call by the number dialled.
        assert_eq!(store.search("bob@example.com", 10).len(), 1);
        assert_eq!(store.search("BOB@EXAMPLE.COM", 10).len(), 1);
        assert_eq!(store.search("carol", 10).len(), 0);
    }

    #[test]
    fn search_respects_its_limit() {
        let store = store();
        for index in 0..10 {
            record(&store, &format!("call-{index}"), INVITE);
        }
        assert_eq!(store.search("bob", 3).len(), 3);
    }

    #[test]
    fn redaction_keeps_headers_and_drops_the_body() {
        let store = CaptureStore::default();
        store.enable(CaptureLimits {
            redact_bodies: true,
            ..CaptureLimits::default()
        });
        record(&store, "call-one", INVITE);

        let captured = store.get("call-one").expect("captured");
        let raw = captured["messages"][0]["raw"].as_str().unwrap_or_default();
        assert!(raw.contains("Call-ID: call-one@192.0.2.1"));
        assert!(!raw.contains("v=0"));
        assert!(raw.contains("redacted"));
    }

    #[test]
    fn steady_state_returns_the_store_to_baseline() {
        // Per-module leak gate: a batch of complete calls, evicted by the
        // bounds, must leave byte accounting and the call map at baseline.
        let store = CaptureStore::default();
        store.enable(CaptureLimits {
            max_calls: 4,
            ..CaptureLimits::default()
        });
        for index in 0..2000 {
            record(&store, &format!("call-{index}"), INVITE);
        }
        assert!(store.call_count() <= 4);
        let counted: usize = {
            let inner = store.inner();
            inner.calls.values().map(|call| call.bytes).sum()
        };
        assert_eq!(store.bytes(), counted);

        store.clear();
        assert_eq!(store.call_count(), 0);
        assert_eq!(store.bytes(), 0);
    }
}
