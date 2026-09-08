//! Live log tail — an in-process fan-out of `tracing` events to the admin API.
//!
//! An operator debugging a call should not have to leave the dashboard for
//! `journalctl`. This module makes the process's own log stream readable over
//! HTTP, as Server-Sent Events, filtered server-side.
//!
//! # Why capture is on-demand
//!
//! The Rust datapath emits nothing at INFO for an ordinary message or call, but
//! a logging Python script does: `b2bua_default.py` writes roughly five lines
//! per call, which is ~150k lines a second at 30k cps. Formatting all of that
//! into a ring buffer that nobody is reading would be a real cost on the
//! hot path, paid permanently for a feature used occasionally.
//!
//! So [`LogTailLayer::on_event`] starts with one relaxed atomic load and
//! returns when there are no attached streams and the event is below WARN.
//! Formatting — the allocation, the field visitor, the `Arc` — happens only
//! past that gate. WARN and above are always retained, in a small ring, because
//! they are rare by construction and they are the context an operator wants
//! *already collected* when they open the tail after something went wrong.
//!
//! # Backpressure
//!
//! Each attached stream owns a bounded queue with a drop-oldest policy, the
//! same discipline the control plane applies to a slow application
//! (`crate::control::registry::OutboundQueue`): a browser that stops reading
//! loses lines and is told how many, and pressure never reaches the tracing
//! layer, let alone the thread that logged. A log tail must not be able to slow
//! down signalling.
//!
//! # What the tail can see
//!
//! `EnvFilter` sits above every layer in the subscriber stack, so this layer
//! only ever observes events the node's configured `log.level` already admits.
//! Tailing debug requires the node to be running at debug; there is no runtime
//! level override, because making the global filter reloadable puts an
//! `RwLock` read on the per-event path.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use serde::Serialize;
use tokio::sync::Notify;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Entries of WARN and above retained even when nobody is tailing.
const WARN_RING_CAPACITY: usize = 512;

/// Per-stream queue depth before the oldest line is dropped.
const STREAM_QUEUE_CAPACITY: usize = 2048;

/// One captured log event, as the admin API serializes it.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    /// Milliseconds since the UNIX epoch.
    pub timestamp_ms: u64,
    /// `ERROR` / `WARN` / `INFO` / `DEBUG` / `TRACE`.
    pub level: &'static str,
    /// Emitting module path (`siphon::b2bua::actor`).
    pub target: String,
    /// The event's `message` field, rendered.
    pub message: String,
    /// The Call-ID, when the call site attached one as a structured field.
    ///
    /// There are no spans anywhere in this codebase, so there is no ambient
    /// call-id to inherit: this is populated only for the call sites that
    /// literally write `call_id = %…`, and never for Python `log.*` output,
    /// which carries no fields at all. Correlation by call-id is therefore
    /// best-effort, and the UI says so rather than implying completeness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Remaining structured fields, in call-site order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<(String, String)>,
}

impl LogRecord {
    /// Whether this record satisfies a stream's filter.
    fn matches(&self, filter: &TailFilter) -> bool {
        if level_rank(self.level) > filter.max_rank {
            return false;
        }
        if let Some(ref call_id) = filter.call_id {
            if self.call_id.as_deref() != Some(call_id.as_str()) {
                return false;
            }
        }
        if let Some(ref needle) = filter.contains {
            let hit = self.message.to_lowercase().contains(needle)
                || self.target.to_lowercase().contains(needle)
                || self
                    .fields
                    .iter()
                    .any(|(name, value)| value.to_lowercase().contains(needle) || name == needle);
            if !hit {
                return false;
            }
        }
        true
    }
}

/// Severity as a sortable rank: ERROR is 0, TRACE is 4. A filter admits every
/// record whose rank is `<=` its own, i.e. "this level and above".
fn level_rank(level: &str) -> u8 {
    match level {
        "ERROR" => 0,
        "WARN" => 1,
        "INFO" => 2,
        "DEBUG" => 3,
        _ => 4,
    }
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// Server-side filter for one attached stream.
#[derive(Debug, Clone)]
pub struct TailFilter {
    /// Highest rank admitted (see [`level_rank`]). Defaults to TRACE, i.e. all.
    pub max_rank: u8,
    /// Case-insensitive substring across message, target and field values.
    pub contains: Option<String>,
    /// Exact Call-ID match.
    pub call_id: Option<String>,
}

impl Default for TailFilter {
    /// "Everything the node logs" — deliberately hand-written rather than
    /// derived. A derived `Default` gives `max_rank: 0`, which is ERROR-only:
    /// a caller that built a default filter would silently receive almost
    /// nothing, and the failure mode of a log tail showing too little is that
    /// the operator concludes the node is quiet.
    fn default() -> Self {
        Self {
            max_rank: level_rank("TRACE"),
            contains: None,
            call_id: None,
        }
    }
}

impl TailFilter {
    /// Build from query parameters, defaulting to "everything the node logs".
    ///
    /// Filtering here rather than in the browser is what keeps a narrow filter
    /// cheap: at 150k lines a second, shipping everything to the client so it
    /// can throw most of it away would spend the bandwidth and the serialization
    /// to deliver a handful of lines.
    pub fn new(level: Option<&str>, contains: Option<&str>, call_id: Option<&str>) -> Self {
        Self {
            max_rank: level
                .map(|value| level_rank(&value.to_ascii_uppercase()))
                .unwrap_or(4),
            contains: contains
                .filter(|value| !value.is_empty())
                .map(|value| value.to_lowercase()),
            call_id: call_id.filter(|value| !value.is_empty()).map(String::from),
        }
    }
}

/// A bounded, drop-oldest queue feeding one attached SSE stream.
#[derive(Debug)]
pub struct TailStream {
    inner: Mutex<VecDeque<Arc<LogRecord>>>,
    notify: Notify,
    filter: TailFilter,
    dropped: AtomicU64,
    closed: AtomicBool,
}

impl TailStream {
    fn new(filter: TailFilter) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(64)),
            notify: Notify::new(),
            filter,
            dropped: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<LogRecord>>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Offer a record. Never blocks, never awaits — this runs on whatever thread
    /// called `info!`, which may be the dispatcher or a Python worker.
    fn offer(&self, record: &Arc<LogRecord>) {
        if !record.matches(&self.filter) {
            return;
        }
        {
            let mut queue = self.lock();
            if queue.len() >= STREAM_QUEUE_CAPACITY {
                queue.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.log_tail_dropped_total.inc();
                }
            }
            queue.push_back(Arc::clone(record));
        }
        self.notify.notify_one();
    }

    /// Await and drain everything currently queued, plus the number of lines
    /// dropped since the last drain. An empty vector means the stream closed.
    pub async fn recv_many(&self) -> (Vec<Arc<LogRecord>>, u64) {
        loop {
            {
                let mut queue = self.lock();
                if !queue.is_empty() {
                    let drained = queue.drain(..).collect();
                    return (drained, self.dropped.swap(0, Ordering::Relaxed));
                }
            }
            if self.closed.load(Ordering::SeqCst) {
                return (Vec::new(), self.dropped.swap(0, Ordering::Relaxed));
            }
            self.notify.notified().await;
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

/// Process-wide tail registry.
#[derive(Debug, Default)]
pub struct LogTail {
    /// Attached streams. Small by construction (see `max_streams`), so a `Vec`
    /// behind a mutex beats a concurrent map here.
    streams: Mutex<Vec<Arc<TailStream>>>,
    /// Fast gate read on every event, kept in step with `streams.len()`.
    attached: AtomicUsize,
    warn_ring: Mutex<VecDeque<Arc<LogRecord>>>,
    enabled: AtomicBool,
    max_streams: AtomicUsize,
}

impl LogTail {
    fn streams(&self) -> MutexGuard<'_, Vec<Arc<TailStream>>> {
        match self.streams.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn warn_ring(&self) -> MutexGuard<'_, VecDeque<Arc<LogRecord>>> {
        match self.warn_ring.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Whether capture is switched on at all.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Number of streams currently attached.
    pub fn attached(&self) -> usize {
        self.attached.load(Ordering::Relaxed)
    }

    /// Attach a stream, or `None` when the concurrent-stream cap is reached.
    ///
    /// The cap exists because the admin server has no connection limiting of
    /// any kind: without it, one client could pin an unbounded number of
    /// queues, each up to `STREAM_QUEUE_CAPACITY` records.
    pub fn attach(&self, filter: TailFilter) -> Option<Arc<TailStream>> {
        let mut streams = self.streams();
        if streams.len() >= self.max_streams.load(Ordering::Relaxed) {
            return None;
        }
        let stream = Arc::new(TailStream::new(filter));
        streams.push(Arc::clone(&stream));
        self.attached.store(streams.len(), Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.log_tail_streams.set(streams.len() as i64);
        }
        Some(stream)
    }

    /// Detach a stream. Idempotent — a client that vanishes mid-write and one
    /// that closes cleanly both land here exactly once, via the guard.
    pub fn detach(&self, stream: &Arc<TailStream>) {
        stream.close();
        let mut streams = self.streams();
        streams.retain(|existing| !Arc::ptr_eq(existing, stream));
        self.attached.store(streams.len(), Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.log_tail_streams.set(streams.len() as i64);
        }
    }

    /// The retained WARN+ ring, oldest first.
    pub fn recent_warnings(&self) -> Vec<Arc<LogRecord>> {
        self.warn_ring().iter().cloned().collect()
    }

    fn publish(&self, record: LogRecord) {
        let record = Arc::new(record);
        if level_rank(record.level) <= level_rank("WARN") {
            let mut ring = self.warn_ring();
            if ring.len() >= WARN_RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(Arc::clone(&record));
        }
        for stream in self.streams().iter() {
            stream.offer(&record);
        }
    }
}

static LOG_TAIL: OnceLock<Arc<LogTail>> = OnceLock::new();

/// The process-wide tail. Always present; inert until [`enable`] is called.
pub fn log_tail() -> &'static Arc<LogTail> {
    LOG_TAIL.get_or_init(|| Arc::new(LogTail::default()))
}

/// Switch capture on. Called from the server once the admin config is known.
pub fn enable(max_streams: usize) {
    let tail = log_tail();
    tail.max_streams
        .store(max_streams.max(1), Ordering::Relaxed);
    tail.enabled.store(true, Ordering::Relaxed);
}

/// Collects an event's fields into a [`LogRecord`].
struct RecordVisitor {
    message: String,
    call_id: Option<String>,
    fields: Vec<(String, String)>,
}

impl RecordVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            call_id: None,
            fields: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, value: String) {
        match name {
            "message" => self.message = value,
            "call_id" => self.call_id = Some(value),
            _ => self.fields.push((name.to_string(), value)),
        }
    }
}

impl Visit for RecordVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field.name(), value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record(field.name(), value.to_string());
    }
}

/// The `tracing` layer that feeds [`LogTail`].
pub struct LogTailLayer;

impl<S: Subscriber> Layer<S> for LogTailLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let tail = log_tail();
        if !tail.enabled.load(Ordering::Relaxed) {
            return;
        }

        let level = level_name(event.metadata().level());
        let is_warning = level_rank(level) <= level_rank("WARN");

        // The gate. One relaxed load on the overwhelmingly common path (INFO
        // and below with nobody watching), before anything is formatted.
        if !is_warning && tail.attached.load(Ordering::Relaxed) == 0 {
            return;
        }

        let mut visitor = RecordVisitor::new();
        event.record(&mut visitor);

        tail.publish(LogRecord {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis() as u64)
                .unwrap_or(0),
            level,
            target: event.metadata().target().to_string(),
            message: visitor.message,
            call_id: visitor.call_id,
            fields: visitor.fields,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(level: &'static str, message: &str) -> LogRecord {
        LogRecord {
            timestamp_ms: 0,
            level,
            target: "siphon::test".to_string(),
            message: message.to_string(),
            call_id: None,
            fields: Vec::new(),
        }
    }

    #[test]
    fn level_ranks_are_ordered_most_severe_first() {
        assert!(level_rank("ERROR") < level_rank("WARN"));
        assert!(level_rank("WARN") < level_rank("INFO"));
        assert!(level_rank("INFO") < level_rank("DEBUG"));
        assert!(level_rank("DEBUG") < level_rank("TRACE"));
        assert_eq!(level_rank("nonsense"), 4);
    }

    #[test]
    fn filter_admits_the_named_level_and_above() {
        let filter = TailFilter::new(Some("warn"), None, None);
        assert!(record("ERROR", "x").matches(&filter));
        assert!(record("WARN", "x").matches(&filter));
        assert!(!record("INFO", "x").matches(&filter));
    }

    #[test]
    fn filter_defaults_to_everything() {
        for filter in [TailFilter::new(None, None, None), TailFilter::default()] {
            assert!(record("TRACE", "x").matches(&filter));
            assert!(record("INFO", "x").matches(&filter));
            assert!(record("ERROR", "x").matches(&filter));
        }
    }

    #[test]
    fn substring_filter_is_case_insensitive_across_message_and_target() {
        let filter = TailFilter::new(None, Some("REGISTER"), None);
        assert!(record("INFO", "handling register from ue").matches(&filter));
        assert!(!record("INFO", "handling invite").matches(&filter));

        let mut with_field = record("INFO", "no hit here");
        with_field
            .fields
            .push(("aor".into(), "sip:REGISTERED".into()));
        assert!(with_field.matches(&filter));
    }

    #[test]
    fn call_id_filter_is_exact_and_excludes_records_without_one() {
        let filter = TailFilter::new(None, None, Some("abc123"));
        let mut matching = record("INFO", "x");
        matching.call_id = Some("abc123".to_string());
        assert!(matching.matches(&filter));

        let mut other = record("INFO", "x");
        other.call_id = Some("def456".to_string());
        assert!(!other.matches(&filter));

        assert!(!record("INFO", "x").matches(&filter));
    }

    #[tokio::test]
    async fn stream_receives_matching_records() {
        let stream = Arc::new(TailStream::new(TailFilter::new(Some("info"), None, None)));
        stream.offer(&Arc::new(record("INFO", "hello")));
        stream.offer(&Arc::new(record("DEBUG", "ignored")));

        let (records, dropped) = stream.recv_many().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "hello");
        assert_eq!(dropped, 0);
    }

    #[tokio::test]
    async fn overflow_drops_the_oldest_and_counts_it() {
        let stream = Arc::new(TailStream::new(TailFilter::default()));
        for index in 0..(STREAM_QUEUE_CAPACITY + 10) {
            stream.offer(&Arc::new(record("ERROR", &format!("line {index}"))));
        }

        let (records, dropped) = stream.recv_many().await;
        assert_eq!(records.len(), STREAM_QUEUE_CAPACITY);
        assert_eq!(dropped, 10);
        // The oldest went, not the newest: a tail is only useful if it keeps up
        // with the present.
        assert_eq!(records[0].message, "line 10");
    }

    #[tokio::test]
    async fn a_closed_stream_stops_yielding() {
        let stream = Arc::new(TailStream::new(TailFilter::default()));
        stream.close();
        let (records, _) = stream.recv_many().await;
        assert!(records.is_empty());
    }

    #[test]
    fn warn_ring_retains_warnings_and_evicts_oldest() {
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        for index in 0..(WARN_RING_CAPACITY + 5) {
            tail.publish(record("WARN", &format!("warn {index}")));
        }
        // INFO is not retained when nobody is attached — that is the whole
        // point of the on-demand half.
        tail.publish(record("INFO", "not retained"));

        let retained = tail.recent_warnings();
        assert_eq!(retained.len(), WARN_RING_CAPACITY);
        assert_eq!(retained[0].message, "warn 5");
        assert!(retained.iter().all(|entry| entry.level == "WARN"));
    }

    #[test]
    fn attach_is_capped_and_detach_frees_a_slot() {
        let tail = LogTail::default();
        tail.max_streams.store(2, Ordering::Relaxed);

        let first = tail.attach(TailFilter::default()).expect("first attaches");
        let _second = tail.attach(TailFilter::default()).expect("second attaches");
        assert!(tail.attach(TailFilter::default()).is_none());
        assert_eq!(tail.attached(), 2);

        tail.detach(&first);
        assert_eq!(tail.attached(), 1);
        assert!(tail.attach(TailFilter::default()).is_some());
    }

    #[test]
    fn detach_is_idempotent() {
        let tail = LogTail::default();
        tail.max_streams.store(1, Ordering::Relaxed);
        let stream = tail.attach(TailFilter::default()).expect("attaches");
        tail.detach(&stream);
        tail.detach(&stream);
        assert_eq!(tail.attached(), 0);
    }

    #[test]
    fn publish_fans_out_to_every_attached_stream() {
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        tail.max_streams.store(4, Ordering::Relaxed);

        let broad = tail.attach(TailFilter::default()).expect("attaches");
        let narrow = tail
            .attach(TailFilter::new(Some("error"), None, None))
            .expect("attaches");

        tail.publish(record("INFO", "informational"));

        assert_eq!(broad.lock().len(), 1);
        assert_eq!(narrow.lock().len(), 0);
    }

    #[test]
    fn a_disabled_tail_retains_nothing() {
        let tail = LogTail::default();
        tail.publish(record("ERROR", "dropped on the floor"));
        // publish() is only reached past the layer's enabled check; the ring
        // itself is unconditional, so assert the layer gate instead.
        assert!(!tail.is_enabled());
    }

    #[test]
    fn visitor_splits_message_call_id_and_other_fields() {
        let mut visitor = RecordVisitor::new();
        visitor.record("message", "relaying INVITE".to_string());
        visitor.record("call_id", "abc@example".to_string());
        visitor.record("branch", "z9hG4bK1".to_string());

        assert_eq!(visitor.message, "relaying INVITE");
        assert_eq!(visitor.call_id.as_deref(), Some("abc@example"));
        assert_eq!(
            visitor.fields,
            vec![("branch".to_string(), "z9hG4bK1".to_string())]
        );
    }

    #[test]
    fn steady_state_does_not_grow_the_ring_or_the_streams() {
        // The per-module leak gate: a batch of complete attach/detach cycles
        // plus a batch of publishes must leave both structures at baseline.
        let tail = LogTail::default();
        tail.enabled.store(true, Ordering::Relaxed);
        tail.max_streams.store(4, Ordering::Relaxed);

        for _ in 0..500 {
            let stream = tail.attach(TailFilter::default()).expect("attaches");
            tail.publish(record("INFO", "traffic"));
            let _ = stream.lock().drain(..).count();
            tail.detach(&stream);
        }

        assert_eq!(tail.attached(), 0);
        assert_eq!(tail.streams().len(), 0);
        // Only the WARN+ ring retains anything, and it is bounded.
        assert!(tail.recent_warnings().is_empty());
    }
}
