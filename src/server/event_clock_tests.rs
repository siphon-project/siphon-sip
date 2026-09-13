use super::event_clock::{EventClock, SharedTime};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::prelude::*;

/// An in-memory sink standing in for one of the two real ones.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn rendered(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
    }
}

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn timestamp_of(rendered: &str) -> &str {
    rendered
        .split_whitespace()
        .next()
        .expect("a rendered line starts with its timestamp")
}

/// One event must carry ONE timestamp, whichever sink it is read from.
///
/// Two `fmt` layers each timed the event as they formatted it, so the
/// console and the file disagreed about when the same line happened — by up
/// to 1.4 ms on a live process. That is invisible while reading a log and
/// costly the moment a log line is correlated against a CDR, a HEP capture
/// or an intercept record, since which stamp is authoritative then depends
/// on which log is in hand.
#[test]
fn one_event_carries_one_timestamp_in_both_sinks() {
    let console = Buffer::default();
    let file = Buffer::default();

    let subscriber = tracing_subscriber::registry()
        .with(EventClock)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_timer(SharedTime)
                .with_writer(console.clone()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_timer(SharedTime)
                .with_writer(file.clone()),
        );

    tracing::subscriber::with_default(subscriber, || {
        tracing::error!("answered by carrier");
    });

    let (console, file) = (console.rendered(), file.rendered());
    assert!(!console.is_empty() && !file.is_empty(), "both sinks wrote");
    assert_eq!(
        timestamp_of(&console),
        timestamp_of(&file),
        "the same event was stamped twice:\nconsole: {console}file:    {file}"
    );
}

/// The rendered stamp must stay what it has always been — this changes
/// which instant is written, never how it is written, so anything parsing
/// these logs is unaffected. Guards against a future rewrite of the timer
/// silently reshaping the field.
#[test]
fn the_timestamp_format_is_unchanged() {
    let sink = Buffer::default();
    let subscriber = tracing_subscriber::registry().with(EventClock).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(SharedTime)
            .with_writer(sink.clone()),
    );
    tracing::subscriber::with_default(subscriber, || tracing::error!("x"));

    let rendered = sink.rendered();
    let stamp = timestamp_of(&rendered);
    // RFC 3339 UTC to sub-second precision, e.g. 2026-09-03T13:15:45.671735Z
    assert!(stamp.ends_with('Z'), "not UTC-suffixed: {stamp}");
    assert!(stamp.contains('T') && stamp.contains('.'), "{stamp}");
    assert_eq!(stamp.matches('-').count(), 2, "{stamp}");
}

/// A subscriber built WITHOUT `EventClock` still renders a real timestamp
/// rather than a blank field — `SharedTime` times the event itself when
/// nothing stamped it.
#[test]
fn the_timer_falls_back_when_nothing_stamped_the_event() {
    // On its own thread deliberately: the stamp is thread-local, so a test
    // that had already run here would leave one behind and this would read
    // that instead of taking the fallback it exists to cover. A fresh
    // thread has an empty stamp by construction.
    std::thread::spawn(|| {
        let sink = Buffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_timer(SharedTime)
                .with_writer(sink.clone()),
        );
        tracing::subscriber::with_default(subscriber, || tracing::error!("x"));

        let rendered = sink.rendered();
        assert!(
            timestamp_of(&rendered).ends_with('Z'),
            "no timestamp without EventClock: {rendered}"
        );
    })
    .join()
    .expect("fallback assertions hold");
}
