//! A clock the event loop reads without a syscall per read.

use std::cell::RefCell;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};

thread_local! {
    /// The current event's rendered timestamp. Thread-local because layers
    /// format an event synchronously, on the thread that emitted it, before
    /// that thread can emit another.
    static STAMP: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Stamps the event, once, ahead of the `fmt` layers.
///
/// Must be composed BEFORE them — `Layered` runs the layer added first on
/// each event first — or they render a stamp from the previous event.
pub struct EventClock;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventClock {
    fn on_event(
        &self,
        _event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        STAMP.with(|stamp| {
            let mut stamp = stamp.borrow_mut();
            stamp.clear();
            let _ = SystemTime.format_time(&mut Writer::new(&mut *stamp));
        });
    }
}

/// Writes the timestamp [`EventClock`] recorded for this event.
#[derive(Clone, Copy, Debug)]
pub struct SharedTime;

impl FormatTime for SharedTime {
    fn format_time(&self, writer: &mut Writer<'_>) -> std::fmt::Result {
        STAMP.with(|stamp| {
            let stamp = stamp.borrow();
            if stamp.is_empty() {
                // Nothing stamped this event — a subscriber built without
                // EventClock. Time it here rather than emit a blank field.
                SystemTime.format_time(writer)
            } else {
                writer.write_str(&stamp)
            }
        })
    }
}
