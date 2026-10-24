//! Log lines the console and file writers dropped.
//!
//! Both log writers are `tracing_appender::non_blocking`: the thread that logs
//! hands the line to a writer thread and returns, so a slow log consumer (a
//! container log pipe applying backpressure) never parks a thread that is
//! attached to the interpreter, which would hold a garbage collection's
//! stop-the-world open for as long as the pipe stays full. The price is that a
//! line arriving while the writer's buffer is full is dropped, and this counts
//! them, read at scrape time.

use std::sync::{Mutex, OnceLock};

use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{IntCounter, Opts, Registry};
use tracing_appender::non_blocking::ErrorCounter;

const NAME: &str = "siphon_log_lines_dropped_total";
const HELP: &str = "Log lines dropped because the console or file log writer's buffer was full (the log consumer could not keep up); a rate above zero means the log pipe is the bottleneck";

static WRITERS: OnceLock<Mutex<Vec<ErrorCounter>>> = OnceLock::new();

/// Count what `counter`'s writer drops. Called once per writer at startup.
pub fn track(counter: ErrorCounter) {
    WRITERS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(counter);
}

/// Lines dropped so far, over every tracked writer.
pub fn dropped_lines() -> u64 {
    WRITERS.get().map_or(0, |writers| {
        writers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|counter| counter.dropped_lines() as u64)
            .sum()
    })
}

struct DroppedLines {
    desc: Desc,
}

impl Collector for DroppedLines {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        match IntCounter::with_opts(Opts::new(NAME, HELP)) {
            Ok(counter) => {
                counter.inc_by(dropped_lines());
                counter.collect()
            }
            Err(_) => Vec::new(),
        }
    }
}

/// Register the counter. Called once from the metrics startup.
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let desc = Desc::new(
        NAME.to_string(),
        HELP.to_string(),
        Vec::new(),
        Default::default(),
    )?;
    registry.register(Box::new(DroppedLines { desc }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_reads_what_the_writers_dropped() {
        let registry = Registry::new();
        init(&registry).expect("registered");
        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == NAME)
            .expect("exposed");
        let value = family.get_metric()[0].get_counter().value();
        assert!(value >= 0.0);
        assert_eq!(value as u64, dropped_lines());
    }
}
