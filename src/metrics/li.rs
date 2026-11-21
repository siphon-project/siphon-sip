//! Metrics for lawful-intercept content delivery ([`crate::li`]).

use std::sync::OnceLock;

use prometheus::{IntCounter, Opts, Registry};

static UNANSWERED_X3_ENDS_OVERFLOWED: OnceLock<IntCounter> = OnceLock::new();
static LIVE_DIALOGS_OVERFLOWED: OnceLock<IntCounter> = OnceLock::new();

/// Create and register the metrics. Called once from [`super::startup::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let overflowed = IntCounter::with_opts(Opts::new(
        "siphon_li_x3_unanswered_ends_overflowed_total",
        "X3 delivery end reports that waited for the answer to an end siphon asked for, \
         were still waiting when their session was released, and could not be kept for \
         the ADMF because too many were waiting already; each is counted for its \
         destinations and reported there as a count. Above zero means warranted \
         content ended unaccounted for faster than it could be reported",
    ))?;
    registry.register(Box::new(overflowed.clone()))?;
    let _ = UNANSWERED_X3_ENDS_OVERFLOWED.set(overflowed);
    let dialogs_overflowed = IntCounter::with_opts(Opts::new(
        "siphon_li_live_dialogs_overflowed_total",
        "Dialog-forming INVITEs the lawful-intercept live-dialog index had no room \
         to remember. A warrant activated while such a call is up cannot find it, so          the call is intercepted from its next message instead of at once. Above \
         zero means more calls are up than the index holds",
    ))?;
    registry.register(Box::new(dialogs_overflowed.clone()))?;
    let _ = LIVE_DIALOGS_OVERFLOWED.set(dialogs_overflowed);
    Ok(())
}

/// Count one end report there was no room to keep.
pub fn unanswered_x3_end_overflowed() {
    if let Some(overflowed) = UNANSWERED_X3_ENDS_OVERFLOWED.get() {
        overflowed.inc();
    }
}

/// Count one dialog the live-dialog index had no room for.
pub fn live_dialog_overflowed() {
    if let Some(overflowed) = LIVE_DIALOGS_OVERFLOWED.get() {
        overflowed.inc();
    }
}

/// How many dialogs have been counted as overflowed. `None` before
/// [`super::startup::init`].
pub fn live_dialogs_overflowed() -> Option<u64> {
    LIVE_DIALOGS_OVERFLOWED.get().map(IntCounter::get)
}

/// How many have been counted. `None` before [`super::startup::init`].
pub fn unanswered_x3_ends_overflowed() -> Option<u64> {
    UNANSWERED_X3_ENDS_OVERFLOWED.get().map(IntCounter::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overflowed_live_dialog_is_counted() {
        crate::metrics::init().expect("metrics");
        let before = live_dialogs_overflowed().expect("registered");
        live_dialog_overflowed();
        assert!(live_dialogs_overflowed().expect("registered") > before);
    }

    #[test]
    fn an_overflowed_end_report_is_counted() {
        crate::metrics::init().expect("metrics");
        let before = unanswered_x3_ends_overflowed().expect("registered");
        unanswered_x3_end_overflowed();
        assert!(unanswered_x3_ends_overflowed().expect("registered") > before);
    }
}
