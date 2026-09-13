//! The B2BUA half of the dispatcher.
//!
//! This is orchestration, not call state. `crate::b2bua` owns the per-call
//! state and the pure protocol logic; everything here drives it — building
//! messages, sending them, arming timers, and reacting to what comes back.
//!
//! It lives under `dispatcher` rather than in `crate::b2bua` because it is
//! bound to `DispatcherState` and to the dispatcher's private helpers on both
//! sides. Moving it into `crate::b2bua` would mean making ~100 private items
//! crate-visible and making the call-state layer depend on transport, script,
//! rtpengine, diameter, cdr and li. `tests/integration/module_boundary_tests.rs`
//! enforces that direction.

mod b_leg;
mod builders;
mod cancel;
mod handover;
mod invite;
mod outbound;
mod response;
mod routing;
mod timeouts;

pub(super) use b_leg::*;
pub(super) use builders::*;
pub(super) use cancel::*;
pub(super) use handover::*;
pub(super) use invite::*;
pub(super) use outbound::*;
pub(super) use response::*;
pub(super) use routing::*;
pub(super) use timeouts::*;
