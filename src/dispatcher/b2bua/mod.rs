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

mod ack;
mod b_leg;
mod bridge;
mod builders;
mod bye;
mod cancel;
mod control;
mod control_media;
mod forward;
mod handover;
mod held_bye;
mod info;
mod invite;
mod late_prack_offer;
mod on_failure;
mod originate;
mod outbound;
mod prack_bridge;
mod refer;
mod refer_outbound;
mod refresh_offer_relay;
mod reinvite_in;
mod reinvite_out;
mod reliable;
mod response;
mod routing;
mod session_timer;
pub mod shutdown;
mod terminate;
mod timeouts;
mod transfer;
mod update;

pub use ack::*;
pub use b_leg::*;
pub use bridge::*;
pub use builders::*;
pub use bye::*;
pub use cancel::*;
pub use control::*;
pub use control_media::*;
pub use forward::*;
pub use handover::*;
pub use held_bye::*;
pub use info::*;
pub use invite::*;
pub use late_prack_offer::*;
pub use on_failure::*;
pub use originate::*;
pub use outbound::*;
pub use prack_bridge::*;
pub use refer::*;
pub use refer_outbound::*;
pub use refresh_offer_relay::*;
pub use reinvite_in::*;
pub use reinvite_out::*;
pub use reliable::*;
pub use response::*;
pub use routing::*;
pub use session_timer::*;
pub use terminate::*;
pub use timeouts::*;
pub use transfer::*;
pub use update::*;

/// Whether B2BUA mode handles this call.
///
/// A registered `@b2bua.*` Python handler turns it on, and so does
/// `control.inbound`: a deployment whose policy lives in its controller should
/// not have to ship a routing script that exists only to forward every call.
pub fn b2bua_mode_active(
    engine_state: &crate::script::engine::ScriptState,
    state: &crate::dispatcher::DispatcherState,
) -> bool {
    engine_state.has_b2bua_handlers() || state.control_inbound.is_some()
}
