//! Diameter charging driven from the call lifecycle.
//!
//! Rf is offline (a record per call, billed later); Ro is online (credit
//! reserved before the call connects). Both are auto-emitted from dispatcher
//! events rather than from a script, which is why they live here and not in
//! `crate::diameter` — that module owns the protocol, this owns when to speak
//! it.

mod rf;
mod ro;

pub(super) use rf::*;
pub(super) use ro::*;
pub use ro::{ro_authorize_b2bua, RoAuthorizeOutcome};
