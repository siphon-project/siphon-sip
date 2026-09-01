//! B2BUA (Back-to-Back User Agent) — actor-based call leg model.
//!
//! Each call leg runs as an independent actor (tokio task) that owns its SIP
//! dialog state and communicates with peer legs via message channels.
//!
//! ## Modules
//!
//! - [`actor`]: Core actor types — `LegActor`, `CallActor`, `LegHandle`,
//!   `LegRegistry`, dialog state, and intercommunication messages.
//! - [`bridge`]: Joining two answered legs this process already owns — the
//!   3PCC re-negotiation, the media re-anchor across two call actors, and the
//!   glare rules.
//! - [`fork`]: Forking state machine (parallel/sequential B-leg strategies).
//! - [`transfer`]: REFER/Replaces call transfer handling.
//! - [`header_policy`]: Versioned per-call header policy (which headers
//!   cross the trust boundary, which are stripped, rewritten, or translated).
//! - [`retransmit`]: RFC 3261 §17.1 retransmission schedules for
//!   siphon-originated requests (the B2BUA owns its legs and registers no
//!   client transaction, so it gets no Timer A / Timer E from the
//!   transaction layer).

pub mod actor;
pub mod bridge;
pub mod fork;
pub mod header_policy;
pub mod retransmit;
pub mod transfer;
