//! External remote-control plane (experimental, proof-of-concept).
//!
//! An out-of-process application connects over a single bidirectional WebSocket
//! and drives B2BUA calls that a Python `@b2bua.on_invite` handler explicitly
//! hands over with `call.handover("app")` (the ARI *Stasis* model). Calls that
//! are not handed over cost nothing.
//!
//! This POC proves one thing end-to-end: a WebSocket app can drive a live B2BUA
//! call **without ever blocking siphon's pools or dispatcher**. The protocol,
//! auth, event bus + backpressure, and the `handover` + `answer`/`hangup` verbs
//! are wired; everything else in the design (channels/bridges/originate/media/
//! adapters/TLS/SS7/SMPP) is out of scope.
//!
//! ## Layout
//!
//! - [`protocol`] — the JSON wire DTOs (command/reply/event).
//! - [`registry`] — [`ControlBus`], the app/connection/channel registry and the
//!   bounded per-connection event queue.
//! - [`listener`] — the axum WebSocket server (token auth + async read/write
//!   tasks).
//!
//! The dispatcher owns the command *apply* consumer (co-located with the B2BUA
//! handlers), so it can reach the `CallActorStore` and SIP send helpers.

pub mod listener;
pub mod protocol;
pub mod registry;

pub use listener::{router, serve, ControlServerState};
pub use protocol::{
    CommandFrame, ControlErrorCode, ControlResult, EventFrame, ReplyFrame, ReplyStatus,
};
pub use registry::{
    ChannelOwner, ConnHandle, ControlBus, ControlCommand, EventQueue, PushOutcome,
    SlowConsumerPolicy,
};
