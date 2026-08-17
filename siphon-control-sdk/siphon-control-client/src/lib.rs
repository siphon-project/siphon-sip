//! Async Rust client for the SIPhon external control plane (`siphon-control.v1`).
//!
//! An ARI/ESL-class rail for driving handed-over calls out of process. The
//! client hides the wire completely — no manual JSON, no request-id bookkeeping,
//! no hand-rolled `rpc()`.
//!
//! # Layering (protocol-agnostic core + typed facades)
//!
//! - [`ControlClient`] / [`ControlServer`] are the **generic core**: transport,
//!   `hello`, request-id correlation, reconnect + `resync`, and a generic event
//!   stream. Their headline primitive is
//!   [`ControlClient::command`]`(module, verb, target, args)`, which works for
//!   any adapter (`sip`, and future `smpp`/`ss7`) with zero changes.
//! - [`sip`] is a **typed facade** over that core: [`sip::Call`]'s verbs
//!   (`answer`/`progress`/`hangup`/`refer`/…) are thin wrappers over
//!   `command("sip", …)`, and `StasisStart`→`Call` dispatch lives there. A
//!   future `smpp` facade is an additive sibling over the same core.
//!
//! ```no_run
//! use siphon_control_client::{ClientConfig, sip::SipClient};
//!
//! # async fn demo() -> Result<(), siphon_control_client::ControlError> {
//! let client = SipClient::connect(
//!     ClientConfig::new("ws://siphon:9090/control/ws", "ivr-app", "s3cr3t"),
//! )
//! .await?;
//!
//! client
//!     .on_call(|call| async move {
//!         call.answer().await?;
//!         call.transfer("sip:agent@pbx").await // REFER, awaits correlated reply
//!     })
//!     .await?; // drives reconnect + resync to completion
//! # Ok(())
//! # }
//! ```
//!
//! # Two connection modes
//!
//! - **Inbound-persistent** ([`ControlClient`] / [`sip::SipClient`]): the app
//!   connects to siphon and keeps one long-lived socket (does `hello`).
//! - **Per-call-connect** ([`ControlServer`] / [`sip::SipServer`]): siphon dials
//!   the app per handed-over call (the app is a WS server; no `hello`).
//!
//! # Errors
//!
//! A `status:"error"` reply becomes [`ControlError::Command`], carrying the
//! stable [`siphon_control_proto::ControlErrorCode`]. Media verbs
//! ([`sip::Call::play_file`] / [`sip::Call::dtmf`]) resolve to
//! [`ControlError::is_unsupported_verb`] until the server implements them.

#![forbid(unsafe_code)]

mod client;
mod error;
mod server;
mod session;
pub mod sip;

pub use client::{ClientConfig, ClientEvent, ControlClient, EventStream};
pub use error::ControlError;
pub use server::{ControlServer, ServerConfig};

// Ergonomic top-level re-exports of the common SIP facade.
pub use sip::{Call, CallEvent, CallStream, SipClient, SipServer};

// Re-export the wire contract so downstreams need only depend on this crate.
pub use siphon_control_proto::{self as proto, ControlErrorCode};
