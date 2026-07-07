//! RTPEngine NG protocol client — media proxy integration.
//!
//! RTPEngine is a media relay that rewrites SDP to anchor RTP/SRTP/DTLS-SRTP
//! streams through itself.  Communication uses the NG (next generation)
//! protocol: bencode-encoded dictionaries over UDP, with a random cookie
//! prefix for request/response correlation.
//!
//! This module is Rust-only (transport is never exposed to Python).
//! Python scripts interact via `from siphon import rtpengine` or
//! `call.media.anchor()`.

pub mod backend;
pub mod bencode;
pub mod client;
pub mod error;
pub mod events;
pub mod profile;
pub mod rtpproxy;
pub mod session;
pub mod siphon_rtp;

pub use backend::MediaBackend;
pub use client::{RtpEngineClient, RtpEngineSet};
pub use error::RtpEngineError;
pub use profile::{NgFlags, ProfileEntry, ProfileRegistry};
pub use rtpproxy::{RtpProxyClient, RtpProxyClientSet};
pub use session::{MediaSession, MediaSessionStore};
pub use siphon_rtp::{SiphonRtpClient, SiphonRtpClientSet};
