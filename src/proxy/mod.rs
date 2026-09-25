//! Stateful SIP proxy — RFC 3261 §16.
//!
//! The proxy module owns the request lifecycle from the moment a Python script
//! calls `request.fork()` or `request.relay()` until a final response is sent
//! upstream.  Forking, response aggregation, and CANCEL propagation are handled
//! entirely in Rust; the Python script only provides the target list and
//! strategy.

pub mod core;
pub mod fork;
pub mod session;
