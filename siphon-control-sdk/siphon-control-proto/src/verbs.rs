//! Generic, protocol-agnostic names: module routing keys and substrate verbs.
//!
//! These are the tokens the control **substrate** understands regardless of
//! which adapter a command targets. Per-protocol verb/event helpers live in
//! their own submodule (e.g. [`crate::sip`]) so the core envelope stays generic.

/// Adapter routing key for the built-in SIP adapter.
pub const MODULE_SIP: &str = "sip";
/// Adapter routing key for an SMPP adapter (registered by a host binary).
pub const MODULE_SMPP: &str = "smpp";
/// Adapter routing key for an SS7 adapter (registered by a host binary).
pub const MODULE_SS7: &str = "ss7";

/// The mandatory first-frame handshake verb.
pub const HELLO: &str = "hello";
/// Substrate verb: re-enumerate the channels this connection owns.
pub const RESYNC: &str = "resync";
/// Substrate verb: fetch the registered adapters' schema.
pub const DESCRIBE: &str = "describe";
/// Substrate verb: set a per-channel variable.
pub const SET_VAR: &str = "set_var";
/// Substrate verb: read a per-channel variable.
pub const GET_VAR: &str = "get_var";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_tokens_are_stable() {
        assert_eq!(MODULE_SIP, "sip");
        assert_eq!(HELLO, "hello");
        assert_eq!(SET_VAR, "set_var");
    }
}
