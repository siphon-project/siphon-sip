//! SIP protocol implementation — parser, message types, URI, headers, builder.

pub mod builder;
pub mod codec;
pub mod headers;
pub mod message;
pub mod parser;
pub mod privacy;
pub mod uri;
pub mod validate;

pub use builder::SipMessageBuilder;
pub use headers::SipHeaders;
pub use message::*;
pub use parser::parse_sip_message;
pub use uri::SipUri;

/// SIP methods siphon implements, formatted for an `Allow` header (RFC 3261
/// §20.5). Advertised verbatim on siphon's own UA surfaces — OPTIONS responses,
/// OPTIONS keepalives, and B2BUA responses — so peers can discover the supported
/// method set. Microsoft Teams Direct Routing, for one, selects its call-transfer
/// method from the SBC's advertised `Allow`: without `REFER`/`NOTIFY` here it
/// never hands siphon a REFER, even though transfer is implemented. Keep this in
/// sync with the methods the dispatcher/transaction layer actually handles.
pub const SUPPORTED_METHODS: &str =
    "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, SUBSCRIBE, NOTIFY, REFER, MESSAGE, PUBLISH";
