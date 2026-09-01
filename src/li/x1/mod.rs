//! ETSI TS 103 221-1 X1 — the lawful-interception provisioning interface.
//!
//! X1 is how an Administration Function (ADMF) provisions warrants on a
//! network element: it creates delivery destinations, activates tasks against
//! target identifiers, queries what is provisioned, and is told when something
//! goes wrong. siphon implements the network-element side of the interface,
//! and the network-element-to-ADMF direction as a client.
//!
//! # Shape of the interface
//!
//! One HTTPS endpoint (conventionally `/X1/NE`), mutual TLS, `application/xml`.
//! A request is an `X1Request` container of one or more messages, each
//! discriminated by `xsi:type`; the answer is an `X1Response` container with
//! one message per request message, correlated by `x1TransactionId`. There are
//! no REST resources and no HTTP-status error bodies: a failure is an
//! `ErrorResponse` message carrying a clause 6.7 error code.
//!
//! # Module layout
//!
//! * [`compat`] — narrow rewrites for peers that emit non-conformant XML.
//! * [`error`] — the clause 6.7 code table and the error type.
//! * [`types`] — the data dictionary as types that cannot hold invalid values.
//! * [`message`] — the message set.
//! * [`schema`] — validation against the published XSDs, both directions.
//! * [`codec`] — XML encoding and decoding, including `xsi:type` dispatch.
//! * [`store`] — the task and destination stores.
//! * [`server`] — the mutual-TLS listener and message dispatch.
//! * [`client`] — the network-element-to-ADMF direction.

pub mod client;
pub mod compat;
pub mod codec;
pub mod error;
pub mod message;
pub mod schema;
pub mod server;
pub mod store;
pub mod types;

pub use error::{ErrorCode, X1Error};
pub use message::{
    DestinationDetails, Envelope, MessageKind, RequestBody, RequestMessage, ResponseBody,
    ResponseMessage, TaskDetails,
};
pub use schema::X1Schema;
pub use store::{ContentCapability, DestinationStore, TaskStore};
pub use types::{DId, DeliveryType, TargetIdentifier, XId};
