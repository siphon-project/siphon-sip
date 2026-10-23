//! Which way a captured flow faces.

/// Which way a [`PyFlow`](super::registrar::PyFlow) faces, which decides what a route set dialled with
/// it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    /// A flow a peer opened toward siphon: the one a REGISTER or a request
    /// arrived on. Its far end is the callee, so a Path route set replaces it
    /// (RFC 3327 §5.3): the edge proxy asked for terminating requests to come
    /// back through it.
    Inbound,
    /// siphon's own flow to its first hop, as a UA: the registrant's IPsec SA
    /// to the P-CSCF (`registration.flow()`). Its far end is the first hop of
    /// the UA's route set, so the route set rides it as Route headers (RFC 5626
    /// §4.3, TS 24.229 §5.1.2A.1.1) instead of replacing it.
    Outbound,
}
