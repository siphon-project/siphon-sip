//! Which way a captured flow faces.

use super::registrar::PyFlow;

/// Which way a [`PyFlow`] faces, which decides what a route set sent with it
/// means.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    Outbound(RegistrantFlow),
}

/// What an outbound flow knows about the registration it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistrantFlow {
    /// The AoR of the registration whose security association this is. A
    /// dialog made over the flow looks the association up again by it for
    /// each request, since a re-registration replaces the association.
    pub aor: String,
    /// The Via sent-by of a request over the flow: the UE's protected server
    /// port, where the P-CSCF sends the responses (TS 33.203 clause 7.1).
    pub sent_by: std::net::SocketAddr,
}

impl FlowKind {
    /// The registration behind an outbound flow; `None` for an inbound one.
    pub fn registrant(&self) -> Option<&RegistrantFlow> {
        match self {
            FlowKind::Inbound => None,
            FlowKind::Outbound(registrant) => Some(registrant),
        }
    }
}

impl PyFlow {
    /// The TCP path a request of `serialized_len` bytes takes over this flow
    /// instead of UDP: only for siphon's own UDP flow to its first hop as a UE
    /// (the registrant's SA, `registration.flow()`), from the UE's protected
    /// client port to the P-CSCF's protected server port, once it is over the
    /// MTU (RFC 3261 clause 18.1.1, [`OverMtuTcp::decide`]). Every other flow
    /// keeps its transport: a callee's flow (the proxy and registrar side), a
    /// stream flow, a WebSocket flow.
    ///
    /// `None` is one comparison when the flow is not a registrant's, and the
    /// size is read only for a UE flow with an MTU set.
    pub fn over_mtu_tcp(
        &self,
        mtu: Option<u16>,
        serialized_len: impl FnOnce() -> usize,
    ) -> Option<crate::registrant::OverMtuTcp> {
        self.kind.registrant()?;
        if self.transport != "udp" {
            return None;
        }
        crate::registrant::OverMtuTcp::decide(
            self.local_addr,
            self.source_addr,
            crate::transport::Transport::Udp,
            mtu,
            serialized_len,
        )
    }
}

/// The flow a request goes over, once its route set has had its say.
///
/// A callee's flow yields to a route set, which for it is a Path (RFC 3327
/// §5.3); with no route set it is the way back to the callee (RFC 5626 §5.3).
/// siphon's own flow to its first hop is kept whatever the route set: the route
/// set is the UA's own and rides the flow. One rule for every request siphon
/// sends with a `flow=`, dialled or originated.
pub fn flow_under_route_set(flow: Option<&PyFlow>, route_set_is_empty: bool) -> Option<&PyFlow> {
    flow.filter(|flow| flow.kind.registrant().is_some() || route_set_is_empty)
}

/// The flow over `aor`'s established SA set, from `ue_ip`: what
/// `registration.flow()` returns, and what a dialog made over such a flow
/// sends each later request over. `None` until a set is established.
pub fn registrant_flow(
    manager: &crate::registrant::RegistrantManager,
    aor: &str,
    ue_ip: std::net::IpAddr,
) -> Option<PyFlow> {
    let egress = manager.ue_egress(aor, ue_ip)?;
    Some(PyFlow {
        transport: egress.transport.as_scheme().to_string(),
        // A request over the flow goes to source_addr, from local_addr.
        source_addr: egress.destination,
        local_addr: egress.local,
        // Selected by source_local_addr, not a connection id: the UDP socket
        // there, or over TCP the pool's connection from it.
        connection_id: 0,
        kind: FlowKind::Outbound(RegistrantFlow {
            aor: aor.to_string(),
            sent_by: egress.sent_by,
        }),
    })
}
