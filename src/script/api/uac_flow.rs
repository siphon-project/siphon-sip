//! Where a request siphon originates as a UAC goes when the script names a
//! flow: `proxy.send_request(flow=)` and `proxy.subscribe_state.send(flow=)`.

use std::net::SocketAddr;

use crate::transport::{ConnectionId, Transport};
use crate::uac::UacSender;

use super::registrar::PyFlow;

/// The addresses of a request sent over a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowEgress {
    /// The flow's far end.
    pub(crate) destination: SocketAddr,
    /// The flow's transport.
    pub(crate) transport: Transport,
    /// The connection the flow is, for a stream transport.
    pub(crate) connection_id: ConnectionId,
    /// The socket the request leaves from.
    pub(crate) local: SocketAddr,
    /// The Via sent-by, `host:port`.
    pub(crate) sent_by: String,
    /// The flow, kept only when it is a registrant UE's: the only kind a
    /// request over the MTU leaves over TCP ([`PyFlow::over_mtu_tcp`]).
    ue_flow: Option<PyFlow>,
}

impl FlowEgress {
    /// The egress over `flow`.
    ///
    /// A registrant flow names the UE's protected server port in the Via, where
    /// the P-CSCF sends the responses (TS 33.203 clause 7.1), as the protected
    /// REGISTER does. Any other flow names the listener it is anchored on.
    pub(crate) fn of(flow: &PyFlow, uac: &UacSender) -> pyo3::PyResult<Self> {
        let transport = Transport::from_scheme(&flow.transport).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "flow transport '{}' is not one a request can be sent over",
                flow.transport
            ))
        })?;
        let sent_by = match flow.kind.registrant() {
            Some(registrant) => registrant.sent_by.to_string(),
            None => {
                let (host, port) = uac.listener_sent_by(transport, flow.local_addr);
                format_host_port(&host, port)
            }
        };
        Ok(Self {
            destination: flow.source_addr,
            transport,
            connection_id: ConnectionId(flow.connection_id),
            local: flow.local_addr,
            sent_by,
            ue_flow: flow.kind.registrant().is_some().then(|| flow.clone()),
        })
    }

    /// `message` and the transport it leaves over: a request over a UE's UDP SA
    /// flow that is over `listen.mtu` goes over TCP from the UE's protected
    /// client port to the P-CSCF's protected server port once the connection is
    /// up, with a TCP top Via (RFC 3261 clause 18.1.1, [`OverMtuTcp`]); when it
    /// cannot be opened the request goes over UDP as it would have, with a
    /// warning. Every other flow, and any send without an MTU, is returned
    /// as it is: one branch.
    ///
    /// Each request decides by its own size, in dialog too: clause 18.1.1 is a
    /// rule about a request and the path MTU, and clause 12.2.1.1 makes the next
    /// hop of an in-dialog request a fresh decision that does not bind the
    /// dialog to the transport of an earlier request. The response to a request
    /// sent this way comes back over the same connection (clause 18.2.2), which
    /// the UE's stream machinery reads like the P-CSCF's own requests.
    async fn route(
        &self,
        uac: &UacSender,
        mut message: crate::sip::message::SipMessage,
    ) -> (crate::sip::message::SipMessage, Transport, ConnectionId) {
        if let (Some(flow), Some((pool, mtu))) = (&self.ue_flow, uac.over_mtu()) {
            let path = flow.over_mtu_tcp(Some(mtu), || message.to_bytes().len());
            if let Some(path) = path {
                if path.connect(pool, request_label(&message)).await {
                    path.apply(&mut message);
                    return (message, Transport::Tcp, ConnectionId::default());
                }
            }
        }
        (message, self.transport, self.connection_id)
    }

    /// Send `message` over the flow and register its response, as
    /// [`UacSender::send_request_with_response`] does for a resolved one.
    pub(crate) async fn send(
        &self,
        uac: &UacSender,
        message: crate::sip::message::SipMessage,
    ) -> tokio::sync::oneshot::Receiver<crate::uac::UacResult> {
        let (message, transport, connection_id) = self.route(uac, message).await;
        uac.send_request_with_response_on(
            message,
            self.destination,
            transport,
            connection_id,
            Some(self.local),
        )
    }

    /// Send `message` over the flow with no response tracking, as
    /// [`UacSender::send_request`] does for a resolved one.
    pub(crate) async fn send_and_forget(
        &self,
        uac: &UacSender,
        message: crate::sip::message::SipMessage,
    ) {
        let (message, transport, connection_id) = self.route(uac, message).await;
        uac.send_request_from(
            message,
            self.destination,
            transport,
            connection_id,
            Some(self.local),
        );
    }
}

/// The method of `message`, to name it in the log.
fn request_label(message: &crate::sip::message::SipMessage) -> &str {
    match &message.start_line {
        crate::sip::message::StartLine::Request(line) => line.method.as_str(),
        crate::sip::message::StartLine::Response(_) => "",
    }
}

/// `host:port`, bracketing an IPv6 literal (RFC 3261 §25.1 `hostport`).
fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A script's `route=` for a request it originates: one `name-addr` per entry
/// (RFC 3261 §20.34), refused when `conflicting` names another argument that
/// already says where the request is routed (a Route in `headers`), which
/// would leave the route set ambiguous.
pub(crate) fn route_set_argument(
    route: &[String],
    conflicting: Option<&str>,
    api: &str,
) -> pyo3::PyResult<Vec<String>> {
    let route = super::route_entries::route_set_from(route)?;
    if let (false, Some(other)) = (route.is_empty(), conflicting) {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{api}: pass the route set as route= or as {other}, not both"
        )));
    }
    Ok(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv6_host_is_bracketed_once() {
        assert_eq!(format_host_port("2001:db8::1", 5060), "[2001:db8::1]:5060");
        assert_eq!(
            format_host_port("[2001:db8::1]", 5060),
            "[2001:db8::1]:5060"
        );
        assert_eq!(format_host_port("192.0.2.1", 5060), "192.0.2.1:5060");
    }

    #[test]
    fn a_route_set_in_both_places_is_refused() {
        let route = vec!["sip:pcscf.example.net:5066;lr".to_string()];
        assert_eq!(
            route_set_argument(&route, None, "proxy.send_request").unwrap(),
            vec!["<sip:pcscf.example.net:5066;lr>".to_string()]
        );
        assert!(
            route_set_argument(&route, Some("a Route in headers="), "proxy.send_request").is_err()
        );
        assert!(
            route_set_argument(&[], Some("a Route in headers="), "proxy.send_request")
                .unwrap()
                .is_empty()
        );
    }
}
