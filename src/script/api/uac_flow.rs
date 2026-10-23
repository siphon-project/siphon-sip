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
        })
    }

    /// Send `message` over the flow and register its response, as
    /// [`UacSender::send_request_with_response`] does for a resolved one.
    pub(crate) fn send(
        &self,
        uac: &UacSender,
        message: crate::sip::message::SipMessage,
    ) -> tokio::sync::oneshot::Receiver<crate::uac::UacResult> {
        uac.send_request_with_response_on(
            message,
            self.destination,
            self.transport,
            self.connection_id,
            Some(self.local),
        )
    }

    /// Send `message` over the flow with no response tracking, as
    /// [`UacSender::send_request`] does for a resolved one.
    pub(crate) fn send_and_forget(
        &self,
        uac: &UacSender,
        message: crate::sip::message::SipMessage,
    ) {
        uac.send_request_from(
            message,
            self.destination,
            self.transport,
            self.connection_id,
            Some(self.local),
        );
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
