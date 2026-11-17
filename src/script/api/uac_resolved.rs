//! Where a request siphon originates as a UAC goes when its next hop was
//! resolved rather than given as a flow, and the transport it leaves over.
//!
//! RFC 3261 §18.1.1: a request within 200 bytes of the path MTU "MUST be sent
//! using an RFC 2914 congestion controlled transport protocol, such as TCP",
//! and falls back to UDP only when the connection attempt fails. With
//! `listen.mtu` set, the relay and the B2BUA apply that to what they forward;
//! [`ResolvedEgress`] applies the same decision (the dispatcher's
//! [`OriginatedOverMtu`](crate::dispatcher::OriginatedOverMtu): one threshold,
//! one probe, one negative cache) to what a script originates:
//! `proxy.send_request`, the NOTIFYs and SUBSCRIBEs of `proxy.subscribe_state`
//! and `presence.notify`.
//!
//! The client transaction the UAC sender opens for a non-INVITE request reads
//! the transport it is sent with: over UDP it retransmits on Timer E, over TCP
//! it does not (§17.1.2.2). So a request moved to TCP here loses Timer E with
//! no further step; the top Via is what has to follow the transport, and does.

use std::borrow::Cow;
use std::net::SocketAddr;

use crate::dispatcher::OriginatedTcp;
use crate::dns::SipResolver;
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_uri_standalone;
use crate::transport::mtu::{over_mtu, upgrade_metrics, OverMtuPath};
use crate::transport::{ConnectionId, Transport};
use crate::uac::{UacResult, UacSender};

/// What a resolved destination came from.
#[derive(Debug, Clone, Copy)]
enum Target<'a> {
    /// A URI the resolver was given: the Request-URI, a `next_hop`, the first
    /// Route. Its host is the one probed for a TCP path (a hostname may name
    /// another address for TCP, RFC 3263 §4.1).
    Uri(&'a str),
    /// The address a dialog's request arrived from, kept as the way back to a
    /// peer with no route set. Such a peer listens for TCP on the address and
    /// port it sends UDP from (RFC 3261 §18.2.1), so that address is probed;
    /// the URI is the dialog's remote target.
    Learned(&'a str),
}

/// A resolved destination and the transport the resolve chose for it.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedEgress<'a> {
    pub(crate) destination: SocketAddr,
    pub(crate) transport: Transport,
    target: Target<'a>,
}

/// A request as it leaves: the message, with the top Via of the transport it
/// goes over, and where to.
pub(crate) struct Routed {
    pub(crate) message: SipMessage,
    pub(crate) destination: SocketAddr,
    pub(crate) transport: Transport,
}

impl<'a> ResolvedEgress<'a> {
    /// To `destination`, which `uri` resolved to.
    pub fn resolved(uri: &'a str, destination: SocketAddr, transport: Transport) -> Self {
        Self {
            destination,
            transport,
            target: Target::Uri(uri),
        }
    }

    /// To `destination`, the address a dialog whose remote target is
    /// `remote_target` was learned from.
    pub(crate) fn learned(
        remote_target: &'a str,
        destination: SocketAddr,
        transport: Transport,
    ) -> Self {
        Self {
            destination,
            transport,
            target: Target::Learned(remote_target),
        }
    }

    /// To `destination`, the next hop of a request inside `dialog`: the
    /// address the subscription was learned from when the dialog has no route
    /// set, else what its first Route, or its remote target, resolved to.
    pub(crate) fn of_dialog(
        dialog: &'a crate::subscribe_state::SubscribeDialog,
        destination: SocketAddr,
        transport: Transport,
    ) -> Self {
        let learned = dialog.route_set.is_empty()
            && dialog.received_address.is_some()
            && dialog.received_transport.is_some();
        if learned {
            Self::learned(&dialog.remote_target, destination, transport)
        } else {
            let next_hop = next_hop_uri(dialog.route_set.first(), &dialog.remote_target);
            Self::resolved(next_hop, destination, transport)
        }
    }

    /// `message` and where it leaves for: over TCP, with a TCP top Via, when
    /// it was built for UDP, is over the `listen.mtu` threshold and a TCP path
    /// to the next hop is up (RFC 3261 §18.1.1); otherwise as it is. With no
    /// reachable TCP path the request goes over UDP, as §18.1.1 asks when the
    /// connection attempt fails, and the next hop is not probed again for a
    /// while.
    ///
    /// A URI that asks for UDP by name (`;transport=udp`) keeps UDP: the
    /// transport was chosen by whoever wrote the URI (RFC 3263 §4.1), not
    /// defaulted to.
    ///
    /// Each request decides by its own size, in a dialog too: §12.2.1.1 makes
    /// the next hop of an in-dialog request a fresh decision.
    pub(crate) async fn route(
        &self,
        uac: &UacSender,
        resolver: &SipResolver,
        mut message: SipMessage,
    ) -> Routed {
        match self.over_tcp(uac, resolver, &message).await {
            Some(tcp) => {
                via_over_tcp(&mut message, uac, self.destination, tcp);
                upgrade_metrics::record(OverMtuPath::of_originated(&message));
                Routed {
                    message,
                    destination: tcp.destination,
                    transport: Transport::Tcp,
                }
            }
            None => Routed {
                message,
                destination: self.destination,
                transport: self.transport,
            },
        }
    }

    /// The TCP path `message` takes instead of UDP, if it is to switch.
    async fn over_tcp(
        &self,
        uac: &UacSender,
        resolver: &SipResolver,
        message: &SipMessage,
    ) -> Option<OriginatedTcp> {
        let decision = uac.originated_over_mtu(resolver)?;
        let serialized_len = self.over_threshold(Some(decision.mtu), message)?;
        let probed = match self.target {
            Target::Uri(uri) => Cow::Borrowed(uri),
            Target::Learned(_) => Cow::Owned(self.destination.to_string()),
        };
        decision
            .upgrade(serialized_len, &probed, self.destination)
            .await
    }

    /// The serialised length of `message` when it is a candidate for TCP: built
    /// for UDP, over the threshold of `mtu` (`listen.mtu`), and not routed by
    /// a URI that names `;transport=udp`. `None` otherwise, which is what every
    /// request costs when it does not switch: nothing without an MTU or on a
    /// stream transport, one serialisation under the threshold.
    pub fn over_threshold(&self, mtu: Option<u16>, message: &SipMessage) -> Option<usize> {
        let mtu = mtu?;
        if self.transport != Transport::Udp {
            return None;
        }
        let serialized_len = message.to_bytes().len();
        if !over_mtu(serialized_len, mtu) {
            return None;
        }
        let (Target::Uri(uri) | Target::Learned(uri)) = self.target;
        if asks_for_udp(uri) {
            tracing::debug!(
                serialized_len,
                mtu,
                destination = %self.destination,
                "transport: over-MTU request stays on UDP, its target URI names transport=udp"
            );
            return None;
        }
        Some(serialized_len)
    }

    /// Send `message` and register its response, as
    /// [`UacSender::send_request_with_response`] does, over the transport
    /// [`route`](Self::route) picks.
    pub(crate) async fn send(
        &self,
        uac: &UacSender,
        resolver: &SipResolver,
        message: SipMessage,
    ) -> tokio::sync::oneshot::Receiver<UacResult> {
        let routed = self.route(uac, resolver, message).await;
        uac.send_request_with_response(routed.message, routed.destination, routed.transport)
    }

    /// Send `message` with no response tracking, as [`UacSender::send_request`]
    /// does, over the transport [`route`](Self::route) picks.
    pub(crate) async fn send_and_forget(
        &self,
        uac: &UacSender,
        resolver: &SipResolver,
        message: SipMessage,
    ) {
        let routed = self.route(uac, resolver, message).await;
        uac.send_request(routed.message, routed.destination, routed.transport);
    }
}

/// The URI a request's next hop is resolved from (RFC 3261 §12.2.1.1,
/// §8.1.2): the first entry of its route set, without its angle brackets,
/// else `target`.
pub(crate) fn next_hop_uri<'a>(first_route: Option<&'a String>, target: &'a str) -> &'a str {
    match first_route {
        Some(route) => route
            .trim()
            .trim_start_matches('<')
            .split('>')
            .next()
            .unwrap_or_default(),
        None => target,
    }
}

/// Whether `uri` carries `;transport=udp`. Parameter names and this value
/// compare case-insensitively (RFC 3261 §19.1.4).
fn asks_for_udp(uri: &str) -> bool {
    parse_uri_standalone(uri).is_ok_and(|uri| {
        uri.params.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transport")
                && value
                    .as_deref()
                    .is_some_and(|transport| transport.eq_ignore_ascii_case("udp"))
        })
    })
}

/// Make the top Via of `message` a TCP one (RFC 3261 §18.1.1: the transport in
/// the top Via is the one the request is sent over). The branch stays, so the
/// response still finds its pending entry.
///
/// The sent-by follows to this node's TCP listener when it has one and the Via
/// names the UDP identity siphon put there for `udp_destination`: a response
/// comes back on the connection the request went over, and only when that is
/// gone does the peer connect to the sent-by (§18.2.2). A Via a script wrote
/// and a request over a UE's security association keep their sent-by.
fn via_over_tcp(
    message: &mut SipMessage,
    uac: &UacSender,
    udp_destination: SocketAddr,
    tcp: OriginatedTcp,
) {
    let Some(via) = message.headers.get("Via") else {
        return;
    };
    let mut via = crate::registrant::tcp_via(via);
    if !tcp.protected && uac.listens_on(Transport::Tcp) {
        let sent_by = |transport, destination| {
            let (host, port) =
                uac.sent_by_for(transport, Some(destination), ConnectionId::default());
            format!("{host}:{port}")
        };
        via = with_sent_by(
            &via,
            &sent_by(Transport::Udp, udp_destination),
            &sent_by(Transport::Tcp, tcp.destination),
        );
    }
    message.headers.set("Via", via);
}

/// `via` with its sent-by `from` replaced by `to`; unchanged when its sent-by
/// is anything else.
fn with_sent_by(via: &str, from: &str, to: &str) -> String {
    let Some((protocol, rest)) = via.split_once(char::is_whitespace) else {
        return via.to_string();
    };
    let rest = rest.trim_start();
    let (sent_by, parameters) = match rest.find(';') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if sent_by.trim_end() != from {
        return via.to_string();
    }
    format!("{protocol} {to}{parameters}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_udp_transport_parameter_asks_for_udp() {
        assert!(asks_for_udp("sip:as.example.com;transport=udp"));
        assert!(asks_for_udp("sip:as.example.com:5060;lr;transport=UDP"));
        assert!(asks_for_udp("sip:as.example.com;Transport=udp"));
        assert!(!asks_for_udp("sip:as.example.com"));
        assert!(!asks_for_udp("sip:as.example.com;transport=tcp"));
        assert!(!asks_for_udp("192.0.2.10:5060"));
    }

    #[test]
    fn the_sent_by_is_replaced_only_when_it_is_the_one_named() {
        assert_eq!(
            with_sent_by(
                "SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK-uac-1;rport",
                "192.0.2.1:5060",
                "192.0.2.1:5070",
            ),
            "SIP/2.0/TCP 192.0.2.1:5070;branch=z9hG4bK-uac-1;rport"
        );
        assert_eq!(
            with_sent_by(
                "SIP/2.0/TCP edge.example.com:5080;branch=z9hG4bK-uac-2",
                "192.0.2.1:5060",
                "192.0.2.1:5070",
            ),
            "SIP/2.0/TCP edge.example.com:5080;branch=z9hG4bK-uac-2",
            "a Via the script wrote keeps its sent-by"
        );
        assert_eq!(
            with_sent_by("SIP/2.0/TCP 192.0.2.1:5060", "192.0.2.1:5060", "h:1"),
            "SIP/2.0/TCP h:1"
        );
    }
}
