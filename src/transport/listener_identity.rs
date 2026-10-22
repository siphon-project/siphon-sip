//! Which listener a message leaves from, and what that listener tells peers.
//!
//! A listener's `advertise` is its own identity (RFC 3261 §18.2.1 sent-by,
//! §12.1.1 Contact, §16.6 step 4 Record-Route). It is not the identity of every
//! socket of the same transport: a TLS listener facing phones and a second one
//! facing a trunk that requires an FQDN are two identities, and a message that
//! leaves on one of them has to name that one, or the peer's next request (a
//! phone reconnecting to its Contact, an in-dialog request following the
//! Record-Route) reaches the other listener.
//!
//! [`ListenerRegistry::identity`] answers "what does this listener advertise",
//! and [`StreamConnections`] remembers which listener each accepted connection
//! arrived on, so a request sent over that connection can be stamped with it.

use super::{ConnectionId, ListenerRegistry, StreamConnections, Transport};
use crate::sip::uri::{format_sip_host, strip_ipv6_brackets};
use std::net::{IpAddr, SocketAddr};

impl ListenerRegistry {
    /// The sent-by `(host, port)` the listener bound at exactly
    /// `(transport, listener)` advertises, the host already formatted for a SIP
    /// header (a v6 literal bracketed). `None` when no such listener is
    /// configured, so the caller keeps its own fallback.
    ///
    /// The host, most specific first:
    ///
    /// 1. the listener's own `advertise`;
    /// 2. the global `advertised_address`, when it is an FQDN or an address of
    ///    the listener's family;
    /// 3. the bound IP, when concrete;
    /// 4. a wildcard bind: the host's routable IP of that family, else loopback.
    ///    Never the unspecified address itself: no peer can answer to
    ///    `0.0.0.0`, and no self-identity recognises it, so an in-dialog request
    ///    following it would come back to siphon as `482 Loop Detected`.
    ///
    /// Deliberately absent: another listener's `advertise`. A listener without
    /// one of its own does not borrow a sibling's, which is how a phone-facing
    /// listener used to hand phones the FQDN of a trunk-facing one.
    ///
    /// The port is the `advertise` port when it names one (a front translating
    /// the port), else the bound port.
    ///
    /// `local` is the local address a message used: a listener's bind address,
    /// or the concrete address a stream connection was accepted on, which for a
    /// wildcard listener (`0.0.0.0:5061`) is the interface address the peer
    /// reached (`192.0.2.10:5061`). The latter is matched to the wildcard
    /// listener of the same family and port, and step 3 names that interface
    /// address, the one the peer demonstrably reached.
    pub fn identity(&self, transport: Transport, local: SocketAddr) -> Option<(String, u16)> {
        // A per-UE socket opened at run time names itself: it is one UE's
        // address, and the global `advertised_address` is the process's, so a
        // Contact or Via built from that would send the UE's traffic elsewhere.
        if self.is_dynamic(transport, local) {
            return Some((format_sip_host(&local.ip().to_string()), local.port()));
        }
        let advertise = self.listener_advertise(transport, local)?;
        let port = advertise
            .and_then(|advertise| advertise.port)
            .unwrap_or(local.port());
        let host = match advertise {
            Some(advertise) => format_sip_host(&advertise.host),
            None => self.unadvertised_host(local),
        };
        Some((host, port))
    }

    /// The port half of [`identity`](Self::identity), without building the
    /// host: the `advertise` port when it names one, else `local`'s own port.
    /// `None` when `local` belongs to no listener.
    pub fn identity_port(&self, transport: Transport, local: SocketAddr) -> Option<u16> {
        if self.is_dynamic(transport, local) {
            return Some(local.port());
        }
        let advertise = self.listener_advertise(transport, local)?;
        Some(
            advertise
                .and_then(|advertise| advertise.port)
                .unwrap_or(local.port()),
        )
    }

    /// The `advertise` of the listener `local` belongs to: the one bound at
    /// exactly `local`, else the wildcard listener of its family and port.
    /// The outer `None` means `local` belongs to no listener.
    fn listener_advertise(
        &self,
        transport: Transport,
        local: SocketAddr,
    ) -> Option<Option<&crate::transport::AdvertisedAddress>> {
        if let Some(advertise) = self.entries.get(&(transport, local)) {
            return Some(advertise.as_ref());
        }
        if local.ip().is_unspecified() {
            return None;
        }
        let wildcard = if local.is_ipv6() {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };
        self.entries
            .get(&(transport, SocketAddr::new(wildcard, local.port())))
            .map(Option::as_ref)
    }

    /// Steps 2 to 4 of [`identity`](Self::identity): the host of a listener
    /// that has no `advertise`.
    fn unadvertised_host(&self, listener: SocketAddr) -> String {
        let ipv6 = listener.is_ipv6();
        if let Some(global) = self.global_advertised.as_deref() {
            let family_ok = match strip_ipv6_brackets(global).parse::<IpAddr>() {
                Ok(ip) => ip.is_ipv6() == ipv6,
                // An FQDN resolves to whichever family the peer needs.
                Err(_) => true,
            };
            if family_ok {
                return format_sip_host(global);
            }
        }
        if !listener.ip().is_unspecified() {
            return format_sip_host(&listener.ip().to_string());
        }
        let ip = cached_routable_local_ip(ipv6).unwrap_or(if ipv6 {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });
        format_sip_host(&ip.to_string())
    }
}

/// Process-lifetime cache of [`super::detect_routable_local_ip`] per family.
///
/// Only a wildcard bind with no `advertise` and no usable `advertised_address`
/// reaches the probe, but that path can be per message, and the probe does a
/// socket create + `connect` + `getsockname`. The routable local IP does not
/// change at runtime, so it is memoised.
pub fn cached_routable_local_ip(ipv6: bool) -> Option<IpAddr> {
    static V4: std::sync::OnceLock<Option<IpAddr>> = std::sync::OnceLock::new();
    static V6: std::sync::OnceLock<Option<IpAddr>> = std::sync::OnceLock::new();
    let cache = if ipv6 { &V6 } else { &V4 };
    *cache.get_or_init(|| super::detect_routable_local_ip(ipv6))
}

impl StreamConnections {
    /// [`register`](Self::register) a connection a listener accepted, and
    /// remember that listener, so a request siphon later sends over the
    /// connection advertises the listener the peer reached (see
    /// [`listener_of`](Self::listener_of)).
    pub fn register_on_listener(
        &self,
        peer: SocketAddr,
        transport: Transport,
        connection_id: ConnectionId,
        listener: SocketAddr,
    ) {
        self.listeners.insert(connection_id, listener);
        self.register(peer, transport, connection_id);
    }

    /// The listener connection `connection_id` belongs to: the one that
    /// accepted it, or the one an outbound connection was opened for (a
    /// `send_socket=` pin). `None` for a connection with no listener recorded,
    /// such as an outbound connection from the default source.
    pub fn listener_of(&self, connection_id: ConnectionId) -> Option<SocketAddr> {
        self.listeners
            .get(&connection_id)
            .map(|listener| *listener.value())
    }

    /// The listener of the connection [`reuse`](Self::reuse) would pick to
    /// reach `destination` on `transport`, so the headers of a request can name
    /// the listener the request is about to leave on.
    pub fn reuse_listener(
        &self,
        destination: SocketAddr,
        transport: Transport,
    ) -> Option<SocketAddr> {
        self.reuse(destination, transport)
            .and_then(|connection_id| self.listener_of(connection_id))
    }

    /// Number of connections with a recorded listener: one per live entry, so
    /// it drains to zero when every connection has closed.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::AdvertisedAddress;

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("a literal address")
    }

    /// One phone-facing TLS listener with no advertise and one trunk-facing
    /// TLS listener advertising an FQDN and port.
    fn phone_and_trunk() -> ListenerRegistry {
        ListenerRegistry::from_entries(vec![
            (Transport::Tls, addr("192.0.2.10:5061"), None),
            (
                Transport::Tls,
                addr("192.0.2.10:15068"),
                Some(AdvertisedAddress::parse("sbc.example.test:5068").expect("valid")),
            ),
        ])
    }

    #[test]
    fn a_listener_advertises_its_own_advertise() {
        assert_eq!(
            phone_and_trunk().identity(Transport::Tls, addr("192.0.2.10:15068")),
            Some(("sbc.example.test".to_string(), 5068))
        );
    }

    #[test]
    fn a_listener_without_advertise_never_borrows_a_siblings() {
        assert_eq!(
            phone_and_trunk().identity(Transport::Tls, addr("192.0.2.10:5061")),
            Some(("192.0.2.10".to_string(), 5061)),
            "the phone listener must not hand out the trunk listener's FQDN"
        );
    }

    #[test]
    fn a_listener_without_advertise_takes_the_global_advertised_address() {
        let registry = phone_and_trunk().with_global_advertised(Some("203.0.113.5"));
        assert_eq!(
            registry.identity(Transport::Tls, addr("192.0.2.10:5061")),
            Some(("203.0.113.5".to_string(), 5061))
        );
        // The listener's own advertise still outranks it.
        assert_eq!(
            registry.identity(Transport::Tls, addr("192.0.2.10:15068")),
            Some(("sbc.example.test".to_string(), 5068))
        );
    }

    #[test]
    fn the_global_advertised_address_of_the_other_family_is_skipped() {
        let registry = ListenerRegistry::from_entries(vec![(
            Transport::Udp,
            addr("[2001:db8::10]:5060"),
            None,
        )])
        .with_global_advertised(Some("203.0.113.5"));
        assert_eq!(
            registry.identity(Transport::Udp, addr("[2001:db8::10]:5060")),
            Some(("[2001:db8::10]".to_string(), 5060))
        );
        let fqdn = ListenerRegistry::from_entries(vec![(
            Transport::Udp,
            addr("[2001:db8::10]:5060"),
            None,
        )])
        .with_global_advertised(Some("sip.example.test"));
        assert_eq!(
            fqdn.identity(Transport::Udp, addr("[2001:db8::10]:5060")),
            Some(("sip.example.test".to_string(), 5060))
        );
    }

    #[test]
    fn a_wildcard_listener_never_advertises_the_unspecified_address() {
        let registry = ListenerRegistry::from_entries(vec![
            (Transport::Tls, addr("0.0.0.0:5061"), None),
            (
                Transport::Tls,
                addr("0.0.0.0:5068"),
                Some(AdvertisedAddress::host_only("sbc.example.test")),
            ),
        ]);
        let (host, port) = registry
            .identity(Transport::Tls, addr("0.0.0.0:5061"))
            .expect("a configured listener");
        assert_ne!(host, "0.0.0.0", "an unspecified sent-by is a 482 loop");
        assert_ne!(host, "sbc.example.test", "nor the sibling's FQDN");
        assert!(
            host.parse::<IpAddr>().is_ok(),
            "a routable IP or loopback: {host}"
        );
        assert_eq!(port, 5061);
    }

    #[test]
    fn a_connection_accepted_on_a_wildcard_listener_takes_that_listeners_identity() {
        let registry = ListenerRegistry::from_entries(vec![
            (Transport::Tls, addr("0.0.0.0:5061"), None),
            (
                Transport::Tls,
                addr("0.0.0.0:15068"),
                Some(AdvertisedAddress::parse("sbc.example.test:5068").expect("valid")),
            ),
        ]);
        // A stream connection reports the interface address it was accepted on.
        assert_eq!(
            registry.identity(Transport::Tls, addr("192.0.2.10:15068")),
            Some(("sbc.example.test".to_string(), 5068))
        );
        assert_eq!(
            registry.identity(Transport::Tls, addr("192.0.2.10:5061")),
            Some(("192.0.2.10".to_string(), 5061)),
            "the interface the phone reached, never the sibling's FQDN"
        );
        assert_eq!(
            registry.identity(Transport::Tls, addr("192.0.2.10:5099")),
            None,
            "a port no listener binds"
        );
    }

    #[test]
    fn an_address_that_is_no_listener_has_no_identity() {
        assert_eq!(
            phone_and_trunk().identity(Transport::Tls, addr("192.0.2.10:40000")),
            None
        );
        assert_eq!(
            phone_and_trunk().identity(Transport::Tcp, addr("192.0.2.10:5061")),
            None,
            "a listener is keyed by its transport too"
        );
    }

    #[test]
    fn only_a_transport_with_two_listeners_is_shared() {
        let registry = ListenerRegistry::from_entries(vec![
            (Transport::Tls, addr("192.0.2.10:5061"), None),
            (Transport::Tls, addr("192.0.2.10:5068"), None),
            (Transport::Udp, addr("192.0.2.10:5060"), None),
        ]);
        assert!(registry.is_shared(Transport::Tls));
        assert!(!registry.is_shared(Transport::Udp));
        assert!(!registry.is_shared(Transport::Tcp));
    }

    #[test]
    fn an_accepted_connection_remembers_its_listener() {
        let connections = StreamConnections::new();
        let phone = addr("198.51.100.20:40000");
        connections.register_on_listener(
            phone,
            Transport::Tls,
            ConnectionId(41),
            addr("192.0.2.10:5061"),
        );
        assert_eq!(
            connections.listener_of(ConnectionId(41)),
            Some(addr("192.0.2.10:5061"))
        );
        // Exact peer and the IP-only reuse a NAT'd Contact port relies on.
        assert_eq!(
            connections.reuse_listener(phone, Transport::Tls),
            Some(addr("192.0.2.10:5061"))
        );
        assert_eq!(
            connections.reuse_listener(addr("198.51.100.20:5061"), Transport::Tls),
            Some(addr("192.0.2.10:5061"))
        );
        // A connection registered without a listener (an outbound pool
        // connection from the default source) reports none.
        connections.register(addr("198.51.100.30:5061"), Transport::Tls, ConnectionId(42));
        assert_eq!(
            connections.reuse_listener(addr("198.51.100.30:5061"), Transport::Tls),
            None
        );
    }

    /// The per-connection listener record is a store keyed by a live entity, so
    /// it must drain back to empty once every connection has closed.
    #[test]
    fn the_listener_record_drains_when_connections_close() {
        let connections = StreamConnections::new();
        let listener = addr("192.0.2.10:5061");
        for index in 0..2_000u64 {
            let peer = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, (index % 200) as u8)),
                40_000 + (index % 20_000) as u16,
            );
            connections.register_on_listener(peer, Transport::Tls, ConnectionId(index), listener);
            connections.unregister(&peer, Transport::Tls, ConnectionId(index));
        }
        assert_eq!(connections.listener_count(), 0);
        assert!(connections.is_empty());
    }

    /// A connection whose peer registration was taken over by a newer one still
    /// leaves the listener record when it closes: the record is per connection.
    #[test]
    fn a_superseded_connection_still_releases_its_listener_record() {
        let connections = StreamConnections::new();
        let peer = addr("198.51.100.20:40000");
        let listener = addr("192.0.2.10:5061");
        connections.register_on_listener(peer, Transport::Tls, ConnectionId(1), listener);
        connections.register_on_listener(peer, Transport::Tls, ConnectionId(2), listener);
        connections.unregister(&peer, Transport::Tls, ConnectionId(1));
        assert_eq!(connections.listener_of(ConnectionId(1)), None);
        assert_eq!(connections.listener_of(ConnectionId(2)), Some(listener));
        connections.unregister(&peer, Transport::Tls, ConnectionId(2));
        assert_eq!(connections.listener_count(), 0);
    }
}
