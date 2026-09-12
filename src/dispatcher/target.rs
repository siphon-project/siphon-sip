//! Resolving a request URI to somewhere to send it, and sending it.
//!
//! Candidate resolution (RFC 3263), the MTU-driven UDP-to-TCP upgrade, and
//! `send_to_target`, which every relay and fork branch goes through.

use super::*;

/// Resolve a SIP URI string to a socket address using DNS (RFC 3263).
///
/// Supports numeric IPs, bare `ip:port` strings, and full SIP URIs with
/// DNS A/AAAA/SRV resolution.  Called from synchronous context using
/// `block_in_place` because the callers (relay, fork, B2BUA) are sync
/// functions running on the tokio multi-threaded runtime.
/// Resolved relay target: address + optional transport override.
pub(super) struct RelayTarget {
    pub(super) address: SocketAddr,
    /// Transport from URI params or SRV; `None` means use the inbound transport.
    pub(super) transport: Option<Transport>,
    /// Hostname from the resolved SIP URI, used as TLS SNI / certificate
    /// hostname when a new outbound TLS connection must be opened. `None` for
    /// bare-IP targets (RFC 6066 sends no SNI for an IP literal) and for
    /// in-dialog / failover paths that route by address.
    pub(super) server_name: Option<String>,
}

/// Resolve a SIP target URI to its full ordered candidate set (RFC 3263).
///
/// A bare `IP:port` short-circuits to a single candidate. A SIP URI is resolved
/// via DNS (SRV → A/AAAA); the order is the resolver's RFC 3263 §4.2 /
/// RFC 2782 selection (A/AAAA Fisher-Yates shuffled per call, SRV
/// weighted-random), so a caller that wants a single target takes
/// `.into_iter().next()` — see [`resolve_target`]. In-dialog connection reuse
/// ([`resolve_in_dialog_flow_uri`]) needs the *whole* set to test whether the
/// dialog's established peer is still among the next hop's members.
pub(super) fn resolve_candidates(uri_string: &str, resolver: &SipResolver) -> Vec<RelayTarget> {
    // Inject the process-wide gateway manager (the same one `from_gateway`
    // reads) so a next hop that is a configured gateway FQDN can reuse the
    // prober's already-resolved address instead of a per-call DNS lookup.
    resolve_candidates_inner(
        uri_string,
        resolver,
        crate::script::api::gateway_manager().map(|manager| &**manager),
    )
}

/// Map a SIP `transport=` token (or SRV proto hint) to the internal
/// [`Transport`]. Case-insensitive; `None` for an unrecognised token.
pub(super) fn transport_from_token(token: &str) -> Option<Transport> {
    match token.to_lowercase().as_str() {
        "tcp" => Some(Transport::Tcp),
        "tls" => Some(Transport::Tls),
        "udp" => Some(Transport::Udp),
        "ws" => Some(Transport::WebSocket),
        "wss" => Some(Transport::WebSocketSecure),
        _ => None,
    }
}

/// Core of [`resolve_candidates`] with the gateway address cache injected, so it
/// is unit-testable without the process-wide gateway singleton.
///
/// Before falling back to a blocking DNS resolve, this checks whether the next
/// hop is a configured gateway hostname destination whose address the health
/// prober has already resolved (and `set_address`'d every probe cycle). A hit
/// returns that cached, health-checked address with **zero** DNS on the hot
/// path — the fix for a per-call ~1s stall routing to an FQDN trunk / Teams
/// Direct Routing SBC on a low-traffic node where the resolver's own cache has
/// gone cold between calls. The hostname is preserved as `server_name` so TLS
/// SNI is unchanged, and the R-URI (built elsewhere from the same URI) is
/// untouched.
pub(super) fn resolve_candidates_inner(
    uri_string: &str,
    resolver: &SipResolver,
    gateway: Option<&crate::gateway::DispatcherManager>,
) -> Vec<RelayTarget> {
    // Try as bare IP:port first (cheapest check)
    if let Ok(addr) = uri_string.parse::<SocketAddr>() {
        return vec![RelayTarget {
            address: addr,
            transport: None,
            server_name: None,
        }];
    }

    // Try parsing as a full SIP URI
    if let Ok(uri) = parse_uri_standalone(uri_string) {
        // Extract transport hint from URI params (e.g. ;transport=tcp)
        let transport_hint = uri.get_param("transport").map(|s| s.to_string());

        // Gateway hot-path shortcut: if this next hop is a gateway hostname
        // destination, reuse the address the prober already resolved instead of
        // a blocking resolver.resolve on every call. Keyed on the same
        // normalized `host:port` the gateway stored (extract_address_from_uri).
        if let Some(gateway) = gateway {
            let host_port = crate::gateway::extract_address_from_uri(uri_string);
            if let Some((address, gateway_transport)) = gateway.cached_address_for(&host_port) {
                // A script-supplied ;transport= wins; else the destination's
                // configured transport.
                let transport = transport_hint
                    .as_deref()
                    .and_then(transport_from_token)
                    .or(Some(gateway_transport));
                return vec![RelayTarget {
                    address,
                    transport,
                    server_name: Some(uri.host.clone()),
                }];
            }
        }

        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(resolver.resolve(
                &uri.host,
                uri.port,
                uri.scheme.as_str(),
                transport_hint.as_deref(),
            ))
        });

        return results
            .into_iter()
            .map(|r| {
                let transport = r
                    .transport
                    .as_deref()
                    .or(transport_hint.as_deref())
                    .and_then(transport_from_token);
                // All candidates from one URI share the target hostname — carry
                // it for TLS SNI so a hostname-vhost peer routes the handshake.
                RelayTarget {
                    address: r.address,
                    transport,
                    server_name: Some(uri.host.clone()),
                }
            })
            .collect();
    }

    Vec::new()
}

/// Resolve a SIP target URI to a single send destination (RFC 3263).
///
/// Returns the first candidate from [`resolve_candidates`] — the resolver has
/// already applied RFC 3263 §4.2 / RFC 2782 ordering, so "first" is a fresh
/// weighted-random / shuffled pick on every call.
pub(super) fn resolve_target(uri_string: &str, resolver: &SipResolver) -> Option<RelayTarget> {
    resolve_candidates(uri_string, resolver).into_iter().next()
}

/// RFC 3261 §18.1.1: a UDP request whose serialised length exceeds `mtu - 200`
/// bytes must be sent over a congestion-controlled transport (TCP).  The 200
/// bytes is headroom for the Via siphon adds plus additions by downstream hops.
pub(super) fn over_mtu(len: usize, mtu: u16) -> bool {
    len > mtu.saturating_sub(200) as usize
}

/// Time budget for the §18.1.1 TCP-reachability probe (below).  Kept short so a
/// blackholed TCP port on the (rare) over-MTU path adds only bounded latency; a
/// peer with no TCP listener refuses immediately (ECONNREFUSED), well under it.
pub(super) const TCP_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Probe a **reachable** TCP path to the next hop for the §18.1.1 over-MTU
/// switch.  Returns the TCP `SocketAddr` to send to, or `None` when no TCP
/// listener answers — in which case the caller keeps UDP and delivers the
/// request (fragmented) rather than dropping it, honouring RFC 3261 §18.1.1's
/// "retry using UDP" on a TCP connection failure.
///
/// The candidate address is the same `SocketAddr` for a numeric next hop (SIP
/// peers co-locate UDP+TCP; there is no SRV to consult, matching Kamailio's
/// `udp_mtu_try_proto=TCP`), or the `_sip._tcp` SRV / A/AAAA result for a
/// hostname.  A short blocking connect then confirms a TCP listener is actually
/// there before we commit the Via/transaction to TCP: the resolver's A/AAAA
/// fallback means a hostname almost always "resolves" for TCP even with no TCP
/// service, so the connect — not the resolution — is the real reachability test.
pub(super) fn resolve_tcp_path(
    uri_string: &str,
    udp_destination: SocketAddr,
    resolver: &SipResolver,
) -> Option<SocketAddr> {
    let candidate = if uri_string.parse::<SocketAddr>().is_ok() {
        udp_destination
    } else {
        let uri = parse_uri_standalone(uri_string).ok()?;
        if crate::sip::uri::strip_ipv6_brackets(&uri.host)
            .parse::<std::net::IpAddr>()
            .is_ok()
        {
            // Numeric host (v4 or bracketed v6) — same address, TCP.
            udp_destination
        } else {
            let results = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(resolver.resolve(
                    &uri.host,
                    uri.port,
                    uri.scheme.as_str(),
                    Some("tcp"),
                ))
            });
            results.into_iter().next()?.address
        }
    };
    // The real reachability test: only switch if a TCP listener answers.
    let reachable = tokio::task::block_in_place(|| {
        std::net::TcpStream::connect_timeout(&candidate, TCP_PROBE_TIMEOUT).is_ok()
    });
    reachable.then_some(candidate)
}

/// Whether a B-leg INVITE routes over the binding's captured inbound flow, or
/// is freshly resolved because it has a Path route set to follow.
///
/// A Path route set wins — the same precedence `relay_fork_branch` applies on the
/// proxy path, and the reason is RFC 3327 §5.3: the Path *is* the route set for
/// terminating requests to that binding, an explicit statement by the edge proxy
/// that MT traffic comes back through it carrying its per-registration token.
/// Routing over the flow instead reaches whatever address the REGISTER happened
/// to arrive from and drops that statement on the floor — and since
/// `registrar.lookup()` marks a binding this process accepted as `is_local`, its
/// flow is surfaced, so flow-first would mean a single siphon acting as both
/// registrar and B2BUA never honoured a Path at all.
///
/// A binding with **no** Path still routes over its flow, which is what keeps
/// connection reuse (RFC 5626 §5.3, mandatory for a WebSocket callee per RFC
/// 7118 §5) working for a UE that registered directly.
pub(super) fn b_leg_flow<'a>(
    flow: Option<&'a crate::script::api::registrar::PyFlow>,
    b_leg_route: &[String],
) -> Option<&'a crate::script::api::registrar::PyFlow> {
    flow.filter(|_| b_leg_route.is_empty())
}

/// Which URI a B-leg INVITE's wire destination is resolved from.
///
/// Precedence, highest first:
///
/// 1. an explicit `next_hop=` — the script overrode routing outright;
/// 2. the topmost `Route` of the B-leg route set (RFC 3261 §16.6 step 6), which
///    for a binding registered through an edge proxy is its RFC 3327 Path;
/// 3. the target URI, i.e. plain Request-URI routing.
///
/// Separate from the R-URI, which stays `target_uri` in every case so the called
/// party's IMPU shape survives on the wire.  Every destination decision in
/// [`b2bua_send_b_leg_invite`] resolves from this one value — the initial
/// resolve and the over-MTU TCP re-probe alike, so the two cannot disagree about
/// which host the B-leg is going to.
pub(super) fn b_leg_routing_uri<'a>(
    next_hop: Option<&'a str>,
    route_next_hop: Option<&'a str>,
    target_uri: &'a str,
) -> &'a str {
    next_hop.or(route_next_hop).unwrap_or(target_uri)
}

/// Apply the RFC 3261 §18.1.1 over-MTU UDP→TCP decision for one outbound
/// request.  Given the current transport, the serialised (pre-Via) request
/// length and its next hop, returns `Some((Tcp, tcp_addr))` when the request is
/// too big for UDP and a TCP path resolves, else `None` (keep UDP — logging the
/// forced over-MTU send when a switch was wanted but no TCP path exists).
///
/// `target_uri_string` decides *which host* is probed, and the probe's result
/// replaces `destination` — so it must be the URI `destination` itself was
/// resolved from, not some other URI attached to the same request.
pub(super) fn mtu_tcp_upgrade(
    mtu: Option<u16>,
    outbound_transport: Transport,
    serialized_len: usize,
    target_uri_string: &str,
    destination: SocketAddr,
    resolver: &SipResolver,
) -> Option<(Transport, SocketAddr)> {
    let mtu = mtu?;
    if outbound_transport != Transport::Udp || !over_mtu(serialized_len, mtu) {
        return None;
    }
    match resolve_tcp_path(target_uri_string, destination, resolver) {
        Some(tcp_addr) => {
            debug!(
                serialized_len, mtu, %destination,
                "RFC 3261 §18.1.1: over-MTU UDP request → TCP"
            );
            Some((Transport::Tcp, tcp_addr))
        }
        None => {
            warn!(
                serialized_len, mtu, %destination,
                "transport: forced UDP over-MTU send (no reachable TCP path)"
            );
            None
        }
    }
}

/// For a B→A in-dialog forward over **TLS**, decide whether to dial the remote
/// target Contact instead of the target leg's cached socket.
///
/// A peer that opens a fresh TLS connection per transaction (e.g. a Teams
/// Direct Routing SBC) closes its old connection; the leg's cached
/// `remote_addr` is then the peer's dead *source* port and its cached
/// `connection_id` is gone from the connection map, so both the reuse path and
/// the cached-socket fallback would time out. In that case dial the remote
/// target Contact's resolved host:port (RFC 3261 §12.2.1.1 — e.g. the SBC's
/// `…pstnhub…:443`), carrying the SNI needed for the new TLS handshake.
///
/// Returns `None` (keep the default reuse / cached-socket path) unless: the
/// forward is B→A, over TLS, there is no dialog route set to follow, and the
/// leg's TLS connection is no longer registered as alive. Scoped to TLS
/// because only the TLS listener registers inbound connections in
/// `stream_connections` (a TCP inbound connection is invisible there, so its
/// liveness can't be judged this way, and a NAT'd peer must keep its cached
/// source socket).
pub(super) fn contact_fallback_target(
    from_a_leg: bool,
    send_dest: SocketAddr,
    send_transport: Transport,
    target_connection_id: ConnectionId,
    route_set_empty: bool,
    remote_contact: Option<&str>,
    state: &DispatcherState,
) -> Option<RelayTarget> {
    if from_a_leg
        || send_transport != Transport::Tls
        || !route_set_empty
        || state
            .stream_connections
            .is_alive(send_dest, send_transport, target_connection_id)
    {
        return None;
    }
    resolve_target(remote_contact?, &state.dns_resolver)
}

/// Send a relayed request to a resolved target, using the connection pool for
/// TCP/TLS when no existing inbound connection is available.
///
/// Returns the `ConnectionId` used (new pool connection or the existing one).
/// What a downstream send did.
///
/// The connection id alone cannot carry this: on failure the stream transports
/// return `ConnectionId::default()` as a sentinel, but UDP returns the caller's
/// `fallback_connection_id` — which several call sites legitimately pass as
/// `ConnectionId::default()`. A caller cannot tell the two apart, which is why
/// a transport failure used to reach nobody.
#[derive(Debug, Clone, Copy)]
pub(super) struct SendOutcome {
    /// Connection the message went out on, or `ConnectionId::default()` when it
    /// did not go out at all.
    pub(super) connection_id: ConnectionId,
    /// The transport refused the message outright — a pool connect failed, a
    /// WebSocket peer has no live connection, the outbound channel is gone.
    ///
    /// RFC 3261 §16.9 makes this equivalent to having received a 503 on that
    /// branch, so a caller that owns a client transaction must answer upstream
    /// rather than fall silent.
    ///
    /// `false` is **not** a delivery guarantee: a UDP datagram that is enqueued
    /// and then lost reports success here, and only the client transaction's
    /// timeout (§16.7 step 2) covers that.
    pub(super) delivery_failed: bool,
}

impl SendOutcome {
    pub(super) fn sent(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            delivery_failed: false,
        }
    }

    pub(super) fn failed() -> Self {
        Self {
            connection_id: ConnectionId::default(),
            delivery_failed: true,
        }
    }
}

pub(super) fn send_to_target(
    data: Bytes,
    target: &RelayTarget,
    fallback_transport: Transport,
    fallback_connection_id: ConnectionId,
    send_source: Option<SocketAddr>,
    state: &DispatcherState,
) -> SendOutcome {
    let transport = target.transport.unwrap_or(fallback_transport);
    let destination = target.address;
    // A script `send_socket=` egress pin translated to a bind address:
    // - UDP pins the exact `(ip, port)` listener socket (`source_local_addr`).
    // - TCP/TLS bind the source *IP* with an ephemeral port (`port 0`) — the
    //   listen port would collide on the 4-tuple in `TIME_WAIT`.
    let send_bind_stream = send_source.map(|addr| SocketAddr::new(addr.ip(), 0));

    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        let local = state
            .listen_addrs
            .get(&transport)
            .copied()
            .unwrap_or(state.local_addr);
        hep.capture_outbound(
            state.hep_local_addr(local, transport),
            destination,
            transport,
            &data,
        );
    }

    match transport {
        Transport::Tcp => {
            // Use connection pool for outbound TCP.  For ESP-over-TCP
            // IPsec destinations (TS 33.203 §7.2 — iOS clients),
            // bind the local socket to the SA-pair source endpoint
            // (`pcscf_addr:pcscf_port_c`) so the kernel egress XFRM
            // selector for SA #3 matches.  An ephemerally-bound socket
            // never matches and the packet is silently dropped.
            let pool = Arc::clone(&state.connection_pool);
            let data_clone = data;
            // IPsec's fixed-port source wins over a script send_socket pin (the
            // kernel XFRM selector requires it); otherwise use the pin's
            // interface IP with an ephemeral source port.
            let source = crate::script::api::ipsec::outbound_local_addr_for(destination)
                .or(send_bind_stream);
            let connect_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match source {
                        Some(source) => pool.send_tcp_from(source, destination, data_clone).await,
                        None => pool.send_tcp(destination, data_clone).await,
                    }
                })
            });
            match connect_result {
                Ok(connection_id) => {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TCP pool"
                    );
                    SendOutcome::sent(connection_id)
                }
                Err(error) => {
                    // Pool send failed (connect refused, broken pipe, etc.).
                    // DO NOT fall back to the inbound connection_id — for TCP
                    // that's the UAC's connection, and routing the outbound
                    // request to it would echo the message back to the sender.
                    // Return the sentinel ConnectionId::default() so the
                    // caller stores 0 on the ClientBranch; future in-dialog
                    // sends (ACK, BYE) on that branch will miss the
                    // connection_map lookup and be dropped — which is the
                    // correct outcome when we never reached the upstream.
                    error!(
                        destination = %destination,
                        "TCP pool send failed: {error}"
                    );
                    SendOutcome::failed()
                }
            }
        }
        Transport::Tls => {
            // Script send_socket= egress pin over TLS: open (or reuse) a
            // source-bound pool connection.  The pool keys on the bind address,
            // so this stays distinct from a default-source connection to the
            // same peer.  We bypass the generic `reuse` below because that
            // ignores the source — reusing a connection off the wrong interface
            // would violate the operator's egress pin.
            if let Some(bind) = send_bind_stream {
                let pool = Arc::clone(&state.connection_pool);
                let server_name = target.server_name.clone();
                let data_clone = data;
                return match tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(pool.send_tls_from(
                        bind,
                        destination,
                        server_name.as_deref(),
                        data_clone,
                    ))
                }) {
                    Ok(connection_id) => {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            bind = %bind,
                            "relayed via source-bound TLS pool (send_socket)"
                        );
                        SendOutcome::sent(connection_id)
                    }
                    Err(error) => {
                        error!(destination = %destination, "source-bound TLS pool send failed: {error}");
                        SendOutcome::failed()
                    }
                };
            }

            // TLS connection reuse: find an existing inbound (or pool-created
            // outbound) TLS connection to the destination (like OpenSIPS
            // connection reuse).  `reuse` tries an exact SocketAddr match, then
            // an IP-only fallback (handles NAT where the Contact-URI port
            // differs from the source port), filtered to TLS.
            let connection_id = state.stream_connections.reuse(destination, Transport::Tls);

            if let Some(connection_id) = connection_id {
                let outbound_message = OutboundMessage {
                    followups: None,
                    connection_id,
                    transport: Transport::Tls,
                    destination,
                    data,
                    source_local_addr: None,
                    // Connection *reuse* — no TLS handshake, so no SNI needed.
                    server_name: None,
                };
                if let Err(error) = state.outbound.send(outbound_message) {
                    error!(destination = %destination, "TLS connection reuse send failed: {error}");
                } else {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TLS connection reuse"
                    );
                }
                SendOutcome::sent(connection_id)
            } else {
                // No inbound connection to reuse — create outbound TLS via pool
                let pool = Arc::clone(&state.connection_pool);
                let data_clone = data;
                let server_name = target.server_name.clone();
                match tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(pool.send_tls(
                        destination,
                        server_name.as_deref(),
                        data_clone,
                    ))
                }) {
                    Ok(connection_id) => {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            "relayed via TLS pool"
                        );
                        SendOutcome::sent(connection_id)
                    }
                    Err(error) => {
                        // Same rationale as the TCP arm above — never echo to
                        // the inbound connection on outbound failure.
                        error!(destination = %destination, "TLS pool send failed: {error}");
                        SendOutcome::failed()
                    }
                }
            }
        }
        Transport::WebSocket | Transport::WebSocketSecure => {
            // WebSocket connection reuse is *mandatory*: the connection is
            // client-initiated and can never be re-opened by the server
            // (RFC 7118 §5 / RFC 5626 §5.3).  Look up the live connection for
            // this UE (exact, then IP-only fallback, filtered to this WS/WSS
            // transport).
            //
            // This URI-relay path only fires when the target resolved to the
            // UE's real address — the primary WS MT path is the captured-flow
            // path (`relay(flow=...)` / forked flow), which bypasses
            // `send_to_target` entirely.  On a miss we DROP (return the
            // sentinel `ConnectionId::default()`) instead of falling back to
            // `fallback_connection_id` (the inbound caller's connection): the
            // UE is simply unreachable, and echoing the request back to the
            // sender — the pre-fix behaviour of the `_` arm — is exactly the
            // bug being closed.
            match state.stream_connections.reuse(destination, transport) {
                Some(connection_id) => {
                    let outbound_message = OutboundMessage {
                        followups: None,
                        connection_id,
                        transport,
                        destination,
                        data,
                        source_local_addr: None,
                        server_name: None,
                    };
                    if let Err(error) = state.outbound.send(outbound_message) {
                        error!(destination = %destination, %transport, "WS/WSS connection reuse send failed: {error}");
                    } else {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            %transport,
                            "relayed via WS/WSS connection reuse"
                        );
                    }
                    SendOutcome::sent(connection_id)
                }
                None => {
                    warn!(
                        destination = %destination,
                        %transport,
                        "no live WS/WSS connection to reuse — dropping (client-initiated transport cannot be dialed; use relay(flow=...) for MT routing)"
                    );
                    SendOutcome::failed()
                }
            }
        }
        _ => {
            // UDP and other transports: use the existing outbound channel.
            //
            // IPsec auto-source (3GPP TS 33.203 §6.3): when the
            // destination matches an installed SA pair, ask the IPsec
            // module which P-CSCF port to egress from.  Without this,
            // an MT INVITE to an IPsec-protected UE leaves on the
            // default listener (typically port 5060), the kernel
            // selector for SA #3 (src=`port_pc`, dst=`port_us`)
            // doesn't match, and the packet is silently dropped.
            // Returns `None` for non-IPsec deployments and ordinary
            // (non-UE) destinations — i.e. zero impact on the hot
            // path when no IpsecManager is wired.
            // IPsec auto-source wins over a script send_socket pin (kernel XFRM
            // selector); otherwise the pin selects the exact `(ip, port)` UDP
            // listener socket to egress from (routed via `udp_by_local`).
            let source_local_addr =
                crate::script::api::ipsec::outbound_local_addr_for(destination).or(send_source);
            let outbound_message = OutboundMessage {
                followups: None,
                connection_id: fallback_connection_id,
                transport,
                destination,
                data,
                source_local_addr,
                server_name: None,
            };
            if let Err(error) = state.outbound.send(outbound_message) {
                // The outbound router is gone (shutdown, or the task died).
                // Nothing will ever carry this message, so report it as a
                // transport failure rather than a delivered send.
                error!("failed to enqueue relayed request: {error}");
                return SendOutcome::failed();
            }
            SendOutcome::sent(fallback_connection_id)
        }
    }
}
