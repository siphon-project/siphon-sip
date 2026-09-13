//! Forwarding a request onward, single target or forked.
//!
//! Stamps Via and Record-Route, registers the client transaction and the
//! session entry before the send — responses on loopback can beat a
//! post-send registration and strand the call.

use super::*;

/// Where `request.relay(flow=...)` sends: the UE's source address, over the
/// flow's transport, egressing the listener the REGISTER landed on, on the
/// captured connection.  An unrecognised transport name falls back to
/// `fallback` (the inbound transport) with a warning.
///
/// Named so the registrar-liveness probe's agreement test builds the MT route
/// from the relay's own mapping rather than from a copy of it.
pub(super) fn flow_relay_egress(
    flow: &crate::script::api::registrar::PyFlow,
    fallback: Transport,
) -> (SocketAddr, Transport, SocketAddr, ConnectionId) {
    let transport = match flow.transport.as_str() {
        "udp" => Transport::Udp,
        "tcp" => Transport::Tcp,
        "tls" => Transport::Tls,
        "ws" => Transport::WebSocket,
        "wss" => Transport::WebSocketSecure,
        other => {
            warn!(transport = %other, "flow-relay: unknown transport, falling back to inbound");
            fallback
        }
    };
    (
        flow.source_addr,
        transport,
        flow.local_addr,
        ConnectionId(flow.connection_id),
    )
}

/// Relay a SIP request to its destination.
///
/// 1. Determine target address (explicit next_hop, or Request-URI)
/// 2. Clone the message, add Via, decrement Max-Forwards
/// 3. Store branch in pending map for response routing
/// 4. Send to target
///
/// When `flow` is `Some`, target resolution is bypassed entirely:
/// the destination, transport, and outbound listener are taken from
/// the captured inbound flow.  Used for P-CSCF Path-token MT routing
/// (TS 24.229 §5.2.7.2) where the Contact URI is unreachable and
/// the only path back to the UE is the listener that received the
/// REGISTER.  Via host/port are derived from `flow.local_addr` so
/// the UE's response routes back to the right port (load-bearing for
/// IPSec sec-agree port pairs — 3GPP TS 33.203 §7.4).
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. relay_request: shares most of its body with relay_fork_branch; dedupe pending
pub(super) fn relay_request(
    message: &SipMessage,
    next_hop: Option<&str>,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
    on_reply_callback: Option<Py<PyAny>>,
    on_failure_callback: Option<Py<PyAny>>,
    send_via_transport: Option<&str>,
    send_via_target: Option<&str>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    send_socket: Option<&crate::transport::SendSocket>,
) {
    // Two ways to know where this request is going:
    //   a) flow=Some — use the captured inbound flow directly,
    //      bypassing DNS resolution of any URI.
    //   b) flow=None — resolve the next_hop / top Route / R-URI as usual.
    let (target_uri_string, mut destination, mut outbound_transport, flow_local_addr) =
        if let Some(flow) = flow {
            let (flow_destination, transport, flow_local, _) =
                flow_relay_egress(flow, inbound.transport);
            // For diagnostics only — the URI isn't used to pick the destination.
            let uri_string = match &message.start_line {
                StartLine::Request(request_line) => request_line.request_uri.to_string(),
                _ => {
                    error!("flow-relay called on non-request");
                    return;
                }
            };
            (uri_string, flow_destination, transport, Some(flow_local))
        } else {
            // Determine target URI string (RFC 3261 §16.6 step 6):
            // 1. Explicit next-hop from script
            // 2. Top Route header URI (loose-routing — remaining after loose_route() popped ours)
            // 3. Request-URI (no Route headers)
            let target_uri_string = match next_hop {
                Some(hop) => hop.to_string(),
                None => {
                    if let Some(route_uri) = core::next_hop_from_route(&message.headers) {
                        route_uri
                    } else {
                        match &message.start_line {
                            StartLine::Request(request_line) => {
                                request_line.request_uri.to_string()
                            }
                            _ => {
                                error!("relay called on non-request");
                                return;
                            }
                        }
                    }
                }
            };
            let target = match resolve_target(&target_uri_string, &state.dns_resolver) {
                Some(t) => t,
                None => {
                    // The next hop didn't resolve.  For an in-dialog request to
                    // a WebSocket UE this is expected — its Contact is an
                    // unresolvable `<uuid>.invalid` host (RFC 7118), so fall
                    // back to the connection the dialog was established on
                    // (RFC 5923 / RFC 5626 §5.3).  `send_to_target` then reuses
                    // the live WS/WSS/TLS connection.  Mirrors the 2xx-ACK path
                    // (`handle_ack_via_session`), which already does this — that
                    // is why the ACK reaches the UE but the BYE used to 502.
                    match in_dialog_reuse_destination(message, state) {
                        Some((dest, transport)) => RelayTarget {
                            address: dest,
                            transport: Some(transport),
                            server_name: None,
                        },
                        None => {
                            warn!(target = %target_uri_string, "cannot resolve relay target");
                            let response = build_response(
                                message,
                                502,
                                "Bad Gateway",
                                state.server_header.as_deref(),
                                &[],
                            );
                            send_message_from(
                                response,
                                inbound.transport,
                                inbound.remote_addr,
                                inbound.connection_id,
                                Some(inbound.local_addr),
                                state,
                            );
                            return;
                        }
                    }
                }
            };
            (
                target_uri_string,
                target.address,
                target.transport.unwrap_or(inbound.transport),
                None,
            )
        };

    // Apply force_send_via transport override from script (non-flow path only;
    // the flow already pins the transport).
    if flow.is_none() {
        if let Some(via_transport) = send_via_transport {
            outbound_transport = match via_transport.to_lowercase().as_str() {
                "udp" => Transport::Udp,
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                _ => outbound_transport,
            };
        }
    }

    // Prevent routing loops — don't relay to ourselves.  Before treating this
    // as a loop, try the mid-dialog rescue: a UAC that keeps the proxy's
    // address in the R-URI of its re-INVITE/UPDATE/BYE (instead of the remote
    // target per RFC 3261 §12.2.1.1) computes a next hop that is us, but the
    // dialog's session still knows the established downstream branch — forward
    // there rather than failing a call we can route (§16.5).
    if state.is_own_address(&destination) {
        if let Some((established_destination, established_transport)) =
            rescue_in_dialog_self_next_hop(message, &state.session_store, &|address| {
                state.is_own_address(address)
            })
        {
            debug!(
                target = %target_uri_string,
                resolved = %destination,
                destination = %established_destination,
                "in-dialog next hop resolves to ourselves — forwarding to the dialog's established branch (RFC 3261 §12.2.1.1)"
            );
            destination = established_destination;
            outbound_transport = established_transport;
        } else {
            // ACK to 2xx is end-to-end and should go to the UAS Contact, not the
            // proxy. If the R-URI still points at us, silently drop rather than
            // generating a response (ACK never gets a response per RFC 3261).
            let is_ack = matches!(
                &message.start_line,
                StartLine::Request(rl) if rl.method == crate::sip::message::Method::Ack
            );
            if is_ack {
                debug!(target = %target_uri_string, "ACK to self — silently dropping");
                return;
            }

            warn!(
                target = %target_uri_string,
                destination = %destination,
                "relay loop detected — destination is ourselves"
            );
            let response = build_response(
                message,
                482,
                "Loop Detected",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            return;
        }
    }

    // Clone the message for modification
    let mut relayed = message.clone();

    // Decrement Max-Forwards
    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        let response = build_response(
            message,
            483,
            "Too Many Hops",
            state.server_header.as_deref(),
            &[],
        );
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        return;
    }

    // Ask the IPsec module whether this destination is on a registered
    // SA pair — if so, the source (and therefore Via) must reflect the
    // matching P-CSCF port (e.g. `pcscf_port_c` for an MT INVITE landing
    // on the UE's `port_us`) rather than the default per-transport
    // via_host / listener (3GPP TS 33.203 §6.3 / §7.4).  The SA's
    // pinned protocol (UDP/TCP, TS 33.203 §7.2) also overrides whatever
    // transport the URI / inbound suggested: in-dialog BYE/UPDATE often
    // routes via a cached Contact that lacks `;transport=`, and the
    // kernel XFRM selector silently drops every protected frame whose
    // upper-layer protocol doesn't match.  Initial INVITE works without
    // this pin because the script stamps the Path; in-dialog re-uses
    // the dialog route set and that stamp is gone.
    //
    // Applies to both UDP (ESP-over-UDP, the common case) and TCP
    // (ESP-over-TCP, used by some iOS clients).  For TCP the source
    // also drives `pool.send_tcp_from(source, ...)` so the outbound
    // socket binds to the SA's source endpoint instead of ephemeral;
    // an ephemerally-bound socket would never match the kernel
    // selector for SA #3.  Returns `None` for non-IPsec deployments
    // and ordinary destinations — zero impact on the hot path when
    // no IpsecManager is wired.  Computed once here and reused for
    // Via construction and the outbound send.
    let ipsec_source = match outbound_transport {
        Transport::Udp | Transport::Tcp => {
            if let Some((source, sa_transport)) =
                crate::script::api::ipsec::outbound_for(destination, outbound_transport)
            {
                if sa_transport != outbound_transport {
                    debug!(
                        %destination,
                        from = %outbound_transport,
                        to = %sa_transport,
                        "IPsec: pinning outbound transport to SA protocol",
                    );
                    outbound_transport = sa_transport;
                }
                Some(source)
            } else {
                None
            }
        }
        _ => None,
    };

    // RFC 3261 §18.1.1 — bias an over-MTU UDP request to TCP.  The length is
    // measured before our Via is added (`mtu - 200` leaves headroom for it plus
    // downstream Via additions).  Skipped for flow-/IPsec-pinned egress: a
    // captured flow and an IPsec SA both pin the transport authoritatively (the
    // kernel XFRM selector would drop a switched-transport frame).  The
    // `state.mtu.is_some()` guard keeps the serialise off the default hot path.
    if state.mtu.is_some() && flow.is_none() && ipsec_source.is_none() {
        if let Some((tcp_transport, tcp_addr)) = mtu_tcp_upgrade(
            state.mtu,
            outbound_transport,
            relayed.to_bytes().len(),
            &target_uri_string,
            destination,
            &state.dns_resolver,
        ) {
            // A hostname's _sip._tcp path could point back at us — don't switch
            // into a loop (the UDP destination already passed is_own_address).
            if state.is_own_address(&tcp_addr) {
                warn!(%tcp_addr, "§18.1.1: TCP path loops back to us — keeping UDP");
            } else {
                outbound_transport = tcp_transport;
                destination = tcp_addr;
            }
        }
    }

    // Resolve the script `send_socket=` egress pin against the *final*
    // outbound transport (the IPsec block above may have re-pinned it).  It
    // applies only when: there is no captured flow (a flow already pins the
    // egress listener), IPsec has not claimed the source (the kernel XFRM
    // selector must win), and its transport matches the outbound transport.
    // A transport mismatch is an operator config error — warn and ignore it
    // rather than egress on the wrong socket.
    let send_socket = match send_socket {
        _ if flow.is_some() || ipsec_source.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                "send_socket transport does not match the outbound transport — ignoring the egress pin"
            );
            None
        }
        None => None,
    };

    // Add our Via — use the outbound transport for the Via header.
    // If force_send_via set a target, use it as the Via sent-by address.
    let transport_str = format!("{}", outbound_transport);
    let (via_host, via_port) = if let Some(local) = flow_local_addr {
        // Flow-relay: pin Via to the listener that received the
        // REGISTER.  Critical for IPSec sec-agree where the protected
        // server port (e.g. 5066) is non-default — using the per-
        // transport via_host would emit a Via with the wrong port and
        // the UE's response would land on the wrong listener
        // (3GPP TS 33.203 §7.4).  A wildcard-bound listener keeps the
        // pinned port and borrows the advertised host, and a v6 literal
        // is bracketed — see `pinned_sent_by`.
        let (host, port) = pinned_sent_by(local, || state.via_host(&outbound_transport));
        (host, Some(port))
    } else if let Some(local) = ipsec_source {
        // IPsec auto-source: same correctness invariant as the flow
        // path — the UE's response on SA #4 (UE → port_pc) must land
        // on the Via we advertise, otherwise the kernel selector
        // doesn't match and the response is silently dropped.
        let (host, port) = pinned_sent_by(local, || state.via_host(&outbound_transport));
        (host, Some(port))
    } else if let Some(pin) = send_socket {
        // Script send_socket= egress pin: advertise the selected listener's
        // sent-by (its configured advertise host, else the bound IP) with the
        // listener's port, so the peer's response comes back to this socket.
        let (host, port) = pin.via_sent_by();
        (format_sip_host(&host), Some(port))
    } else if let Some(target_str) = send_via_target {
        // Script force_send_via override — bracket-aware split so a bare
        // bracketed v6 literal (`[2001:db8::1]`, no port) isn't truncated by a
        // naive rsplit_once(':').  Re-bracket the host so an unbracketed v6
        // still renders a valid sent-by.
        let (host, port) = split_host_port(target_str);
        (format_sip_host(host), port)
    } else {
        (
            state.via_host(&outbound_transport),
            Some(state.via_port(&outbound_transport)),
        )
    };
    let branch = core::add_via(&mut relayed.headers, &transport_str, &via_host, via_port);

    // Add Record-Route if the script requested it — one entry per *socket* the
    // dialog crosses, so each peer is handed the socket facing it.  See
    // [`record_route_uris`].  The outbound leg reuses the Via sent-by computed
    // above, so the two can never disagree about which listener this relay
    // used; the Gm port pair is the one place they are allowed to differ,
    // because a Record-Route advertises where requests *arrive* and a Via where
    // the response comes back (see `record_route_port_for`).
    if record_routed {
        let outbound_rr_port = crate::script::api::ipsec::record_route_port_for(
            via_port.unwrap_or_else(|| state.via_port(&outbound_transport)),
        );
        let (first, second) = record_route_uris(
            inbound.transport,
            crate::script::api::ipsec::record_route_port_for(inbound.local_addr.port()),
            || state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
            outbound_transport,
            outbound_rr_port,
            &via_host,
        );
        core::add_record_route(&mut relayed.headers, &first);
        if let Some(ref second) = second {
            core::add_record_route(&mut relayed.headers, second);
        }
    }

    // Serialize the relayed request
    let data = Bytes::from(relayed.to_bytes());

    debug!(
        branch = %branch,
        destination = %destination,
        transport = %outbound_transport,
        "relaying request"
    );

    // IMPORTANT: register the client transaction and session BEFORE sending.
    // On low-latency transports (loopback, fast LANs), the response can arrive
    // before this code finishes, leaving the response handler with no matching
    // session ("response for unknown branch"). The connection_id stored here is
    // a placeholder for UDP (where send_to_target returns the same value passed
    // in) and is updated below for TCP/TLS once the connection is established.
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    let placeholder_connection_id = inbound.connection_id;
    let retransmit_source =
        client_retransmit_source(outbound_transport, destination, flow, send_socket);
    let mut inserted_session_arc: Option<Arc<RwLock<ProxySession>>> = None;
    let client_key_opt = match state
        .transaction_manager
        .new_client_transaction(relayed, txn_transport)
    {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(
                        timer_id,
                        Box::new(TimerEntry {
                            key: client_key.clone(),
                            name: *name,
                            fires_at: std::time::Instant::now() + *duration,
                            destination: Some(destination),
                            transport: Some(outbound_transport),
                            connection_id: Some(placeholder_connection_id),
                            source_local_addr: retransmit_source,
                        }),
                    );
                }
            }

            if let Some(srv_key) = server_key {
                let mut session = ProxySession::new(
                    srv_key.clone(),
                    inbound.remote_addr,
                    inbound.local_addr,
                    inbound.connection_id,
                    inbound.transport,
                    message.clone(),
                    record_routed,
                );
                session.add_client_key(client_key.clone());
                session.set_client_branch(
                    client_key.clone(),
                    ClientBranch {
                        destination,
                        transport: outbound_transport,
                        connection_id: placeholder_connection_id,
                    },
                );
                session.on_reply_callback = on_reply_callback;
                session.on_failure_callback = on_failure_callback;
                let arc = state.session_store.insert(session);
                inserted_session_arc = Some(arc);
            }
            Some(client_key)
        }
        Err(error) => {
            debug!(branch = %branch, "failed to create client transaction: {error}");
            None
        }
    };

    // Now actually send.  Two paths:
    //   - Flow-relay: build the OutboundMessage directly with the captured
    //     `(connection_id, transport, destination, source_local_addr)` so
    //     UDP egresses from the right listener and stream transports route
    //     to the live accepted-connection write half registered in
    //     `connection_map`.  No DNS, no pool lookup.
    //   - URI-relay: the legacy path through `send_to_target`.
    let outcome = if let Some(local) = flow_local_addr {
        let outbound_message = OutboundMessage {
            followups: None,
            connection_id: ConnectionId(flow.map(|f| f.connection_id).unwrap_or(0)),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(local),
            server_name: None,
        };
        let cid = outbound_message.connection_id;
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(
                destination = %destination,
                transport = %outbound_transport,
                "flow-relay outbound send failed: {error}"
            );
            SendOutcome::failed()
        } else {
            debug!(
                destination = %destination,
                transport = %outbound_transport,
                connection_id = ?cid,
                "relayed via captured flow"
            );
            SendOutcome::sent(cid)
        }
    } else {
        // Build the legacy RelayTarget for the URI path.
        let target = RelayTarget {
            address: destination,
            transport: Some(outbound_transport),
            server_name: None,
        };
        send_to_target(
            data,
            &target,
            inbound.transport,
            inbound.connection_id,
            send_socket.map(|pin| pin.addr),
            state,
        )
    };
    let connection_id = outcome.connection_id;

    // RFC 3261 §16.9: a transport error on forwarding MUST be handled as if a
    // 503 had been received on that branch.  Without this the branch simply
    // goes quiet — the upstream UAC sits on the 100 Trying until its own
    // Timer F, which is 32 s of nothing where the caller should have been
    // told in milliseconds.
    if outcome.delivery_failed {
        if let Some(ref client_key) = client_key_opt {
            fail_branch_locally(
                client_key,
                503,
                "Service Unavailable",
                "transport error on forwarding (RFC 3261 §16.9)",
                state,
            );
            return;
        }
    }

    // Patch the session's ClientBranch via the locally-held `Arc` we got
    // back from `session_store.insert(...)` rather than re-looking up
    // through the store: at high CPS on TCP loopback the UAS 200 OK can
    // arrive and trigger `remove_client_key` before `send_to_target`
    // returns here, dropping the by_client_key / server_to_clients index
    // entries — a store-side lookup would then miss and the branch would
    // stay pinned to `placeholder_connection_id` (the inbound UAC's
    // connection_id), routing every later in-dialog send (ACK, BYE) to
    // the UAC instead of the UAS.  The `Arc` keeps the session alive
    // across the index removal, so the write always lands.
    if connection_id != placeholder_connection_id {
        if let (Some(client_key), Some(arc)) =
            (client_key_opt.as_ref(), inserted_session_arc.as_ref())
        {
            if let Ok(mut session) = arc.write() {
                session.set_client_branch(
                    client_key.clone(),
                    ClientBranch {
                        destination,
                        transport: outbound_transport,
                        connection_id,
                    },
                );
            }
        }
    }
}

/// Relay a forked request to multiple targets.
///
/// Creates a ProxySession with a ForkAggregator and sends to all targets
/// (parallel) or just the first (sequential, rest tried on failure).
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_fork_request(
    message: &SipMessage,
    targets: &[String],
    flows: &[Option<crate::script::api::registrar::PyFlow>],
    routes: &[Vec<String>],
    strategy: crate::proxy::fork::ForkStrategy,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
    send_socket: Option<&crate::transport::SendSocket>,
    on_reply_callback: Option<Py<PyAny>>,
    on_failure_callback: Option<Py<PyAny>>,
) {
    use crate::proxy::fork::ForkAggregator;

    // Parse target URIs
    let target_uris: Vec<crate::sip::uri::SipUri> = targets
        .iter()
        .filter_map(|target| parse_uri_standalone(target).ok())
        .collect();

    if target_uris.is_empty() {
        warn!("fork: no valid target URIs");
        let response = build_response(
            message,
            500,
            "No Valid Targets",
            state.server_header.as_deref(),
            &[],
        );
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        return;
    }

    let aggregator = Arc::new(std::sync::Mutex::new(ForkAggregator::new(
        target_uris,
        strategy,
    )));

    // Create ProxySession (even without server_key, we need the aggregator)
    let srv_key = match server_key {
        Some(key) => key.clone(),
        None => {
            // Fall back to single-target relay if no server transaction —
            // carry the first branch's flow so a single WS contact still
            // routes, its Path route set so it still reaches the right
            // binding, and the per-relay callbacks the script attached (this
            // path is a plain relay in everything but name, so silently
            // dropping them would make `relay(on_failure=…)` a no-op).
            let first_target = targets.first().map(|s| s.as_str()).unwrap_or("");
            let first_path = routes.first().map(Vec::as_slice).unwrap_or(&[]);
            let Some(routing) = core::branch_routing(first_path, first_target) else {
                warn!(
                    target = %first_target,
                    path = ?first_path,
                    "fork: single target has an unusable Path route set — dropping"
                );
                return;
            };
            // A branch with a Path route set is routed by its top Route
            // (RFC 3261 §16.6 step 6), not by the Contact URI — passing no
            // next-hop lets relay_request pick that Route up itself.
            let has_route_set = routing.route_set.is_some();
            let next_hop = if has_route_set {
                None
            } else {
                targets.first().map(|s| s.as_str())
            };
            let single_message;
            let relay_message = match routing.route_set {
                Some(route_value) => {
                    let mut cloned = message.clone();
                    cloned.headers.set("Route", route_value);
                    single_message = cloned;
                    &single_message
                }
                None => message,
            };
            relay_request(
                relay_message,
                next_hop,
                record_routed,
                inbound,
                None,
                state,
                on_reply_callback,
                on_failure_callback,
                None,
                None,
                // Same precedence as a real fork branch: a Path route set
                // outranks the captured flow (see `relay_fork_branch`).
                flows
                    .first()
                    .and_then(|f| f.as_ref())
                    .filter(|_| !has_route_set),
                send_socket,
            );
            return;
        }
    };

    let mut session = ProxySession::new(
        srv_key.clone(),
        inbound.remote_addr,
        inbound.local_addr,
        inbound.connection_id,
        inbound.transport,
        message.clone(),
        record_routed,
    );
    session.fork_aggregator = Some(Arc::clone(&aggregator));
    session.fork_flows = flows.to_vec();
    session.fork_routes = routes.to_vec();
    session.fork_send_socket = send_socket.cloned();

    // Determine which branches to start now
    let branches_to_start: Vec<usize> = match strategy {
        crate::proxy::fork::ForkStrategy::Parallel => (0..targets.len()).collect(),
        crate::proxy::fork::ForkStrategy::Sequential => {
            if targets.is_empty() {
                vec![]
            } else {
                vec![0]
            }
        }
    };

    // Insert the session into the store *before* any branch is sent so the
    // response handler can look it up via by_client_key (after each branch
    // pre-registers itself below). Without this, a fast peer (loopback) can
    // deliver a response before the branch is registered, stranding the call.
    let session_arc = state.session_store.insert_for_fork(session);

    for branch_index in branches_to_start {
        let target = &targets[branch_index];
        relay_fork_branch(
            message,
            target,
            branch_index,
            record_routed,
            inbound,
            &srv_key,
            &session_arc,
            &aggregator,
            flows.get(branch_index).and_then(|f| f.as_ref()),
            routes.get(branch_index).map(Vec::as_slice).unwrap_or(&[]),
            send_socket,
            state,
        );
    }
}

/// Relay a single branch of a forked request.
///
/// Resolves the target, adds Via, sends the request, creates a client transaction,
/// and registers the branch in the ProxySession.
///
/// `branch_path` is this branch's RFC 3327 Path vector (empty for a bare-URI
/// target).  When non-empty it becomes the branch's Route header set, replacing
/// whatever Route the request carried, and the top Route becomes the branch's
/// next hop (RFC 3327 §5.3 + RFC 3261 §16.6 step 6).  The Request-URI stays the
/// branch target either way.
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_fork_branch(
    message: &SipMessage,
    target: &str,
    branch_index: usize,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    aggregator: &Arc<std::sync::Mutex<crate::proxy::fork::ForkAggregator>>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    branch_path: &[String],
    send_socket: Option<&crate::transport::SendSocket>,
    state: &DispatcherState,
) {
    // This branch's own route set, from the Path stored with its registration
    // binding.  Two bindings of one AoR usually traverse different proxy chains
    // (or the same edge proxy with a different per-registration token), so
    // without this every branch inherits branch 0's Route and a Path-token
    // proxy resolves them all back to the *first* binding — the second branch
    // is then a retry of the first, not a second contact.
    let routing = match core::branch_routing(branch_path, target) {
        Some(routing) => routing,
        None => {
            warn!(
                target = %target,
                branch = branch_index,
                path = ?branch_path,
                "fork: branch has an unusable Path route set — dropping the branch"
            );
            return;
        }
    };
    let branch_route_set = routing.route_set;

    // A Path route set outranks the captured inbound flow.  A binding with a
    // Path was registered *through* an intermediate proxy, and RFC 3327 §5.3
    // makes that vector the route set for reaching it — the per-registration
    // token in the Path URI is the only thing that tells the edge proxy which
    // of its bindings this request is for.  The captured flow answers a
    // narrower question ("the Contact URI is unreachable, write back on the
    // connection the REGISTER came in on"), and using it here would send the
    // branch to the REGISTER's source while dropping the token that identifies
    // the binding.  With no Path, the flow is still the only way back to a
    // WebSocket UE (RFC 5626 §5.3 / RFC 7118 §5), so nothing changes there.
    let flow = flow.filter(|_| branch_route_set.is_none());

    // Resolve the branch destination + transport: over the captured inbound flow
    // when one applies, else by DNS-resolving the branch's top Route (RFC 3261
    // §16.6 step 6) or, with no route set, the target URI.
    let (mut destination, mut outbound_transport) = if let Some(flow) = flow {
        let transport = match flow.transport.as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "ws" => Transport::WebSocket,
            "wss" => Transport::WebSocketSecure,
            other => {
                warn!(target = %target, branch = branch_index, transport = %other, "fork: unknown flow transport");
                return;
            }
        };
        (flow.source_addr, transport)
    } else {
        // Route set present → the next hop is its topmost entry, not the
        // Contact URI (RFC 3261 §16.6 step 6).  This is what actually sends
        // branch N through binding N's own edge proxy.
        let relay_target = match resolve_target(&routing.next_hop, &state.dns_resolver) {
            Some(t) => t,
            None => {
                warn!(target = %routing.next_hop, branch = branch_index, "fork: cannot resolve target");
                return;
            }
        };
        (
            relay_target.address,
            relay_target.transport.unwrap_or(inbound.transport),
        )
    };

    // Loop detection — check all listen addresses (including per-transport)
    if state.is_own_address(&destination) {
        warn!(target = %target, "fork: loop detected");
        return;
    }

    // Clone and modify message
    let mut relayed = message.clone();

    // Give the branch its own route set (RFC 3327 §5.3).  This *replaces* any
    // Route on the request: the Path vector is the complete route set for
    // reaching this binding, and leaving an inherited entry in front of it
    // would send the branch through the previous binding's proxy chain.
    if let Some(ref route_value) = branch_route_set {
        relayed.headers.set("Route", route_value.clone());
    }

    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        return; // caller handles the error for the whole fork
    }

    // RFC 3261 §18.1.1 — bias an over-MTU UDP fork branch to TCP.  Skipped for a
    // flow-pinned branch (its transport is fixed by connection reuse).
    if state.mtu.is_some() && flow.is_none() {
        if let Some((tcp_transport, tcp_addr)) = mtu_tcp_upgrade(
            state.mtu,
            outbound_transport,
            relayed.to_bytes().len(),
            target,
            destination,
            &state.dns_resolver,
        ) {
            if state.is_own_address(&tcp_addr) {
                warn!(%tcp_addr, "fork §18.1.1: TCP path loops back to us — keeping UDP");
            } else {
                outbound_transport = tcp_transport;
                destination = tcp_addr;
            }
        }
    }

    // A script send_socket= egress pin applies to this branch only when it has
    // no captured flow (a flow already pins egress) and its transport matches
    // the branch's outbound transport.  When it applies, the Via sent-by is the
    // pinned listener's advertised address so the branch's response comes back
    // to that socket.
    let send_socket = match send_socket {
        _ if flow.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                branch = branch_index,
                "fork: send_socket transport does not match the branch transport — ignoring"
            );
            None
        }
        None => None,
    };

    let transport_str = format!("{}", outbound_transport);
    // Same egress-pin precedence as every other request siphon originates: a
    // captured flow writes this branch to its own socket (see the flow arm of
    // the send below), so the sent-by has to name *that* socket or the peer
    // answers somewhere we are not — on an IPsec-protected MT branch, to a port
    // with no SA covering it (3GPP TS 33.203 §7.4).
    let (via_host, via_port) = egress_sent_by(
        flow.map(|flow| flow.local_addr),
        send_socket.map(|pin| pin.via_sent_by()),
        || {
            (
                state.via_host(&outbound_transport),
                state.via_port(&outbound_transport),
            )
        },
    );
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &via_host,
        Some(via_port),
    );

    // One Record-Route entry per socket the dialog crosses — see the same block
    // in [`relay_request`] and [`record_route_uris`].
    if record_routed {
        let (first, second) = record_route_uris(
            inbound.transport,
            crate::script::api::ipsec::record_route_port_for(inbound.local_addr.port()),
            || state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
            outbound_transport,
            crate::script::api::ipsec::record_route_port_for(via_port),
            &via_host,
        );
        core::add_record_route(&mut relayed.headers, &first);
        if let Some(ref second) = second {
            core::add_record_route(&mut relayed.headers, second);
        }
    }

    // Update Request-URI to the fork target (each branch gets its own Contact URI)
    if let Ok(new_uri) = parse_uri_standalone(target) {
        if let StartLine::Request(ref mut request_line) = relayed.start_line {
            request_line.request_uri = new_uri;
        }
    }

    let data = Bytes::from(relayed.to_bytes());

    // Mark branch as Trying in aggregator (before any send, so a synchronous
    // response can find a branch in the right state).
    if let Ok(mut agg) = aggregator.lock() {
        agg.mark_trying(branch_index);
    }

    // Pre-register the client transaction and the branch in the session_store
    // BEFORE sending. The placeholder connection_id is fine for UDP (the
    // listener fd is shared); for TCP/TLS it's updated below once the actual
    // connection is established.
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    let placeholder_connection_id = inbound.connection_id;
    let retransmit_source =
        client_retransmit_source(outbound_transport, destination, flow, send_socket);
    let client_key_opt = match state
        .transaction_manager
        .new_client_transaction(relayed, txn_transport)
    {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(
                        timer_id,
                        Box::new(TimerEntry {
                            key: client_key.clone(),
                            name: *name,
                            fires_at: std::time::Instant::now() + *duration,
                            destination: Some(destination),
                            transport: Some(outbound_transport),
                            connection_id: Some(placeholder_connection_id),
                            source_local_addr: retransmit_source,
                        }),
                    );
                }
            }
            state.session_store.register_fork_branch(
                session_arc,
                server_key,
                client_key.clone(),
                ClientBranch {
                    destination,
                    transport: outbound_transport,
                    connection_id: placeholder_connection_id,
                },
                branch_index,
            );
            Some(client_key)
        }
        Err(error) => {
            debug!(branch = %branch, "fork: failed to create client transaction: {error}");
            None
        }
    };

    // Send: over the captured flow (direct OutboundMessage, bypassing DNS/pool
    // — mirrors the relay(flow=...) path) when one is attached, else via the
    // normal resolver/pool path.
    let outcome = if let Some(flow) = flow {
        // This branch bypasses `send_to_target`, so it has to do that helper's
        // HEP capture itself — otherwise a flow-pinned relay is the one request
        // that never reaches Homer.
        if let Some(ref hep) = state.hep_sender {
            hep.capture_outbound(
                state.hep_local_addr(flow.local_addr, outbound_transport),
                destination,
                outbound_transport,
                &data,
            );
        }
        let outbound_message = OutboundMessage {
            followups: None,
            connection_id: ConnectionId(flow.connection_id),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(flow.local_addr),
            server_name: None,
        };
        let cid = outbound_message.connection_id;
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(branch = %branch, destination = %destination, transport = %outbound_transport, "fork: flow send failed: {error}");
            SendOutcome::failed()
        } else {
            SendOutcome::sent(cid)
        }
    } else {
        let relay_target = RelayTarget {
            address: destination,
            transport: Some(outbound_transport),
            server_name: None,
        };
        send_to_target(
            data,
            &relay_target,
            inbound.transport,
            inbound.connection_id,
            send_socket.map(|pin| pin.addr),
            state,
        )
    };
    let connection_id = outcome.connection_id;

    // RFC 3261 §16.9 — a transport error on this branch is a 503 on this
    // branch.  Feeding it to the aggregator is what lets a parallel fork carry
    // on with its other branches and a sequential fork move to the next one,
    // instead of the whole fork stalling on a branch that never left the box.
    if outcome.delivery_failed {
        if let Some(ref client_key) = client_key_opt {
            fail_branch_locally(
                client_key,
                503,
                "Service Unavailable",
                "transport error on forwarding (RFC 3261 §16.9)",
                state,
            );
            return;
        }
    }

    debug!(
        branch = %branch,
        target = %target,
        branch_index = branch_index,
        destination = %destination,
        transport = %outbound_transport,
        flow = flow.is_some(),
        "fork: sent branch"
    );

    // For TCP/TLS the actual connection_id may differ from the placeholder
    // — patch the session's ClientBranch so retransmits/CANCEL hit the right
    // connection.
    //
    // Patch via the local `session_arc` rather than re-looking up through
    // `state.session_store.update_branch_connection_id(...)`: under TCP
    // loopback at high CPS, the UAS 200 OK can arrive and be forwarded
    // (which calls `session_store.remove_client_key`) before
    // `send_to_target` returns here.  A store-side lookup would then miss
    // and the branch would stay pinned to `placeholder_connection_id`
    // (the inbound UAC's connection_id).  Subsequent in-dialog ACK relay
    // via `handle_ack_via_session` would route on that placeholder and
    // bounce the ACK back to the UAC — sipp logs it as "ACK CSeq value
    // does NOT match value of related INVITE CSeq -- aborting call" and
    // drops the subsequent BYE 200 OK.  The local `session_arc` survives
    // `remove_client_key`, so this write always lands.
    if connection_id != placeholder_connection_id {
        if let Some(client_key) = client_key_opt.as_ref() {
            if let Ok(mut session) = session_arc.write() {
                if let Some(branch) = session.client_branches.get_mut(client_key) {
                    branch.connection_id = connection_id;
                }
            }
        }
    }
}
