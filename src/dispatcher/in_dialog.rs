//! Where an in-dialog request goes.
//!
//! An established dialog carries a route set and a remote target, and the next
//! hop is whichever of those survives NAT, a flow pin, and a peer that has
//! since moved. `resolve_in_dialog_destination` has 15 callers across both the
//! proxy and B2BUA paths; the rest of this module is the cases it defers to.

use super::*;

/// Build an ACK for a non-2xx B-leg response in B2BUA mode (RFC 3261 §17.1.1.3).
///
/// Unlike the proxy path, we don't store the B-leg INVITE. Instead we
/// reconstruct the ACK from the response (which carries the same Call-ID,
/// From, and CSeq as the original B-leg INVITE) plus the B-leg target URI.
/// Extract the bare URI string from the first entry of a dialog route set.
///
/// Route entries are stored in wire form (e.g. `<sip:p.example.com;lr>`); this
/// strips angle brackets and any header-level params and returns
/// `sip:p.example.com;lr` ready to feed to `resolve_target`. Returns `None`
/// if the route set is empty or the first entry cannot be parsed.
pub(super) fn first_route_uri(route_set: &[String]) -> Option<String> {
    let first = route_set.first()?;
    crate::sip::headers::route::RouteEntry::parse(first)
        .ok()
        .map(|entry| entry.uri.to_string())
}

/// Resolve the destination for a B2BUA in-dialog request per RFC 3261
/// §12.2.1.1 / §16.12, preferring the dialog's established connection
/// (RFC 5923) — see [`resolve_in_dialog_flow_uri`] for the full reasoning.
///
/// The next hop is the first `Route` URI of the dialog route set (or the cached
/// remote target when the route set is empty). When that next hop still
/// resolves to the peer the dialog was established with (`fallback_addr`'s IP),
/// the cached address/transport are returned so the existing send reuses the
/// established connection rather than re-resolving — which, since the RFC 3263
/// §4.2 A/AAAA shuffle, can land on a different member of a load-balanced trunk
/// that holds no dialog state. It still follows the route set to a genuinely
/// different next hop (e.g. an IMS S-CSCF reached via the route set while the
/// INVITE traversed a non-Record-Routing I-CSCF — TS 24.229 §5.3.2).
///
/// The B2BUA send sites already supply the leg's `connection_id` to
/// [`send_message`] (A-leg, where an inbound connection can only be reached by
/// reuse) or reuse the outbound pool connection by address via
/// [`send_b2bua_to_bleg`] (B-leg), so this returns just `(addr, transport)`.
pub(super) fn resolve_in_dialog_destination(
    route_set: &[String],
    state: &DispatcherState,
    fallback_addr: SocketAddr,
    fallback_transport: Transport,
) -> (SocketAddr, Transport) {
    let next_hop = first_route_uri(route_set);
    let (destination, transport, _connection_id) = resolve_in_dialog_flow_uri(
        next_hop.as_deref(),
        &state.dns_resolver,
        fallback_addr,
        fallback_transport,
        ConnectionId::default(),
    );
    (destination, transport)
}

/// For an in-dialog request whose next hop did not resolve — e.g. a WebSocket
/// UE registered a `<uuid>.invalid` Contact (RFC 7118), so the R-URI can't be
/// DNS-resolved — recover the destination from the connection the dialog was
/// established on (RFC 5923 / RFC 5626 §5.3 connection reuse).
///
/// Returns the established far-end `(destination, transport)`.  The destination
/// is the peer's source address, which the stream-connection registry is keyed
/// on, so [`send_to_target`]'s per-transport reuse (TCP/TLS/WS/WSS arms) then
/// routes the request over the live connection — the only way back to a WS/WSS
/// UE.  Looked up by the dialog key `(Call-ID, From-tag)`; finds the session for
/// any in-dialog request originated by the dialog's creator (the common case:
/// a UAC sending BYE/re-INVITE/UPDATE for its own call).
pub(super) fn in_dialog_reuse_destination(
    message: &SipMessage,
    state: &DispatcherState,
) -> Option<(SocketAddr, Transport)> {
    in_dialog_established_branch(message, &state.session_store)
}

/// Store-level core of [`in_dialog_reuse_destination`]: the dialog's
/// established downstream branch, looked up by the dialog key
/// `(Call-ID, From-tag)`.  Split from `DispatcherState` so the self-next-hop
/// rescue below is unit-testable against a bare [`ProxySessionStore`].
pub(super) fn in_dialog_established_branch(
    message: &SipMessage,
    session_store: &ProxySessionStore,
) -> Option<(SocketAddr, Transport)> {
    let call_id = message.headers.get("Call-ID")?;
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag)?;
    let session_arc = session_store.get_by_dialog_key(call_id, &from_tag)?;
    let session = session_arc.read().ok()?;
    let client_key = session.client_keys.first()?;
    let branch = session.get_client_branch(client_key)?;
    Some((branch.destination, branch.transport))
}

/// Rescue an in-dialog request whose computed next hop resolved to one of OUR
/// OWN listeners.
///
/// RFC 3261 §12.2.1.1 has the UAC build a mid-dialog request from the remote
/// target (the peer's Contact) and the route set (our Record-Route).  A
/// non-compliant-but-common UAC instead keeps the proxy's address in the
/// Request-URI — so after `loose_route()` consumed our Route (§16.4) the
/// remaining next hop (the R-URI) *is us*, and blindly answering
/// `482 Loop Detected` fails a request we hold the correct destination for:
/// the dialog's established downstream branch.  §16.5 makes us responsible
/// for a Request-URI in our own domain, and for a mid-dialog request the only
/// consistent target is the dialog peer, so forward there.
///
/// Returns `None` — caller keeps its existing drop/482 behaviour — when the
/// request is not mid-dialog (no To-tag, RFC 3261 §12.2), the dialog is not in
/// the session store, or the established branch is (also) one of our own
/// addresses (a genuine loop).
pub(super) fn rescue_in_dialog_self_next_hop(
    message: &SipMessage,
    session_store: &ProxySessionStore,
    is_self: &dyn Fn(&SocketAddr) -> bool,
) -> Option<(SocketAddr, Transport)> {
    let has_to_tag = message
        .typed_to()
        .ok()
        .flatten()
        .and_then(|name_addr| name_addr.tag)
        .is_some();
    if !has_to_tag {
        return None;
    }
    let (destination, transport) = in_dialog_established_branch(message, session_store)?;
    if is_self(&destination) {
        return None;
    }
    Some((destination, transport))
}

/// Decide the forward hop for an end-to-end 2xx ACK after dialog-route-set
/// resolution: keep the resolved hop unless it is one of our own addresses, in
/// which case fall back to the dialog's established branch (same
/// RFC 3261 §12.2.1.1 rescue as [`rescue_in_dialog_self_next_hop`] — the UAC
/// kept the proxy's address in the R-URI instead of the remote target).  `None`
/// means both hops point back at us — a genuine loop, drop the ACK silently
/// (RFC 3261 §17.1.1.3: an ACK never gets a response).
pub(super) fn ack_forward_hop(
    resolved: (SocketAddr, Transport, ConnectionId),
    established: (SocketAddr, Transport, ConnectionId),
    is_self: &dyn Fn(&SocketAddr) -> bool,
) -> Option<(SocketAddr, Transport, ConnectionId)> {
    if !is_self(&resolved.0) {
        return Some(resolved);
    }
    if is_self(&established.0) {
        return None;
    }
    Some(established)
}

/// Pin the outbound transport to a matching IPsec SA's protocol
/// (3GPP TS 33.203 §7.2).  When `destination` matches a registered UE binding,
/// the SA's pinned protocol (UDP vs TCP) overrides whatever the dialog route
/// set or cached transport selected.  In-dialog requests (BYE, UPDATE,
/// in-dialog re-INVITE, end-to-end 2xx ACK) often arrive with a Route URI /
/// cached Contact that lacks `;transport=`, and the kernel XFRM selector
/// silently drops every protected frame whose upper-layer protocol doesn't
/// match.  No-op for non-IPsec deployments and ordinary destinations — zero
/// impact when no IpsecManager is wired.
pub(super) fn ipsec_pin_transport(destination: SocketAddr, transport: Transport) -> Transport {
    if matches!(transport, Transport::Udp | Transport::Tcp) {
        if let Some((_, sa_transport)) =
            crate::script::api::ipsec::outbound_for(destination, transport)
        {
            if sa_transport != transport {
                debug!(
                    %destination,
                    from = %transport,
                    to = %sa_transport,
                    "IPsec: pinning in-dialog transport to SA protocol",
                );
                return sa_transport;
            }
        }
    }
    transport
}

/// Test whether an in-dialog request should reuse the dialog's established
/// connection (RFC 5923) instead of opening one to a freshly-resolved next hop.
///
/// Reuse when the established peer's IP is among the next hop's resolved
/// candidates — IP-only, because the cached address carries the peer's *source*
/// port (an ephemeral port for an inbound connection, or the pooled outbound
/// socket's peer), not its SIP listening port — or when nothing resolved (the
/// established peer is then the best available target). Returns `false` only
/// when the next hop points at a genuinely different peer (e.g. an IMS S-CSCF
/// reached via the dialog route set while the INVITE was forwarded to a
/// non-Record-Routing I-CSCF).
pub(super) fn established_peer_in_candidates(
    cached_ip: std::net::IpAddr,
    candidates: &[RelayTarget],
) -> bool {
    candidates.is_empty()
        || candidates
            .iter()
            .any(|target| target.address.ip() == cached_ip)
}

/// Resolve the destination for an in-dialog request, preferring the dialog's
/// established connection (RFC 5923) when the next hop still resolves to the
/// peer the dialog was established with.
///
/// On a connection-oriented transport to a multi-member peer behind one DNS
/// name (a load-balanced Record-Route), the next hop resolves to several
/// siblings; since the RFC 3263 §4.2 A/AAAA shuffle picks one at random per
/// call, a fresh resolution can land on a member that holds no dialog state, so
/// an in-dialog BYE/re-INVITE/UPDATE hits the wrong node and the far leg is
/// never released / the request is never applied. RFC 5923 says to send
/// in-dialog traffic over the connection the dialog was established on; we do
/// exactly that whenever the established peer is still one of the next hop's
/// resolved members.
///
/// Returns `(destination, transport, connection_id)`. On the reuse path the
/// connection_id is the cached one, so [`send_message_from`] routes over the
/// live connection (and the per-transport outbound distributor falls back to
/// the pool against the *same member's* address if it has since closed). On the
/// fresh-resolution path it is [`ConnectionId::default`] (open / pool a new
/// connection). The IPsec transport pin is applied to the final destination in
/// both cases.
pub(super) fn resolve_in_dialog_flow_uri(
    next_hop_uri: Option<&str>,
    resolver: &SipResolver,
    cached_addr: SocketAddr,
    cached_transport: Transport,
    cached_connection_id: ConnectionId,
) -> (SocketAddr, Transport, ConnectionId) {
    let (destination, transport, connection_id) = match next_hop_uri {
        // No next hop (empty route set) → the cached peer IS the remote target
        // (RFC 3261 §12.2.1.1); reuse its connection.
        None => (cached_addr, cached_transport, cached_connection_id),
        Some(uri) => {
            let candidates = resolve_candidates(uri, resolver);
            if established_peer_in_candidates(cached_addr.ip(), &candidates) {
                (cached_addr, cached_transport, cached_connection_id)
            } else {
                // Genuinely different next hop (IMS route-set divergence) —
                // resolve fresh and open/pool a new connection.
                let target = &candidates[0];
                (
                    target.address,
                    target.transport.unwrap_or(cached_transport),
                    ConnectionId::default(),
                )
            }
        }
    };

    (
        destination,
        ipsec_pin_transport(destination, transport),
        connection_id,
    )
}

/// Choose the wire destination for a B2BUA retry INVITE that supersedes a failed
/// outbound leg in place — the 401/407 credentialed re-INVITE and the RFC 4028
/// 422 higher-Session-Expires re-INVITE both take this path (RFC 5923 connection
/// reuse).
///
/// The CSeq-1 INVITE, its non-2xx final response, and any server nonce all
/// traversed one specific trunk member. The retry is a *fresh* pre-dialog
/// transaction (new Via branch, new CSeq, no To-tag yet), so the in-dialog
/// connection-reuse path doesn't apply to it. Re-resolving the trunk hostname
/// here would re-run the RFC 3263 §4.2 A/AAAA shuffle and can pick a *different*
/// member than the one that issued the challenge — on a strict trunk a 401 retry
/// draws another 401 (auth loop), and even on a lenient trunk it splits one
/// INVITE transaction across two members (fragile CANCEL/BYE/session-timer
/// correlation, per-member state divergence).
///
/// So when the failed leg has a recorded destination, reuse it verbatim
/// (address + transport + connection_id): for TCP/TLS [`send_to_target`] then
/// reuses the pooled connection to that member (keyed by address); for UDP it
/// pins the datagram to the same member. Only when the leg has no recorded
/// destination (defensive — in the live path `b_leg_dest` is derived from the
/// same matched leg as the target URI) do we resolve `target_uri` afresh and
/// open/pool a new connection.
///
/// Returns `(destination, transport, connection_id, relay_target)`, or `None`
/// when there is no leg destination and `target_uri` does not resolve.
pub(super) fn select_b2bua_retry_destination(
    b_leg_dest: Option<(SocketAddr, Transport)>,
    b_leg_connection_id: ConnectionId,
    target_uri: &str,
    resolver: &SipResolver,
) -> Option<(SocketAddr, Transport, ConnectionId, RelayTarget)> {
    match b_leg_dest {
        Some((member_addr, member_transport)) => Some((
            member_addr,
            member_transport,
            b_leg_connection_id,
            RelayTarget {
                address: member_addr,
                transport: Some(member_transport),
                server_name: None,
            },
        )),
        None => resolve_target(target_uri, resolver).map(|relay_target| {
            let transport = relay_target.transport.unwrap_or(Transport::Udp);
            (
                relay_target.address,
                transport,
                ConnectionId::default(),
                relay_target,
            )
        }),
    }
}

/// Flatten Record-Route header lines into one URI per entry.
///
/// SIP allows multiple URIs per Record-Route header line separated by commas
/// (RFC 3261 §7.3.1), so a Vec of raw header lines can contain anywhere from
/// one URI per element to all URIs on a single element. Splitting on commas
/// preserves wire order; callers reverse only if RFC 3261 §12.1.1 requires it
/// (UAC route-set = Record-Route from 2xx reversed; UAS route-set = in order).
pub(super) fn flatten_record_route_headers(headers: &[String]) -> Vec<String> {
    let mut routes = Vec::new();
    for header_line in headers {
        for entry in header_line.split(',') {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                routes.push(trimmed.to_string());
            }
        }
    }
    routes
}

/// Compute the UAC-side dialog route set (RFC 3261 §12.1.2) from a response's
/// Record-Route header lines: flatten multi-URI lines (RFC 3261 §7.3.1) into one
/// URI per entry, then reverse (the UAC route set is the responder's Record-Route
/// in reverse order). Used for the early dialog (reliable 1xx, RFC 3262 §4) and
/// the confirmed dialog (2xx).
pub(super) fn uac_route_set_from_record_routes(record_routes: &[String]) -> Vec<String> {
    let mut routes = flatten_record_route_headers(record_routes);
    routes.reverse();
    routes
}

/// Store the route set a dialog-establishing 2xx defines on the B-leg it answers
/// (RFC 3261 §12.1.2 — the UAC's route set is that response's `Record-Route`,
/// reversed).
///
/// Split out of the transfer-completion path so the capture is testable against a
/// bare [`CallActorStore`], because the leg is where every later in-dialog request
/// reads its route set from: the ACK for this 2xx, the BYE at hangup, a re-INVITE.
/// A leg that never captured one sends all of them with no `Route` at all, which
/// reaches the peer stripped of the state tokens the proxies in between wrote into
/// their `Record-Route` — a lenient proxy forwards it anyway, one that keys media
/// on that token never opens the media path, and the call answers silent.
///
/// Returns whether a route set was stored. `false` covers the ordinary
/// direct-peer case where the 2xx carries no `Record-Route`, and leaves whatever
/// the leg already had alone.
pub(super) fn store_b_leg_route_set_from_2xx(
    call_actors: &CallActorStore,
    call_id: &str,
    leg_index: usize,
    response: &SipMessage,
) -> bool {
    let route_set = uac_route_set_from_record_routes(
        &response
            .headers
            .get_all("Record-Route")
            .cloned()
            .unwrap_or_default(),
    );
    if route_set.is_empty() {
        return false;
    }
    let Some(mut call) = call_actors.get_call_mut(call_id) else {
        return false;
    };
    let Some(leg) = call.b_legs.get_mut(leg_index) else {
        return false;
    };
    leg.dialog.route_set = route_set;
    true
}

/// Resolve a script-supplied translate-op name (from `call.dial(translate=[(…, "rfc7044")])`)
/// to a [`crate::b2bua::header_policy::TranslateOp`].  Returns `None` for
/// unknown names; the caller is expected to log and skip.
pub(super) fn parse_translate_op_name(
    name: &str,
) -> Option<crate::b2bua::header_policy::TranslateOp> {
    crate::b2bua::header_policy::TranslateOp::from_token(name)
}
