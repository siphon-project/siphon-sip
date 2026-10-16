//! `proxy.release`: a proxy ending a session it Record-Routed, from outside any
//! SIP transaction (an Rx abort, an N5 termination, a media timeout, a timer).
//!
//! TS 24.229 §5.2.8.1 has the P-CSCF do exactly this when the bearer of a
//! session is gone: a confirmed dialog gets a BYE "based on the information
//! saved for the related dialog" (§5.2.8.1.2), a session still being
//! established gets a CANCEL downstream and a final response upstream
//! (§5.2.8.1.1), and a request that arrives on a dialog it released is answered
//! `481` (§5.2.8.1.3). The dialog state is the proxy's own
//! ([`crate::proxy::dialog_state::ProxyDialogStore`]), kept for every INVITE the
//! script Record-Routes once `dialog.proxy_release` is on, so a script never has
//! to shadow CSeqs or route sets to cover a rare event.
//!
//! What a relayed BYE closes in Rust is closed here too: the Rf ACR-STOP
//! (TS 32.299 §6.2.2) and the CDR. Media and QoS sessions in proxy mode belong
//! to the script (`rtpengine.delete`, `diameter.rx_str`), as they do for a BYE
//! it relays, and the script that calls `proxy.release` ends them itself.

use std::time::{Duration, Instant};

use crate::b2bua::actor::publish_dialog_states;
use crate::dispatcher::*;
use crate::proxy::dialog_state::{DialogKey, Release, ReleaseBye, Toward, RELEASE_HOLD};

/// Where a BYE of a release goes, and from which socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReleaseEgress {
    pub(super) destination: SocketAddr,
    pub(super) transport: Transport,
    pub(super) connection_id: ConnectionId,
    /// The socket to send from: the SA's P-CSCF port toward a UE on IPsec
    /// (TS 33.203 §7.4), or the listener the dialog's hop is pinned to.
    pub(super) source: Option<SocketAddr>,
}

/// The next hop of `bye`, the way a relayed in-dialog request toward the same
/// end finds it (RFC 3261 §12.2.1.1): the first Route URI when there is a route
/// set, else the Request-URI. `ipsec` is the SA lookup
/// ([`crate::script::api::ipsec::outbound_for`] on a live node): a destination
/// on a registered SA pair leaves from the SA's P-CSCF port over the SA's
/// transport, as the relay's IPsec egress step has it.
///
/// With no route set and no SA, the BYE goes to the hop the dialog's INVITE
/// came from or went to, rather than to the Contact resolved afresh: that is
/// the address in-dialog traffic from that end actually arrives from (a UE
/// behind NAT, a flow siphon holds), and the one siphon has a connection to.
pub(super) fn release_egress(
    bye: &ReleaseBye,
    resolver: &SipResolver,
    ipsec: &dyn Fn(SocketAddr, Transport) -> Option<(SocketAddr, Transport)>,
) -> ReleaseEgress {
    let hop = bye.hop;
    let pinned =
        |destination: SocketAddr, transport: Transport, connection_id: ConnectionId| match ipsec(
            destination,
            transport,
        ) {
            Some((source, sa_transport)) => ReleaseEgress {
                destination,
                transport: sa_transport,
                connection_id: ConnectionId::default(),
                source: Some(source),
            },
            None => ReleaseEgress {
                destination,
                transport,
                connection_id,
                source: (destination == hop.destination)
                    .then_some(hop.local_addr)
                    .flatten(),
            },
        };
    match first_route_uri(&bye.route) {
        Some(next_hop) => {
            let (destination, transport, connection_id) = resolve_in_dialog_flow_uri(
                Some(&next_hop),
                resolver,
                hop.destination,
                hop.transport,
                hop.connection_id,
            );
            pinned(destination, transport, connection_id)
        }
        None => {
            if let Some(target) = resolve_target(&bye.request_uri, resolver) {
                let transport = target.transport.unwrap_or(hop.transport);
                if ipsec(target.address, transport).is_some() {
                    return pinned(target.address, transport, ConnectionId::default());
                }
            }
            pinned(hop.destination, hop.transport, hop.connection_id)
        }
    }
}

/// The BYE of `bye` as it goes out of `egress`, with `reason` (RFC 3326) when
/// the script gave one.
pub(super) fn release_bye_request(
    bye: &ReleaseBye,
    egress: &ReleaseEgress,
    reason: Option<&str>,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let transport = egress.transport;
    let (host, port) = match egress.source {
        Some(local) => pinned_sent_by(local, || state.wildcard_pinned_sent_by(&transport, local)),
        None => (state.via_host(&transport), state.via_port(&transport)),
    };
    let mut raw = format!(
        "BYE {ruri} SIP/2.0\r\nVia: SIP/2.0/{transport} {host}:{port};branch={branch}\r\nMax-Forwards: 70\r\n",
        ruri = bye.request_uri,
        transport = format!("{transport}").to_uppercase(),
        branch = bye.branch,
    );
    for route in &bye.route {
        raw.push_str(&format!("Route: {route}\r\n"));
    }
    raw.push_str(&format!(
        "From: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {} BYE\r\n",
        bye.from, bye.to, bye.call_id, bye.cseq
    ));
    if let Some(reason) = reason {
        raw.push_str(&format!("Reason: {reason}\r\n"));
    }
    if let Some(user_agent) = state.user_agent_header.as_deref() {
        raw.push_str(&format!("User-Agent: {user_agent}\r\n"));
    }
    raw.push_str("Content-Length: 0\r\n\r\n");
    match parse_sip_message_bytes(raw.as_bytes()) {
        Ok(message) => Some(message),
        Err(error) => {
            error!(call_id = %bye.call_id, end = ?bye.end, %error, "proxy.release: could not build the BYE");
            None
        }
    }
}

/// `proxy.release` from a script, on whatever thread it runs: the running
/// dispatcher's [`proxy_release`]. `false` when no dispatcher is running.
pub(crate) fn proxy_release_call(
    call_id: &str,
    reason: Option<&str>,
    toward: Toward,
    status: u16,
) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    // The caller may be on a thread with no tokio context (an asyncio loop of
    // the script pool, a media event driver); the sends and the spawned waits
    // below need one.
    let _enter = control.runtime.enter();
    proxy_release(&control.state, call_id, reason, toward, status)
}

/// End every dialog of `call_id` this proxy keeps state for. A confirmed one
/// gets a BYE toward each end in `toward`; one still being established has its
/// branches CANCELled and the caller answered `status` (both with `reason`).
/// Returns whether the Call-ID named a dialog that was ended; an unknown or
/// already ended one is `false` and puts nothing on the wire.
pub(super) fn proxy_release(
    state: &DispatcherState,
    call_id: &str,
    reason: Option<&str>,
    toward: Toward,
    status: u16,
) -> bool {
    let releases = state.proxy_dialogs.release(call_id, toward, Instant::now());
    let mut released = false;
    for release in releases {
        match release {
            Release::Confirmed { key, byes, reports } => {
                publish_dialog_states(reports);
                send_release_byes(&key, byes, reason, state);
                released = true;
            }
            Release::Early { key } => {
                released |= release_pending_invite(&key, reason, status, state);
            }
        }
    }
    released
}

/// Put the BYEs of one released dialog on the wire, close its accounting, and
/// forget the dialog once each BYE is answered.
fn send_release_byes(
    key: &DialogKey,
    byes: Vec<ReleaseBye>,
    reason: Option<&str>,
    state: &DispatcherState,
) {
    if byes.is_empty() {
        warn!(
            call_id = %key.0,
            "proxy.release: the dialog has no Contact stored for the ends asked for, so no BYE could be built"
        );
    }
    let mut first: Option<SipMessage> = None;
    for bye in byes {
        let egress = release_egress(&bye, &state.dns_resolver, &|destination, transport| {
            crate::script::api::ipsec::outbound_for(destination, transport)
        });
        let Some(request) = release_bye_request(&bye, &egress, reason, state) else {
            state.proxy_dialogs.release_answered(key);
            continue;
        };
        info!(
            call_id = %key.0,
            end = ?bye.end,
            destination = %egress.destination,
            transport = %egress.transport,
            cseq = bye.cseq,
            "proxy.release: BYE (TS 24.229 §5.2.8.1.2)"
        );
        let answered = state.uac_sender.expect_response(&bye.branch);
        if first.is_none() {
            first = Some(request.clone());
        }
        if egress.transport == Transport::Udp || egress.connection_id == ConnectionId::default() {
            // Datagrams get the RFC 3261 §17.1.2 retransmissions every request
            // siphon originates gets; a stream with no held connection goes
            // through the pool.
            send_b2bua_to_bleg(
                request,
                egress.transport,
                egress.destination,
                egress.source,
                state,
            );
        } else {
            send_message_from(
                request,
                egress.transport,
                egress.destination,
                egress.connection_id,
                egress.source,
                state,
            );
        }
        settle_release_bye(key.clone(), bye.branch, answered, state);
    }
    if let Some(bye) = first {
        // One ACR-STOP for the session, as a relayed BYE closes it; a BYE of the
        // same dialog seen later finds the record already stopped.
        spawn_rf_proxy_stop_if_tracked(state, &bye);
        if crate::cdr::auto_emit_enabled() {
            cdr_finalize(
                &state.cdr_sessions,
                &cdr_dialog_key(&key.0, &key.1),
                "proxy",
                None,
                cdr_extract_reason(&bye),
            );
        }
    }
}

/// Wait for the response to the BYE on `branch` (or give up at 64*T1), then
/// let the released dialog go once none of its BYEs is still out.
fn settle_release_bye(
    key: DialogKey,
    branch: String,
    answered: tokio::sync::oneshot::Receiver<crate::uac::UacResult>,
    state: &DispatcherState,
) {
    let store = Arc::clone(&state.proxy_dialogs);
    let uac_sender = Arc::clone(&state.uac_sender);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        store.release_answered(&key);
        return;
    };
    runtime.spawn(async move {
        let wait = RELEASE_HOLD + Duration::from_secs(1);
        match tokio::time::timeout(wait, answered).await {
            Ok(Ok(crate::uac::UacResult::Response(response))) => debug!(
                call_id = %key.0,
                status = response.status_code().unwrap_or(0),
                "proxy.release: BYE answered"
            ),
            _ => {
                uac_sender.expire_branch(&branch);
                debug!(call_id = %key.0, "proxy.release: BYE unanswered");
            }
        }
        store.release_answered(&key);
    });
}

/// Abandon the INVITE of the early dialog `key`: CANCEL every pending branch
/// and answer the caller `status` (TS 24.229 §5.2.8.1.1), through the same
/// path the caller's own CANCEL takes, so `@proxy.on_cancel` runs once and the
/// CDR is written. Whether there was an INVITE still to abandon.
fn release_pending_invite(
    key: &DialogKey,
    reason: Option<&str>,
    status: u16,
    state: &DispatcherState,
) -> bool {
    let Some(session_arc) = state.session_store.get_by_dialog_key(&key.0, &key.1) else {
        return false;
    };
    let server_key = match session_arc.read() {
        Ok(session) => session.server_key.clone(),
        Err(_) => {
            error!(call_id = %key.0, "proxy.release: proxy session lock poisoned");
            return false;
        }
    };
    let reasons: Vec<String> = reason.map(str::to_string).into_iter().collect();
    let abandoned = abandon_pending_invite(
        &server_key,
        session_arc,
        &reasons,
        status,
        best_error_reason(status),
        state,
    );
    if abandoned {
        info!(call_id = %key.0, status, "proxy.release: INVITE abandoned (TS 24.229 §5.2.8.1.1)");
        publish_dialog_states(state.proxy_dialogs.release_early(key));
    }
    abandoned
}

/// TS 24.229 §5.2.8.1.3: a request on a dialog siphon released, other than one
/// of that release's own BYEs coming back through siphon on a spiral, is
/// answered `481`. Returns whether it was. An ACK has no response and goes on.
pub(super) fn answer_request_on_released_dialog(
    inbound: &InboundMessage,
    message: &SipMessage,
    method: &str,
    state: &DispatcherState,
) -> bool {
    if state.proxy_dialogs.is_empty() || method == "ACK" {
        return false;
    }
    let tag = |value: Option<&String>| {
        value.and_then(|value| {
            value
                .split(';')
                .find_map(|parameter| parameter.trim().strip_prefix("tag="))
                .map(str::to_string)
        })
    };
    let (Some(call_id), Some(from_tag), Some(to_tag)) = (
        message.headers.call_id(),
        tag(message.headers.from()),
        tag(message.headers.to()),
    ) else {
        return false;
    };
    let via_branches: Vec<String> = message
        .headers
        .get_all("Via")
        .into_iter()
        .flatten()
        .filter_map(|raw| Via::parse_multi(raw).ok())
        .flatten()
        .filter_map(|via| via.branch)
        .collect();
    if !state
        .proxy_dialogs
        .is_released(call_id, &from_tag, &to_tag, &via_branches)
    {
        return false;
    }
    debug!(%call_id, %method, "request on a dialog proxy.release ended — 481 (TS 24.229 §5.2.8.1.3)");
    let response = build_response(
        message,
        481,
        "Call/Transaction Does Not Exist",
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
    true
}
