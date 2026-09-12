//! The timer wheel: firing due entries and acting on what they produce.
//!
//! Transaction timers, B2BUA retransmits and media-session cleanup all land
//! here, so this runs on every sweep tick regardless of call rate.

use super::*;

/// Drop siphon-sip's own media-session bookkeeping for a call the media engine
/// already reaped (media-timeout). The engine owns the call and tore it down
/// before emitting the `MediaTimeout` event, so a later safety-net `delete`
/// would just return "unknown call". Every safety-net delete site is gated on
/// `if let Some(session) = rtpengine_sessions.remove(&…)`, so removing the
/// record here makes those sites no-ops — no delete is issued.
///
/// Returns true if a record was actually present (i.e. we cleared something).
pub(super) fn clear_media_session_on_timeout(
    rtpengine_sessions: Option<&Arc<crate::rtpengine::session::MediaSessionStore>>,
    call_id: &str,
) -> bool {
    match rtpengine_sessions {
        Some(store) if store.remove(call_id).is_some() => {
            debug!(
                %call_id,
                "media timeout: dropped media-session bookkeeping (engine already reaped call)"
            );
            true
        }
        _ => false,
    }
}

/// The local UDP socket [`send_to_target`] will egress from for `destination`,
/// given the caller's own pin.
///
/// Mirrors that helper's UDP arm exactly — IPsec auto-source first (the kernel
/// XFRM selector requires it), then the caller's pin — so anything that has to
/// predict where a datagram will leave from (a retransmit schedule, a
/// transaction timer entry) agrees with where it actually left from. Stream
/// transports get `None`: they are reached over a live connection keyed by
/// `connection_id`, and RFC 3261 §17.1.1.2/§17.1.2.2 do not retransmit on a
/// reliable transport anyway.
pub(super) fn udp_egress_source(
    transport: Transport,
    destination: SocketAddr,
    pin: Option<SocketAddr>,
) -> Option<SocketAddr> {
    match transport {
        Transport::Udp => crate::script::api::ipsec::outbound_local_addr_for(destination).or(pin),
        _ => None,
    }
}

/// The local socket a relayed request will actually leave from, so the client
/// transaction's Timer A / Timer E retransmits egress from the same place the
/// first attempt did.
///
/// A retransmission that leaves a different socket is not a retransmission: on
/// a multi-listener host the fallback is the *default* UDP channel — the first
/// configured listener, typically the plain `:5060` — so a request relayed over
/// an IPsec-protected flow would have its retries emitted outside the SA and
/// silently dropped by the peer's kernel selector (3GPP TS 33.203 §7.4). The
/// first send has resolved this correctly since flows shipped; the timer entry
/// pinned `None` and quietly downgraded every retry.
///
/// A captured flow wins outright — that branch bypasses [`send_to_target`] and
/// writes to `flow.local_addr` directly. Everything else defers to
/// [`udp_egress_source`].
pub(super) fn client_retransmit_source(
    outbound_transport: Transport,
    destination: SocketAddr,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    send_socket: Option<&crate::transport::SendSocket>,
) -> Option<SocketAddr> {
    if outbound_transport == Transport::Udp {
        if let Some(flow) = flow {
            return Some(flow.local_addr);
        }
    }
    udp_egress_source(
        outbound_transport,
        destination,
        send_socket.map(|pin| pin.addr),
    )
}

/// Re-emit every siphon-originated B2BUA request whose RFC 3261 §17.1
/// retransmit interval has elapsed, and reap the schedules that reached 64·T1.
///
/// Runs on the same 100 ms tick as [`fire_expired_timers`] and costs nothing
/// when nothing is armed — entries exist only for requests still awaiting
/// their first response.
///
/// Each retransmission goes back out through [`send_outbound_from`] with the
/// **original** `source_local_addr`, so a flow-pinned B-leg's retransmit leaves
/// the same protected socket the first attempt did. Falling back to the default
/// listener here would put the retry outside the IPsec SA, which is precisely
/// the failure this whole path exists to survive (3GPP TS 33.203 §7.4).
pub(super) fn sweep_b2bua_retransmits(state: &DispatcherState) {
    use crate::b2bua::retransmit::Due;

    // `due` walks every shard, so skip it outright on a proxy-only deployment
    // or a B2BUA with nothing in flight — one relaxed atomic read per tick.
    if !state.b2bua_retransmits.is_armed() {
        return;
    }

    for event in state.b2bua_retransmits.due(std::time::Instant::now()) {
        match event {
            Due::Send {
                key,
                data,
                target,
                attempt,
            } => {
                debug!(
                    branch = %key.branch,
                    method = %key.method.as_str(),
                    destination = %target.destination,
                    source = ?target.source_local_addr,
                    transport = %target.transport,
                    attempt,
                    size = data.len(),
                    "B2BUA: retransmitting request (RFC 3261 §17.1)"
                );
                send_outbound_from(
                    data,
                    target.transport,
                    target.destination,
                    target.connection_id,
                    target.source_local_addr,
                    state,
                );
            }
            Due::GaveUp {
                key,
                destination,
                attempts,
            } => {
                warn!(
                    branch = %key.branch,
                    method = %key.method.as_str(),
                    %destination,
                    attempts,
                    "B2BUA: no response after 64*T1 — giving up on retransmitting request"
                );
            }
        }
    }
}

/// Fire all expired timers in the timer wheel.
pub(super) fn fire_expired_timers(state: &DispatcherState) {
    let now = std::time::Instant::now();
    let mut fired: Vec<TimerEntry> = Vec::new();

    state.timer_wheel.retain(|_id, entry| {
        if now >= entry.fires_at {
            // Deref out of the box: the wheel owns boxes, the fired list is
            // consumed by value below.
            fired.push((**entry).clone());
            false // remove from wheel
        } else {
            true
        }
    });

    for entry in fired {
        // Non-ACK INVITE auto-ban signal. Timer H is the INVITE *server*
        // transaction timeout (RFC 3261 §17.2.1 — a non-2xx final was sent and no
        // ACK arrived within 64*T1). That is exactly the toll-fraud-scanner
        // pattern: the peer sent an INVITE, got the 401/403, and walked away
        // without ACKing. `entry.destination` is the UAC (the source), so this can
        // only ever count against the originator — never a downstream relay/trunk
        // (whose failures would surface as ICT Timer B, deliberately not counted).
        if matches!(entry.name, TimerName::H) {
            if let (Some(ban), Some(dest)) = (crate::security::auto_ban(), entry.destination) {
                if ban.record_failure(dest.ip()) {
                    warn!(source = %dest.ip(), "auto-ban: source banned (non-ACK INVITE timeout)");
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.auth_failures_total.inc();
                }
            }
        }

        let event = match entry.name {
            // Server transaction timers
            TimerName::J => Some(ServerEvent::Nist(NistEvent::TimerJ)),
            TimerName::G => Some(ServerEvent::Ist(IstEvent::TimerG)),
            TimerName::H => Some(ServerEvent::Ist(IstEvent::TimerH)),
            TimerName::I => Some(ServerEvent::Ist(IstEvent::TimerI)),
            TimerName::Trying100 => Some(ServerEvent::Nist(NistEvent::Trying100Fired)),
            _ => None,
        };

        if let Some(server_event) = event {
            match state
                .transaction_manager
                .process_server_event(&entry.key, server_event)
            {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        entry.source_local_addr,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
            continue;
        }

        let client_event = match entry.name {
            TimerName::A => Some(ClientEvent::Ict(IctEvent::TimerA)),
            TimerName::B => Some(ClientEvent::Ict(IctEvent::TimerB)),
            TimerName::D => Some(ClientEvent::Ict(IctEvent::TimerD)),
            TimerName::E => Some(ClientEvent::Nict(NictEvent::TimerE)),
            TimerName::F => Some(ClientEvent::Nict(NictEvent::TimerF)),
            TimerName::K => Some(ClientEvent::Nict(NictEvent::TimerK)),
            _ => None,
        };

        if let Some(client_event) = client_event {
            match state
                .transaction_manager
                .process_client_event(&entry.key, client_event)
            {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        entry.source_local_addr,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
        }
    }
}

/// Process actions from a timer-driven state machine event.
///
/// `source_local_addr` is the local socket the original request
/// arrived on — required by 3GPP TS 33.203 §7.4 for IPsec sec-agree
/// (responses cached by server transactions and re-emitted as
/// `Action::SendMessage` must egress on the same socket the request
/// arrived on).  For client transactions or paths where the source
/// doesn't matter, callers pass `None`.
pub(super) fn process_timer_actions(
    actions: &[Action],
    key: &TransactionKey,
    destination: Option<SocketAddr>,
    transport: Option<Transport>,
    connection_id: Option<ConnectionId>,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    process_timer_actions_with_followups(
        actions,
        key,
        destination,
        transport,
        connection_id,
        source_local_addr,
        Vec::new(),
        state,
    )
}

/// As [`process_timer_actions`], but `followups` are appended to the FIRST
/// `Action::SendMessage` so they leave immediately after it, in order, with
/// nothing interleaved (see [`OutboundMessage::followups`]).
///
/// Only the first-send path of a script reply passes a non-empty list. Every
/// other caller — timer-driven retransmits above all — goes through
/// [`process_timer_actions`] with an empty one, so a cached response being
/// re-emitted never drags a stale NOTIFY along with it.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_timer_actions_with_followups(
    actions: &[Action],
    key: &TransactionKey,
    destination: Option<SocketAddr>,
    transport: Option<Transport>,
    connection_id: Option<ConnectionId>,
    source_local_addr: Option<SocketAddr>,
    mut followups: Vec<Bytes>,
    state: &DispatcherState,
) {
    for action in actions {
        match action {
            Action::SendMessage(message) => {
                if let (Some(dest), Some(trans)) = (destination, transport) {
                    let conn_id = connection_id.unwrap_or_default();
                    if followups.is_empty() {
                        send_message_from(
                            message.clone(),
                            trans,
                            dest,
                            conn_id,
                            source_local_addr,
                            state,
                        );
                    } else {
                        send_frames_in_order_from(
                            Bytes::from(message.to_bytes()),
                            std::mem::take(&mut followups),
                            trans,
                            dest,
                            conn_id,
                            source_local_addr,
                            state,
                        );
                    }
                }
            }
            Action::StartTimer(name, duration) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.insert(
                    timer_id,
                    Box::new(TimerEntry {
                        key: key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        destination,
                        transport,
                        connection_id,
                        source_local_addr,
                    }),
                );
            }
            Action::CancelTimer(name) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.remove(&timer_id);
            }
            Action::Timeout => {
                // RFC 3261 §16.7 step 2: when a client transaction times out
                // (Timer B for INVITE, Timer F otherwise), the proxy MUST
                // behave as if a 408 had been received on that branch.  Logging
                // and reaping left the upstream UAC waiting on its `100 Trying`
                // until its own Timer F — the proxy knew the branch was dead 32
                // seconds earlier and said nothing.
                //
                // This is the backstop for *every* way a branch can go quiet,
                // not just the connect failures §16.9 covers: a black-holed
                // route, a peer that accepts the TCP connection and never
                // answers, a datagram lost on the wire.
                //
                // Server transactions reach this arm too (Timer H waiting for
                // an ACK); `fail_branch_locally` no-ops for anything that is
                // not a client branch of a live proxy session.
                warn!(key = %key, "transaction timeout");
                fail_branch_locally(
                    key,
                    408,
                    "Request Timeout",
                    "client transaction timed out (RFC 3261 §16.7)",
                    state,
                );
                // Remaining session cleanup happens via sweep_stale_entries.
            }
            Action::ProtocolError(message) => {
                warn!(key = %key, "transaction protocol error: {message}");
            }
            Action::Terminated | Action::PassToTu(_) => {
                // PassToTu from timer context is unusual (shouldn't happen)
                // Terminated: transaction already auto-removed by manager
            }
        }
    }
}
