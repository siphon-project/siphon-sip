//! ACKs and retransmit arming for the messages siphon owns: the 2xx it sent
//! the A-leg (RFC 3261 §13.3.1.4) and the reliable provisionals (RFC 3262 §3).
use crate::dispatcher::*;

/// Everything the ACK for a re-INVITE's final response is built from.
///
/// A struct rather than ten arguments: the re-INVITE response arm has already
/// worked out each field (which party is the responder, its Contact, its CSeq,
/// the sent-by to advertise) by the time the ACK is due.
pub struct ReinviteAck<'a> {
    /// The responder's own `Contact` — the remote target (RFC 3261 §12.2.1.1).
    pub request_uri: SipUri,
    /// Transport token for the `Via` (`UDP` / `TCP` / `TLS` / `WS` / `WSS`).
    pub via_transport: &'a str,
    pub via_host: &'a str,
    pub via_port: u16,
    /// Fresh for a 2xx (§13.2.2.4), the request's own for a non-2xx (§17.1.1.3).
    pub branch: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub call_id: &'a str,
    /// The responder's CSeq number — the one the re-INVITE went out with.
    pub cseq_number: &'a str,
    /// The dialog's route set, as stored on the tracking leg when the re-INVITE
    /// was sent.
    pub route_set: &'a [String],
}

/// Build the ACK a re-INVITE's final response is owed (RFC 3261 §13.2.2.4 for a
/// 2xx, §17.1.1.3 for a final non-2xx).
///
/// Pure, so the invariant that no two-party test can see is unit-testable: the
/// ACK carries the dialog's route set. A mid-dialog 2xx does not re-advertise
/// `Record-Route`, so the route set cannot be recovered from the response the
/// way an initial INVITE's ACK recovers it (§12.1.2) — it has to come from the
/// dialog, and an ACK sent without it reaches the responder stripped of the
/// state tokens the proxies in between wrote into their `Record-Route`.
pub fn build_reinvite_ack(ack: ReinviteAck<'_>) -> Option<SipMessage> {
    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, ack.request_uri)
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            ack.via_transport, ack.via_host, ack.via_port, ack.branch,
        ))
        .from(ack.from.to_string())
        .to(ack.to.to_string())
        .call_id(ack.call_id.to_string())
        .cseq(format!("{} ACK", ack.cseq_number))
        .header("Max-Forwards", "70".to_string());
    for route in ack.route_set {
        builder = builder.header("Route", route.clone());
    }
    builder
        .content_length(0)
        .build()
        .map_err(|error| {
            error!(%error, "B2BUA ACK for re-INVITE build failed");
            error
        })
        .ok()
}

/// Build the ACK for a 2xx (or final non-2xx) to a request siphon originated on
/// a leg it owns.
///
/// The dialog identity comes off the response itself (RFC 3261 §13.2.2.4: the
/// ACK's To carries the tag the 2xx assigned, and its Request-URI is the
/// responder's Contact), with the leg's stored remote target as the fallback for
/// a 2xx that carried no Contact. `ack_branch` is a fresh branch for a 2xx and
/// the request's own for a final non-2xx (§17.1.1.3).
pub fn build_ack_for_owned_leg(
    leg: &Leg,
    response: &SipMessage,
    ack_branch: &str,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let (via_host, via_port) = leg_sent_by(leg, state);
    build_owned_leg_ack(leg, response, ack_branch, &via_host, via_port)
}

/// Pure half of [`build_ack_for_owned_leg`], split out so the invariant that is
/// invisible in a two-party test is unit-testable: the ACK carries the dialog's
/// route set, so it reaches the responder through the same proxies the request
/// traversed (RFC 3261 §12.2.1.1). Without it the ACK arrives stripped of the
/// state tokens those proxies wrote into their `Record-Route`; a lenient proxy
/// still forwards it, one that keys media on that token never opens the path and
/// the call answers with no audio.
///
/// The caller supplies the local `via_host` / `via_port` (from [`leg_sent_by`]),
/// the only thing the ACK needs that is not on the leg or the response.
pub fn build_owned_leg_ack(
    leg: &Leg,
    response: &SipMessage,
    ack_branch: &str,
    via_host: &str,
    via_port: u16,
) -> Option<SipMessage> {
    let request_uri = response
        .headers
        .get("Contact")
        .or_else(|| response.headers.get("m"))
        .map(|value| crate::b2bua::actor::extract_contact_uri(value))
        .and_then(|uri| parse_uri_standalone(&uri).ok())
        .or_else(|| {
            leg.dialog
                .remote_contact
                .as_deref()
                .and_then(|uri| parse_uri_standalone(uri).ok())
        })
        .or_else(|| {
            leg.dialog
                .target_uri
                .as_deref()
                .and_then(|uri| parse_uri_standalone(uri).ok())
        })
        .unwrap_or_else(|| {
            SipUri::new(leg.transport.remote_addr.ip().to_string())
                .with_port(leg.transport.remote_addr.port())
        });
    let cseq_num = response
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "1".to_string());
    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri)
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            format!("{}", leg.transport.transport).to_uppercase(),
            via_host,
            via_port,
            ack_branch,
        ))
        .from(response.headers.from().cloned().unwrap_or_default())
        .to(response.headers.to().cloned().unwrap_or_default())
        .call_id(leg.dialog.call_id.clone())
        .cseq(format!("{cseq_num} ACK"))
        .header("Max-Forwards", "70".to_string());
    // RFC 3261 §12.2.1.1 — every request within the dialog carries its route set,
    // the ACK for a 2xx included. The leg's own route set is used rather than the
    // response's Record-Route because this builder also serves in-dialog requests
    // whose response does not re-advertise it (§12.1.2 applies to the dialog's
    // first 2xx only, and the caller stores that on the leg).
    for route in &leg.dialog.route_set {
        builder = builder.header("Route", route.clone());
    }
    builder
        .content_length(0)
        .build()
        .map_err(|error| {
            error!(call_id = %leg.dialog.call_id, %error, "B2BUA: ACK build failed for an owned leg");
            error
        })
        .ok()
}

/// Arm the RFC 3262 §3 retransmit task for a reliable provisional response.
///
/// Stores a [`ReliableProvisional`] entry in the dispatcher state under
/// `(Call-ID, RSeq)` and spawns a background task that resends `response`
/// every interval (T1 = 500 ms doubling up to T2 = 4 s, max 64×T1 = 32 s).
/// The task watches the entry's [`tokio::sync::Notify`] and exits as soon
/// as the inbound-PRACK handler signals a match — see the proxy PRACK
/// short-circuit in [`run`].
///
/// The transport-layer write goes through `state.outbound`, the same channel
/// the dispatcher uses, so retransmits look identical to the original send.
pub fn arm_reliable_provisional_retransmit(
    rseq: u32,
    request: &SipMessage,
    response: SipMessage,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let call_id = request.headers.call_id().cloned().unwrap_or_default();
    let cseq_num = request
        .headers
        .cseq()
        .and_then(|c| c.split_whitespace().next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(1);
    let entry = Arc::new(ReliableProvisional {
        cancel: tokio::sync::Notify::new(),
        cseq_num,
    });
    state
        .reliable_provisionals
        .insert((call_id.clone(), rseq), Arc::clone(&entry));

    let store = Arc::clone(&state.reliable_provisionals);
    let outbound = Arc::clone(&state.outbound);
    let destination = inbound.remote_addr;
    let transport = inbound.transport;
    let connection_id = inbound.connection_id;
    // Retransmit the reliable 1xx on the same listener the request arrived on so a
    // multi-homed UDP host keeps a consistent source port (matches the initial send).
    let source_local_addr = Some(inbound.local_addr);
    let key = (call_id.clone(), rseq);

    tokio::spawn(async move {
        // RFC 3262 §3 timing: start at T1 = 500 ms, double on each retransmit
        // up to T2 = 4 s, give up after 64 × T1 = 32 s if no PRACK.
        let mut interval = std::time::Duration::from_millis(500);
        let cap = std::time::Duration::from_secs(4);
        let started = tokio::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(32);
        let bytes = bytes::Bytes::from(response.to_bytes());

        loop {
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = entry.cancel.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            call_id = %key.0, rseq = key.1,
                            "RFC 3262: no PRACK after 32s — giving up reliable 1xx retransmits"
                        );
                        store.remove(&key);
                        break;
                    }
                    debug!(
                        call_id = %key.0, rseq = key.1, interval_ms = interval.as_millis() as u64,
                        "retransmitting reliable 1xx (RFC 3262)"
                    );
                    let _ = outbound.send(OutboundMessage {
                        followups: None,
                        connection_id,
                        transport,
                        destination,
                        data: bytes.clone(),
                        source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(cap);
                }
            }
        }
    });
}

/// Arm B2BUA A-leg 2xx retransmission (RFC 3261 §13.3.1.4).
///
/// The B2BUA intercepts the A-leg INVITE before a server transaction is
/// created (see `handle_b2bua_invite`), so the transaction layer never
/// retransmits the A-leg 2xx — and the IST would step aside on 2xx anyway
/// ("TU owns retransmissions"). Without this, a single lost 200 leaves the
/// caller ringing until it CANCELs. Stores a `Notify` under the internal call
/// ID and spawns a task that resends `response` on the RFC 3261 §17.2.1 UAS
/// schedule (T1 = 500 ms doubling to T2 = 4 s, give up after 64×T1 = 32 s).
/// The late-ACK handler fires the `Notify` when the caller's ACK arrives.
///
/// Mirrors [`arm_reliable_provisional_retransmit`]. On give-up it removes its
/// own entry and warns (a genuinely abandoned answered call is reclaimed by the
/// session timer / orphan sweep) rather than tearing down from the task, which
/// would need a `&DispatcherState` the spawned future cannot hold.
pub fn arm_b2bua_2xx_retransmit(
    internal_call_id: &str,
    response: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let entry = Arc::new(tokio::sync::Notify::new());
    state
        .uas_2xx_retransmits
        .insert(internal_call_id.to_string(), Arc::clone(&entry));

    let store = Arc::clone(&state.uas_2xx_retransmits);
    let outbound = Arc::clone(&state.outbound);
    let key = internal_call_id.to_string();

    tokio::spawn(async move {
        // RFC 3261 §17.2.1 UAS timing: start at T1 = 500 ms, double on each
        // retransmit up to T2 = 4 s, give up after 64 × T1 = 32 s if no ACK.
        let mut interval = std::time::Duration::from_millis(500);
        let cap = std::time::Duration::from_secs(4);
        let started = tokio::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(32);
        let bytes = bytes::Bytes::from(response.to_bytes());

        loop {
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = entry.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            call_id = %key,
                            "RFC 3261 §13.3.1.4: no ACK after 32s — giving up A-leg 2xx retransmits"
                        );
                        store.remove(&key);
                        break;
                    }
                    debug!(
                        call_id = %key, interval_ms = interval.as_millis() as u64,
                        "retransmitting A-leg 2xx (RFC 3261 §13.3.1.4)"
                    );
                    let _ = outbound.send(OutboundMessage {
                        followups: None,
                        connection_id,
                        transport,
                        destination,
                        data: bytes.clone(),
                        source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(cap);
                }
            }
        }
    });
}

/// Handle an A-leg PRACK in a B2BUA call (RFC 3262).
///
/// The B2BUA strips Require/RSeq from forwarded reliable provisionals (see
/// sanitize_b2bua_response) so a well-behaved A-leg never sends PRACK in
/// the first place. This handler exists for A-legs that PRACK anyway —
/// either because the original INVITE carried Require: 100rel, or because
/// the UAC is configured to PRACK whenever it sent Supported: 100rel. The
/// B-leg side is already PRACKed locally by the auto-PRACK path in the
/// response handler, so all that's left is to terminate the A-leg PRACK
/// transaction with 200 OK.
pub fn handle_b2bua_prack(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    debug!(
        call_id = %message.headers.get("Call-ID").map(|s| s.as_str()).unwrap_or(""),
        "B2BUA: auto-200 OK for A-leg PRACK",
    );
    // Answer the PRACK on its arrival socket (multi-homed UDP source-port parity).
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// Handle a mid-dialog re-INVITE for a B2BUA call.
///
/// Re-INVITEs are used for session timer refreshes (RFC 4028), hold/resume,
/// and codec renegotiation. They are forwarded to the other leg transparently.
/// Answer an in-dialog offer the media engine will not anchor with 488 Not Acceptable Here (RFC 3261
/// §14.2; under §14.1 the offerer then keeps the session exactly as it was, which is the safe
/// outcome). Forwarding the offer with its own SDP instead would route both parties around the
/// anchor — each told the other's real address — and nothing downstream reports a fault.
///
/// `clear_pending_on_a_leg` names the leg whose glare flag the caller took before reaching this
/// point (`Some(!from_a_leg)` on the re-INVITE path, `None` on UPDATE, which takes none): leaving it
/// set would have the dialog answer 491 to every later re-INVITE.
pub fn reject_unanchorable_offer(
    message: &SipMessage,
    inbound: &InboundMessage,
    state: &DispatcherState,
    call_id: &str,
    clear_pending_on_a_leg: Option<bool>,
) {
    if let Some(on_a_leg) = clear_pending_on_a_leg {
        state
            .call_actors
            .set_pending_reinvite(call_id, on_a_leg, false);
    }
    let response = build_response(
        message,
        488,
        "Not Acceptable Here",
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
}
