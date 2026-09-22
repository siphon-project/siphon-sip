//! ACKs and retransmit arming for the messages siphon owns: the 2xx it sent
//! the A-leg (RFC 3261 §13.3.1.4) and the reliable provisionals (RFC 3262 §3).
use super::terminate::q850_reason;
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

/// Where a reliable provisional's retransmissions go: the same transport, peer,
/// connection and local socket as the first send, so they look identical to it.
#[derive(Debug, Clone, Copy)]
pub struct ReliableProvisionalRoute {
    pub transport: Transport,
    pub destination: SocketAddr,
    pub connection_id: ConnectionId,
    pub source_local_addr: Option<SocketAddr>,
}

/// Arm the RFC 3262 §3 retransmit task for a reliable provisional a script sent
/// with `reply(reliable=True)`, back to where `request` came from. See
/// [`arm_reliable_provisional_retransmit_on`].
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
    let route = ReliableProvisionalRoute {
        transport: inbound.transport,
        destination: inbound.remote_addr,
        connection_id: inbound.connection_id,
        // Retransmit the reliable 1xx on the same listener the request arrived on
        // so a multi-homed UDP host keeps a consistent source port (matches the
        // initial send).
        source_local_addr: Some(inbound.local_addr),
    };
    arm_reliable_provisional_retransmit_on(
        call_id,
        rseq,
        cseq_num,
        response,
        route,
        Arc::new(tokio::sync::Notify::new()),
        state,
    );
}

/// Arm the RFC 3262 §3 retransmit task for a reliable provisional response.
///
/// Stores a [`ReliableProvisional`] entry in the dispatcher state under
/// `(call_id, rseq)` and spawns a background task that resends `response` along
/// `route` (T1 = 500 ms doubling up to T2 = 4 s) until a matching PRACK notifies
/// the entry's `cancel`, giving up after 64×T1 = 32 s. `stop` ends the
/// retransmissions early, once a final response has gone to the peer (RFC 3262
/// §3: the UAS "SHOULD NOT continue to retransmit"); the entry then stays until
/// 64×T1 has passed, because the UAS "MUST be prepared to process PRACK requests
/// for those outstanding responses".
///
/// The transport-layer write goes through `state.outbound`, the same channel
/// the dispatcher uses, so retransmits look identical to the original send, and
/// each copy is captured to HEP as the original was ([`TaskCapture`]).
pub fn arm_reliable_provisional_retransmit_on(
    call_id: String,
    rseq: u32,
    cseq_num: u32,
    response: SipMessage,
    route: ReliableProvisionalRoute,
    stop: Arc<tokio::sync::Notify>,
    state: &DispatcherState,
) {
    let entry = Arc::new(ReliableProvisional {
        cancel: tokio::sync::Notify::new(),
        stop,
        cseq_num,
    });
    let key = (call_id, rseq);
    state
        .reliable_provisionals
        .insert(key.clone(), Arc::clone(&entry));

    let store = Arc::clone(&state.reliable_provisionals);
    let outbound = Arc::clone(&state.outbound);
    let capture = TaskCapture::for_task(state, route.transport, route.source_local_addr);

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
                _ = entry.cancel.notified() => return,
                _ = entry.stop.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            call_id = %key.0, rseq = key.1,
                            "RFC 3262: no PRACK after 32s — giving up reliable 1xx retransmits"
                        );
                        store.remove_if(&key, |_, current| Arc::ptr_eq(current, &entry));
                        return;
                    }
                    debug!(
                        call_id = %key.0, rseq = key.1, interval_ms = interval.as_millis() as u64,
                        "retransmitting reliable 1xx (RFC 3262)"
                    );
                    if let Some(capture) = &capture {
                        capture.capture(route.destination, route.transport, &bytes);
                    }
                    let _ = outbound.send(OutboundMessage {
                        followups: None,
                        connection_id: route.connection_id,
                        transport: route.transport,
                        destination: route.destination,
                        data: bytes.clone(),
                        source_local_addr: route.source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(cap);
                }
            }
        }

        // A final response went to the peer: no more retransmissions, but a
        // PRACK for this provisional is still matched until 64×T1 has passed.
        tokio::select! {
            _ = entry.cancel.notified() => {}
            _ = tokio::time::sleep_until(deadline) => {
                store.remove_if(&key, |_, current| Arc::ptr_eq(current, &entry));
            }
        }
    });
}

/// [`register_unacked_answer`] then [`start_2xx_retransmits`], for a test that puts
/// a 2xx under retransmission as if it had just been sent. siphon's own answer
/// path registers before it sends, and starts the retransmissions after.
#[cfg(test)]
pub fn arm_b2bua_2xx_retransmit(
    internal_call_id: &str,
    response: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let unacked = register_unacked_answer(internal_call_id, &response, state);
    start_2xx_retransmits(
        unacked,
        response,
        transport,
        destination,
        connection_id,
        source_local_addr,
        state,
    );
}

/// Record the caller's 2xx `response` as waiting for its ACK, under the Call-ID
/// of the dialog it goes out on, which that ACK names: the first half of B2BUA
/// A-leg 2xx retransmission (RFC 3261 §13.3.1.4), [`start_2xx_retransmits`] the
/// second.
///
/// The B2BUA intercepts the A-leg INVITE before a server transaction is created
/// (see `handle_b2bua_invite`), so the transaction layer never retransmits the
/// A-leg 2xx, and the IST would step aside on a 2xx anyway ("TU owns
/// retransmissions"). Without this, a single lost 200 leaves the caller ringing
/// until it CANCELs. What happens at 64×T1 is not the retransmit task's to decide:
/// [`sweep_unacked_uas_2xx`], on the dispatcher's timer tick, ends the call. The
/// task holds no `&DispatcherState` to run the teardown with, and leaving the entry
/// in the store until the sweep claims it is what lets an ACK that races the
/// deadline win. Every 2xx siphon sends the caller is registered this way, relayed
/// (`b_leg_answered`) or its own (`b2bua_send_uas_response`, behind `call.answer()`
/// and the control plane's answer), so both are held to the same deadline.
///
/// From here a BYE for the dialog is held until the ACK (RFC 3261 §15,
/// [`send_or_hold_bye`]), and the 64×T1 sweep holds the 2xx to its deadline. So
/// it comes before anything a peer can react to is sent: the 2xx itself, and the
/// ACK to a callee that may BYE the moment it is ACKed, on another worker. It
/// changes nothing on the wire: retransmission starts only with
/// [`start_2xx_retransmits`], once the 2xx is sent. A 2xx that is held (for a PRACK)
/// is not registered until it goes out.
pub fn register_unacked_answer(
    internal_call_id: &str,
    response: &SipMessage,
    state: &DispatcherState,
) -> Arc<UnackedAnswer> {
    let timers = crate::transaction::timer::TimerConfig::default();
    let unacked = Arc::new(UnackedAnswer {
        cancel: tokio::sync::Notify::new(),
        deadline: tokio::time::Instant::now() + timers.t1 * 64,
        internal_call_id: internal_call_id.to_string(),
    });
    // Keyed by the dialog the 2xx goes out on, which its ACK names.
    let dialog_call_id = response
        .headers
        .call_id()
        .map(|call_id| call_id.to_string())
        .unwrap_or_else(|| internal_call_id.to_string());
    // A second 2xx registered for the same dialog replaces the first: stop the
    // task still retransmitting the one it replaced.
    if let Some(replaced) = state
        .uas_2xx_retransmits
        .insert(dialog_call_id, Arc::clone(&unacked))
    {
        replaced.cancel.notify_one();
    }
    unacked
}

/// Retransmit the caller's 2xx `response`, registered as `unacked`, on the RFC
/// 3261 §17.2.1 UAS schedule (T1 doubling to T2) until the caller's ACK cancels it
/// or 64×T1 has passed. Started once the 2xx is sent: the first copy follows it by
/// T1. An ACK that arrived in between has already cancelled `unacked`, so the task
/// ends before sending any.
pub fn start_2xx_retransmits(
    unacked: Arc<UnackedAnswer>,
    response: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let timers = crate::transaction::timer::TimerConfig::default();
    let outbound = Arc::clone(&state.outbound);
    // Each copy is captured to HEP as the first send was.
    let capture = TaskCapture::for_task(state, transport, source_local_addr);
    let key = unacked.internal_call_id.clone();

    tokio::spawn(async move {
        let mut interval = timers.t1;
        let bytes = bytes::Bytes::from(response.to_bytes());

        loop {
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = unacked.cancel.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= unacked.deadline {
                        debug!(
                            call_id = %key,
                            "A-leg 2xx still unACKed at 64*T1: retransmission stopped, the timer sweep ends the call"
                        );
                        break;
                    }
                    debug!(
                        call_id = %key, interval_ms = interval.as_millis() as u64,
                        "retransmitting A-leg 2xx (RFC 3261 §13.3.1.4)"
                    );
                    if let Some(capture) = &capture {
                        capture.capture(destination, transport, &bytes);
                    }
                    let _ = outbound.send(OutboundMessage {
                        followups: None,
                        connection_id,
                        transport,
                        destination,
                        data: bytes.clone(),
                        source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(timers.t2);
                }
            }
        }
    });
}

/// End every call whose 2xx to the caller went 64×T1 without an ACK, and drop
/// the retransmit entries of calls that ended some other way.
///
/// RFC 3261 §13.3.1.4: when the 2xx has been retransmitted for 64×T1 with no
/// ACK, "the dialog is confirmed, but the session SHOULD be terminated", with a
/// BYE. [`b2bua_unacked_answer_terminate`] runs it through the ordinary
/// teardown, so both legs are BYEd and media, charging and the CDR are closed.
/// Before this the retransmit task only logged, and the call stayed up with a
/// caller that never confirmed it until something else ended it.
///
/// An entry is claimed with a `remove_if` on the very `Arc` found, and only a
/// claimed entry is acted on. The caller's ACK removes the same entry, so of
/// the two, whichever gets to it first decides: an ACK processed before the
/// sweep, even one that lands after the deadline, leaves nothing to claim and
/// no BYE follows it. A call already torn down gets no BYE here either; its
/// entry is just removed, which also stops its 2xx being retransmitted. The
/// exception is a call that ended with the caller's BYE held for this ACK
/// (RFC 3261 §15, [`send_or_hold_bye`]): its 2xx goes on being
/// retransmitted until the deadline, and that held BYE is then the one sent.
///
/// Runs on the 100 ms timer tick. Entries exist only for answers still waiting
/// for their ACK, and an empty store returns straight away.
pub fn sweep_unacked_uas_2xx(state: &DispatcherState) {
    if state.uas_2xx_retransmits.is_empty() {
        return;
    }
    let now = tokio::time::Instant::now();
    // Snapshot first: nothing below runs while a store shard is locked.
    let armed: Vec<(String, Arc<UnackedAnswer>)> = state
        .uas_2xx_retransmits
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    for (dialog_call_id, unacked) in armed {
        // The dialog is part of its call only while one of the call's legs still
        // carries it: a transfer or a takeover can release the party the 2xx went
        // to while the call goes on without it.
        let dialog_ended = !state
            .call_actors
            .get_call(&unacked.internal_call_id)
            .is_some_and(|call| call.carries_dialog(&dialog_call_id));
        // A dialog that ended with its BYE held for this ACK is still owed its 2xx,
        // until the ACK or 64×T1 (RFC 3261 §13.3.1.4, §15).
        let still_owed = !dialog_ended || state.held_byes.contains_key(&dialog_call_id);
        if still_owed && now < unacked.deadline {
            continue;
        }
        let claimed = state
            .uas_2xx_retransmits
            .remove_if(&dialog_call_id, |_, current| Arc::ptr_eq(current, &unacked))
            .is_some();
        if !claimed {
            continue;
        }
        unacked.cancel.notify_one();
        // The dialog was already ended some other way, with its BYE held for the
        // ACK that never came: that BYE is the one the party gets.
        if release_held_bye(&dialog_call_id, state) {
            warn!(
                call_id = %unacked.internal_call_id,
                "RFC 3261 §15: the 2xx was never ACKed within 64*T1, sent the BYE held for it"
            );
            continue;
        }
        if dialog_ended {
            debug!(call_id = %unacked.internal_call_id, "2xx retransmission stopped: its dialog already ended");
            continue;
        }
        warn!(
            call_id = %unacked.internal_call_id,
            "RFC 3261 §13.3.1.4: the caller never ACKed the 2xx within 64*T1, ending the call"
        );
        b2bua_unacked_answer_terminate(&unacked.internal_call_id, state);
    }
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

/// What a call ended because the caller ACKed an offer without an answer
/// carries on its BYEs. Q.850 cause 111, "protocol error, unspecified": the
/// caller broke the offer/answer exchange (RFC 3264 §4 puts the answer to an
/// offer in a 2xx into the ACK). Not 16: nothing about this ending was normal,
/// and no party hung up. The text says which rule was broken.
const NO_ANSWER_IN_ACK_REASON: &str = q850_reason!(111, "No SDP answer in ACK");

/// What a call ended because the media engine refused the caller's answer to an
/// anchored delayed offer carries on its BYEs. Q.850 cause 47, "resource
/// unavailable, unspecified": the media resource the call is anchored on could
/// not complete the session.
const MEDIA_ANCHOR_FAILED_REASON: &str = q850_reason!(47, "Media anchor failed");

/// An SDP answer that declines every stream `offer` makes (RFC 3264 §6): one
/// `m=` line for each offered one, in the same order, with port 0 and the first
/// format the offer listed.
///
/// siphon puts it in the ACK to a 2xx that carried the offer when it has to ACK
/// that 2xx and has no answer from the caller to give: RFC 3261 §13.2.2.4 has an
/// ACK to a 2xx offer carry an answer, and a dialog ending without one still owes
/// it. The origin and connection lines are placeholders, stamped with siphon's
/// own identity by [`stamp_b_leg_origin`].
pub fn rejecting_answer(offer: &[u8]) -> Vec<u8> {
    let mut answer =
        String::from("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n");
    for line in String::from_utf8_lossy(offer).lines() {
        let Some(media) = line.trim_end_matches('\r').strip_prefix("m=") else {
            continue;
        };
        let mut fields = media.split_whitespace();
        let (Some(kind), Some(_port), Some(protocol)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // An m= line lists at least one format, and the answer's has to be one
        // the offer named.
        let format = fields.next().unwrap_or("0");
        answer.push_str(&format!("m={kind} 0 {protocol} {format}\r\n"));
    }
    answer.into_bytes()
}

/// Put `body` on `message`, typed `content_type`, with a Content-Length to match.
pub fn set_sdp_body(message: &mut SipMessage, body: Vec<u8>, content_type: &str) {
    message
        .headers
        .set("Content-Type", content_type.to_string());
    message.body = body;
    message
        .headers
        .set("Content-Length", message.body.len().to_string());
}

/// Give an SDP body siphon sends a B-leg what every SDP relayed toward a leg gets,
/// in the same order as [`own_sdp_toward_leg`]: siphon's `o=` owner, `s=` and `o=`
/// address (topology hiding), the leg's session id at its next version (RFC 3264
/// §8), which this advances, and then the configured `media.sdp_strip_attributes`
/// removed. `content_type` scopes the strip to the SDP part of a multipart body.
///
/// For a caller that already holds the leg, under the call's lock or detached
/// from the call, where `own_sdp_toward_leg` would reserve the version through
/// the store again.
pub fn stamp_b_leg_origin(
    body: &mut Vec<u8>,
    content_type: &str,
    leg: &mut Leg,
    transport: &Transport,
    state: &DispatcherState,
) {
    let host = state.via_host(transport);
    sanitize_sdp_identity(body, &state.sdp_name, Some(&host));
    stamp_sdp_origin(
        body,
        &state.sdp_name,
        leg.dialog.sdp_session_id,
        leg.dialog.sdp_version,
        Some(&host),
    );
    leg.dialog.sdp_version += 1;
    crate::media::body::strip_sdp_attributes(content_type, body, &state.sdp_strip_attributes);
}

/// Absorb an ACK for a 2xx siphon sent on the dialog named `dialog_call_id`, and
/// do what it releases. Returns `false` when the ACK belongs to no such dialog.
///
/// It confirms that dialog. The B-leg's 2xx was ACKed when it arrived (RFC 3261
/// §13.2.2.4, see `ack_b_leg_2xx`), except when that 2xx carried the offer: its
/// ACK has waited for the answer this ACK carries, and goes now. The ACK stops
/// the retransmission of the 2xx siphon sent on this dialog (RFC 3261 §13.3.1.4);
/// the store is keyed by the dialog's Call-ID. Removing the entry is also what
/// keeps the 64*T1 sweep from ending the call: the sweep only acts on an entry it
/// removes itself, so an ACK processed first always wins. No-op if none is armed
/// (the ACK for a non-2xx).
pub fn absorb_b2bua_ack(dialog_call_id: &str, ack: &SipMessage, state: &DispatcherState) -> bool {
    let acked_now = match state.uas_2xx_retransmits.remove(dialog_call_id) {
        Some((_, unacked)) => {
            unacked.cancel.notify_one();
            true
        }
        None => false,
    };
    if let Some(internal_id) = state.call_actors.find_by_sip_call_id(dialog_call_id) {
        // The leg carrying this dialog is confirmed, whichever slot a takeover
        // has moved it to.
        if let Some(mut call) = state.call_actors.get_call_mut(&internal_id) {
            if call.a_leg.dialog.call_id == dialog_call_id {
                call.a_leg.initial_acked = true;
            } else if let Some(leg) = call
                .b_legs
                .iter_mut()
                .find(|leg| leg.dialog.call_id == dialog_call_id)
            {
                leg.initial_acked = true;
            }
        }
        send_delayed_offer_ack(&internal_id, ack, state);
        // A teardown that began while this ACK was on its way may have held the
        // BYE for it (RFC 3261 §15): it goes out now, right after the ACK. Only
        // the ACK that took the answer can find one.
        if acked_now {
            release_held_bye(dialog_call_id, state);
        }
        debug!(call_id = %internal_id, "B2BUA: absorbed A-leg ACK");
        return true;
    }
    // The dialog has ended while its 2xx waited for this ACK, and its BYE was held
    // for it (RFC 3261 §15): the ACK sends it.
    if release_held_bye(dialog_call_id, state) || acked_now {
        debug!(sip_call_id = %dialog_call_id, "B2BUA: ACK for a dialog that has ended");
        return true;
    }
    false
}

/// Send the B-leg ACK held for a delayed offer (see `ack_b_leg_2xx`) with the
/// answer the caller's ACK carries. Called for every caller ACK on a B2BUA call,
/// and a no-op unless an ACK is still held.
///
/// The answer is the caller's SDP with siphon's own identity, as every SDP
/// relayed toward the callee gets. The ACK is then kept as sent, so a
/// retransmission of the 2xx is ACKed with it again, answer included.
///
/// A caller ACK with no body has not answered the offer siphon relayed it
/// (RFC 3264 §4 puts the answer there). siphon has nothing to answer the callee
/// with and no media agreed on either leg, so it ends the call: the teardown ACKs
/// the callee with every stream rejected and BYEs both legs.
///
/// On a media-anchored call the callee's offer went to the media engine when
/// `rtpengine.answer` saw the 2xx carry it, and the engine is still waiting for
/// the answer. The caller's answer goes to the engine as that `answer`, and the
/// callee's ACK carries the SDP the engine returns, so both parties' media runs
/// through the anchor. An engine that refuses leaves no valid answer to give the
/// callee: the call is ended the same way, with Q.850 cause 47.
pub fn send_delayed_offer_ack(call_id: &str, caller_ack: &SipMessage, state: &DispatcherState) {
    let held = state.call_actors.get_call(call_id).is_some_and(|call| {
        call.delayed_offer_ack
            .as_ref()
            .is_some_and(|held| !held.sent)
    });
    if !held {
        return;
    }
    if caller_ack.body.is_empty() {
        warn!(
            call_id = %call_id,
            "B2BUA: the caller ACKed the callee's offer without an answer (RFC 3264 §4); \
             rejecting the offer toward the callee and ending the call"
        );
        b2bua_terminate_call_inner(call_id, Some(NO_ANSWER_IN_ACK_REASON), "b2bua", state);
        return;
    }
    let content_type = caller_ack
        .headers
        .get("Content-Type")
        .or_else(|| caller_ack.headers.get("c"))
        .cloned()
        .unwrap_or_else(|| "application/sdp".to_string());
    let answer = match anchored_answer(call_id, caller_ack, state) {
        AnchoredAnswer::NotAnchored => caller_ack.body.clone(),
        AnchoredAnswer::Rewritten(answer) => answer,
        AnchoredAnswer::Refused => {
            warn!(
                call_id = %call_id,
                "B2BUA: the media engine refused the caller's answer to an anchored delayed offer; \
                 rejecting the offer toward the callee and ending the call"
            );
            b2bua_terminate_call_inner(call_id, Some(MEDIA_ANCHOR_FAILED_REASON), "b2bua", state);
            return;
        }
    };
    let sent = {
        let Some(mut call) = state.call_actors.get_call_mut(call_id) else {
            return;
        };
        // Claimed under the call's lock, so a retransmitted caller ACK racing
        // this one finds it sent and adds nothing.
        let Some(held) = call.delayed_offer_ack.clone().filter(|held| !held.sent) else {
            return;
        };
        let mut body = answer;
        if let Some(leg) = call.b_legs.get_mut(held.b_leg_index) {
            stamp_b_leg_origin(&mut body, &content_type, leg, &held.transport, state);
            leg.initial_acked = true;
            // The answer as the callee gets it is the session description in
            // force on the callee's dialog.
            if let Some(sdp) = sdp_in_body(&content_type, &body) {
                leg.dialog.last_sent_sdp = Some(sdp);
            }
        }
        let mut ack = held.ack.clone();
        set_sdp_body(&mut ack, body, &content_type);
        let sent = crate::b2bua::actor::DelayedOfferAck {
            ack,
            sent: true,
            ..held
        };
        call.delayed_offer_ack = Some(sent.clone());
        sent
    };
    debug!(call_id = %call_id, destination = %sent.destination, "B2BUA: sent the callee's ACK with the caller's answer");
    send_b2bua_to_bleg(
        sent.ack,
        sent.transport,
        sent.destination,
        sent.local_addr,
        state,
    );
}

/// How the caller's answer to a delayed offer reaches the callee.
pub enum AnchoredAnswer {
    /// The call's media is not anchored: the caller's SDP goes as written.
    NotAnchored,
    /// The media engine's answer, for the callee's ACK.
    Rewritten(Vec<u8>),
    /// The media engine refused the answer.
    Refused,
}

/// Send the caller's answer to the media engine when the callee's offer is
/// anchored there and waiting for it: `rtpengine.answer` recorded the session
/// from that offer, with the callee as offerer and no answerer yet.
pub fn anchored_answer(
    call_id: &str,
    caller_ack: &SipMessage,
    state: &DispatcherState,
) -> AnchoredAnswer {
    let Some(a_leg_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return AnchoredAnswer::NotAnchored;
    };
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return AnchoredAnswer::NotAnchored;
    };
    let Some(session) = sessions.get(&a_leg_call_id) else {
        return AnchoredAnswer::NotAnchored;
    };
    if session.to_tag.is_some() {
        // The engine already has an answer for this call, so there is no offer
        // for this ACK to complete there.
        warn!(
            call_id = %call_id,
            "B2BUA: delayed offer on a media-anchored call whose engine session is already answered; \
             the caller's answer is relayed to the callee as it was written"
        );
        return AnchoredAnswer::NotAnchored;
    }
    let Some(caller_tag) = caller_ack
        .typed_from()
        .ok()
        .flatten()
        .and_then(|from| from.tag)
    else {
        return AnchoredAnswer::Refused;
    };
    match b2bua_transfer_rtpengine_answer(
        state,
        session.rtpengine_id(),
        &session.from_tag,
        &caller_tag,
        &caller_ack.body,
        &session.profile,
    ) {
        Some(answer) => {
            sessions.set_to_tag(&a_leg_call_id, caller_tag);
            AnchoredAnswer::Rewritten(answer)
        }
        None => AnchoredAnswer::Refused,
    }
}

/// The ACK still held for a delayed offer on `dialog_leg`'s dialog, completed with
/// an answer that rejects every stream, for a dialog ending before the caller
/// answered. Marks it sent. `None` when no ACK is held for that dialog.
///
/// RFC 3261 §13.2.2.4 still has the 2xx ACKed with a valid answer, and §15 lets
/// the dialog be released with a BYE only once it is. The returned ACK goes out
/// right before that BYE: see [`send_or_hold_bye`]. The leg is found on the call
/// by its Call-ID, since a transfer can move it or take it off the call; a leg
/// taken off is stamped from `dialog_leg` itself.
pub fn take_held_ack_rejecting_offer(
    call_id: &str,
    dialog_leg: &Leg,
    state: &DispatcherState,
) -> Option<crate::b2bua::actor::DelayedOfferAck> {
    let mut call = state.call_actors.get_call_mut(call_id)?;
    let held = call.delayed_offer_ack.clone().filter(|held| {
        !held.sent
            && held
                .ack
                .headers
                .call_id()
                .is_some_and(|ack_call_id| *ack_call_id == dialog_leg.dialog.call_id)
    })?;
    let mut body = rejecting_answer(&held.offer);
    match call
        .b_legs
        .iter_mut()
        .find(|leg| leg.dialog.call_id == dialog_leg.dialog.call_id)
    {
        Some(leg) => {
            stamp_b_leg_origin(&mut body, "application/sdp", leg, &held.transport, state);
            leg.initial_acked = true;
            leg.dialog.last_sent_sdp = Some(body.clone());
        }
        None => {
            let mut detached = dialog_leg.clone();
            stamp_b_leg_origin(
                &mut body,
                "application/sdp",
                &mut detached,
                &held.transport,
                state,
            );
        }
    }
    let mut ack = held.ack.clone();
    set_sdp_body(&mut ack, body, "application/sdp");
    let sent = crate::b2bua::actor::DelayedOfferAck {
        ack,
        sent: true,
        ..held
    };
    call.delayed_offer_ack = Some(sent.clone());
    Some(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer_text(offer: &str) -> String {
        String::from_utf8(rejecting_answer(offer.as_bytes())).expect("the answer is UTF-8")
    }

    /// RFC 3264 §6: one m= line per offered stream, in order, port 0, with a
    /// format the offer named.
    #[test]
    fn a_rejecting_answer_declines_every_offered_stream_in_order() {
        let answer = answer_text(concat!(
            "v=0\r\n",
            "o=callee 1 1 IN IP4 198.51.100.5\r\n",
            "s=-\r\n",
            "c=IN IP4 198.51.100.5\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8 0 101\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "m=video 30002 RTP/SAVPF 96\r\n",
            "a=rtpmap:96 H264/90000\r\n",
            "m=application 30004 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        ));
        let media: Vec<&str> = answer
            .lines()
            .filter(|line| line.starts_with("m="))
            .collect();
        assert_eq!(
            media,
            [
                "m=audio 0 RTP/AVP 8",
                "m=video 0 RTP/SAVPF 96",
                "m=application 0 UDP/DTLS/SCTP webrtc-datachannel",
            ]
        );
        assert!(answer.starts_with("v=0\r\no="), "{answer}");
        assert!(
            !answer.contains("a="),
            "a rejected stream carries no attributes"
        );
    }

    #[test]
    fn a_rejecting_answer_to_an_offer_with_no_streams_is_a_bare_session() {
        let answer = answer_text("v=0\r\no=- 1 1 IN IP4 198.51.100.5\r\ns=-\r\nt=0 0\r\n");
        assert!(!answer.contains("m="), "{answer}");
        assert!(answer.contains("t=0 0\r\n"));
    }

    #[test]
    fn a_body_set_on_a_message_carries_its_own_type_and_length() {
        let mut message = SipMessageBuilder::new()
            .request(Method::Ack, SipUri::new("198.51.100.5".to_string()))
            .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-body".to_string())
            .from("<sip:a@192.0.2.1>;tag=a".to_string())
            .to("<sip:b@198.51.100.5>;tag=b".to_string())
            .call_id("body@192.0.2.1".to_string())
            .cseq("1 ACK".to_string())
            .content_length(0)
            .build()
            .expect("an ACK builds");
        set_sdp_body(&mut message, b"v=0\r\n".to_vec(), "application/sdp");
        assert_eq!(
            message.headers.get("Content-Type").map(String::as_str),
            Some("application/sdp")
        );
        assert_eq!(
            message.headers.get("Content-Length").map(String::as_str),
            Some("5")
        );
        assert_eq!(message.body, b"v=0\r\n");
    }
}
