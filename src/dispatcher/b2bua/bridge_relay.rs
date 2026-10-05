//! Relaying an in-dialog offer across a formed controller bridge.
//!
//! Each leg of a controller bridge is the A-leg of its own call actor, so the
//! ordinary relay (which forwards an A-leg's re-INVITE to its call's winning
//! B-leg) never sees the other party. Without this a re-offer on a bridged leg
//! looked like a call with nobody on the other side: the anchor's was answered
//! by the engine itself with an `answer_local` on the pair's call-id — which the
//! engine takes as a new single-party call, dropping the relay the other party
//! was on — and the peer's was refused `488` for want of a session of its own.
//!
//! A re-INVITE or UPDATE carrying an offer on either leg of a **formed**
//! bridge is instead relayed to the other leg, as a B2BUA relays any re-offer
//! (RFC 3261 §14, RFC 3311): the offer is re-offered on the pair's engine
//! session under the **sender's** tag, shaped by the **receiver's** side of the
//! bridge ([`crate::rtpengine::session::BridgeSides`]); the other leg is sent a
//! re-INVITE (or UPDATE) of siphon's own with the result; and the answer that
//! comes back goes to the engine as the `answer`, shaped by the sender's side,
//! whose result is the 200 the sender gets. `received_from` is stamped with the
//! signalling source of the party whose SDP each command carries, where that
//! party's own profile asks for it — not the profile that shapes the command,
//! which is the other party's.
//!
//! * **Refused** — the other leg's final status goes back to the sender, and
//!   the engine is put back: the sender's previous media re-offered and closed
//!   with the receiver's current answer, so the relay is where it was before
//!   the offer (RFC 3264 §8: a refused offer leaves the session unchanged).
//! * **Glare** — one relay per pair at a time. An offer on either leg while
//!   either leg has an offer/answer outstanding is refused `491` (RFC 3261
//!   §14.1, RFC 3311 §5.2).
//! * **Bodyless** — a re-INVITE or UPDATE without an offer is a session refresh
//!   (RFC 4028 §10): answered at once from the session in force on that leg
//!   (an INVITE's 2xx has to carry an offer, RFC 3261 §14.2; an UPDATE's needs
//!   none), with nothing sent to the engine or to the other party.
//! * **A leg ending mid-relay** — the sender's pending request is answered
//!   `487` (RFC 3261 §15.1.2), and the relay forgotten.
//! * **No answer** — a relay with no final response after 64·T1 answers the
//!   sender `408` and restores the engine as for a refusal.
use crate::dispatcher::*;

/// Tracking-leg target of a relayed re-INVITE on the receiving leg.
pub const BRIDGE_RELAY_INVITE: &str = "bridge_relay:invite";
/// Tracking-leg target of a relayed UPDATE on the receiving leg.
pub const BRIDGE_RELAY_UPDATE: &str = "bridge_relay:update";
/// A relayed re-INVITE answered 2xx, kept so a retransmitted 2xx is re-ACKed.
pub const BRIDGE_RELAY_DONE_INVITE: &str = "bridge_relay_done:invite";
/// A relayed UPDATE answered 2xx, kept so a retransmitted 2xx is absorbed.
pub const BRIDGE_RELAY_DONE_UPDATE: &str = "bridge_relay_done:update";

/// The pair's engine session as a relay addresses it.
#[derive(Debug, Clone)]
struct RelayMedia {
    media_call_id: String,
    /// The engine tag of the party that sent the offer.
    sender_tag: String,
    /// The engine tag of the party it is relayed to.
    receiver_tag: String,
    /// What shapes SDP the engine sends the sender.
    sender_side: crate::rtpengine::session::SideFlags,
    /// What shapes SDP the engine sends the receiver.
    receiver_side: crate::rtpengine::session::SideFlags,
    /// Whose `received_from` policy pins the sender's media ingress, on the
    /// re-offer that carries the sender's SDP.
    sender_ingress: crate::rtpengine::session::SideFlags,
    /// Whose policy pins the receiver's, on the answer that carries its SDP.
    receiver_ingress: crate::rtpengine::session::SideFlags,
    /// The sender's SIP Call-ID: the dialog the re-offered SDP belongs to.
    sender_sip_call_id: String,
    /// The receiver's SIP Call-ID: the dialog the answer belongs to.
    receiver_sip_call_id: String,
}

/// A relay in flight: the sender's request waits for the receiver's answer.
pub struct PendingBridgeRelay {
    /// The sending leg's `CallActor` id.
    originator_call_id: String,
    /// The sender's request, whose server transaction the relay holds.
    request: SipMessage,
    /// Where the sender's request came from, for its response.
    inbound: InboundMessage,
    /// The sender's media description before this offer, for a restore.
    originator_previous_sdp: Option<Vec<u8>>,
    /// The receiver's current media description, for a restore.
    receiver_current_sdp: Option<Vec<u8>>,
    /// Where the receiver's signalling comes from, for a restore's `answer`.
    receiver_source: std::net::IpAddr,
    /// The offer the receiver was sent, as siphon built it.
    offer: Vec<u8>,
    media: Option<RelayMedia>,
    created_at: std::time::Instant,
}

/// Every relay in flight, keyed by the receiving leg's `CallActor` id. One per
/// pair at a time: the glare rule refuses a second while one is outstanding.
#[derive(Default)]
pub struct BridgeRelayStore {
    pending: DashMap<String, PendingBridgeRelay>,
}

impl std::fmt::Debug for BridgeRelayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BridgeRelayStore")
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl BridgeRelayStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Relays in flight. Drains with the relays — the leak gate.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.pending.len()
    }
}

/// Answer `request` from `inbound` with `status_code`, on the listener it came
/// in on.
fn respond(
    inbound: &InboundMessage,
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let response = build_response(
        request,
        status_code,
        reason,
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

/// Relay an in-dialog re-INVITE or UPDATE on a leg of a formed controller
/// bridge to the other leg. Returns `false` when `call_id` is no such leg, so
/// the ordinary in-dialog handling runs; `true` when the request was taken
/// here, whatever became of it — every request taken is answered.
pub fn relay_bridged_offer(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) -> bool {
    use crate::b2bua::bridge::BridgeStage;

    let Some(context) = state.call_actors.bridge(call_id) else {
        return false;
    };
    // A bridged leg is the A-leg of a call with no B-leg of its own; anything
    // else is an ordinary call and relays the ordinary way.
    if !state
        .call_actors
        .get_call(call_id)
        .is_some_and(|call| call.winner.is_none())
    {
        return false;
    }
    let is_invite = message.method() == Some(&Method::Invite);
    if context.stage != BridgeStage::Bridged {
        // The bridge's own re-INVITEs (forming or releasing) are the offer
        // outstanding on this dialog (RFC 3261 §14.1).
        respond(inbound, message, 491, "Request Pending", state);
        return true;
    }
    if message.body.is_empty() {
        answer_refresh(inbound, message, call_id, is_invite, state);
        return true;
    }

    let receiver = context.peer_call_id.clone();
    if state.call_actors.set_pending_reinvite(call_id, true, true) {
        respond(inbound, message, 491, "Request Pending", state);
        return true;
    }
    if state
        .call_actors
        .set_pending_reinvite(&receiver, true, true)
    {
        state.call_actors.set_pending_reinvite(call_id, true, false);
        respond(inbound, message, 491, "Request Pending", state);
        return true;
    }
    let release_claims = || {
        state.call_actors.set_pending_reinvite(call_id, true, false);
        state
            .call_actors
            .set_pending_reinvite(&receiver, true, false);
    };
    let last_sdp = |leg: &str| {
        state
            .call_actors
            .get_call(leg)
            .and_then(|call| call.a_leg.last_sdp.clone())
    };
    let originator_previous_sdp = last_sdp(call_id);
    let receiver_current_sdp = last_sdp(&receiver);
    let receiver_source = state
        .call_actors
        .get_call(&receiver)
        .map_or(inbound.remote_addr.ip(), |call| {
            call.a_leg.transport.remote_addr.ip()
        });

    let media = match relay_media(&context, call_id, state) {
        Ok(media) => media,
        Err(reason) => {
            warn!(%call_id, %reason, "B2BUA bridge relay: the pair's media cannot take the offer — 488");
            release_claims();
            respond(inbound, message, 488, "Not Acceptable Here", state);
            return true;
        }
    };
    let offer = match &media {
        Some(media) => match reoffer(
            state,
            media,
            &message.body,
            inbound.remote_addr.ip(),
            &media.receiver_side,
        ) {
            Ok(offer) => offer,
            Err(reason) => {
                warn!(%call_id, %reason, "B2BUA bridge relay: the engine refused the offer — 488");
                release_claims();
                respond(inbound, message, 488, "Not Acceptable Here", state);
                return true;
            }
        },
        None => message.body.clone(),
    };
    // The sender's own new description, as the ordinary relay records it.
    state
        .call_actors
        .set_leg_last_sdp(call_id, true, &message.body);

    // Owned before it is on the wire: a receiver that answers at once must
    // find the relay waiting for it.
    state.bridge_relays.pending.insert(
        receiver.clone(),
        PendingBridgeRelay {
            originator_call_id: call_id.to_string(),
            request: message.clone(),
            inbound: inbound.clone(),
            originator_previous_sdp,
            receiver_current_sdp,
            receiver_source,
            offer: offer.clone(),
            media,
            created_at: std::time::Instant::now(),
        },
    );
    if is_invite {
        respond(inbound, message, 100, "Trying", state);
    }
    let sent = if is_invite {
        b2bua_send_reinvite_on_leg(&receiver, true, offer, BRIDGE_RELAY_INVITE, state)
    } else {
        send_update_on_leg(&receiver, offer, state)
    };
    if !sent {
        if let Some((_, pending)) = state.bridge_relays.pending.remove(&receiver) {
            restore(&pending, state);
        }
        release_claims();
        respond(inbound, message, 500, "Server Internal Error", state);
        return true;
    }
    debug!(%call_id, %receiver, is_invite, "B2BUA bridge relay: offer relayed to the other leg");
    true
}

/// A session refresh on a bridged leg: answered from the session in force on
/// it, touching neither the engine nor the other party.
fn answer_refresh(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    is_invite: bool,
    state: &DispatcherState,
) {
    if !is_invite {
        send_one_legged_ok(inbound, message, call_id, Vec::new(), state);
        return;
    }
    let in_force = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg.dialog.last_sent_sdp.clone());
    match in_force {
        Some(sdp) => send_one_legged_ok(inbound, message, call_id, sdp, state),
        None => {
            warn!(%call_id, "B2BUA bridge relay: an offerless re-INVITE on a leg with no session in force — 488");
            respond(inbound, message, 488, "Not Acceptable Here", state);
        }
    }
}

/// The pair's engine session as a relay from `call_id` addresses it, or
/// `None` for a raw crossing.
fn relay_media(
    context: &crate::b2bua::bridge::BridgeContext,
    call_id: &str,
    state: &DispatcherState,
) -> Result<Option<RelayMedia>, String> {
    use crate::b2bua::bridge::BridgeRole;
    use crate::rtpengine::session::{BridgeSides, ProfileHalf, SideFlags};

    let Some(media_call_id) = context.media_call_id.clone() else {
        return Ok(None);
    };
    let from_anchor = context.role == BridgeRole::Anchor;
    // The sending leg's own dialog, and the other leg's as its bridge names it.
    let sender_sip_call_id = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
        .ok_or("the leg is gone")?;
    let receiver_sip_call_id = context.peer_sip_call_id.clone();
    let anchor_key = if from_anchor {
        sender_sip_call_id.clone()
    } else {
        receiver_sip_call_id.clone()
    };
    let session = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|store| store.get(&anchor_key))
        .ok_or("the pair has no media session")?;
    // A session with no sides recorded has one profile describing the pair the
    // way a dial's does: its `offer` half is the one the offerer's (the
    // anchor's) SDP was sent under, its `answer` half the answerer's.
    let half = |half| SideFlags {
        profile: session.profile.clone(),
        half,
    };
    let sides = session.bridge_sides.clone().unwrap_or_else(|| BridgeSides {
        anchor: half(ProfileHalf::Answer),
        peer: half(ProfileHalf::Offer),
        anchor_ingress: half(ProfileHalf::Offer),
        peer_ingress: half(ProfileHalf::Answer),
    });
    let peer_tag = session
        .to_tag
        .clone()
        .ok_or("the pair's session has no tag for the peer")?;
    let anchor_tag = session.from_tag.clone();
    Ok(Some(if from_anchor {
        RelayMedia {
            media_call_id,
            sender_tag: anchor_tag,
            receiver_tag: peer_tag,
            sender_side: sides.anchor,
            receiver_side: sides.peer,
            sender_ingress: sides.anchor_ingress,
            receiver_ingress: sides.peer_ingress,
            sender_sip_call_id,
            receiver_sip_call_id,
        }
    } else {
        RelayMedia {
            media_call_id,
            sender_tag: peer_tag,
            receiver_tag: anchor_tag,
            sender_side: sides.peer,
            receiver_side: sides.anchor,
            sender_ingress: sides.peer_ingress,
            receiver_ingress: sides.anchor_ingress,
            sender_sip_call_id,
            receiver_sip_call_id,
        }
    }))
}

/// `side`'s flags resolved, with `received_from` stamped where `ingress` asks
/// for it and the Call-ID of the dialog whose SDP the command carries.
///
/// Two parties are in play on every command: `side` shapes the SDP the engine
/// sends one of them, and the SDP the command carries — with the `source` it
/// came from — is the other's. `ingress` is that other party's own policy, so
/// neither party is pinned, or left unpinned, by the profile of the one it is
/// talking to.
fn side_flags(
    state: &DispatcherState,
    side: &crate::rtpengine::session::SideFlags,
    ingress: &crate::rtpengine::session::SideFlags,
    source: std::net::IpAddr,
    sip_call_id: &str,
) -> Result<crate::rtpengine::profile::NgFlags, String> {
    let registry = state
        .rtpengine_profiles
        .as_ref()
        .ok_or("no media profiles are configured")?;
    let mut flags = side
        .resolve(registry)
        .ok_or_else(|| format!("unknown media profile '{}'", side.profile))?;
    flags.carry_received_from = ingress.pins_ingress(registry);
    flags.stamp_received_from(source);
    flags.stamp_sip_call_id(sip_call_id);
    Ok(flags)
}

/// Re-offer the sender's `sdp` on the pair's session, shaped by `toward`.
fn reoffer(
    state: &DispatcherState,
    media: &RelayMedia,
    sdp: &[u8],
    sender_source: std::net::IpAddr,
    toward: &crate::rtpengine::session::SideFlags,
) -> Result<Vec<u8>, String> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("no media backend is configured")?;
    let flags = side_flags(
        state,
        toward,
        &media.sender_ingress,
        sender_source,
        &media.sender_sip_call_id,
    )?;
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.reoffer(
            &media.media_call_id,
            &media.sender_tag,
            sdp,
            &flags,
        ))
    })
    .map_err(|error| error.to_string())
}

/// Complete the offer with the receiver's `sdp`, shaped by the sender's side.
fn answer(
    state: &DispatcherState,
    media: &RelayMedia,
    sdp: &[u8],
    receiver_source: std::net::IpAddr,
) -> Result<Vec<u8>, String> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("no media backend is configured")?;
    let flags = side_flags(
        state,
        &media.sender_side,
        &media.receiver_ingress,
        receiver_source,
        &media.receiver_sip_call_id,
    )?;
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer(
            &media.media_call_id,
            &media.sender_tag,
            &media.receiver_tag,
            sdp,
            &flags,
        ))
    })
    .map_err(|error| error.to_string())
}

/// Send `offer` to the bridged leg `call_id` in an UPDATE of siphon's own on
/// its dialog, shaped as every SDP siphon sends that leg is.
fn send_update_on_leg(call_id: &str, mut offer: Vec<u8>, state: &DispatcherState) -> bool {
    let Some(leg) = state.call_actors.clone_leg(call_id, true) else {
        return false;
    };
    let host = state.a_leg_advertised_host(leg.transport.local_addr, &leg.transport.transport);
    crate::dispatcher::sanitize::own_sdp_toward_leg(
        &mut offer,
        "application/sdp",
        state,
        call_id,
        true,
        Some(&host),
    );
    // An UPDATE is a session refresh of its dialog too (RFC 4028 §7.4).
    let (headers, requested_session_expires) = session_timer_headers_for_leg(call_id, true, state);
    send_in_dialog_request(
        call_id,
        true,
        InDialogRequest {
            method: Method::Update,
            body: Some(offer),
            extra_headers: &headers,
            tracking_target: BRIDGE_RELAY_UPDATE,
            requested_session_expires,
        },
        |_| {},
        state,
    )
}

/// Put the engine back where it was before a relay that will not complete:
/// the sender's previous media re-offered and closed with the receiver's
/// current answer, each shaped as the relay's own commands were. The sender's
/// recorded media goes back too.
fn restore(pending: &PendingBridgeRelay, state: &DispatcherState) {
    if let Some(previous) = pending.originator_previous_sdp.as_deref() {
        state
            .call_actors
            .set_leg_last_sdp(&pending.originator_call_id, true, previous);
    }
    let Some(media) = pending.media.as_ref() else {
        return;
    };
    let (Some(previous), Some(current)) = (
        pending.originator_previous_sdp.as_deref(),
        pending.receiver_current_sdp.as_deref(),
    ) else {
        warn!(
            call = %pending.originator_call_id,
            "B2BUA bridge relay: no previous media to restore the pair's session to"
        );
        return;
    };
    let restored = reoffer(
        state,
        media,
        previous,
        pending.inbound.remote_addr.ip(),
        &media.receiver_side,
    )
    .and_then(|_| answer(state, media, current, pending.receiver_source));
    if let Err(reason) = restored {
        warn!(
            call = %pending.originator_call_id,
            %reason,
            "B2BUA bridge relay: the pair's session could not be put back after a relay that did not complete"
        );
    }
}

/// A final response from the receiving leg `call_id` to a relayed offer.
pub fn handle_bridge_relay_response(
    call_id: &str,
    method: &str,
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    snapshot: &BLegResponseSnapshot,
    state: &DispatcherState,
) {
    if status_code < 200 {
        return;
    }
    let is_invite = method == "invite";
    settle_owned_leg_response(
        call_id,
        branch,
        message,
        status_code,
        snapshot,
        OwnedLegRequest {
            done_target: if is_invite {
                BRIDGE_RELAY_DONE_INVITE
            } else {
                BRIDGE_RELAY_DONE_UPDATE
            }
            .to_string(),
            is_invite,
        },
        state,
    );
    let Some((_, pending)) = state.bridge_relays.pending.remove(call_id) else {
        debug!(%call_id, "B2BUA bridge relay: a response for a relay no longer waited on");
        return;
    };
    let originator = pending.originator_call_id.clone();
    state
        .call_actors
        .set_pending_reinvite(&originator, true, false);

    if !(200..300).contains(&status_code) {
        let reason = match &message.start_line {
            StartLine::Response(status) => status.reason_phrase.clone(),
            StartLine::Request(_) => "Refused".to_string(),
        };
        restore(&pending, state);
        respond(
            &pending.inbound,
            &pending.request,
            status_code,
            &reason,
            state,
        );
        return;
    }
    if message.body.is_empty() {
        warn!(%call_id, "B2BUA bridge relay: the other leg accepted the offer without an answer — 500");
        restore(&pending, state);
        respond(
            &pending.inbound,
            &pending.request,
            500,
            "Server Internal Error",
            state,
        );
        return;
    }
    state
        .call_actors
        .set_leg_last_sdp(call_id, true, &message.body);
    let answered = match &pending.media {
        Some(media) => answer(
            state,
            media,
            &message.body,
            snapshot.a_leg.transport.remote_addr.ip(),
        ),
        None => Ok(message.body.clone()),
    };
    let mut body = match answered {
        Ok(body) => body,
        Err(reason) => {
            warn!(%call_id, %reason, "B2BUA bridge relay: the engine refused the other leg's answer — 500");
            respond(
                &pending.inbound,
                &pending.request,
                500,
                "Server Internal Error",
                state,
            );
            return;
        }
    };
    // What each leg now has from siphon is what an unbridge holds it with.
    for (leg, sdp) in [(call_id, &pending.offer), (originator.as_str(), &body)] {
        if let Some(mut call) = state.call_actors.get_call_mut(leg) {
            if let Some(bridge) = call.bridge.as_mut() {
                bridge.last_local_offer = sdp.clone();
            }
        }
    }
    let host = state.a_leg_advertised_host(
        state
            .call_actors
            .clone_leg(&originator, true)
            .and_then(|leg| leg.transport.local_addr),
        &pending.inbound.transport,
    );
    crate::dispatcher::sanitize::own_sdp_toward_leg(
        &mut body,
        "application/sdp",
        state,
        &originator,
        true,
        Some(&host),
    );
    crate::dispatcher::sanitize::record_sdp_sent_to_leg(
        state,
        &originator,
        true,
        "application/sdp",
        &body,
    );
    send_one_legged_ok(&pending.inbound, &pending.request, &originator, body, state);
    debug!(%call_id, %originator, "B2BUA bridge relay: answered the sender");
}

/// A bridged leg is ending: every relay it sends or receives is abandoned and
/// the sender's request answered `487` (RFC 3261 §15.1.2). The engine is left
/// alone — the pair is ending, or the survivor is held by the peer-hangup
/// policy with a fresh offer of its own.
pub fn bridge_relay_call_ended(internal_call_id: &str, state: &DispatcherState) {
    let abandoned: Vec<String> = state
        .bridge_relays
        .pending
        .iter()
        .filter(|entry| {
            entry.key() == internal_call_id || entry.originator_call_id == internal_call_id
        })
        .map(|entry| entry.key().clone())
        .collect();
    for receiver in abandoned {
        let Some((_, pending)) = state.bridge_relays.pending.remove(&receiver) else {
            continue;
        };
        state
            .call_actors
            .set_pending_reinvite(&pending.originator_call_id, true, false);
        state
            .call_actors
            .set_pending_reinvite(&receiver, true, false);
        respond(
            &pending.inbound,
            &pending.request,
            487,
            "Request Terminated",
            state,
        );
        info!(originator = %pending.originator_call_id, %receiver, "B2BUA bridge relay: a leg ended mid-relay — the sender's request answered 487");
    }
}

/// Answer `408` to every relay that has had no final response for a whole
/// transaction timeout (64·T1), and put the engine back as for a refusal.
pub fn bridge_relay_sweep(state: &DispatcherState, now: std::time::Instant) {
    let timeout = state.transaction_timeout;
    let expired: Vec<String> = state
        .bridge_relays
        .pending
        .iter()
        .filter(|entry| now.saturating_duration_since(entry.created_at) >= timeout)
        .map(|entry| entry.key().clone())
        .collect();
    for receiver in expired {
        let Some((_, pending)) = state.bridge_relays.pending.remove(&receiver) else {
            continue;
        };
        state
            .call_actors
            .set_pending_reinvite(&pending.originator_call_id, true, false);
        state
            .call_actors
            .set_pending_reinvite(&receiver, true, false);
        restore(&pending, state);
        respond(
            &pending.inbound,
            &pending.request,
            408,
            "Request Timeout",
            state,
        );
        warn!(originator = %pending.originator_call_id, %receiver, "B2BUA bridge relay: no answer from the other leg — 408");
    }
}

#[cfg(test)]
mod tests {
    use crate::dispatcher::control_bridge_relay_tests::{
        accept_with, deliver, finals_to, request, sdp_from, srtp_pair, wait_for,
    };
    use crate::dispatcher::dial_bridge_test_harness::{
        eventually, in_dialog_response, reinvites_to, CALLER,
    };
    use crate::dispatcher::originate_test_harness::{phone_sends, socket};

    /// The leak gate: over a batch of relayed holds, refusals and glare, and a
    /// hangup in the middle of a relay, the relay store drains back to empty
    /// after every one, and a pair torn down mid-relay leaves nothing on the
    /// engine or in the media session store.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_store_drains_over_holds_refusals_glare_and_hangups() {
        const PHONE: &str = "198.51.100.181:5060";
        let pair = srtp_pair("relay-leak", PHONE).await;
        let state = pair.state();
        assert_eq!(state.bridge_relays.len(), 0);
        for round in 0..25 {
            // A hold relayed and accepted, with an UPDATE crossing it.
            deliver(
                &pair,
                CALLER,
                request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
            );
            let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
            let to_phone = reinvites_to(&sent, PHONE).remove(0);
            assert_eq!(state.bridge_relays.len(), 1, "round {round}: one in flight");
            deliver(
                &pair,
                PHONE,
                request(&pair, false, "UPDATE", Some(&sdp_from(PHONE, "sendonly"))),
            );
            accept_with(&pair, PHONE, &to_phone, "recvonly");
            wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
            assert_eq!(state.bridge_relays.len(), 0, "round {round}: accepted");

            // A resume the phone refuses.
            deliver(
                &pair,
                CALLER,
                request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendrecv"))),
            );
            let sent = wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
            let to_phone = reinvites_to(&sent, PHONE).remove(0);
            phone_sends(
                state,
                socket(PHONE),
                &in_dialog_response(&to_phone, 488, "Not Acceptable Here", &pair.contact, None),
            );
            wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
            assert_eq!(state.bridge_relays.len(), 0, "round {round}: refused");
        }

        // The carrier hangs up mid-relay.
        deliver(
            &pair,
            CALLER,
            request(&pair, true, "INVITE", Some(&sdp_from(CALLER, "sendonly"))),
        );
        wait_for(&pair, |sent| !reinvites_to(sent, PHONE).is_empty()).await;
        assert_eq!(state.bridge_relays.len(), 1);
        deliver(&pair, CALLER, request(&pair, true, "BYE", None));
        assert!(eventually(|| state.bridge_relays.len() == 0).await);
        assert!(eventually(|| pair.engine.held_count() == 0).await);
        assert!(state
            .rtpengine_sessions
            .as_ref()
            .is_some_and(|store| store.is_empty()));
    }
}
