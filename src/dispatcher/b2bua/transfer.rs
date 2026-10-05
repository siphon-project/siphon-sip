//! Executing a transfer once REFER has been accepted: the leg replacement,
//! the inbound `Replaces` bridge, and completing or failing either.
use crate::dispatcher::*;

/// Hand an existing call's dialog over to the party that sent an INVITE with
/// `Replaces` (RFC 3891 §3 / RFC 5589 §7 attended transfer).
///
/// This is the inbound half of attended transfer — the transferee calls *us*
/// naming the dialog it is taking over, where `b2bua_refer_accept` is the half
/// where siphon places that call itself. The named party is dropped, the new
/// caller takes its slot, and the party on the other side of the named dialog
/// carries on without ever seeing a new call.
///
/// Runs only after `@b2bua.on_invite` has admitted the INVITE — see
/// [`PendingReplaces`](crate::b2bua::actor::PendingReplaces) for why the header
/// alone is not enough authority to end someone's call.
pub fn b2bua_bridge_inbound_replaces(
    inbound: &InboundMessage,
    invite: &SipMessage,
    new_call_id: &str,
    pending: &crate::b2bua::actor::PendingReplaces,
    state: &DispatcherState,
) {
    let replaced_call_id = pending.replaced_call_id.clone();

    // Answer the new party with a hard failure rather than half a takeover:
    // every one of these means the call it asked to join cannot be handed over
    // intact, and the alternative is a connected call with dead audio.
    let refuse = |code: u16, reason: &str, why: &str| {
        warn!(
            call_id = %new_call_id,
            replaced_call = %replaced_call_id,
            "B2BUA Replaces: refusing takeover with {code} — {why}"
        );
        let response = build_response(invite, code, reason, state.server_header.as_deref(), &[]);
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        state.call_actors.remove_call(new_call_id);
        state.call_event_receivers.remove(new_call_id);
    };

    // siphon answers the takeover itself (RFC 3261 §8.2.2.3): a required
    // extension it does not honour is refused on this INVITE's transaction.
    let verified = state
        .call_actors
        .get_call(new_call_id)
        .is_some_and(|call| call.sec_agree_verified);
    let unsupported = unimplemented_required_tags(&invite.headers, verified);
    if !unsupported.is_empty() {
        refuse_unhonoured_on_transaction(inbound, invite, new_call_id, unsupported, state);
        return;
    }

    // The transferee offers (RFC 5589 §7). An offerless INVITE would make siphon
    // the offerer and push the answer into the ACK, which is a different
    // negotiation than the one the surviving leg is already in.
    if invite.body.is_empty() {
        refuse(488, "Not Acceptable Here", "the INVITE carries no offer");
        return;
    }

    // The survivor is the peer of the dialog being replaced.
    let survivor_on_a_leg = !pending.replaced_on_a_leg;
    let Some(survivor) = state
        .call_actors
        .clone_leg(&replaced_call_id, survivor_on_a_leg)
    else {
        refuse(
            481,
            "Call/Transaction Does Not Exist",
            "the replaced call went away",
        );
        return;
    };
    let Some(survivor_tag) = survivor.dialog.remote_tag.clone() else {
        refuse(
            488,
            "Not Acceptable Here",
            "the surviving leg has no remote tag — its dialog is not confirmed",
        );
        return;
    };
    let Some(survivor_sdp) = survivor.last_sdp.clone() else {
        refuse(
            488,
            "Not Acceptable Here",
            "the surviving leg has no recorded SDP to hand over",
        );
        return;
    };

    let Some(new_leg) = state.call_actors.clone_leg(new_call_id, true) else {
        refuse(
            481,
            "Call/Transaction Does Not Exist",
            "the new call went away",
        );
        return;
    };
    let new_tag = new_leg.dialog.local_tag.clone();
    // The fresh engine call-id is the new party's SIP Call-ID, which is what the
    // media store is keyed on once this leg occupies the A-leg slot.
    let cid_new = new_leg.dialog.call_id.clone();

    // The pre-takeover anchor, keyed on the replaced call's A-leg Call-ID.
    let old_anchor = state
        .call_actors
        .get_call(&replaced_call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
        .and_then(|key| {
            state
                .rtpengine_sessions
                .as_ref()
                .and_then(|store| store.get(&key))
                .map(|session| (key, session))
        });

    // Media. Anchored: re-offer the new party onto a fresh engine call-id and
    // answer it with the survivor's already-negotiated SDP, so the 200 can go out
    // now instead of waiting for the survivor's re-INVITE to come back.
    // Unanchored: the two SDPs cross directly.
    if let Some((_, session)) = &old_anchor {
        if state
            .rtpengine_profiles
            .as_ref()
            .and_then(|registry| registry.get(&session.profile))
            .map(|entry| entry.is_direction_bound())
            .unwrap_or(false)
        {
            warn!(
                call_id = %replaced_call_id,
                profile = %session.profile,
                "B2BUA Replaces: the call is anchored with a direction-bound media profile and the takeover re-pairs it — the surviving leg may be re-offered the replaced party's transport. A symmetric profile is required for takeovers across an SRTP or transcoding boundary."
            );
        }
    }

    // Whose policy pins each party on the fresh engine call: the survivor
    // keeps its own, the newcomer takes the replaced party's. Here the
    // newcomer's SDP is the offer and the survivor's the answer.
    let repaired = old_anchor
        .as_ref()
        .map(|(_, session)| RepairedIngress::of(None, session, &survivor_tag, false));

    let (sdp_for_new_party, sdp_for_survivor) = match (&old_anchor, &repaired) {
        (Some((_, session)), Some(repaired)) => {
            let to_survivor = b2bua_transfer_rtpengine_offer(
                state,
                &cid_new,
                &new_tag,
                &invite.body,
                &cid_new,
                &session.profile,
                Some(&PartyIngress {
                    source: inbound.remote_addr.ip(),
                    policy: repaired.joining.clone(),
                }),
            );
            let to_new_party = b2bua_transfer_rtpengine_answer(
                state,
                &cid_new,
                &new_tag,
                &survivor_tag,
                &survivor_sdp,
                &survivor.dialog.call_id,
                &crate::rtpengine::session::SideFlags {
                    profile: session.profile.clone(),
                    half: crate::rtpengine::session::ProfileHalf::Answer,
                },
                Some(&PartyIngress {
                    source: survivor.transport.remote_addr.ip(),
                    policy: repaired.survivor.clone(),
                }),
            );
            match (to_survivor, to_new_party) {
                (Some(survivor_side), Some(new_side)) => (new_side, survivor_side),
                _ => {
                    warn!(
                        call_id = %new_call_id,
                        "B2BUA Replaces: rtpengine re-anchor failed — crossing the raw SDP instead"
                    );
                    (survivor_sdp.clone(), invite.body.clone())
                }
            }
        }
        _ => (survivor_sdp.clone(), invite.body.clone()),
    };

    // Move the new party's leg onto the call it is joining. Its own (now empty)
    // call is dropped without retiring the dialog — the leg is moving, not ending.
    let (stored_invite, stored_local_addr) = match state.call_actors.get_call(new_call_id) {
        Some(call) => (call.a_leg_invite.clone(), call.a_leg_local_addr),
        None => (None, None),
    };
    let Some(new_leg_owned) = state.call_actors.detach_a_leg_for_adoption(new_call_id) else {
        refuse(
            481,
            "Call/Transaction Does Not Exist",
            "the new call went away",
        );
        return;
    };
    state.call_event_receivers.remove(new_call_id);

    let Some((replaced, survivor)) = state.call_actors.adopt_replaced_dialog(
        &replaced_call_id,
        pending.replaced_on_a_leg,
        new_leg_owned,
    ) else {
        // The call vanished between the snapshot and the swap. The new party's
        // actor is already gone, so answer from the raw INVITE and stop.
        warn!(
            call_id = %new_call_id,
            replaced_call = %replaced_call_id,
            "B2BUA Replaces: the call being taken over disappeared mid-swap — 481"
        );
        let response = build_response(
            invite,
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
        return;
    };

    // The newcomer holds the A-leg slot now, on a Call-ID of its own: a control
    // channel on the joined call follows it there. The slot's previous holder
    // is the replaced party, or the survivor when the callee was replaced.
    let previous_a_leg = if pending.replaced_on_a_leg {
        &replaced
    } else {
        &survivor
    };
    control_channel_follows_a_leg(state, &replaced_call_id, &previous_a_leg.dialog.call_id);

    // Handlers that rebuild a PyCall (on_bye, CDR finalize) read these off the
    // call, and they now describe the new party.
    if let Some(mut call) = state.call_actors.get_call_mut(&replaced_call_id) {
        call.a_leg_invite = stored_invite;
        call.a_leg_local_addr = stored_local_addr;
    }

    // The survivor's SDP, or the engine's answer built from it, reaches the new
    // party in this 200, so it gets the topology hiding every relayed answer gets:
    // siphon's `o=` owner, `s=` and `o=` address (the listener the newcomer's
    // INVITE arrived on) in place of the survivor's, and the configured
    // attributes stripped. The newcomer now holds the A-leg slot, so the `o=` is
    // that leg's session id at its next version (RFC 3264 §8). The survivor's
    // re-INVITE below gets the same on the siphon-originated re-INVITE path.
    let mut sdp_for_new_party = sdp_for_new_party;
    let newcomer_host = state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport);
    own_sdp_toward_leg(
        &mut sdp_for_new_party,
        "application/sdp",
        state,
        &replaced_call_id,
        true,
        Some(&newcomer_host),
    );

    // Accept the takeover. Sent before the BYE below so the transferee is
    // connected to the surviving party before the replaced one is told to go.
    // Sent on the dispatcher in hand rather than through the process-wide
    // control handle: the takeover already runs inside the dispatcher, and this
    // 200 always carries a body, so the early-media fallback `b2bua_answer_call`
    // adds has nothing to do.
    if !send_uas_response(
        state,
        &replaced_call_id,
        invite,
        200,
        "OK",
        Some(sdp_for_new_party),
        Some("application/sdp"),
        true,
    ) {
        warn!(call_id = %replaced_call_id, "B2BUA Replaces: failed to answer the taking-over INVITE");
    }

    // A REFER the replaced party sent, still held for its application, is
    // answered ahead of the BYE that ends its dialog.
    pending_refer_leg_released(state, &replaced_call_id, &replaced);

    // RFC 3891 §3: the replaced dialog is terminated once the new INVITE is
    // accepted. Its leg is already off the call, so this BYE is built from the
    // snapshot taken during the swap. A replaced party that has not ACKed its 2xx
    // gets the BYE after the ACK (RFC 3261 §15).
    if let Some(bye) = build_b2bua_bye(&replaced, state) {
        send_or_hold_bye(&replaced_call_id, &replaced, bye, ByeSender::Dialog, state);
    }

    // Re-point the survivor at the new party (RFC 3261 §14) — it is still
    // sending to the address of the party that just left. The survivor is the
    // winning B-leg after the swap, always.
    b2bua_send_media_reinvite(&replaced_call_id, false, sdp_for_survivor, state);

    // Re-key the media session onto the new A-leg Call-ID and drop the old
    // anchor, mirroring the terminate-transfer re-anchor.
    if let Some((old_key, old_session)) = &old_anchor {
        if let Some(store) = state.rtpengine_sessions.as_ref() {
            store.insert(crate::rtpengine::session::MediaSession {
                call_id: cid_new.clone(),
                rtpengine_call_id: cid_new.clone(),
                from_tag: new_tag.clone(),
                to_tag: Some(survivor_tag.clone()),
                profile: old_session.profile.clone(),
                // A fresh engine call-id: any WebSocket bridge the old anchor
                // held belonged to the call-id that just went away.
                ws_uri: None,
                ws_tee: None,
                ws_bridge_attached: false,
                // Each party's own ingress policy stays with the pair, for
                // the next time this call is re-paired.
                bridge_sides: repaired
                    .as_ref()
                    .map(|repaired| repaired.sides(&old_session.profile, true, true)),
                created_at: std::time::Instant::now(),
            });
            store.remove(old_key);
        }
        b2bua_transfer_rtpengine_delete(state, old_session.rtpengine_id(), &old_session.from_tag);
    }

    info!(
        call_id = %replaced_call_id,
        replaced_on_a_leg = pending.replaced_on_a_leg,
        "B2BUA Replaces: dialog taken over — replaced party BYE'd, survivor re-INVITEd to the new party"
    );
}

/// rtpengine `delete` for the OLD anchor of a siphon-terminated transfer: tears
/// down the survivor↔referrer media once the survivor has been re-anchored to
/// the target. A `call-not-found` is benign (the call may already be gone).
pub fn b2bua_transfer_rtpengine_delete(state: &DispatcherState, cid_old: &str, from_tag: &str) {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.delete(cid_old, from_tag))
    }) {
        Ok(()) => {}
        Err(error) if error.is_call_not_found() => {}
        Err(error) => {
            warn!(rtpengine_call_id = %cid_old, "REFER terminate: rtpengine delete of old anchor failed: {error}");
        }
    }
}

/// Carry out an accepted REFER in `mode`.
///
/// Transparent: the REFER is re-emitted on the far leg's own dialog and siphon
/// owns no subscription; the far end's response and its sipfrag NOTIFYs are
/// relayed back to the referrer.
///
/// Siphon-terminated (default): answer `202 Accepted` to the referrer, open the
/// implicit REFER subscription, and start feeding it `message/sipfrag` NOTIFY
/// progress (RFC 3515 §2.4.4). Siphon dials the Refer-To (or the script's
/// `target=`) as a new leg, re-bridges the surviving party to it, then BYEs the
/// referred-away leg and sends the terminating `NOTIFY 200`.
///
/// The new leg is dialled *directly* — `@b2bua.on_invite` does not run again for
/// it, so nothing the dial plan does there is repeated here. `number_policy` is
/// the one piece of that shaping the transfer path applies itself, because a
/// referrer names its target in its own number format and the carrier the leg is
/// dialled at expects the trunk's.
///
/// The `202 + NOTIFY 100 Trying + subscription` opening and the new-leg dial
/// are done here; the transfer-aware bridge/BYE completion is driven off the
/// dialed leg's 2xx in the response path
/// ([`b2bua_complete_terminated_transfer`]).
#[allow(clippy::too_many_arguments)]
pub fn b2bua_refer_accept(
    inbound: InboundMessage,
    message: SipMessage,
    call_id: &str,
    from_a_leg: bool,
    target_uri: &str,
    next_hop: Option<&str>,
    replaces: Option<crate::sip::headers::refer::Replaces>,
    mode: crate::script::api::call::ReferMode,
    media_profile: Option<&str>,
    number_shape: Option<&crate::script::api::numbers::NumberShape>,
    dial: &ReplacementDial,
    state: &DispatcherState,
) {
    use crate::script::api::call::ReferMode;

    // The subscription `id` token (RFC 3515 §2.4.4) is the REFER's CSeq number.
    let refer_cseq = refer_subscription_id(&message);

    match mode {
        ReferMode::Transparent => {
            // Re-emit the REFER on the far leg's own dialog. Siphon owns no
            // subscription here — the far end answers 202 (relayed back by the
            // `refer:` response arm) and its sipfrag NOTIFYs are bridged back by
            // handle_b2bua_notify. The referrer's Refer-To rides across intact
            // (a script that rewrote the target did so via `target=`, already
            // applied to the message's Refer-To by the caller when set).
            info!(
                call_id = %call_id,
                target = %target_uri,
                attended = replaces.is_some(),
                "B2BUA REFER: accepting (transparent) — forwarding on the far leg"
            );
            // The far end answers this REFER and siphon relays what it says.
            // Until then a retransmission has nothing to be answered with, and
            // must not be relayed as a second REFER on the far leg's dialog.
            state
                .answered_refers
                .proceeding(call_id, &message, std::time::Instant::now());
            b2bua_forward_indialog_request(
                &inbound,
                &message,
                call_id,
                from_a_leg,
                Method::Refer,
                crate::b2bua::actor::ForwardedMarker::Refer,
                state,
            );
        }
        ReferMode::Terminate => {
            let attended = replaces.is_some();
            info!(
                call_id = %call_id,
                target = %target_uri,
                next_hop = ?next_hop,
                attended,
                "B2BUA REFER: accepting (siphon-terminated) — 202 + NOTIFY 100 Trying"
            );

            // Attended transfer (RFC 5589 §7): the INVITE siphon triggers towards
            // the target MUST carry the `Replaces` naming the dialog it is to
            // replace (RFC 3891 §3), otherwise the target treats it as an
            // ordinary new call and the held call it was supposed to take over is
            // left up — the referrer's second leg strands.
            //
            // The referrer named that dialog with the identifiers it can see. On
            // a B2BUA those belong to the leg facing the referrer, and the target
            // knows only the leg facing itself, so the triple is rewritten to the
            // target's own view; a dialog siphon does not host is passed through
            // untouched (best effort — it is not ours to translate).
            let replaces_header = replaces.as_ref().map(|replaces| {
                let translated = state
                    .call_actors
                    .replaces_as_seen_by_peer(
                        &replaces.call_id,
                        &replaces.from_tag,
                        &replaces.to_tag,
                    )
                    // A `Replaces` pointing back at the very call carrying the
                    // REFER would name the surviving party's own dialog: that is
                    // not an attended transfer, and rewriting it would aim the
                    // target at the leg it is meant to join. Leave it verbatim
                    // and let the target reject it.
                    .filter(|(replaced_call_id, _)| replaced_call_id != call_id);
                match translated {
                    Some((replaced_call_id, peer)) => {
                        debug!(
                            call_id = %call_id,
                            replaced_call = %replaced_call_id,
                            "B2BUA REFER (terminate): translated attended Replaces to the target's dialog view"
                        );
                        crate::sip::headers::refer::Replaces {
                            call_id: peer.call_id,
                            from_tag: peer.from_tag,
                            to_tag: peer.to_tag,
                            early_only: replaces.early_only,
                        }
                    }
                    None => {
                        debug!(
                            call_id = %call_id,
                            "B2BUA REFER (terminate): attended Replaces names a dialog this node does not host — forwarding verbatim"
                        );
                        replaces.clone()
                    }
                }
            });

            // 202 Accepted to the referrer, then the first NOTIFY (sipfrag 100
            // Trying) opening the implicit subscription, as one ordered unit.
            send_refer_accepted(
                &inbound, &message, call_id, from_a_leg, refer_cseq, 60, state,
            );

            // RFC 3892 §3: the triggered INVITE carries the REFER's own
            // `Referred-By`. Read here, off the REFER, because the dial
            // template is the A-leg INVITE and never had it.
            let referred_by = crate::b2bua::transfer::triggered_referred_by(
                message.headers.get("Referred-By").map(String::as_str),
            );
            b2bua_start_leg_replacement(
                call_id,
                from_a_leg,
                target_uri,
                next_hop,
                replaces_header,
                referred_by,
                media_profile,
                number_shape,
                refer_cseq,
                crate::b2bua::transfer::ReplacementOrigin::Refer,
                0,
                dial,
                state,
            );
        }
    }
}

/// Complete a siphon-terminated transfer when a dialed transfer-target leg
/// answers (2xx): ACK it, send the terminating `NOTIFY 200 OK` sipfrag to the
/// referrer, promote the target into the surviving pair, and BYE the referrer.
///
/// `branch` is the Via branch of the INVITE the 2xx answers, which is how a
/// target is told from its siblings when several ring. The first to answer is
/// the one brought in; the others are CANCELled here, once it is. A 2xx from a
/// target that lost that race, on another worker at the same moment or after
/// its CANCEL, established a dialog nobody wants: it is ACKed and released with
/// a BYE (RFC 3261 §13.2.2.4, §15) and the call is left alone.
///
/// `response_source` is where the 2xx came from: the target's signalling
/// source, which its answer is pinned to on the media engine where the
/// target's own policy asks for it (see `transfer_media`).
///
/// The signaling here (ACK / NOTIFY / promote / BYE) is what makes the transfer
/// visible on the wire. The surviving party is then re-INVITEd to the target's
/// media (RFC 3261 §14): on an anchored call with the media engine's answer on
/// the target's own engine call, whose session replaces the old anchor;
/// otherwise with the target's answer SDP as it arrived.
pub fn b2bua_complete_terminated_transfer(
    call_id: &str,
    branch: &str,
    response: &SipMessage,
    response_source: SocketAddr,
    state: &DispatcherState,
) {
    // Who answered first is decided in the store, under the call's lock: the
    // check and the claim are one step, so two targets answering on two
    // workers cannot both be promoted.
    //
    // What it hands back was read under that same lock. `referrer_gone` is set
    // when the leg being replaced already BYE'd this call while the target was
    // still ringing (see `mark_transfer_referrer_gone`): the replacement still
    // completes, but there is no dialog left to BYE — nor, for a REFER, to
    // NOTIFY.
    //
    // `origin` is the other half of that, and the two are independent. A
    // `SiphonInitiated` replacement never had a subscription, so it owes no
    // NOTIFY however alive the replaced leg is; it does still owe the BYE.
    // Deriving both from `referrer_gone` alone is what made this path
    // unreachable without a REFER: `true` dropped the BYE on the floor after
    // `retire_promoted_referrer` had already blacklisted that Call-ID, and
    // `false` sent a terminated-subscription NOTIFY, with a fabricated
    // `event_id`, to a peer that never subscribed.
    let win = match state.call_actors.claim_replacement(call_id, branch) {
        crate::b2bua::actor::ReplacementClaim::Won(win) => *win,
        crate::b2bua::actor::ReplacementClaim::Lost => {
            release_losing_target_answer(call_id, branch, response, state);
            return;
        }
        // The winner's own 2xx again while it is being brought in: the ACK
        // this path sends below answers it.
        crate::b2bua::actor::ReplacementClaim::Duplicate => return,
        // No replacement names this branch. The caller found one a moment
        // ago, so a sibling completed it in between and this is its loser,
        // by now cancelled and kept answerable. Nothing but that is acted on:
        // a branch that is neither is not this function's to ACK or end.
        crate::b2bua::actor::ReplacementClaim::NotATarget => {
            absorb_cancelled_branch_response(call_id, branch, response, 200, state);
            return;
        }
    };
    let crate::b2bua::actor::ReplacementWin {
        replaced_on_a_leg: referrer_on_a_leg,
        referrer_gone,
        origin,
        event_id,
        media_profile: transfer_profile,
        target,
        mut target_leg,
        cancelled,
        released_media,
    } = win;

    // Capture the target dialog's route set before anything reads the leg —
    // everything siphon sends the target from here on takes it from there.
    if store_b_leg_route_set_from_2xx(&state.call_actors, call_id, branch, response) {
        if let Some(leg) = state.call_actors.get_call(call_id).and_then(|call| {
            call.find_b_leg_by_branch(branch)
                .map(|(_, leg)| leg.clone())
        }) {
            target_leg = leg;
        }
    }

    // Media re-anchor inputs, snapshotted BEFORE any mutation — promotion changes
    // a_leg.dialog.call_id, which is the old anchor's store key. Meaningful only
    // when the call is media-anchored (an old session exists); otherwise the
    // transfer re-INVITE below relays the target's raw answer SDP.
    let survivor_on_a_leg = !referrer_on_a_leg;
    let survivor_tag = state
        .call_actors
        .clone_leg(call_id, survivor_on_a_leg)
        .and_then(|leg| leg.dialog.remote_tag.clone());
    let target_answer_tag = response
        .headers
        .to()
        .and_then(|to| to.split(";tag=").nth(1))
        .map(|rest| {
            rest.split([';', ' ', '>', '\r', '\n'])
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|tag| !tag.is_empty());
    let old_anchor = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
        .and_then(|key| {
            state
                .rtpengine_sessions
                .as_ref()
                .and_then(|store| store.get(&key))
                .map(|session| (key, session))
        });
    // The engine call this target's INVITE was offered from, which its answer
    // completes. It is the target's own: every target is offered on a separate
    // one, forced onto its leg's Call-ID when anchored.
    let target_sip_call_id = target_leg.dialog.call_id.clone();
    let cid_new = target
        .media
        .as_ref()
        .map(|media| media.call_id.clone())
        .unwrap_or_else(|| target_sip_call_id.clone());

    // The ACK for the target's 2xx — siphon is the UAC for this leg (RFC 3261
    // §13.2.2.4). Built here, from the leg as it answered, but not sent until the
    // target is the surviving party's peer: see where it goes out, below.
    let target_ack = build_ack_for_owned_leg(
        &target_leg,
        response,
        &TransactionKey::generate_branch(),
        state,
    )
    .map(|ack| {
        let (dest, transport) = resolve_in_dialog_destination(
            &target_leg.dialog.route_set,
            state,
            target_leg.transport.remote_addr,
            target_leg.transport.transport,
        );
        (ack, transport, dest)
    });

    // Terminating NOTIFY (sipfrag 200 OK) and then BYE, both to the referrer.
    //
    // The order is load-bearing, and arrival order is not enough to secure it:
    // the BYE ends the very dialog the NOTIFY is sent on, and a referrer
    // dispatches the two to different places — the NOTIFY to the subscription,
    // the BYE to the dialog — so the teardown can win even when the NOTIFY
    // arrived first. It then answers the BYE and rejects the NOTIFY 481 on a
    // dialog that is already gone, never learning the transfer succeeded (RFC
    // 3515 §2.4.4; RFC 5589 §6 shows the result NOTIFY ahead of the BYE). So
    // the NOTIFY goes out alone and the BYE is parked on its branch until the
    // referrer answers it — see [`DeferredReferrerByeStore`], which also owns
    // the Timer F backstop for a referrer that never does.
    //
    // Both are skipped entirely when the replaced leg already left: its dialog
    // is gone, so the NOTIFY would draw a 481 and the BYE would be addressed to
    // a dialog that no longer exists (RFC 3515 §2.4.4).
    //
    // The NOTIFY is skipped on a second, independent condition: a
    // `SiphonInitiated` replacement has no subscription behind it, so there is
    // no referrer to tell and the sipfrag would arrive at a peer that never
    // asked for one. The BYE is unconditional on origin — that leg is being
    // replaced either way.
    let final_notify = if referrer_gone || !origin.notifies_referrer() {
        None
    } else {
        build_refer_final_notify(call_id, referrer_on_a_leg, event_id, 200, "OK", state)
    };
    // The terminating NOTIFY's own branch, once one is built — the key the BYE
    // is parked under until the referrer answers it.
    let mut notify_branch = final_notify
        .as_ref()
        .and_then(|notify| top_via_branch(&notify.message).map(str::to_string));

    // Promote the target into the surviving pair, then BYE the referrer leg.
    // The promotion runs either way — it is what makes the target the surviving
    // party's peer, and is the whole point of the transfer. Only the BYE is
    // conditional on there still being a referrer to receive it.
    let previous_a_leg = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone());
    let promoted_referrer =
        state
            .call_actors
            .promote_replacement_target(call_id, branch, referrer_on_a_leg);
    if let Some(previous) = previous_a_leg.as_deref() {
        // Before anything is published for the call: `PeerReplaced` below is
        // addressed by the A-leg's Call-ID, which the promotion just changed
        // when the referrer was the A-leg.
        control_channel_follows_a_leg(state, call_id, previous);
    }
    if let Some(referrer_leg) = promoted_referrer.filter(|_| !referrer_gone) {
        // A REFER the replaced party sent before a `replace_peer` took its
        // place, still held for its application, is answered ahead of its BYE.
        pending_refer_leg_released(state, call_id, &referrer_leg);
        if let Some(bye) = build_b2bua_bye(&referrer_leg, state) {
            match notify_branch.take() {
                // A NOTIFY is going out on this dialog, so the BYE waits for it
                // to be answered. Ordering the two sends is NOT enough: the
                // referrer routes them to different places — the NOTIFY to the
                // subscription, the BYE to the dialog — and the dialog teardown
                // wins, so it answers the BYE and then rejects the NOTIFY 481
                // on a dialog that no longer exists. It therefore never learns
                // the transfer completed (RFC 3515 §2.4.4 makes that NOTIFY the
                // only thing that tells it), and sits on whatever it was
                // holding for the transfer — a consultation call, in the
                // attended case — until its own idle timer fires minutes later.
                // A referrer handed the two back to back does exactly that:
                // BYE answered `200`, NOTIFY answered `481`.
                Some(branch) => {
                    state.deferred_referrer_bye.insert(
                        &branch,
                        DeferredReferrerBye {
                            message: bye,
                            leg: referrer_leg,
                            deadline: std::time::Instant::now() + DEFERRED_REFERRER_BYE_TIMEOUT,
                            call_id: call_id.to_string(),
                        },
                    );
                }
                // No NOTIFY was built (a `SiphonInitiated` replacement, which
                // nobody subscribed to): nothing to wait for. Sent now, or after
                // the referrer ACKs a 2xx it has not ACKed yet (RFC 3261 §15).
                None => {
                    send_or_hold_bye(call_id, &referrer_leg, bye, ByeSender::Dialog, state);
                }
            }
        }
    }

    if let Some(notify) = final_notify {
        send_messages_in_order_from(
            vec![notify.message],
            notify.transport,
            notify.destination,
            notify.connection_id,
            notify.local_addr,
            state,
        );
    }

    state
        .call_actors
        .clear_refer_subscriptions_on_leg(call_id, referrer_on_a_leg);
    state.call_actors.set_state(call_id, CallState::Answered);

    // Only now ACK the target. A target may hang up the moment its ACK arrives,
    // and its BYE is handled on another thread. Sent any earlier, that BYE could
    // land before the promotion, when the target's Call-ID matches no dialog leg
    // and it is answered 481 while the surviving party is never released; or
    // after the promotion but before the subscription is cleared, when a BYE from
    // the referrer's side is taken for the referrer leaving mid-transfer and the
    // call is kept for a target that has already gone. The target cannot send
    // that BYE before it has the ACK, so ACKing last closes both.
    if let Some((ack, transport, dest)) = target_ack {
        send_message_from(
            ack,
            transport,
            dest,
            target_leg.transport.connection_id,
            target_leg.transport.local_addr,
            state,
        );
        // That ACK confirms the target's dialog, in whichever slot the
        // promotion put its leg. A re-INVITE from the surviving party is
        // relayed only to a confirmed leg (RFC 3261 §14.1), so without this
        // every hold after the transfer is refused `491` for good.
        if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
            if call.a_leg.dialog.call_id == target_sip_call_id {
                call.a_leg.initial_acked = true;
            } else if let Some(leg) = call
                .b_legs
                .iter_mut()
                .find(|leg| leg.dialog.call_id == target_sip_call_id)
            {
                leg.initial_acked = true;
            }
        }
    }

    // The targets that did not answer first stop ringing (RFC 3261 §9.1), now
    // that the one that did is in the call. Each was kept answerable when the
    // replacement was claimed, so the `487` this draws is ACKed and a 2xx that
    // crosses it is ACKed and released. Their engine calls go with them.
    cancel_settled_branches(call_id, &cancelled, state);
    release_replacement_media(state, released_media);

    // Re-point the surviving party's media at the transfer target (RFC 3261 §14).
    // The referrer is gone, so without this the surviving leg still holds the
    // referrer's SDP and sends RTP nowhere.
    //   Anchored: rtpengine-answer the survivor↔target media on the fresh call-id
    //     (the survivor was offered onto it in Phase 1), re-INVITE the survivor
    //     with the anchored SDP, register the fresh session under the
    //     (post-promotion) A-leg Call-ID, and tear down the old anchor.
    //   Non-anchored: re-INVITE the survivor with the target's raw answer SDP.
    if !response.body.is_empty() {
        // Whose policy pins each party of the new pair: the same reading the
        // survivor's offer was sent under when the target was dialled.
        let repaired = match (&old_anchor, &survivor_tag) {
            (Some((_, old_session)), Some(surv_tag)) => Some(RepairedIngress::of(
                transfer_profile.as_deref(),
                old_session,
                surv_tag,
                true,
            )),
            _ => None,
        };
        let reanchored = match (&old_anchor, &survivor_tag, &target_answer_tag) {
            (Some((_, old_session)), Some(surv_tag), Some(tgt_tag)) => {
                b2bua_transfer_rtpengine_answer(
                    state,
                    &cid_new,
                    surv_tag,
                    tgt_tag,
                    &response.body,
                    response.headers.call_id().map_or("", String::as_str),
                    // The pairing the transfer created, not the one the call
                    // started as — see `accept_refer(profile=…)`.
                    &crate::rtpengine::session::SideFlags {
                        profile: transfer_profile
                            .clone()
                            .unwrap_or_else(|| old_session.profile.clone()),
                        half: crate::rtpengine::session::ProfileHalf::Answer,
                    },
                    // The SDP in this answer is the target's, and this 2xx is
                    // where the target signals from.
                    repaired
                        .as_ref()
                        .map(|repaired| PartyIngress {
                            source: response_source.ip(),
                            policy: repaired.joining.clone(),
                        })
                        .as_ref(),
                )
            }
            _ => None,
        };
        let reinvite_sdp = reanchored.clone().unwrap_or_else(|| response.body.clone());
        b2bua_send_media_reinvite(call_id, survivor_on_a_leg, reinvite_sdp, state);

        // On a successful re-anchor: register the fresh session keyed by the
        // (post-promotion) A-leg Call-ID — so later re-INVITEs/teardown resolve
        // it — and delete the old survivor↔referrer anchor.
        if reanchored.is_some() {
            if let (Some((old_key, old_session)), Some(surv_tag), Some(tgt_tag)) =
                (&old_anchor, &survivor_tag, &target_answer_tag)
            {
                if let Some(store) = state.rtpengine_sessions.as_ref() {
                    let new_store_key = state
                        .call_actors
                        .get_call(call_id)
                        .map(|call| call.a_leg.dialog.call_id.clone())
                        .unwrap_or_else(|| cid_new.clone());
                    let profile = transfer_profile
                        .clone()
                        .unwrap_or_else(|| old_session.profile.clone());
                    // The session names the call's two slots in order, the
                    // A-leg's party on `from_tag` and the B-leg's on `to_tag`,
                    // which is how every in-dialog re-offer finds the tag of
                    // the party sending it. The target holds the A-leg slot
                    // only when it replaced the caller; when it replaced the
                    // callee the surviving caller still does, and naming the
                    // target first would send the caller's re-offers to the
                    // engine as the target's.
                    let (from_tag, to_tag) = if referrer_on_a_leg {
                        (tgt_tag.clone(), surv_tag.clone())
                    } else {
                        (surv_tag.clone(), tgt_tag.clone())
                    };
                    // Each party's own ingress policy stays with the pair: the
                    // tags do not say whose SDP the engine was offered (the
                    // survivor's), so a later re-pairing of this call could
                    // not tell the two policies apart without it.
                    let bridge_sides = repaired
                        .as_ref()
                        .map(|repaired| repaired.sides(&profile, referrer_on_a_leg, false));
                    // The key moves only when the target took the A-leg slot.
                    // When the callee was replaced it is the caller's Call-ID
                    // before and after, and the insert below replaces the old
                    // entry itself: removing "the old key" after it would
                    // remove the pair's own session.
                    let key_moved = new_store_key != *old_key;
                    store.insert(crate::rtpengine::session::MediaSession {
                        call_id: new_store_key,
                        rtpengine_call_id: cid_new.clone(),
                        from_tag,
                        to_tag: Some(to_tag),
                        profile,
                        // Deliberately not carried over from `old_session`: this
                        // is a fresh engine call-id for the survivor↔target
                        // pair, and any WebSocket bridge the pre-transfer anchor
                        // held died with the old call-id.  Copying the URI here
                        // would make a later `answer` on this Call-ID resolve a
                        // bridge that was never established for it.  The tee
                        // and the mid-call takeover flag go the same way and
                        // for the same reason.
                        ws_uri: None,
                        ws_tee: None,
                        ws_bridge_attached: false,
                        bridge_sides,
                        created_at: std::time::Instant::now(),
                    });
                    if key_moved {
                        store.remove(old_key);
                    }
                }
                b2bua_transfer_rtpengine_delete(
                    state,
                    old_session.rtpengine_id(),
                    &old_session.from_tag,
                );
                info!(
                    call_id = %call_id,
                    rtpengine_call_id = %cid_new,
                    "B2BUA REFER (terminate): media re-anchored survivor↔target, old anchor deleted"
                );
            }
        }
    }

    // Tell a controlling app the replacement actually landed. The reply to
    // `replace_peer` said only that the INVITE left the box; everything that
    // decides whether the call still has two parties — the target answering,
    // the promotion, the survivor's re-INVITE, the replaced leg's BYE —
    // happened here. Emitted for a REFER-driven transfer too, which until now
    // completed with nothing on the control rail at all.
    if let Some(sip_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    {
        control_notify_channel_event(
            &sip_call_id,
            "PeerReplaced",
            serde_json::json!({
                "target_sip_call_id": target_sip_call_id,
                "replaced_leg_released": !referrer_gone,
                "origin": if origin.notifies_referrer() { "refer" } else { "siphon" },
            }),
        );
    }

    info!(
        call_id = %call_id,
        referrer_on_a_leg,
        referrer_gone,
        siphon_initiated = !origin.notifies_referrer(),
        "B2BUA: leg replacement completed — target active, replaced leg released"
    );
}
