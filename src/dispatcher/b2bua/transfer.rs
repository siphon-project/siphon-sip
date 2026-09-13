//! Executing a transfer once REFER has been accepted: the leg replacement,
//! the inbound `Replaces` bridge, and completing or failing either.
use crate::dispatcher::*;

/// Execute an accepted REFER transfer (`accept_refer()`), in the resolved mode.
///
/// rtpengine `offer` for a siphon-terminated transfer (Phase 1): anchor the
/// survivor's media (`survivor_sdp`, offered under `survivor_tag`) on the FRESH
/// rtpengine call-id `cid_new` using `profile_name`'s offer flags, and return
/// the SDP to place in the transfer target's INVITE. `None` if media control is
/// not configured or the offer failed (the caller then dials with the survivor's
/// raw SDP). Awaited with the same `block_in_place` idiom as the bridged
/// re-INVITE path.
pub fn b2bua_transfer_rtpengine_offer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    survivor_sdp: &[u8],
    profile_name: &str,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let profile = profiles.get(profile_name)?;
    let offer_flags = profile.offer.clone();
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.offer(
            cid_new,
            survivor_tag,
            survivor_sdp,
            &offer_flags,
        ))
    }) {
        Ok(rewritten) => Some(rewritten),
        Err(error) => {
            warn!(rtpengine_call_id = %cid_new, "REFER terminate: rtpengine offer failed: {error}");
            None
        }
    }
}

/// rtpengine `answer` for a siphon-terminated transfer (Phase 2): complete the
/// survivor↔target media on the fresh rtpengine call-id `cid_new` with the
/// target's answer SDP (`target_sdp`, under `target_tag`) against the offerer
/// (`survivor_tag`), and return the SDP to re-INVITE the survivor with. `None`
/// if media control is not configured or the answer failed.
pub fn b2bua_transfer_rtpengine_answer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    target_tag: &str,
    target_sdp: &[u8],
    profile_name: &str,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let profile = profiles.get(profile_name)?;
    let answer_flags = profile.answer.clone();
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer(
            cid_new,
            survivor_tag,
            target_tag,
            target_sdp,
            &answer_flags,
        ))
    }) {
        Ok(rewritten) => Some(rewritten),
        Err(error) => {
            warn!(rtpengine_call_id = %cid_new, "REFER terminate: rtpengine answer failed: {error}");
            None
        }
    }
}

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

    let (sdp_for_new_party, sdp_for_survivor) = match &old_anchor {
        Some((_, session)) => {
            let to_survivor = b2bua_transfer_rtpengine_offer(
                state,
                &cid_new,
                &new_tag,
                &invite.body,
                &session.profile,
            );
            let to_new_party = b2bua_transfer_rtpengine_answer(
                state,
                &cid_new,
                &new_tag,
                &survivor_tag,
                &survivor_sdp,
                &session.profile,
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
        None => (survivor_sdp.clone(), invite.body.clone()),
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

    let Some((replaced, _survivor)) = state.call_actors.adopt_replaced_dialog(
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

    // Handlers that rebuild a PyCall (on_bye, CDR finalize) read these off the
    // call, and they now describe the new party.
    if let Some(mut call) = state.call_actors.get_call_mut(&replaced_call_id) {
        call.a_leg_invite = stored_invite;
        call.a_leg_local_addr = stored_local_addr;
    }

    // Accept the takeover. Sent before the BYE below so the transferee is
    // connected to the surviving party before the replaced one is told to go.
    if !b2bua_answer_call(
        &replaced_call_id,
        invite,
        200,
        "OK",
        Some(sdp_for_new_party),
        Some("application/sdp"),
    ) {
        warn!(call_id = %replaced_call_id, "B2BUA Replaces: failed to answer the taking-over INVITE");
    }

    // RFC 3891 §3: the replaced dialog is terminated once the new INVITE is
    // accepted. Its leg is already off the call, so this BYE is built from the
    // snapshot taken during the swap.
    if let Some(bye) = build_b2bua_bye(&replaced, state) {
        let (destination, transport) = resolve_in_dialog_destination(
            &replaced.dialog.route_set,
            state,
            replaced.transport.remote_addr,
            replaced.transport.transport,
        );
        send_message_from(
            bye,
            transport,
            destination,
            replaced.transport.connection_id,
            replaced.transport.local_addr,
            state,
        );
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
/// The `202 + NOTIFY 100 Trying + subscription` opening is done here; the
/// new-leg dial and the transfer-aware bridge/BYE completion are driven off the
/// dialed leg's 2xx in the response path.
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
    state: &DispatcherState,
) {
    use crate::script::api::call::ReferMode;

    // The subscription `id` token (RFC 3515 §2.4.4) is the REFER's CSeq number.
    let refer_cseq = message
        .headers
        .get("CSeq")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|number| number.parse::<u32>().ok())
        .unwrap_or(1);

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
            b2bua_forward_indialog_request(
                &inbound,
                &message,
                call_id,
                from_a_leg,
                Method::Refer,
                "refer",
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

            // 202 Accepted to the referrer, on the flow the REFER arrived on,
            // followed by the first NOTIFY (sipfrag 100 Trying) opening the
            // implicit subscription.
            //
            // RFC 3515 §2.4.4 orders these: the 202 is what tells the referrer
            // the subscription exists, so a NOTIFY that overtakes it can be
            // rejected as being for an unknown subscription. They are enqueued
            // as one ordered unit because two separate sends do NOT order on
            // UDP — the workers share the outbound channel and each owns its own
            // SO_REUSEPORT socket, so the NOTIFY could and did win the race.
            let mut accepted = build_response(
                &message,
                202,
                "Accepted",
                state.server_header.as_deref(),
                &[],
            );
            let notify_cseq = state.call_actors.reserve_leg_cseq(call_id, from_a_leg);
            let origin_leg = state.call_actors.clone_leg(call_id, from_a_leg);

            // A REFER creates a subscription, so its 2xx is dialog-forming and
            // `Contact` is mandatory in it — RFC 3515 §2.2 marks Contact `m` for
            // both REFER and its 2xx ("REFER creates a dialog, and MAY be
            // Record-Routed, hence MUST contain a single Contact header field
            // value"). `build_response` copies only the mandatory *echo*
            // headers, which is right for a plain response and one header short
            // for this one. It is the leg's own local contact, the same value
            // the NOTIFYs below carry, so the referrer sees one target for the
            // whole subscription.
            if let Some(contact) = origin_leg
                .as_ref()
                .and_then(|leg| leg.dialog.local_contact.clone())
            {
                if !accepted.headers.has("Contact") {
                    accepted.headers.set("Contact", contact);
                }
            }
            advertise_supported_options(&mut accepted.headers);

            let mut ordered = vec![accepted];

            if let (Some(cseq), Some(leg)) = (notify_cseq, origin_leg) {
                let extra_headers = [
                    (
                        "Event",
                        crate::b2bua::transfer::refer_event_header(refer_cseq),
                    ),
                    (
                        "Subscription-State",
                        crate::b2bua::transfer::subscription_state_header(
                            &crate::b2bua::transfer::TransferState::Trying,
                            60,
                        ),
                    ),
                ];
                if let Some(notify) = build_b2bua_in_dialog_request(
                    &leg,
                    state,
                    Method::Notify,
                    cseq,
                    &extra_headers,
                    Some((
                        "message/sipfrag",
                        crate::b2bua::transfer::build_sipfrag_body(100, "Trying").into_bytes(),
                    )),
                ) {
                    ordered.push(notify);
                }
            }

            send_messages_in_order_from(
                ordered,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
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
                state,
            );
        }
    }
}

/// Upper bound on how long a leg replacement waits for the target it dialed.
///
/// Not a ring policy — a leak guard, and the reason one is needed is that a
/// replacement runs on an **answered** call while the answer-timeout sweep
/// looks only at `Calling`/`Ringing` ones. Without it a target that sends a
/// `180` and then nothing at all leaves the replacement armed for the life of
/// the call, the response path still matching its Call-ID, and the surviving
/// party bridged to nobody.
///
/// Three minutes, for the reason RFC 3261 §16.6 gives Timer C the same shape:
/// an INVITE that never completes has to be bounded by something, and the
/// bound has to sit beyond any legitimate ring rather than in the middle of it.
pub const LEG_REPLACEMENT_GUARD_SECS: u64 = 180;

/// Dial a replacement for one leg of an answered B2BUA call.
///
/// The shared body of both leg replacements: the REFER-terminated transfer
/// (RFC 3515, `origin: Refer`) and the siphon-decided one
/// (`b2bua.replace_peer()`, `origin: SiphonInitiated`). Everything that is
/// genuinely REFER-bound — the `202`, the opening sipfrag NOTIFY, the CSeq that
/// becomes `event_id`, `Referred-By`, the flow those go back on — stays with
/// the caller; what is left is pure topology and identical for both.
///
/// Offers the **surviving** party's media to the target (the leg being replaced
/// is the one going away), re-anchoring it on a fresh media call-id when the
/// call is anchored, and records the replacement tagged with the dialed leg's
/// Call-ID so the response path matches that leg and no other.
///
/// Returns whether the INVITE reached the transport. A `false` means no
/// replacement is in flight and the call is untouched.
#[allow(clippy::too_many_arguments)]
pub fn b2bua_start_leg_replacement(
    call_id: &str,
    replaced_on_a_leg: bool,
    target_uri: &str,
    next_hop: Option<&str>,
    replaces_header: Option<crate::sip::headers::refer::Replaces>,
    referred_by: Option<String>,
    media_profile: Option<&str>,
    number_shape: Option<&crate::script::api::numbers::NumberShape>,
    event_id: u32,
    origin: crate::b2bua::transfer::ReplacementOrigin,
    timeout_secs: u32,
    state: &DispatcherState,
) -> bool {
    // Reshape the target to the carrier's number format before anything reads
    // it — the R-URI, the To, and the wire destination all derive from this one
    // string.
    //
    // A transfer target is named by the *referrer*, in whatever shape the
    // referrer speaks (a Teams `Refer-To` names `+E.164`), while a dialled leg
    // is shaped by `dial(number_policy=…)` / `b2bua.default_number_policy` on
    // the way out. Without this the two disagree on the same trunk: every
    // normal call reaches the carrier as bare digits and every transferred one
    // arrives with the `+` still attached. `@b2bua.on_invite` does not run again
    // for a replacement leg, so this is the only place the shaping can happen.
    //
    // Resolution matches `dial()` exactly — the named policy or inline format,
    // else `b2bua.default_number_policy`, else no reshaping. An unresolvable one
    // is warned about and skipped rather than failing the transfer: every script
    // path rejects a typo eagerly at the call, so one reaching here came from
    // the control plane, and dropping a transfer over a formatting policy would
    // be the worse failure.
    //
    // Resolved once, here, and handed to the send path already resolved — the
    // target and the identity headers must not be able to disagree about which
    // policy they were shaped by.
    let number_policy = match crate::script::api::numbers::resolve_dial_shape(number_shape) {
        Ok(policy) => policy,
        Err(_) => {
            warn!(
                call_id = %call_id,
                shape = ?number_shape,
                "leg replacement: unresolvable number policy — dialling the target unreshaped"
            );
            None
        }
    };
    let reshaped_target;
    let target_uri = match number_policy.as_deref() {
        Some(policy) => {
            reshaped_target = crate::script::api::numbers::reformat_dial_target(target_uri, policy);
            if reshaped_target != target_uri {
                debug!(
                    call_id = %call_id,
                    from = %target_uri,
                    to = %reshaped_target,
                    "leg replacement: number policy reshaped the transfer target"
                );
            }
            reshaped_target.as_str()
        }
        None => target_uri,
    };

    // Dial the target as a new leg, then record the replacement tagged with
    // that leg's Call-ID. The leg's 2xx is intercepted in the response path
    // (b2bua_complete_terminated_transfer) to promote it into the surviving
    // pair, BYE the leg it replaces, and — for a REFER — send the terminating
    // sipfrag NOTIFY 200.
    let a_leg_invite = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone());

    // The target must be offered the SURVIVING party's media, not that of
    // the leg being replaced — that one is going away. The survivor is the
    // other leg.
    let survivor_on_a_leg = !replaced_on_a_leg;
    let survivor = state.call_actors.clone_leg(call_id, survivor_on_a_leg);
    let survivor_tag = survivor
        .as_ref()
        .and_then(|leg| leg.dialog.remote_tag.clone());
    let survivor_sdp = survivor.as_ref().and_then(|leg| leg.last_sdp.clone());

    // If the call is media-anchored, re-anchor the survivor on a FRESH
    // rtpengine call-id so the survivor↔target media stays on the anchor;
    // the target's INVITE then carries the anchored offer, and this fresh
    // id is forced onto the target leg's Call-ID so the post-promotion
    // store key lines up (see b2bua_complete_terminated_transfer). Absent
    // an anchor, offer the survivor's raw SDP directly.
    //
    // The profile is the script's to choose (`accept_refer(profile=…)` /
    // `replace_peer(profile=…)`),
    // because only it knows what the surviving pair looks like. Falling
    // back to the call's own profile is right for a symmetric one and
    // silently wrong for a direction-bound one: `srtp_to_rtp`'s answer
    // half exists to talk to the SRTP party, and after the transfer that
    // party is the one that left, so the survivor gets re-INVITEd with
    // SRTP it never spoke and answers `m=audio 0`. Warned about here
    // rather than guessed at.
    let inherited_profile = state
        .call_actors
        .get_call(call_id)
        .map(|c| c.a_leg.dialog.call_id.clone())
        .and_then(|key| {
            state
                .rtpengine_sessions
                .as_ref()
                .and_then(|store| store.get(&key))
                .map(|session| session.profile.clone())
        });
    if media_profile.is_none() {
        if let Some(inherited) = inherited_profile.as_deref() {
            if state
                .rtpengine_profiles
                .as_ref()
                .and_then(|registry| registry.get(inherited))
                .map(|entry| entry.is_direction_bound())
                .unwrap_or(false)
            {
                warn!(
                    call_id = %call_id,
                    profile = %inherited,
                    "leg replacement: inheriting a direction-bound media profile — its answer half was written for the party being transferred away, so the surviving leg will be re-offered that party's transport. Pass profile=… naming the profile for the pair that remains."
                );
            }
        }
    }
    let anchored_profile = media_profile
        .map(|name| name.to_string())
        .or(inherited_profile);
    let fresh_cid = crate::b2bua::actor::generate_call_id();
    let (target_offer_sdp, forced_cid) = match (&anchored_profile, &survivor_sdp, &survivor_tag) {
        (Some(profile), Some(sdp), Some(tag)) => {
            // Anchored: rtpengine-offer the survivor's media on the
            // fresh call-id → the SDP to put in the target's INVITE.
            match b2bua_transfer_rtpengine_offer(state, &fresh_cid, tag, sdp, profile) {
                Some(anchored) => (Some(anchored), Some(fresh_cid.as_str())),
                None => {
                    warn!(call_id = %call_id, "leg replacement: rtpengine offer for the target failed — falling back to raw survivor SDP");
                    (Some(sdp.clone()), None)
                }
            }
        }
        // Not anchored, but we have the survivor's SDP: offer it raw.
        (None, Some(sdp), _) => (Some(sdp.clone()), None),
        // No survivor SDP captured (pre-existing call, or capture
        // missed): fall back to the replaced leg's INVITE body below.
        _ => (None, None),
    };

    // Clone the A-leg INVITE as the dial template, but point its To at
    // the Refer-To target (not the original callee). The generic B-leg
    // builder rewrites only the To host, so without this the dialed
    // INVITE would carry the original callee's userpart on the target's
    // host (e.g. To: <sip:bob@carol-host>) — wrong for a transfer
    // (RFC 3261 §8.1.1.2). Cloning also lets the lock drop before the send.
    let dial_template = match a_leg_invite {
        Some(invite_arc) => match invite_arc.lock() {
            Ok(invite) => {
                let mut template = invite.clone();
                template.headers.set("To", format!("<{target_uri}>"));
                // A call that itself arrived as a transfer left the
                // PREVIOUS referrer's `Referred-By` on this
                // template. When the REFER in hand names someone it is
                // overwritten by the injection below; when it names
                // nobody the stale value has to go, or the target is
                // told it was called on the authority of a party that
                // has nothing to do with this referral.
                if referred_by.is_none() {
                    template.headers.remove("Referred-By");
                }
                // Offer the survivor's media (anchored or raw) instead of
                // the replaced leg's; leave that body in place only when
                // no survivor SDP was available.
                if let Some(ref sdp) = target_offer_sdp {
                    template.body = sdp.clone();
                    template
                        .headers
                        .set("Content-Length", template.body.len().to_string());
                } else {
                    warn!(call_id = %call_id, "leg replacement: no survivor SDP — dialling the target with the replaced leg's SDP (media may be misaimed until re-negotiated)");
                }
                Some(template)
            }
            Err(_) => {
                error!(call_id = %call_id, "leg replacement: a_leg_invite lock poisoned");
                None
            }
        },
        None => {
            warn!(call_id = %call_id, "leg replacement: no stored A-leg INVITE to dial the target");
            None
        }
    };
    // Injected verbatim onto the triggered INVITE, after the header
    // policy. Neither `Replaces` nor `Referred-By` is dialog-defining
    // for the dialog this INVITE creates — both reference something
    // outside it — so they are safe in this slot.
    //
    // After the policy rather than on the template because neither is a
    // header of the A-leg dialog that the policy governs the crossing
    // of: they are properties of the referral, and a default-strip
    // preset dropping them would break the transfer rather than hide an
    // identity. No shipped preset strips either.
    let mut triggered_extra_headers: Vec<(String, String)> = replaces_header
        .map(|replaces| vec![("Replaces".to_string(), replaces.to_string())])
        .unwrap_or_default();
    if let Some(value) = referred_by {
        triggered_extra_headers.push(("Referred-By".to_string(), value));
    }

    // `dialed` decides whether the transfer proceeds, so it has to be
    // what actually happened. It used to be hardcoded `true` next to a
    // send whose result was discarded, so a target that would not
    // resolve was treated as dialled and the replaced leg was BYE'd for
    // a target that never existed.
    let dialed = if let Some(template) = dial_template {
        b2bua_send_b_leg_invite(
            call_id,
            target_uri,
            next_hop,
            None,
            &[],
            None,
            forced_cid,
            &template,
            // Identity headers of the triggered INVITE get the same policy the
            // target just did — the dial path reshapes both together
            // (`apply_for_dial`), and a From in one shape next to an R-URI in
            // another is what an SBC reads as inconsistent.
            number_policy.as_deref(),
            None,
            None,
            None,
            triggered_extra_headers.as_slice(),
            state,
        )
    } else {
        false
    };

    // The dialed target is the last b_leg; capture its Call-ID so the
    // response path matches only THIS leg as the transfer target.
    let target_leg_call_id = if dialed {
        state
            .call_actors
            .get_call(call_id)
            .and_then(|call| call.b_legs.last().map(|leg| leg.dialog.call_id.clone()))
    } else {
        None
    };
    // A target that answers is promoted; a target that never sends a final
    // response at all is nobody's to sweep, because this call is `Answered`
    // and the answer-timeout path deliberately looks only at un-answered
    // calls. Hence a deadline of its own — see `LEG_REPLACEMENT_GUARD_SECS`.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(match timeout_secs {
            0 => LEG_REPLACEMENT_GUARD_SECS,
            secs => u64::from(secs).min(LEG_REPLACEMENT_GUARD_SECS),
        });
    state.call_actors.push_refer_subscription(
        call_id,
        crate::b2bua::actor::ReferSubscription {
            on_a_leg: replaced_on_a_leg,
            siphon_notifies: true,
            origin,
            event_id,
            notify_cseq: event_id,
            state: crate::b2bua::transfer::TransferState::Trying,
            target_leg_call_id,
            referrer_gone: false,
            deadline: dialed.then_some(deadline),
            media_profile: media_profile.map(|name| name.to_string()),
        },
    );
    dialed
}

/// Complete a siphon-terminated transfer when the dialed transfer-target leg
/// answers (2xx): ACK it, send the terminating `NOTIFY 200 OK` sipfrag to the
/// referrer, promote the target into the surviving pair, and BYE the referrer.
///
/// The signaling here (ACK / NOTIFY / promote / BYE) is what makes the transfer
/// visible on the wire and is covered by the integration tests. The rtpengine
/// media re-anchor (re-bridging the surviving party's media to the transfer
/// target) needs a live rtpengine session to validate and is intentionally left
/// to the standard re-negotiation path rather than reconstructed blind here.
pub fn b2bua_complete_terminated_transfer(
    call_id: &str,
    target_idx: usize,
    response: &SipMessage,
    state: &DispatcherState,
) {
    // Capture the target dialog's route set before anything reads the leg —
    // everything siphon sends the target from here on takes it from there.
    store_b_leg_route_set_from_2xx(&state.call_actors, call_id, target_idx, response);

    // Snapshot the replaced side + the target (Z) leg before mutating.
    //
    // `referrer_gone` is set when the leg being replaced already BYE'd this
    // call while the target was still ringing (see
    // `mark_transfer_referrer_gone`): the replacement still completes, but
    // there is no dialog left to BYE — nor, for a REFER, to NOTIFY.
    //
    // `origin` is the other half of that, and the two are independent. A
    // `SiphonInitiated` replacement never had a subscription, so it owes no
    // NOTIFY however alive the replaced leg is; it does still owe the BYE.
    // Deriving both from `referrer_gone` alone is what made this path
    // unreachable without a REFER: `true` dropped the BYE on the floor after
    // `retire_promoted_referrer` had already blacklisted that Call-ID, and
    // `false` sent a terminated-subscription NOTIFY, with a fabricated
    // `event_id`, to a peer that never subscribed.
    let (referrer_on_a_leg, referrer_gone, origin, event_id, transfer_profile, target_leg) =
        match state.call_actors.get_call(call_id) {
            Some(call) => {
                let Some(subscription) = call
                    .refer_subscriptions
                    .iter()
                    .find(|subscription| subscription.siphon_notifies)
                else {
                    return;
                };
                (
                    subscription.on_a_leg,
                    subscription.referrer_gone,
                    subscription.origin,
                    subscription.event_id,
                    subscription.media_profile.clone(),
                    call.b_legs.get(target_idx).cloned(),
                )
            }
            None => return,
        };
    let Some(target_leg) = target_leg else {
        return;
    };

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
    // The transfer target leg's Call-ID doubles as the fresh rtpengine call-id
    // for the survivor↔target anchor (forced in Phase 1 when anchored).
    let cid_new = target_leg.dialog.call_id.clone();

    // ACK the target's 2xx — siphon is the UAC for this leg (RFC 3261 §13.2.2.4).
    if let Some(ack) = build_ack_for_owned_leg(
        &target_leg,
        response,
        &TransactionKey::generate_branch(),
        state,
    ) {
        let (dest, transport) = resolve_in_dialog_destination(
            &target_leg.dialog.route_set,
            state,
            target_leg.transport.remote_addr,
            target_leg.transport.transport,
        );
        send_message_from(
            ack,
            transport,
            dest,
            target_leg.transport.connection_id,
            target_leg.transport.local_addr,
            state,
        );
    }

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
    let mut referrer_messages: Vec<SipMessage> = Vec::new();
    let mut referrer_route: Option<(Transport, SocketAddr, ConnectionId, Option<SocketAddr>)> =
        None;
    // The terminating NOTIFY's own branch, once one is built — the key the BYE
    // is parked under until the referrer answers it.
    let mut notify_branch: Option<String> = None;

    let notify_cseq = if referrer_gone || !origin.notifies_referrer() {
        None
    } else {
        state
            .call_actors
            .reserve_leg_cseq(call_id, referrer_on_a_leg)
    };
    if let Some(cseq) = notify_cseq {
        if let Some(referrer_leg) = state.call_actors.clone_leg(call_id, referrer_on_a_leg) {
            let extra_headers = [
                (
                    "Event",
                    crate::b2bua::transfer::refer_event_header(event_id),
                ),
                (
                    "Subscription-State",
                    crate::b2bua::transfer::subscription_state_header(
                        &crate::b2bua::transfer::TransferState::Succeeded,
                        0,
                    ),
                ),
            ];
            if let Some(notify) = build_b2bua_in_dialog_request(
                &referrer_leg,
                state,
                Method::Notify,
                cseq,
                &extra_headers,
                Some((
                    "message/sipfrag",
                    crate::b2bua::transfer::build_sipfrag_body(200, "OK").into_bytes(),
                )),
            ) {
                let (dest, transport) = resolve_in_dialog_destination(
                    &referrer_leg.dialog.route_set,
                    state,
                    referrer_leg.transport.remote_addr,
                    referrer_leg.transport.transport,
                );
                referrer_route = Some((
                    transport,
                    dest,
                    referrer_leg.transport.connection_id,
                    referrer_leg.transport.local_addr,
                ));
                notify_branch = top_via_branch(&notify).map(str::to_string);
                referrer_messages.push(notify);
            }
        }
    }

    // Promote the target into the surviving pair, then BYE the referrer leg.
    // The promotion runs either way — it is what makes the target the surviving
    // party's peer, and is the whole point of the transfer. Only the BYE is
    // conditional on there still being a referrer to receive it.
    let promoted_referrer =
        state
            .call_actors
            .promote_transfer_target(call_id, target_idx, referrer_on_a_leg);
    if let Some(referrer_leg) = promoted_referrer.filter(|_| !referrer_gone) {
        if let Some(bye) = build_b2bua_bye(&referrer_leg, state) {
            let (dest, transport) = resolve_in_dialog_destination(
                &referrer_leg.dialog.route_set,
                state,
                referrer_leg.transport.remote_addr,
                referrer_leg.transport.transport,
            );
            let connection_id = referrer_leg.transport.connection_id;
            let local_addr = referrer_leg.transport.local_addr;
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
                // Observed against Microsoft Teams Direct Routing with the two
                // 19 µs apart: BYE answered `200`, NOTIFY answered `481`.
                Some(branch) => {
                    state.deferred_referrer_bye.insert(
                        &branch,
                        DeferredReferrerBye {
                            message: bye,
                            transport,
                            destination: dest,
                            connection_id,
                            local_addr,
                            deadline: std::time::Instant::now() + DEFERRED_REFERRER_BYE_TIMEOUT,
                            call_id: call_id.to_string(),
                        },
                    );
                }
                // No NOTIFY was built (a `SiphonInitiated` replacement, which
                // nobody subscribed to): nothing to wait for, send it now.
                None => {
                    send_message_from(bye, transport, dest, connection_id, local_addr, state);
                }
            }
        }
    }

    if let Some((transport, dest, connection_id, local_addr)) = referrer_route {
        send_messages_in_order_from(
            referrer_messages,
            transport,
            dest,
            connection_id,
            local_addr,
            state,
        );
    }

    state
        .call_actors
        .clear_refer_subscriptions_on_leg(call_id, referrer_on_a_leg);
    state.call_actors.set_state(call_id, CallState::Answered);

    // Re-point the surviving party's media at the transfer target (RFC 3261 §14).
    // The referrer is gone, so without this the surviving leg still holds the
    // referrer's SDP and sends RTP nowhere.
    //   Anchored: rtpengine-answer the survivor↔target media on the fresh call-id
    //     (the survivor was offered onto it in Phase 1), re-INVITE the survivor
    //     with the anchored SDP, register the fresh session under the
    //     (post-promotion) A-leg Call-ID, and tear down the old anchor.
    //   Non-anchored: re-INVITE the survivor with the target's raw answer SDP.
    if !response.body.is_empty() {
        let reanchored = match (&old_anchor, &survivor_tag, &target_answer_tag) {
            (Some((_, old_session)), Some(surv_tag), Some(tgt_tag)) => {
                b2bua_transfer_rtpengine_answer(
                    state,
                    &cid_new,
                    surv_tag,
                    tgt_tag,
                    &response.body,
                    // The pairing the transfer created, not the one the call
                    // started as — see `accept_refer(profile=…)`.
                    transfer_profile.as_deref().unwrap_or(&old_session.profile),
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
                    store.insert(crate::rtpengine::session::MediaSession {
                        call_id: new_store_key,
                        rtpengine_call_id: cid_new.clone(),
                        // a_leg/b_leg role order after promotion: the target is
                        // the offerer for future role-based lookups.
                        from_tag: tgt_tag.clone(),
                        to_tag: Some(surv_tag.clone()),
                        profile: transfer_profile
                            .clone()
                            .unwrap_or_else(|| old_session.profile.clone()),
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
                        created_at: std::time::Instant::now(),
                    });
                    store.remove(old_key);
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
                "target_sip_call_id": cid_new,
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

/// The dialed transfer target failed (non-2xx). Notify the referrer that the
/// transfer failed (terminating sipfrag NOTIFY), drop the failed target leg, and
/// keep the original call intact.
///
/// The failed INVITE has already been ACKed by the caller (RFC 3261 §17.1.1.3).
/// It is done there rather than here because the flow the ACK has to go out on
/// — the target leg's destination, egress socket and Via sent-by — is only in
/// scope in the response handler; this function sees the call, not the leg's
/// transport. Do not assume a transaction layer covers it: B2BUA B-legs ACK
/// their own non-2xx finals explicitly, everywhere on this path.
pub fn b2bua_fail_terminated_transfer(
    call_id: &str,
    target_idx: usize,
    status_code: u16,
    state: &DispatcherState,
) {
    // Match the replacement that owns the leg which just failed, not merely the
    // first notifier subscription on the call. The completion path has always
    // keyed on `target_leg_call_id`; this one did not, which was survivable
    // only because one replacement can be in flight at a time.
    let failed_leg_call_id = state.call_actors.get_call(call_id).and_then(|call| {
        call.b_legs
            .get(target_idx)
            .map(|leg| leg.dialog.call_id.clone())
    });
    let Some((referrer_on_a_leg, referrer_gone, origin, event_id)) =
        state.call_actors.get_call(call_id).and_then(|call| {
            call.refer_subscriptions
                .iter()
                .find(|subscription| {
                    subscription.siphon_notifies
                        && (subscription.target_leg_call_id.is_none()
                            || subscription.target_leg_call_id == failed_leg_call_id)
                })
                .map(|subscription| {
                    (
                        subscription.on_a_leg,
                        subscription.referrer_gone,
                        subscription.origin,
                        subscription.event_id,
                    )
                })
        })
    else {
        return;
    };

    // The referrer already hung up and the target it asked for is now refusing:
    // nobody is left for the surviving party to talk to. Keeping the call would
    // strand it on a dialog whose peer has gone and whose replacement never
    // arrived, so release it and tear the call down. (When the referrer is still
    // there the original call is intact and simply continues — the arm below.)
    if referrer_gone {
        let survivor_on_a_leg = !referrer_on_a_leg;
        if let Some(survivor_leg) = state.call_actors.clone_leg(call_id, survivor_on_a_leg) {
            if let Some(bye) = build_b2bua_bye(&survivor_leg, state) {
                let (dest, transport) = resolve_in_dialog_destination(
                    &survivor_leg.dialog.route_set,
                    state,
                    survivor_leg.transport.remote_addr,
                    survivor_leg.transport.transport,
                );
                send_message_from(
                    bye,
                    transport,
                    dest,
                    survivor_leg.transport.connection_id,
                    survivor_leg.transport.local_addr,
                    state,
                );
            }
        }
        warn!(
            call_id = %call_id,
            status = status_code,
            "B2BUA REFER (terminate): transfer target failed after the referrer left — releasing the orphaned surviving leg"
        );
        b2bua_release_transferred_call(call_id, state);
        return;
    }

    let failure = crate::b2bua::transfer::transfer_result_from_response(status_code);
    let (code, reason) = match &failure {
        crate::b2bua::transfer::TransferState::Failed { code, reason } => (*code, reason.clone()),
        _ => (status_code, "Failure".to_string()),
    };
    // Only a REFER is owed the failure sipfrag. A siphon-decided replacement
    // has no subscriber, and the leg it was going to replace is still on the
    // call, so telling it anything would be reporting on a transfer it never
    // asked for.
    if let Some(cseq) = origin
        .notifies_referrer()
        .then(|| {
            state
                .call_actors
                .reserve_leg_cseq(call_id, referrer_on_a_leg)
        })
        .flatten()
    {
        if let Some(referrer_leg) = state.call_actors.clone_leg(call_id, referrer_on_a_leg) {
            let extra_headers = [
                (
                    "Event",
                    crate::b2bua::transfer::refer_event_header(event_id),
                ),
                (
                    "Subscription-State",
                    crate::b2bua::transfer::subscription_state_header(&failure, 0),
                ),
            ];
            if let Some(notify) = build_b2bua_in_dialog_request(
                &referrer_leg,
                state,
                Method::Notify,
                cseq,
                &extra_headers,
                Some((
                    "message/sipfrag",
                    crate::b2bua::transfer::build_sipfrag_body(code, &reason).into_bytes(),
                )),
            ) {
                let (dest, transport) = resolve_in_dialog_destination(
                    &referrer_leg.dialog.route_set,
                    state,
                    referrer_leg.transport.remote_addr,
                    referrer_leg.transport.transport,
                );
                send_message_from(
                    notify,
                    transport,
                    dest,
                    referrer_leg.transport.connection_id,
                    referrer_leg.transport.local_addr,
                    state,
                );
            }
        }
    }

    // Drop the failed transfer-target leg; the original call is untouched.
    state.call_actors.remove_b_leg(call_id, target_idx);
    state
        .call_actors
        .clear_refer_subscriptions_on_leg(call_id, referrer_on_a_leg);

    // The counterpart of `PeerReplaced`: the original call is intact and still
    // has both its parties, which is precisely what a controller cannot infer
    // from the verb's reply. Without it, an app that asked for a replacement
    // and heard nothing back has no way to distinguish "still ringing" from
    // "refused" and either waits forever or hangs up a healthy call.
    if let Some(sip_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    {
        control_notify_channel_event(
            &sip_call_id,
            "ReplaceFailed",
            serde_json::json!({
                "status": status_code,
                "call_kept": !referrer_gone,
                "origin": if origin.notifies_referrer() { "refer" } else { "siphon" },
            }),
        );
    }

    info!(
        call_id = %call_id,
        status = status_code,
        siphon_initiated = !origin.notifies_referrer(),
        "B2BUA: leg replacement target failed — original call kept, replacement cleared"
    );
}
