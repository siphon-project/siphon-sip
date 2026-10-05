//! Ringing the targets of a leg replacement, and ending the ones that lose.
//!
//! A replacement dials a new party for one side of an answered call. Named by
//! an address-of-record with several registered contacts it rings them all,
//! each on an INVITE and a media engine call of its own. The first to answer is
//! brought into the call ([`b2bua_complete_terminated_transfer`]); every other
//! one is ended here: CANCELled and kept answerable for the response that draws
//! (RFC 3261 §9.1), and its engine call released.
//!
//! The same ending runs wherever a replacement stops short of an answer: its
//! deadline, and the call itself going away while targets still ring.

use crate::b2bua::actor::{FailedReplacement, ReplacementMedia, ReplacementTarget};
use crate::dispatcher::*;

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

/// What every target of one replacement is dialled with.
struct ReplacementPlan<'a> {
    call_id: &'a str,
    next_hop: Option<&'a str>,
    /// The carrier's number format, resolved once so the target and the
    /// identity headers cannot disagree about which policy shaped them.
    number_policy: Option<std::sync::Arc<crate::numbers::policy::NumberPolicy>>,
    /// The surviving party's dialog: the tag and SDP its media is offered to
    /// each target under, and the Call-ID that offer belongs to.
    survivor_tag: Option<String>,
    survivor_sdp: Option<Vec<u8>>,
    survivor_sip_call_id: String,
    /// The media profile the surviving pair is anchored with, when the call
    /// is anchored at all.
    anchored_profile: Option<String>,
    /// The A-leg INVITE the new legs are built from.
    template: Option<SipMessage>,
    /// The headers the referral itself owes each INVITE.
    triggered: Vec<(String, String)>,
    /// Whether more than one target rings, and each therefore needs a Call-ID
    /// no sibling shares.
    several: bool,
    state: &'a DispatcherState,
}

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
/// call is anchored, and records the replacement with the Via branch of each
/// INVITE it sent so the response path matches those legs and no other.
///
/// `dial` may name further contacts to ring alongside the target
/// ([`ReplacementDial::also`]): every one gets an INVITE, a Call-ID and an
/// engine call of its own.
///
/// Returns whether an INVITE reached the transport. A `false` means no
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
    dial: &ReplacementDial,
    state: &DispatcherState,
) -> bool {
    // Reshape the target to the carrier's number format before anything reads
    // it — the R-URI, the To, and the wire destination all derive from this one
    // string.
    //
    // A transfer target is named by the *referrer*, in whatever shape the
    // referrer speaks (a `Refer-To` often names `+E.164`), while a dialled leg
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

    // The target must be offered the SURVIVING party's media, not that of
    // the leg being replaced — that one is going away. The survivor is the
    // other leg.
    let survivor = state.call_actors.clone_leg(call_id, !replaced_on_a_leg);

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
    let template = replacement_template(call_id, referred_by.is_some(), state);
    let mut triggered: Vec<(String, String)> = replaces_header
        .map(|replaces| vec![("Replaces".to_string(), replaces.to_string())])
        .unwrap_or_default();
    if let Some(value) = referred_by {
        triggered.push(("Referred-By".to_string(), value));
    }

    let targets = dial.targets(target_uri);
    let plan = ReplacementPlan {
        call_id,
        next_hop,
        number_policy,
        survivor_tag: survivor
            .as_ref()
            .and_then(|leg| leg.dialog.remote_tag.clone()),
        survivor_sdp: survivor.as_ref().and_then(|leg| leg.last_sdp.clone()),
        survivor_sip_call_id: survivor
            .as_ref()
            .map(|leg| leg.dialog.call_id.clone())
            .unwrap_or_default(),
        anchored_profile: anchored_profile(call_id, media_profile, state),
        template,
        triggered,
        several: targets.len() > 1,
        state,
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
    // Recorded before anything is dialled, and each target entered as its own
    // INVITE goes out: the response path intercepts a target's 2xx
    // (b2bua_complete_terminated_transfer) to promote it into the surviving
    // pair, BYE the leg it replaces, and — for a REFER — send the terminating
    // sipfrag NOTIFY 200, and one target can answer while the next is still
    // being sent.
    state.call_actors.push_refer_subscription(
        call_id,
        crate::b2bua::actor::ReferSubscription {
            on_a_leg: replaced_on_a_leg,
            siphon_notifies: true,
            origin,
            event_id,
            notify_cseq: event_id,
            state: crate::b2bua::transfer::TransferState::Trying,
            targets: Vec::new(),
            referrer_gone: false,
            deadline: None,
            media_profile: media_profile.map(|name| name.to_string()),
        },
    );
    // `dialed` decides whether the transfer proceeds, so it has to be what
    // actually happened: a target that would not resolve is not one that was
    // dialled, and the replaced leg is never BYE'd for a target that never
    // existed.
    let mut dialed = false;
    for (target_uri, dial) in &targets {
        // A target that already answered, or the call ending, settles the
        // replacement while its siblings are still being sent: nothing more
        // is dialled for it.
        if !state
            .call_actors
            .replacement_is_open(call_id, replaced_on_a_leg)
        {
            break;
        }
        let Some(target) = plan.ring(target_uri, dial) else {
            continue;
        };
        dialed = true;
        // And one whose INVITE left in that same instant is taken back.
        if let Some(late) =
            state
                .call_actors
                .add_replacement_target(call_id, replaced_on_a_leg, target, deadline)
        {
            cancel_settled_branches(call_id, &late.cancelled, state);
            release_replacement_media(state, late.released_media);
            break;
        }
    }
    dialed
}

/// The media profile the surviving pair of a replacement is anchored with:
/// the one named for it, else the one the call was anchored with. `None` on a
/// call that is not anchored.
///
/// The profile is the script's to choose (`accept_refer(profile=…)` /
/// `replace_peer(profile=…)`), because only it knows what the surviving pair
/// looks like. Falling back to the call's own profile is right for a symmetric
/// one and silently wrong for a direction-bound one: `srtp_to_rtp`'s answer
/// half exists to talk to the SRTP party, and after the transfer that party is
/// the one that left, so the survivor gets re-INVITEd with SRTP it never spoke
/// and answers `m=audio 0`. Warned about here rather than guessed at.
fn anchored_profile(
    call_id: &str,
    media_profile: Option<&str>,
    state: &DispatcherState,
) -> Option<String> {
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
    media_profile
        .map(|name| name.to_string())
        .or(inherited_profile)
}

/// The A-leg INVITE a replacement's legs are built from, cloned so the lock
/// drops before any send.
///
/// Its To is pointed at each target as that is dialled
/// (`ReplacementDial::shape`), not left on the original callee. The generic
/// B-leg builder rewrites only the To host, so without that the dialed INVITE
/// would carry the original callee's userpart on the target's host (e.g. To:
/// <sip:bob@carol-host>) — wrong for a transfer (RFC 3261 §8.1.1.2).
fn replacement_template(
    call_id: &str,
    referred: bool,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let a_leg_invite = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone());
    match a_leg_invite {
        Some(invite_arc) => match invite_arc.lock() {
            Ok(invite) => {
                let mut template = invite.clone();
                // A call that itself arrived as a transfer left the
                // PREVIOUS referrer's `Referred-By` on this
                // template. When the REFER in hand names someone it is
                // overwritten by the injection below; when it names
                // nobody the stale value has to go, or the target is
                // told it was called on the authority of a party that
                // has nothing to do with this referral.
                if !referred {
                    template.headers.remove("Referred-By");
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
    }
}

impl ReplacementPlan<'_> {
    /// Offer the surviving party's media for one target: the SDP its INVITE
    /// carries, and the engine call that came from when the call is anchored.
    ///
    /// If the call is media-anchored, the survivor is re-anchored on a FRESH
    /// rtpengine call-id so the survivor↔target media stays on the anchor; the
    /// target's INVITE then carries the anchored offer, and this fresh id is
    /// forced onto the target leg's Call-ID so the post-promotion store key
    /// lines up (see b2bua_complete_terminated_transfer). Absent an anchor, the
    /// survivor's raw SDP is offered directly.
    ///
    /// One engine call per target, never one shared: each target answers with
    /// media of its own, and only the winner's is completed.
    fn offer(&self, fresh_cid: &str) -> (Option<Vec<u8>>, Option<ReplacementMedia>) {
        match (
            &self.anchored_profile,
            &self.survivor_sdp,
            &self.survivor_tag,
        ) {
            (Some(profile), Some(sdp), Some(tag)) => {
                // Anchored: rtpengine-offer the survivor's media on the
                // fresh call-id → the SDP to put in the target's INVITE.
                match b2bua_transfer_rtpengine_offer(
                    self.state,
                    fresh_cid,
                    tag,
                    sdp,
                    &self.survivor_sip_call_id,
                    profile,
                ) {
                    Some(anchored) => (
                        Some(anchored),
                        Some(ReplacementMedia {
                            call_id: fresh_cid.to_string(),
                            from_tag: tag.clone(),
                        }),
                    ),
                    None => {
                        warn!(call_id = %self.call_id, "leg replacement: rtpengine offer for the target failed — falling back to raw survivor SDP");
                        (Some(sdp.clone()), None)
                    }
                }
            }
            // Not anchored, but we have the survivor's SDP: offer it raw.
            (None, Some(sdp), _) => (Some(sdp.clone()), None),
            // No survivor SDP captured (pre-existing call, or capture
            // missed): fall back to the replaced leg's INVITE body.
            _ => (None, None),
        }
    }

    /// Send one target its INVITE. `None` when nothing reached the transport,
    /// with whatever engine call was opened for it released again.
    fn ring(&self, target_uri: &str, dial: &ReplacementDial) -> Option<ReplacementTarget> {
        let call_id = self.call_id;
        let reshaped_target;
        // A registered contact is dialled as it registered: not a number to reshape.
        let target_uri = match self
            .number_policy
            .as_deref()
            .filter(|_| !dial.is_registered_contact())
        {
            Some(policy) => {
                reshaped_target =
                    crate::script::api::numbers::reformat_dial_target(target_uri, policy);
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

        let fresh_cid = crate::b2bua::actor::generate_call_id();
        let (target_offer_sdp, media) = self.offer(&fresh_cid);
        // Several targets must not share a Call-ID: a call that preserves the
        // caller's would put every one of them on it.
        let forced_cid = (media.is_some() || self.several).then_some(fresh_cid.as_str());

        let branch = self.template.clone().and_then(|mut template| {
            // Offer the survivor's media (anchored or raw) instead of the
            // replaced leg's; leave that body in place only when no survivor
            // SDP was available.
            if let Some(sdp) = &target_offer_sdp {
                template.body = sdp.clone();
                template
                    .headers
                    .set("Content-Length", template.body.len().to_string());
            } else {
                warn!(call_id = %call_id, "leg replacement: no survivor SDP — dialling the target with the replaced leg's SDP (media may be misaimed until re-negotiated)");
            }
            // Who the leg is called as and what it presents: the target (its
            // AoR, for a registered contact) and the identity the transfer
            // was accepted with.
            let shaped = match dial.shape(&mut template, target_uri, self.triggered.clone()) {
                Ok(shaped) => shaped,
                Err(error) => {
                    warn!(call_id = %call_id, %error, "leg replacement: the identity to present could not be put on the INVITE — nothing dialled");
                    return None;
                }
            };
            b2bua_dial_b_leg(
                call_id,
                target_uri,
                self.next_hop,
                // Over the flow a registered contact holds, through its Path.
                dial.flow.as_ref(),
                &dial.route,
                None,
                forced_cid,
                &template,
                // Identity headers of the triggered INVITE get the same policy the
                // target just did — the dial path reshapes both together
                // (`apply_for_dial`), and a From in one shape next to an R-URI in
                // another is what an SBC reads as inconsistent.
                self.number_policy.as_deref(),
                None,
                None,
                dial.shaping.privacy,
                shaped.from_host.as_deref(),
                shaped.to.as_deref(),
                shaped.headers.as_slice(),
                self.state,
            )
        });
        // The leg is read back by the branch its INVITE went out on, never as
        // "the last one added": a sibling, or a re-INVITE's tracking leg, may
        // have been added since.
        let leg_call_id = branch.as_deref().and_then(|branch| {
            self.state.call_actors.get_call(call_id).and_then(|call| {
                call.find_b_leg_by_branch(branch)
                    .map(|(_, leg)| leg.dialog.call_id.clone())
            })
        });
        match (branch, leg_call_id) {
            (Some(branch), Some(leg_call_id)) => {
                Some(ReplacementTarget::ringing(branch, leg_call_id, media))
            }
            _ => {
                release_replacement_media(self.state, media.into_iter().collect());
                None
            }
        }
    }
}

/// Release the media engine calls opened for replacement targets that did not
/// answer: each was offered the surviving party's media on a call of its own,
/// and one nobody answers would otherwise be held until the engine's own
/// timeout. A `call-not-found` is benign.
///
/// Off the signalling path: nothing waits on the engine's reply.
pub fn release_replacement_media(state: &DispatcherState, released: Vec<ReplacementMedia>) {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    if released.is_empty() {
        return;
    }
    let backend = Arc::clone(backend);
    tokio::spawn(async move {
        for media in released {
            match backend.delete(&media.call_id, &media.from_tag).await {
                Ok(()) => {}
                Err(error) if error.is_call_not_found() => {}
                Err(error) => {
                    warn!(rtpengine_call_id = %media.call_id, "leg replacement: rtpengine delete of an unanswered target's call failed: {error}");
                }
            }
        }
    });
}

/// A replacement target answered 2xx after another had already won, or after
/// the replacement was given up on. The dialog it established is siphon's to
/// confirm and to end: ACK it (RFC 3261 §13.2.2.4) and release it with a BYE
/// (§15), once however often the 2xx is retransmitted.
///
/// The store kept the target answerable when it cancelled it, so this is the
/// handling any cancelled branch gets. One whose INVITE was not yet stashed at
/// that moment was not kept, and is answered from its leg instead.
pub fn release_losing_target_answer(
    call_id: &str,
    branch: &str,
    response: &SipMessage,
    state: &DispatcherState,
) {
    debug!(
        call_id = %call_id,
        "B2BUA: a leg replacement target answered after another had — releasing its dialog"
    );
    if absorb_cancelled_branch_response(call_id, branch, response, 200, state) {
        return;
    }
    let leg = state.call_actors.get_call(call_id).and_then(|call| {
        call.find_b_leg_by_branch(branch)
            .map(|(_, leg)| leg.clone())
    });
    match leg {
        Some(leg) => {
            b2bua_ack_and_bye_answered_leg(leg, response, true, state);
        }
        None => warn!(
            call_id = %call_id,
            "B2BUA: a losing leg replacement target answered and its leg is gone — its 2xx cannot be ACKed"
        ),
    }
}

/// A dialed transfer target failed (non-2xx) on the INVITE that rode Via
/// `branch`.
///
/// One target failing is not the transfer failing while another can still
/// answer (RFC 3261 §16.7): its response is recorded and its engine call
/// released, and nothing is reported. Once no target is left the replacement
/// fails once, on the best of their responses (§16.7 step 6), through
/// [`conclude_failed_replacement`].
///
/// The failed INVITE has already been ACKed by the caller (RFC 3261 §17.1.1.3).
/// It is done there rather than here because the flow the ACK has to go out on
/// — the target leg's destination, egress socket and Via sent-by — is only in
/// scope in the response handler; this function sees the call, not the leg's
/// transport. Do not assume a transaction layer covers it: B2BUA B-legs ACK
/// their own non-2xx finals explicitly, everywhere on this path.
pub fn b2bua_fail_terminated_transfer(
    call_id: &str,
    branch: &str,
    status_code: u16,
    state: &DispatcherState,
) {
    let Some(failure) = state
        .call_actors
        .record_replacement_failure(call_id, branch, status_code)
    else {
        // A retransmission, or a target already cancelled: ACKed, and that is
        // all it was owed.
        return;
    };
    release_replacement_media(state, failure.released_media.into_iter().collect());
    match failure.settled {
        Some(failed) => conclude_failed_replacement(call_id, failed, state),
        None => debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: a leg replacement target failed, another can still answer"
        ),
    }
}

/// Give up on a replacement whose deadline has passed: CANCEL every target
/// still ringing and run the ordinary replacement-failure path.
///
/// Each cancelled target stays answerable, so the `487` its CANCEL draws is
/// ACKed (RFC 3261 §17.1.1.3) and a 2xx that crossed the CANCEL is ACKed and
/// its dialog released with a BYE (§13.2.2.4, §15). A no-op when a target's
/// own answer or failure settled the replacement first.
pub fn b2bua_expire_leg_replacement(call_id: &str, state: &DispatcherState) {
    let Some(failed) = state
        .call_actors
        .expire_replacement(call_id, std::time::Instant::now())
    else {
        return;
    };
    warn!(
        call_id = %call_id,
        targets = failed.branches.len(),
        "B2BUA: leg replacement target never answered — cancelling it and keeping the original call"
    );
    conclude_failed_replacement(call_id, failed, state);
}

/// The call is being torn down: end whatever replacement targets it still has
/// ringing, before the call that would have ended them is gone.
///
/// Without this a party hanging up mid-transfer left the target ringing with
/// nothing left to CANCEL it (RFC 3261 §9.1), and its engine call held.
pub fn b2bua_abandon_leg_replacements(call_id: &str, state: &DispatcherState) {
    let abandoned = state.call_actors.abandon_replacements(call_id);
    if abandoned.is_empty() {
        return;
    }
    info!(
        call_id = %call_id,
        cancelled = abandoned.cancelled.len(),
        "B2BUA: the call ended with a leg replacement in flight — cancelling its targets"
    );
    cancel_settled_branches(call_id, &abandoned.cancelled, state);
    release_replacement_media(state, abandoned.released_media);
}

/// A replacement ended with no target answering: tell whoever asked, and put
/// the call back as it was.
///
/// CANCELs the targets that were still ringing and releases what the engine
/// held for all of them, then notifies the referrer that the transfer failed
/// (terminating sipfrag NOTIFY), drops the target legs and keeps the original
/// call intact. The exception is a call whose replaced leg already left: nobody
/// is left for the surviving party to talk to, and it is released.
pub fn conclude_failed_replacement(
    call_id: &str,
    failed: FailedReplacement,
    state: &DispatcherState,
) {
    let FailedReplacement {
        replaced_on_a_leg: referrer_on_a_leg,
        referrer_gone,
        origin,
        event_id,
        status_code,
        branches,
        cancelled,
        released_media,
    } = failed;
    cancel_settled_branches(call_id, &cancelled, state);
    release_replacement_media(state, released_media);

    // The referrer already hung up and the target it asked for is now refusing:
    // nobody is left for the surviving party to talk to. Keeping the call would
    // strand it on a dialog whose peer has gone and whose replacement never
    // arrived, so release it and tear the call down. (When the referrer is still
    // there the original call is intact and simply continues — below.)
    if referrer_gone {
        // This ends the call, and only one teardown may: one already under way
        // sends what is owed and removes the call itself.
        if !state.call_actors.claim_teardown(call_id) {
            return;
        }
        let survivor_on_a_leg = !referrer_on_a_leg;
        if let Some(survivor_leg) = state.call_actors.clone_leg(call_id, survivor_on_a_leg) {
            if let Some(bye) = build_b2bua_bye(&survivor_leg, state) {
                // Sent now, or after the survivor ACKs a 2xx it has not ACKed yet
                // (RFC 3261 §15).
                send_or_hold_bye(call_id, &survivor_leg, bye, ByeSender::Dialog, state);
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
    if origin.notifies_referrer() {
        if let Some(notify) =
            build_refer_final_notify(call_id, referrer_on_a_leg, event_id, code, &reason, state)
        {
            send_message_from(
                notify.message,
                notify.transport,
                notify.destination,
                notify.connection_id,
                notify.local_addr,
                state,
            );
        }
    }

    // Drop the failed transfer-target legs; the original call is untouched.
    // None of them is in flight any more, so taking them off cannot move a
    // leg another response is about to be matched to.
    state
        .call_actors
        .remove_b_legs_by_branch(call_id, &branches);
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
