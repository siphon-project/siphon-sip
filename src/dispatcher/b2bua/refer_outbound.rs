//! REFER siphon sends of its own accord (`call.refer()` / `b2bua.refer()`)
//! and the sipfrag NOTIFYs it subscribes to (RFC 3515).
use crate::dispatcher::*;

/// Send a siphon-originated in-dialog REFER on one leg of a B2BUA call
/// (`call.refer()` / `b2bua.refer()`).
///
/// Siphon is the referrer: it builds the REFER on the chosen leg's own dialog
/// identity, sends it, and records a *subscriber* REFER subscription so the
/// referee's `message/sipfrag` NOTIFYs are absorbed (200 OK'd + read) by
/// [`handle_b2bua_notify`] rather than bridged. Returns `false` if the call or
/// leg is gone.
/// Handle the response to a REFER siphon originated on one of its own legs.
///
/// A cold transfer off a call siphon answered itself (`call.refer()` /
/// `b2bua.refer()`) is an in-dialog REFER on a leg that already exists, so the
/// peer may challenge it, which trunks commonly do. This is the
/// only place that challenge can be answered: the REFER's branch belongs to no
/// leg, so nothing else matches its response.
///
/// Differences from the B-leg INVITE retry that this deliberately does NOT copy:
///
/// * **No ACK.** REFER is a non-INVITE transaction — only an INVITE client
///   transaction ACKs a non-2xx final (RFC 3261 §17.1.2). ACKing here would put
///   a stray ACK on the dialog.
/// * **A fresh CSeq, not a fresh branch on the same one.** §22.2 wants the
///   credentialed retry to be a new transaction in the dialog.
pub fn handle_originated_refer_response(
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    // Provisionals do not end the transaction; keep waiting for the final.
    if (100..200).contains(&status_code) {
        return;
    }

    let Some(pending) = state.call_actors.take_originated_refer(branch) else {
        return;
    };

    // The attempt this response is about: attempt 1 is the first send, attempt
    // N a credentialed retry (RFC 7616 §3.3).
    let attempt = pending.auth_retries + 1;
    let reason = response_reason_phrase(message);

    if (200..300).contains(&status_code) {
        debug!(
            call_id = %pending.call_id,
            status = status_code,
            "B2BUA: siphon-originated REFER accepted"
        );
        // RFC 3515 §2.4.4: a 2xx to a REFER means the referee accepted it *for
        // processing* — it is NOT the transfer's outcome, which arrives later on
        // the implicit subscription as a message/sipfrag NOTIFY. So this is
        // progress, never completion.
        control_forward_transfer_outcome(
            state,
            &pending.call_id,
            crate::control::TransferOutcome::new(
                crate::control::TransferStage::from_refer_response(status_code, false),
            )
            .with_refer_to(pending.refer_to.uri.clone())
            .with_status(status_code, reason)
            .with_attempt(attempt),
        );
        return;
    }

    let challenged = status_code == 401 || status_code == 407;
    if challenged
        && pending.auth_retries < MAX_B2BUA_AUTH_RETRIES
        && retry_originated_refer_with_credentials(&pending, message, status_code, state)
    {
        // Progress, not failure: the peer challenged and siphon answered. The
        // attempt number is what lets an application tell this apart from a
        // refusal — the same 401/407 status carries both meanings.
        control_forward_transfer_outcome(
            state,
            &pending.call_id,
            crate::control::TransferOutcome::new(
                crate::control::TransferStage::from_refer_response(
                    status_code,
                    /*challenge_answered=*/ true,
                ),
            )
            .with_refer_to(pending.refer_to.uri.clone())
            .with_status(status_code, reason)
            .with_attempt(attempt),
        );
        return;
    }

    // Nothing more to try: no credentials configured, an unparseable challenge,
    // the retry cap reached, or a plain rejection. Drop the pending subscription
    // rather than leaving the script waiting on sipfrag NOTIFYs that will never
    // arrive — a transfer that failed should look failed.
    if challenged {
        warn!(
            call_id = %pending.call_id,
            status = status_code,
            retries = pending.auth_retries,
            "B2BUA: siphon-originated REFER challenged and not retried \
             (no call.set_credentials(), unparseable challenge, or retry cap reached)"
        );
    } else {
        warn!(
            call_id = %pending.call_id,
            status = status_code,
            "B2BUA: siphon-originated REFER rejected by the peer"
        );
    }
    let stage = crate::control::TransferStage::from_refer_response(
        status_code,
        /*challenge_answered=*/ false,
    );
    // Terminal: the transfer never started. Emitted together with the
    // subscription clear below so the two can never diverge — a cleared
    // subscription with no verdict is a transfer that stays pending forever.
    control_forward_transfer_outcome(
        state,
        &pending.call_id,
        crate::control::TransferOutcome::new(stage)
            .with_refer_to(pending.refer_to.uri.clone())
            .with_status(status_code, reason)
            .with_attempt(attempt),
    );
    state
        .call_actors
        .clear_refer_subscriptions_on_leg(&pending.call_id, pending.on_a_leg);
}

/// The reason phrase of a response, or `""` when the peer sent none (RFC 3261
/// §25.1 allows an empty `Reason-Phrase`).
pub fn response_reason_phrase(message: &SipMessage) -> &str {
    match &message.start_line {
        StartLine::Response(status_line) => status_line.reason_phrase.as_str(),
        StartLine::Request(_) => "",
    }
}

/// Forward one verdict on a siphon-originated (outbound) REFER to the control
/// connection owning this call, as `TransferProgress` / `TransferCompleted` /
/// `TransferFailed` (RFC 3515 §2.4.4 — see [`crate::control::TransferStage`]).
///
/// **Additive** — this runs next to, never in place of, the in-process transfer
/// machinery, and fires whether or not any Python handler is registered. A no-op
/// when the control plane isn't configured or the call isn't controlled.
///
/// `internal_call_id` is the `CallActor` id; the control bus keys channels on
/// the **A-leg** SIP Call-ID, which is not the dialog a REFER on the B-leg (or
/// its NOTIFYs) travels on, so the A-leg Call-ID is resolved from the store here
/// rather than taken from the message.
pub fn control_forward_transfer_outcome(
    state: &DispatcherState,
    internal_call_id: &str,
    outcome: crate::control::TransferOutcome,
) {
    let Some(bus) = crate::control::ControlBus::global() else {
        return;
    };
    let Some(sip_call_id) = state
        .call_actors
        .get_call(internal_call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return;
    };
    bus.forward_transfer_outcome(&sip_call_id, &outcome);
}

/// Re-send a challenged REFER carrying digest credentials. Returns `false` when
/// the retry could not be built, so the caller can report the failure.
pub fn retry_originated_refer_with_credentials(
    pending: &crate::b2bua::actor::OriginatedRefer,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    let Some(credentials) = state
        .call_actors
        .get_call(&pending.call_id)
        .and_then(|call| call.outbound_credentials.clone())
    else {
        return false;
    };

    let challenge_header = if status_code == 401 {
        message.headers.get("WWW-Authenticate")
    } else {
        message.headers.get("Proxy-Authenticate")
    };
    let Some(challenge) = challenge_header.and_then(|value| crate::auth::parse_challenge(value))
    else {
        return false;
    };

    let Some(cseq) = state
        .call_actors
        .reserve_leg_cseq(&pending.call_id, pending.on_a_leg)
    else {
        return false;
    };
    let Some(leg) = state
        .call_actors
        .clone_leg(&pending.call_id, pending.on_a_leg)
    else {
        return false;
    };

    // RFC 7616 §3.3: nc starts at 1 for a fresh nonce and increments on reuse.
    // The per-call counter resets itself when the nonce changes, so this is
    // right for both a first challenge and a stale-nonce re-challenge.
    let nc = state
        .call_actors
        .get_call(&pending.call_id)
        .map(|call| call.digest_nc.next_for(&challenge.nonce))
        .unwrap_or(1);

    let auth_value = match crate::auth::format_stored_authorization_header(
        &challenge,
        &credentials.username,
        &credentials.secret,
        Method::Refer.as_str(),
        &pending.target_uri,
        Some(nc),
        None,
    ) {
        Ok(value) => value,
        Err(mismatch) => {
            error!(
                call_id = %pending.call_id,
                status = status_code,
                realm = %challenge.realm,
                error = %mismatch,
                "B2BUA: cannot answer the REFER challenge with the stored credential"
            );
            return false;
        }
    };
    let auth_header_name = if status_code == 401 {
        "Authorization"
    } else {
        "Proxy-Authorization"
    };

    let extra_headers = [
        ("Refer-To", pending.refer_to.to_string()),
        (auth_header_name, auth_value),
    ];
    let Some(retry) =
        build_b2bua_in_dialog_request(&leg, state, Method::Refer, cseq, &extra_headers, None)
    else {
        return false;
    };

    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );

    // Track the retry's own branch — a peer may challenge again with a stale
    // nonce, and the cap is what stops that becoming a loop.
    if let Some(retry_branch) = retry
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
    {
        state.call_actors.register_originated_refer(
            &retry_branch,
            crate::b2bua::actor::OriginatedRefer {
                auth_retries: pending.auth_retries + 1,
                ..pending.clone()
            },
        );
    }

    info!(
        call_id = %pending.call_id,
        status = status_code,
        realm = %challenge.realm,
        attempt = pending.auth_retries + 1,
        "B2BUA: siphon-originated REFER challenged, retrying with credentials"
    );

    send_message_from(
        retry,
        transport,
        destination,
        leg.transport.connection_id,
        leg.transport.local_addr,
        state,
    );
    true
}

pub fn b2bua_send_outbound_refer(
    state: &DispatcherState,
    internal_call_id: &str,
    on_a_leg: bool,
    refer_to: &crate::sip::headers::refer::ReferTo,
) -> bool {
    let Some(cseq) = state
        .call_actors
        .reserve_leg_cseq(internal_call_id, on_a_leg)
    else {
        warn!(call_id = %internal_call_id, "b2bua.refer: no such call/leg");
        return false;
    };
    let Some(leg) = state.call_actors.clone_leg(internal_call_id, on_a_leg) else {
        warn!(call_id = %internal_call_id, "b2bua.refer: leg vanished");
        return false;
    };

    let extra_headers = [("Refer-To", refer_to.to_string())];
    let Some(refer) =
        build_b2bua_in_dialog_request(&leg, state, Method::Refer, cseq, &extra_headers, None)
    else {
        return false;
    };

    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );

    // Record the transaction before it goes out, so its response can be matched.
    // Only the A-leg and B-legs are in the branch registry; an in-dialog request
    // siphon originates carries a fresh branch that belongs to no leg, so without
    // this its 401/407 matches nothing and the transfer fails in silence.
    if let Some(branch) = refer
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
    {
        state.call_actors.register_originated_refer(
            &branch,
            crate::b2bua::actor::OriginatedRefer {
                call_id: internal_call_id.to_string(),
                on_a_leg,
                target_uri: refer
                    .request_uri()
                    .map(|uri| uri.to_string())
                    .unwrap_or_default(),
                refer_to: refer_to.clone(),
                auth_retries: 0,
            },
        );
    }

    // Recorded BEFORE the REFER goes out, for the same reason the branch above
    // is: this is what tells `handle_b2bua_notify` the referee's sipfrag NOTIFYs
    // are siphon's own to absorb rather than somebody else's to bridge. The send
    // and the NOTIFY that answers it are not on the same thread — an imperative
    // `b2bua.refer()` runs on a control-plane task, a timer or an event
    // callback, while the referee's 202 + first NOTIFY come back on the
    // dispatcher's consumer pool — so recording this after the send leaves a
    // window in which the first NOTIFY finds no subscription, takes the
    // bridge path, and on a one-legged call gets a 481 instead of the 200 +
    // sipfrag that carries the transfer's verdict (RFC 3515 §2.4.4).
    state.call_actors.push_refer_subscription(
        internal_call_id,
        crate::b2bua::actor::ReferSubscription {
            on_a_leg,
            siphon_notifies: false,
            // Subscriber role: siphon sent the REFER, so this is a REFER
            // subscription in the plain sense. It dials nothing and promotes
            // nothing, so `origin` never gates anything here.
            origin: crate::b2bua::transfer::ReplacementOrigin::Refer,
            event_id: cseq,
            notify_cseq: cseq,
            state: crate::b2bua::transfer::TransferState::Trying,
            target_leg_call_id: None,
            // Subscriber role: siphon is the referrer here, so there is no
            // remote referrer whose departure this could track.
            referrer_gone: false,
            // No leg of siphon's own is being waited on — the far end runs the
            // transfer and reports by NOTIFY — so there is nothing to time out.
            deadline: None,
            media_profile: None,
        },
    );

    send_message_from(
        refer,
        transport,
        destination,
        leg.transport.connection_id,
        leg.transport.local_addr,
        state,
    );

    info!(
        call_id = %internal_call_id,
        target = %refer_to.uri,
        on_a_leg,
        attended = refer_to.replaces.is_some(),
        "B2BUA: sent siphon-originated REFER"
    );
    true
}

/// Imperative `b2bua.refer(call_id, target, replaces=None)` — send an outbound
/// REFER on a live B2BUA call from any context (event callbacks like
/// `@rtpengine.on_dtmf`, timers), keyed by SIP Call-ID. Refers the A-leg (the
/// caller / IVR-connected party). Returns `false` if the Call-ID is unknown or
/// the dispatcher is not running. Mirrors [`b2bua_terminate_call`].
pub fn b2bua_refer_call(sip_call_id: &str, refer_to: crate::sip::headers::refer::ReferTo) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let Some(internal_call_id) = control.state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return false;
    };
    let _enter = control.runtime.enter();
    b2bua_send_outbound_refer(
        &control.state,
        &internal_call_id,
        /*on_a_leg=*/ true,
        &refer_to,
    )
}

/// Accept a *controlled* call's pending inbound REFER — the control-plane
/// `accept_refer` verb. Pops the REFER held by [`handle_b2bua_refer`] for a
/// controlled call and drives the shipped [`b2bua_refer_accept`] transfer in the
/// resolved mode (terminate = siphon-terminated 202 + NOTIFY + re-dial;
/// transparent = forward on the far leg), reusing the exact same machinery the
/// `@b2bua.on_refer` accept path uses — including #181's single-leg behaviour
/// (a voice-ai / IVR call with no B leg re-dials the target off the A dialog,
/// falling back to the referrer's SDP when there is no surviving leg to bridge).
///
/// `target` overrides the Refer-To URI, `next_hop` steers egress without
/// reshaping the R-URI, `mode` overrides the configured
/// `b2bua.default_refer_mode`, and `media_profile` names the profile for the
/// pairing the transfer creates (see `accept_refer(profile=…)` — required when
/// the call is anchored with a direction-bound profile). Returns `false` (never panics) when no REFER is
/// pending for this call (already decided, timed out, or the call is gone),
/// which the adapter maps to `not_found`. Safe from any thread (enters the
/// dispatcher runtime), mirroring [`b2bua_refer_call`].
pub fn b2bua_accept_refer_call(
    sip_call_id: &str,
    target: Option<String>,
    next_hop: Option<String>,
    mode: Option<crate::script::api::call::ReferMode>,
    media_profile: Option<String>,
    number_shape: Option<crate::script::api::numbers::NumberShape>,
) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let state = &control.state;
    let Some(pending) = state.pending_inbound_refer.take(sip_call_id) else {
        return false;
    };
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        // The call vanished between the REFER and the decision — the referrer's
        // transaction is gone too. The pending entry is already removed (no leak).
        warn!(%sip_call_id, "b2bua_accept_refer_call: call gone before accept — dropping pending REFER");
        return false;
    };

    // The send path re-anchors media (block_in_place) and may spawn (TCP/TLS
    // connect); the caller may be on a non-tokio thread (control apply task) —
    // establish the runtime, mirroring b2bua_route_call / b2bua_refer_call.
    let _enter = control.runtime.enter();

    let mode = mode.unwrap_or(state.default_refer_mode);
    let target_uri = target.unwrap_or_else(|| pending.refer_to.uri.clone());
    b2bua_refer_accept(
        pending.inbound,
        pending.message,
        &internal_call_id,
        pending.from_a_leg,
        &target_uri,
        next_hop.as_deref(),
        pending.refer_to.replaces.clone(),
        mode,
        media_profile.as_deref(),
        number_shape.as_ref(),
        state,
    );
    true
}

/// Replace one leg of an answered B2BUA call with a freshly dialed target,
/// decided by siphon rather than by a REFER (`b2bua.replace_peer()`).
///
/// Runs the machinery a siphon-terminated REFER already runs — dial the target
/// as a new leg on the same call actor, re-anchor the surviving party's media
/// onto it, promote it into the surviving pair when it answers, BYE the leg it
/// replaced — with the one difference that nobody subscribed, so nobody is
/// notified. That path was reachable only through
/// [`b2bua_accept_refer_call`], which opens by taking a *pending inbound
/// REFER* and bails when there is none, so a script or controller that decided
/// on its own had no way in.
///
/// **The replaced leg stays up while the target rings** and is released only
/// once the target answers, so the surviving party hears the transfer rather
/// than silence, and a target that rejects leaves the original call exactly as
/// it was. `timeout_secs` bounds the ring (`0` = no ring policy, just the
/// `LEG_REPLACEMENT_GUARD_SECS` leak guard).
///
/// `replace_a_leg` picks the direction: `false` (the common case) replaces the
/// callee and keeps the caller, `true` does the reverse. Safe from any thread —
/// enters the dispatcher runtime, mirroring [`b2bua_accept_refer_call`].
pub fn b2bua_replace_peer(
    sip_call_id: &str,
    target: &str,
    next_hop: Option<&str>,
    replace_a_leg: bool,
    media_profile: Option<&str>,
    number_shape: Option<&crate::script::api::numbers::NumberShape>,
    timeout_secs: u32,
) -> Result<(), crate::b2bua::transfer::ReplaceError> {
    use crate::b2bua::transfer::{ReplaceError, ReplacementOrigin};

    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(ReplaceError::Unavailable(
            "B2BUA is not running".to_string(),
        ));
    };
    let state = &control.state;
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return Err(ReplaceError::UnknownCall {
            id: sip_call_id.to_string(),
        });
    };

    {
        let Some(call) = state.call_actors.get_call(&internal_call_id) else {
            return Err(ReplaceError::UnknownCall {
                id: sip_call_id.to_string(),
            });
        };
        // A replacement re-INVITEs the survivor, and RFC 3261 §14 defines the
        // re-INVITE only inside a confirmed dialog — so an unanswered call is
        // refused rather than queued behind its own answer.
        if call.state != crate::b2bua::actor::CallState::Answered {
            return Err(ReplaceError::NotAnswered {
                id: sip_call_id.to_string(),
                state: format!("{:?}", call.state).to_lowercase(),
            });
        }
        // Two replacements at once would race for the same promotion slot: the
        // second target's 2xx would promote against a pair the first already
        // changed. `push_refer_subscription` is a bare push with no dedup, so
        // this is the only thing standing between a caller and that race.
        if call
            .refer_subscriptions
            .iter()
            .any(|subscription| subscription.siphon_notifies)
        {
            return Err(ReplaceError::ReplacementInFlight {
                id: sip_call_id.to_string(),
            });
        }
    }

    // Both legs must exist: the one being replaced and the one that survives to
    // be re-INVITEd. `clone_leg(_, false)` resolves the *winning* B-leg, so this
    // also rules out a UAS-mode call that answered without ever dialling.
    if state
        .call_actors
        .clone_leg(&internal_call_id, false)
        .is_none()
    {
        return Err(ReplaceError::NoPeerLeg {
            id: sip_call_id.to_string(),
        });
    }

    // The send path re-anchors media (block_in_place) and may spawn (TCP/TLS
    // connect); the caller may be on a non-tokio thread (a script handler, a
    // timer, the control apply task).
    let _enter = control.runtime.enter();

    let dialed = b2bua_start_leg_replacement(
        &internal_call_id,
        replace_a_leg,
        target,
        next_hop,
        // No REFER, so no attended `Replaces` to translate and no `Referred-By`
        // to carry: this INVITE is triggered by siphon, on nobody's authority
        // but its own. `event_id` is meaningless for the same reason.
        None,
        None,
        media_profile,
        number_shape,
        0,
        ReplacementOrigin::SiphonInitiated,
        timeout_secs,
        state,
    );
    if !dialed {
        return Err(ReplaceError::Unroutable {
            target: target.to_string(),
        });
    }
    info!(
        call_id = %internal_call_id,
        target = %target,
        replace_a_leg,
        timeout_secs,
        "B2BUA: leg replacement started (siphon-initiated, no REFER)"
    );
    Ok(())
}

/// Reject a *controlled* call's pending inbound REFER — the control-plane
/// `reject_refer` verb. Pops the REFER held by [`handle_b2bua_refer`] and sends
/// the given final non-2xx to the referrer on the flow it arrived on (the same
/// builder the no-handler / deadline paths use, so the referrer is always
/// answered per RFC 3515 §2.4.2). Returns `false` (mapped to `not_found` by the
/// adapter) when no REFER is pending for this call. Safe from any thread.
pub fn b2bua_reject_refer_call(sip_call_id: &str, code: u16, reason: &str) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let state = &control.state;
    let Some(pending) = state.pending_inbound_refer.take(sip_call_id) else {
        return false;
    };
    let _enter = control.runtime.enter();
    b2bua_refer_send_final(&pending.inbound, &pending.message, code, reason, state);
    true
}
