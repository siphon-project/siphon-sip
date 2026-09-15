//! RFC 4028 session timers on the dialogs of a B2BUA call.
//!
//! Negotiated per dialog when the callee answers
//! ([`negotiate_answered_session_timers`]), kept with every final response to a
//! re-INVITE or UPDATE that crosses a dialog ([`session_timer_on_response`],
//! [`negotiate_relayed_session_timer`]), and driven by the sweep
//! ([`session_timer_sweep`]): siphon refreshes the dialogs it is the refresher of
//! ([`b2bua_send_session_refresh`]) and ends a call whose session ran out on
//! either dialog.

use std::time::Instant;

use crate::b2bua::session_timer::{
    allows_update, answer_as_uas, declining_answer, min_se_of, requested_interval_of,
    uac_session_timer, withdraw_from_answer, SessionTimerDue, SessionTimerPolicy,
    MIN_SESSION_INTERVAL,
};
use crate::dispatcher::*;
use crate::sip::headers::SipHeaders;

/// What siphon wants from the session timer of `call_id`: its
/// `call.session_timer()`, else the `session_timer:` block when enabled. `None`
/// runs no session timer on the call.
pub fn session_timer_policy(state: &DispatcherState, call_id: &str) -> Option<SessionTimerPolicy> {
    let per_call = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.session_timer_override.clone());
    session_timer_policy_for(state, per_call.as_ref())
}

/// [`session_timer_policy`] for a call whose `call.session_timer()` is at hand.
pub fn session_timer_policy_for(
    state: &DispatcherState,
    per_call: Option<&crate::script::api::call::SessionTimerOverride>,
) -> Option<SessionTimerPolicy> {
    match per_call {
        Some(per_call) => Some(SessionTimerPolicy {
            session_expires: per_call.session_expires,
            min_se: per_call.min_se,
            preference: per_call.refresher,
        }),
        None => state
            .session_timer_config
            .as_ref()
            .filter(|config| config.enabled)
            .map(|config| SessionTimerPolicy {
                session_expires: config.session_expires,
                min_se: config.min_se,
                preference: config.refresher,
            }),
    }
}

/// Negotiate the session timers of both dialogs of a call the callee just
/// answered, and put the caller's on the 2xx siphon sends the caller.
///
/// `callee_answer` is the callee's 2xx as it arrived. On the callee's dialog
/// siphon is the UAC, and that 2xx decides the timer (RFC 4028 §7.2).
/// `caller_answer` is the 2xx siphon sends the caller, on whose dialog siphon is
/// the UAS: its session timer comes from the caller's INVITE and siphon's policy
/// (§9), never from the callee's `Session-Expires`, which describes the other
/// dialog. Each peer's `Allow` is kept either way, for what a later refresh can
/// be.
pub fn negotiate_answered_session_timers(
    call_id: &str,
    callee_answer: &SipMessage,
    caller_answer: &mut SipMessage,
    snapshot: &BLegResponseSnapshot,
    state: &DispatcherState,
) {
    let caller_request = snapshot
        .a_leg_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.headers.clone()));
    state.call_actors.set_leg_peer_allows_update(
        call_id,
        false,
        allows_update(&callee_answer.headers),
    );
    if let Some(request) = &caller_request {
        state
            .call_actors
            .set_leg_peer_allows_update(call_id, true, allows_update(request));
    }

    let Some(policy) = session_timer_policy(state, call_id) else {
        return;
    };
    let now = Instant::now();

    // The INVITE siphon sent the callee asked for the policy's interval; with no
    // Session-Expires in the 2xx siphon still refreshes at that interval (§7.2).
    let callee_request = snapshot
        .b_leg_stored_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.headers.clone()));
    let requested = callee_request
        .as_ref()
        .and_then(requested_interval_of)
        .unwrap_or_else(|| policy.requested_interval());
    let callee_min_se = policy
        .min_se
        .max(callee_request.as_ref().and_then(min_se_of).unwrap_or(0));
    let callee_timer =
        uac_session_timer(&callee_answer.headers, Some(requested), callee_min_se, now);

    let caller_timer = match caller_request
        .as_ref()
        .and_then(|request| answer_as_uas(request, &policy, None))
    {
        Some(answer) => {
            answer.apply(&mut caller_answer.headers);
            Some(answer.timer(policy.min_se.max(answer.request_min_se), now))
        }
        None => {
            withdraw_from_answer(&mut caller_answer.headers);
            None
        }
    };

    debug!(
        call_id = %call_id,
        caller = ?caller_timer.as_ref().map(|timer| (timer.session_expires, timer.siphon_refreshes)),
        callee = ?callee_timer.as_ref().map(|timer| (timer.session_expires, timer.siphon_refreshes)),
        "B2BUA: session timers negotiated (interval, siphon refreshes)"
    );
    state
        .call_actors
        .set_leg_session_timer(call_id, false, callee_timer);
    state
        .call_actors
        .set_leg_session_timer(call_id, true, caller_timer);
}

/// Refresh the session on one leg's dialog (RFC 4028 §7.4, §10): the A-leg, or
/// the winning B-leg.
///
/// A request on that dialog like every other one siphon originates there. It
/// carries the dialog's option tags, `Session-Expires` at the current interval
/// with `refresher=uac`, since siphon refreshes only a dialog it is the refresher
/// of and keeps that role, and the dialog's `Min-SE`.
///
/// A re-INVITE offers the session description in force on the dialog
/// ([`session_refresh_offer`]). With none, the refresh is an UPDATE without a
/// body where the peer allows UPDATE, which §7.4 recommends and which needs no
/// offer, and otherwise a re-INVITE without one, whose 2xx brings an offer siphon
/// answers in the ACK ([`answer_offer_in_ack`]). The refresh is recorded as in
/// flight before it goes out, so its response is always recognised; only a 2xx to
/// it restarts the session.
pub fn b2bua_send_session_refresh(call_id: &str, on_a_leg: bool, state: &DispatcherState) {
    let Some(leg) = state.call_actors.clone_leg(call_id, on_a_leg) else {
        debug!(call_id = %call_id, on_a_leg, "B2BUA refresh: the leg is gone");
        return;
    };
    let Some(timer) = leg.dialog.session_timer.clone() else {
        debug!(call_id = %call_id, on_a_leg, "B2BUA refresh: the dialog has no session timer");
        return;
    };
    let session_expires = timer.refresh_interval();
    let mut headers = if on_a_leg {
        own_option_tags()
    } else {
        initial_option_tags(&leg)
    };
    headers.push((
        "Session-Expires",
        format!("{session_expires};refresher=uac"),
    ));
    headers.push(("Min-SE", timer.min_se.to_string()));

    let offer = session_refresh_offer(&leg, call_id, on_a_leg, state);
    let (method, tracking_target) = match (&offer, leg.dialog.peer_allows_update) {
        (None, true) => (
            Method::Update,
            if on_a_leg { "update:b2a" } else { "update:a2b" },
        ),
        _ => (
            Method::Invite,
            if on_a_leg {
                "reinvite:b2a"
            } else {
                "reinvite:a2b"
            },
        ),
    };
    let request = InDialogRequest {
        method,
        body: offer,
        extra_headers: &headers,
        tracking_target,
        requested_session_expires: Some(session_expires),
    };
    let sent = send_in_dialog_request(
        call_id,
        on_a_leg,
        request,
        |branch| {
            state
                .call_actors
                .update_leg_session_timer(call_id, on_a_leg, |timer| {
                    timer.refresh_sent(branch.to_string(), session_expires, Instant::now())
                });
        },
        state,
    );
    if sent {
        debug!(call_id = %call_id, on_a_leg, tracking = %tracking_target, "B2BUA: sent a session refresh");
    } else {
        debug!(call_id = %call_id, on_a_leg, "B2BUA refresh: the leg went away before the refresh went out");
    }
}

/// The `Supported`, `Require` and `Proxy-Require` values of the INVITE that set
/// `leg`'s dialog up, which RFC 4028 §7.4 says a later session refresh on the
/// dialog MUST use. siphon's own option tags when that INVITE is not on the leg.
fn initial_option_tags(leg: &Leg) -> Vec<(&'static str, String)> {
    let initial = leg
        .b_leg_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.headers.clone()));
    match initial {
        Some(initial) => ["Supported", "Require", "Proxy-Require"]
            .into_iter()
            .flat_map(|name| {
                initial
                    .get_all(name)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |value| (name, value))
            })
            .collect(),
        None => own_option_tags(),
    }
}

/// siphon's own option tags, `timer` among them: the tags of the first session
/// refresh siphon sends on a dialog whose INVITE it did not send, and so of every
/// later one (RFC 4028 §7.1, §7.4).
fn own_option_tags() -> Vec<(&'static str, String)> {
    let mut own = SipHeaders::new();
    advertise_supported_options(&mut own);
    advertise_option_tag(&mut own, "timer");
    own.get("Supported")
        .map(|value| vec![("Supported", value.clone())])
        .unwrap_or_default()
}

/// The offer a session refresh carries: the session description siphon has in
/// force on `leg`'s dialog, which is the offer the peer last accepted or the
/// answer siphon last sent it. A held call stays held.
///
/// RFC 3264 §8 decides its `o=`. When siphon has sent the peer no other SDP since,
/// it goes out byte for byte, and the unchanged version says the session has not
/// changed (RFC 4028 §7.4). When a later offer took a version and was refused, the
/// peer has seen that version, so the session in force goes out under the next
/// one. `None` when siphon never sent the dialog a session description.
fn session_refresh_offer(
    leg: &Leg,
    call_id: &str,
    on_a_leg: bool,
    state: &DispatcherState,
) -> Option<Vec<u8>> {
    let mut sdp = leg.dialog.last_sent_sdp.clone()?;
    let last_version_sent = leg.dialog.sdp_version.checked_sub(1);
    let unchanged = last_version_sent.is_some_and(|version| {
        sdp_origin_identity(&sdp) == Some((leg.dialog.sdp_session_id, version))
    });
    if !unchanged {
        if let Some((session_id, version)) =
            state.call_actors.reserve_leg_sdp_version(call_id, on_a_leg)
        {
            stamp_sdp_origin(&mut sdp, &state.sdp_name, session_id, version, None);
        }
    }
    Some(sdp)
}

/// siphon's answer, for the ACK, to the offer a 2xx brought back to a re-INVITE
/// siphon sent on one leg's dialog without one (RFC 3261 §13.2.1, §14.1): every
/// offered stream declined ([`declining_answer`]), under siphon's identity toward
/// the leg. Recorded as the session description in force on the dialog. `None`
/// without such a 2xx, or when it carries no SDP.
pub fn answer_offer_in_ack(
    call_id: &str,
    on_a_leg: bool,
    response: Option<&SipMessage>,
    state: &DispatcherState,
) -> Option<Vec<u8>> {
    let response = response?;
    let offer = sdp_in_body(message_content_type(response), &response.body)?;
    let leg = state.call_actors.clone_leg(call_id, on_a_leg)?;
    let host = state.a_leg_advertised_host(leg.transport.local_addr, &leg.transport.transport);
    let mut answer = declining_answer(&offer, &host)?;
    own_sdp_toward_leg(
        &mut answer,
        "application/sdp",
        state,
        call_id,
        on_a_leg,
        Some(&host),
    );
    state
        .call_actors
        .set_leg_sent_sdp(call_id, on_a_leg, answer.clone());
    Some(answer)
}

/// Keep the session timer of the dialog a re-INVITE or UPDATE went out on, where
/// siphon is the UAC, with its final response.
///
/// `responder_on_a_leg` names that dialog and `responder_headers` are the response
/// as it arrived there. `requested` is the interval the request's
/// `Session-Expires` asked for.
///
/// A 2xx sets the dialog's session timer, refresher included (RFC 4028 §7.2); a
/// dialog with no timer gets one only on a call that runs session timers, and one
/// whose request asked for no interval keeps the interval it had. For siphon's own
/// refresh, a 408 or 481 ends the call (§10), a 422 raises the dialog's Min-SE and
/// retries at once (§7.3), and any other failure is retried before the session
/// expires. A 422 to a relayed request still raises the dialog's Min-SE (§7.4).
pub fn session_timer_on_response(
    call_id: &str,
    responder_on_a_leg: bool,
    branch: &str,
    status_code: u16,
    responder_headers: &SipHeaders,
    requested: Option<u32>,
    state: &DispatcherState,
) {
    if status_code < 200 {
        return;
    }
    let now = Instant::now();
    let current = state
        .call_actors
        .leg_session_timer(call_id, responder_on_a_leg);
    let refresh = current
        .as_ref()
        .filter(|timer| timer.is_refresh(branch))
        .and_then(|timer| timer.refresh_in_flight.as_ref())
        .map(|in_flight| in_flight.session_expires);

    if (200..300).contains(&status_code) {
        let policy = session_timer_policy(state, call_id);
        if current.is_none() && policy.is_none() {
            return;
        }
        let min_se = current
            .as_ref()
            .map(|timer| timer.min_se)
            .or(policy.map(|policy| policy.min_se))
            .unwrap_or(MIN_SESSION_INTERVAL);
        let requested = refresh
            .or(requested)
            .or(current.as_ref().map(|timer| timer.session_expires));
        let timer = uac_session_timer(responder_headers, requested, min_se, now);
        state
            .call_actors
            .set_leg_session_timer(call_id, responder_on_a_leg, timer);
        return;
    }

    if refresh.is_none() {
        if status_code == 422 {
            if let Some(min_se) = min_se_of(responder_headers) {
                state
                    .call_actors
                    .update_leg_session_timer(call_id, responder_on_a_leg, |timer| {
                        timer.raise_min_se(min_se)
                    });
            }
        }
        return;
    }
    match status_code {
        408 | 481 => {
            info!(
                call_id = %call_id,
                status = status_code,
                on_a_leg = responder_on_a_leg,
                "B2BUA: session refresh answered {status_code}, ending the call (RFC 4028 §10)"
            );
            b2bua_session_timer_terminate(call_id, state);
        }
        422 => {
            let min_se = min_se_of(responder_headers).unwrap_or(MIN_SESSION_INTERVAL);
            state
                .call_actors
                .update_leg_session_timer(call_id, responder_on_a_leg, |timer| {
                    timer.refresh_too_brief(min_se, now)
                });
        }
        _ => {
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: session refresh refused, retrying before the session expires"
            );
            state
                .call_actors
                .update_leg_session_timer(call_id, responder_on_a_leg, |timer| {
                    timer.refresh_refused(now)
                });
        }
    }
}

/// Answer, on the originator's dialog, a session refresh request siphon relayed,
/// by putting siphon's own session timer on the 2xx siphon relays there (RFC 4028
/// §9).
///
/// The 2xx came from the other party, and its `Session-Expires`, if any,
/// describes the other dialog: a party without timer support sends none, and
/// relaying that would take the originator's session timer away. siphon answers
/// the originator's request itself, as it does the caller's INVITE
/// ([`answer_as_uas`]), from `originator_request`, the request's session timer
/// headers. A dialog that already runs a timer keeps its interval, and its
/// refresher where the originator leaves the choice. Nothing changes on a call
/// that runs no session timer.
pub fn negotiate_relayed_session_timer(
    call_id: &str,
    originator_on_a_leg: bool,
    originator_request: Option<&SipHeaders>,
    relayed_answer: &mut SipHeaders,
    state: &DispatcherState,
) {
    let Some(policy) = session_timer_policy(state, call_id) else {
        return;
    };
    let Some(request) = originator_request else {
        return;
    };
    let current = state
        .call_actors
        .leg_session_timer(call_id, originator_on_a_leg);
    let timer = match answer_as_uas(request, &policy, current.as_ref()) {
        Some(answer) => {
            answer.apply(relayed_answer);
            let floor = current
                .as_ref()
                .map_or(policy.min_se, |timer| timer.min_se)
                .max(answer.request_min_se);
            Some(answer.timer(floor, Instant::now()))
        }
        None => {
            withdraw_from_answer(relayed_answer);
            None
        }
    };
    state
        .call_actors
        .set_leg_session_timer(call_id, originator_on_a_leg, timer);
}

/// A session refresh request arrived on one leg's dialog: its `Min-SE` raises
/// the dialog's (RFC 4028 §7.4).
pub fn note_session_refresh_request(
    call_id: &str,
    from_a_leg: bool,
    request: &SipHeaders,
    state: &DispatcherState,
) {
    if let Some(min_se) = min_se_of(request) {
        state
            .call_actors
            .update_leg_session_timer(call_id, from_a_leg, |timer| timer.raise_min_se(min_se));
    }
}

/// Keep the session timers of the dialogs a final response to a re-INVITE
/// crossed. `is_a2b` says the re-INVITE went toward the B-leg. The responder's
/// dialog is kept from the response as it arrived there
/// ([`session_timer_on_response`]); for a bridged re-INVITE's 2xx, `relayed` is
/// the copy relayed to the originator, which carries siphon's answer on the
/// originator's dialog ([`negotiate_relayed_session_timer`]).
pub fn keep_session_timers(
    call_id: &str,
    is_a2b: bool,
    status_code: u16,
    responder_headers: &SipHeaders,
    relayed: Option<&mut SipHeaders>,
    snapshot: &BLegResponseSnapshot,
    state: &DispatcherState,
) {
    session_timer_on_response(
        call_id,
        !is_a2b,
        &snapshot.branch,
        status_code,
        responder_headers,
        snapshot.b_leg_request_session_expires,
        state,
    );
    if let (true, Some(relayed)) = ((200..300).contains(&status_code), relayed) {
        negotiate_relayed_session_timer(
            call_id,
            is_a2b,
            snapshot.b_leg_session_refresh_request.as_ref(),
            relayed,
            state,
        );
    }
}

/// Put an SDP `answer` on an ACK, when there is one: the answer to an offer the
/// 2xx it acknowledges brought (RFC 3261 §13.2.1).
pub fn attach_ack_answer(ack: &mut SipMessage, answer: Option<Vec<u8>>) {
    if let Some(answer) = answer {
        ack.headers
            .set("Content-Type", "application/sdp".to_string());
        ack.headers.set("Content-Length", answer.len().to_string());
        ack.body = answer;
    }
}

/// Act on the session timers of every answered call, run every few seconds
/// (RFC 4028 §10): refresh each dialog siphon is the refresher of once its refresh
/// is due, and end each call one of whose sessions ran out or whose refresh went
/// unanswered.
pub fn session_timer_sweep(state: &DispatcherState) {
    let due = state.call_actors.session_timers_due(
        Instant::now(),
        state.b2bua_retransmits.transaction_timeout(),
    );
    let mut ended: Vec<String> = Vec::new();
    for (call_id, on_a_leg, what) in due {
        if ended.contains(&call_id) {
            continue;
        }
        match what {
            SessionTimerDue::Expire => {
                info!(
                    call_id = %call_id,
                    leg = if on_a_leg { "caller" } else { "callee" },
                    "B2BUA: session timer expired, ending the call (RFC 4028 §10)"
                );
                b2bua_session_timer_terminate(&call_id, state);
                ended.push(call_id);
            }
            SessionTimerDue::Refresh => b2bua_send_session_refresh(&call_id, on_a_leg, state),
            SessionTimerDue::Nothing => {}
        }
    }
}
