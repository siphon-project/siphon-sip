//! A call siphon placed itself, challenged by the callee's side: the
//! credentialed re-INVITE (RFC 3261 §22) it answers a `401`/`407` with.
//! Split from [`super::originate`], whose response handling calls it.
use super::originate::with_invite_route_set;
use crate::dispatcher::*;

/// Answer a `401`/`407` on a call siphon placed itself with a credentialed
/// re-INVITE (RFC 3261 §22). Returns `true` when a retry went out, in which
/// case the caller must not treat the response as a failure.
///
/// The B-leg twin is `retry_with_credentials` in `response/failed.rs`. This is
/// a second implementation of the same rule rather than a shared one because an
/// originated call has no B-leg — it is a UAC on its own A-leg — so none of the
/// `BLegResponseSnapshot` the other path works from exists here. What is shared
/// is the order (ACK the non-2xx first, §17.1.1.3), the retry cap, and the
/// message builder.
///
/// Returning `false` falls through to the ordinary failure path, which ACKs and
/// reports — so an uncredentialed call, an unparseable challenge and an
/// exhausted retry budget all behave exactly as they did before.
pub(super) fn retry_originate_with_credentials(
    internal_call_id: &str,
    leg: &Leg,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    if status_code != 401 && status_code != 407 {
        return false;
    }

    let Some(credentials) = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.outbound_credentials.clone())
    else {
        // No credentials: the challenge is the call's final answer, as before.
        return false;
    };

    // A trunk that rejects every fresh credentialed attempt (wrong password, or
    // a new nonce each time) would otherwise be re-authed for ever, since each
    // retry lands on a new branch and so never self-terminates.
    if state.call_actors.auth_retry_count(internal_call_id) >= MAX_B2BUA_AUTH_RETRIES {
        warn!(
            call_id = %internal_call_id,
            status = status_code,
            limit = MAX_B2BUA_AUTH_RETRIES,
            "originate: auth retry limit reached — failing the call instead of re-authing"
        );
        return false;
    }

    let challenge_header = if status_code == 401 {
        message.headers.get("WWW-Authenticate")
    } else {
        message.headers.get("Proxy-Authenticate")
    };
    let Some(challenge) = challenge_header.and_then(|value| crate::auth::parse_challenge(value))
    else {
        return false;
    };

    let Some(target_uri) = leg.dialog.target_uri.clone() else {
        return false;
    };
    let Some(stored_invite) = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.a_leg_invite.clone())
    else {
        return false;
    };
    let Ok(original) = stored_invite.lock().map(|invite| invite.clone()) else {
        return false;
    };

    // RFC 7616 §3.3: nc starts at 1 for a fresh nonce and increments on reuse.
    // The per-call counter resets itself when the nonce changes.
    let nc = state
        .call_actors
        .get_call(internal_call_id)
        .map(|call| call.digest_nc.next_for(&challenge.nonce))
        .unwrap_or(1);

    let auth_header_name = if status_code == 401 {
        "Authorization"
    } else {
        "Proxy-Authorization"
    };
    let auth_value = match crate::auth::format_stored_authorization_header(
        &challenge,
        &credentials.username,
        &credentials.secret,
        "INVITE",
        &target_uri,
        Some(nc),
        None,
    ) {
        Ok(value) => value,
        Err(mismatch) => {
            error!(
                call_id = %internal_call_id,
                status = status_code,
                realm = %challenge.realm,
                error = %mismatch,
                "originate: cannot answer the challenge with the stored credential"
            );
            return false;
        }
    };

    // ACK the challenge on its own branch before anything else (§17.1.1.3):
    // the callee's server transaction retransmits until it lands.
    let (via_host, via_port) = placed_leg_sent_by(leg, state);
    let ack = build_b2bua_ack_for_non2xx(
        message,
        &leg.branch,
        Some(target_uri.as_str()),
        leg.transport.transport,
        &via_host,
        via_port,
    );
    send_b2bua_to_bleg(
        with_invite_route_set(ack, internal_call_id, state),
        leg.transport.transport,
        leg.transport.remote_addr,
        leg.transport.local_addr,
        state,
    );

    // A new transaction: new branch, next CSeq (§8.1.3.5).
    let branch = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());
    let cseq = leg.dialog.local_cseq.saturating_add(1);
    let via = format!(
        "SIP/2.0/{} {}:{};branch={};rport",
        leg.transport.transport.to_string().to_uppercase(),
        via_host,
        via_port,
        branch
    );
    let retry = build_digest_retry_invite(&original, via, cseq, auth_header_name, auth_value);

    // Index the new branch before sending: on loopback the answer can arrive
    // before a post-send registration would finish, and an unindexed branch is
    // a response for an unknown call.
    state.call_actors.mark_originated(internal_call_id, &branch);
    if let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) {
        call.a_leg.branch = branch.clone();
        call.a_leg.dialog.local_cseq = cseq;
        call.a_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));
    }
    state.call_actors.incr_auth_retry_count(internal_call_id);

    info!(
        call_id = %internal_call_id,
        status = status_code,
        realm = %challenge.realm,
        nc = nc,
        "originate: {status_code} received, retrying with credentials"
    );
    send_b2bua_to_bleg(
        retry,
        leg.transport.transport,
        leg.transport.remote_addr,
        leg.transport.local_addr,
        state,
    );
    true
}
