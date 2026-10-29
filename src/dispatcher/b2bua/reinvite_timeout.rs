//! Timer B on a re-INVITE tracked on a call, whether relayed from the other
//! party or siphon's own (a session refresh, a media re-anchor, a script's
//! `b2bua.reoffer()`).
//!
//! The party it went to never answered, not even with a provisional, and its
//! client transaction is over (RFC 3261 §17.1.1.2). The transaction user is
//! told so, and handles it as the `408` that stands for (§8.1.3.1): the dialog
//! keeps its session (§14.1), the INVITE toward that party is no longer in
//! progress, so the next one may start, the party that sent a relayed one is
//! answered rather than left waiting, and a script waiting on its own re-offer
//! is told `408`. Without this the leg stayed marked as having an INVITE in
//! progress for the rest of the call, so every later re-INVITE toward the
//! party drew `491`.

use crate::dispatcher::*;

/// The `408` for the INVITE on `branch` that Timer B ended, when that INVITE
/// is a re-INVITE tracked on a call; nothing for any other INVITE. `request`
/// is the INVITE as it was sent, which the response is built from, and
/// `destination` where it went.
///
/// Handled as an executor job of its own when called from the timer sweep:
/// the response arm can run a script (`@b2bua.on_reoffer_answered`).
pub fn reinvite_timed_out(
    branch: &str,
    request: &[u8],
    destination: SocketAddr,
    state: &DispatcherState,
) {
    let Some(call_id) = state.call_actors.call_id_for_branch(branch) else {
        return;
    };
    if !is_tracked_reinvite(&call_id, branch, state) {
        return;
    }
    let request = match crate::sip::parser::parse_sip_message_bytes(request) {
        Ok(request) => request,
        Err(error) => {
            error!(
                call_id = %call_id,
                %branch,
                %error,
                "B2BUA: re-INVITE timed out but the request it went out as does not parse; \
                 its leg stays marked as having an INVITE in progress"
            );
            return;
        }
    };
    let response = crate::dispatcher::response_builder::build_response(
        &request,
        408,
        "Request Timeout",
        None,
        &[],
    );
    warn!(
        call_id = %call_id,
        %branch,
        %destination,
        "B2BUA: re-INVITE drew no response before Timer B, ending it as a local 408"
    );
    let branch = branch.to_string();
    crate::dispatcher::tasks::post_expiry(state, move |state| {
        let mut response = response;
        // Read again here: the call can have ended, or a late response
        // settled the re-INVITE, while this job was queued.
        let Some(snapshot) = b_leg_response_snapshot(&call_id, &branch, state) else {
            return;
        };
        if !snapshot
            .b_leg_target
            .as_deref()
            .is_some_and(|target| target.starts_with("reinvite:"))
        {
            return;
        }
        forward_reinvite_response_from(
            &call_id,
            &branch,
            &mut response,
            408,
            destination,
            state,
            &snapshot,
            ReinviteResponseOrigin::TimerB,
        );
    });
}

/// Whether `branch` names a re-INVITE still waiting for its response on the
/// call `call_id`. One that completed is retargeted `reinvite_done:` and is
/// left alone.
fn is_tracked_reinvite(call_id: &str, branch: &str, state: &DispatcherState) -> bool {
    b_leg_response_snapshot(call_id, branch, state).is_some_and(|snapshot| {
        snapshot
            .b_leg_target
            .as_deref()
            .is_some_and(|target| target.starts_with("reinvite:"))
    })
}
