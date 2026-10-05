//! A re-INVITE or an UPDATE on a call with no second leg, from a party the
//! media engine cannot answer for.
//!
//! The engine answers such a request itself only on a session it is the far
//! side of ([`answer_one_legged_reoffer`]). Two kinds of leg have none:
//!
//! * A leg whose media session **relays to a second party**. The session a
//!   controller bridge formed is stored under its anchor and outlives an
//!   `unbridge`: the engine call still joins the two parties, held, so a
//!   second `bridge` renegotiates it in place. A local answer there would
//!   write a one-party call over that relay, or be refused by an engine that
//!   guards against it, and either way the leg is told about media the other
//!   party's side no longer matches.
//! * A leg with **no session at all**: the other leg of such a pair, whose own
//!   session was retired when the bridge formed, or a call siphon answered
//!   with a description that is not the engine's.
//!
//! Such a leg is answered from what its dialog already has, and the engine is
//! sent nothing:
//!
//! * A request that changes nothing is a session refresh (RFC 4028 §10): no
//!   SDP, or the SDP the party last sent, which RFC 3264 §8 has it mark by an
//!   unchanged `o=` line. It is answered `200` with the session in force on
//!   the dialog. A re-INVITE's 2xx has to carry it (RFC 3261 §14.2, the offer
//!   when the request had none); an UPDATE with no offer needs no body.
//! * An offer that would change the session is refused `488 Not Acceptable
//!   Here` (RFC 3261 §14.2). Nothing can answer it truthfully, and under
//!   §14.1 the session stays exactly as it was, which is held. The offer is
//!   not recorded as the party's media either, so a bridge afterwards offers
//!   what the party really has.
use crate::dispatcher::*;

/// The `o=` line of `sdp`, which names a session description and its version.
fn origin_line(sdp: &[u8]) -> Option<&[u8]> {
    sdp.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find(|line| line.starts_with(b"o="))
}

/// Answer the re-INVITE or UPDATE `message` on the A-leg of `call_id` when the
/// call has no second leg and no session the engine could answer it from.
/// Returns `false` for any other call, which the ordinary handling takes;
/// `true` when the request was answered here.
pub fn answer_unanchored_reoffer(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) -> bool {
    let (Some(_), Some(sessions)) = (
        state.rtpengine_set.as_ref(),
        state.rtpengine_sessions.as_ref(),
    ) else {
        return false;
    };
    let Some(sip_call_id) = state
        .call_actors
        .get_call(call_id)
        .filter(|call| call.winner.is_none())
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return false;
    };
    if sessions
        .get(&sip_call_id)
        .is_some_and(|session| session.to_tag.is_none())
    {
        return false;
    }

    let is_invite = message.method() == Some(&Method::Invite);
    let offered = !message.body.is_empty();
    // Read only now: the call the engine answers for never gets this far.
    let (unchanged, in_force) = match state.call_actors.get_call(call_id) {
        Some(call) => (
            !offered
                || call
                    .a_leg
                    .last_sdp
                    .as_deref()
                    .and_then(origin_line)
                    .is_some_and(|known| origin_line(&message.body) == Some(known)),
            call.a_leg.dialog.last_sent_sdp.clone(),
        ),
        None => return false,
    };
    if !unchanged {
        warn!(
            %call_id,
            "B2BUA: an offer from a leg with no second party and no media session the engine \
             answers for it: 488, the session in force stays as it is"
        );
        reject_unanchorable_offer(message, inbound, state, call_id, None);
        return true;
    }
    if !offered && !is_invite {
        send_one_legged_ok(inbound, message, call_id, Vec::new(), state);
        return true;
    }
    match in_force {
        Some(session) => {
            debug!(%call_id, "B2BUA: a session refresh answered from the session in force");
            send_one_legged_ok(inbound, message, call_id, session, state);
        }
        None => {
            warn!(%call_id, "B2BUA: a session refresh on a leg with no session in force: 488");
            reject_unanchorable_offer(message, inbound, state, call_id, None);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::origin_line;

    #[test]
    fn the_origin_line_is_found_whatever_ends_the_lines() {
        assert_eq!(
            origin_line(b"v=0\r\no=- 1 2 IN IP4 192.0.2.10\r\ns=-\r\n"),
            Some(&b"o=- 1 2 IN IP4 192.0.2.10"[..])
        );
        assert_eq!(
            origin_line(b"v=0\no=- 1 2 IN IP4 192.0.2.10\ns=-\n"),
            Some(&b"o=- 1 2 IN IP4 192.0.2.10"[..])
        );
        assert_eq!(origin_line(b"v=0\r\ns=-\r\n"), None);
        assert_eq!(origin_line(b""), None);
    }
}
