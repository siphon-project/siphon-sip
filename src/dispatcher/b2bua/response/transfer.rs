//! Responses to non-INVITE in-dialog requests siphon forwarded across a call.

use crate::dispatcher::*;

/// A response to a forwarded non-INVITE in-dialog request (REFER, NOTIFY, INFO). Returns
/// `true` when the response was consumed here.
pub fn forward_transfer_response(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // A response to a non-INVITE in-dialog request siphon forwarded across the
    // call (transparent REFER / NOTIFY, and INFO): relayed back to the
    // originator like the UPDATE arm — no ACK (non-INVITE) and no media
    // handling (REFER is bodyless; a NOTIFY sipfrag or INFO body is opaque and
    // rides back untouched). The set is `ForwardedMarker`, the same type the
    // forward tagged the pseudo-leg with, so a request type cannot be forwarded
    // without also being recognised here.
    let forwarded_response = snapshot
        .b_leg_target
        .as_deref()
        .and_then(crate::b2bua::actor::ForwardedMarker::from_tracking_target);
    if let Some((marker, direction)) = forwarded_response {
        let marker_name = marker.as_str();
        let is_a2b = direction == "a2b";
        // 4th element: the responder leg's anchored egress socket (see the
        // re-INVITE response path above).
        let (resp_dest, resp_transport, resp_conn_id, resp_local_addr) = if is_a2b {
            (
                snapshot.a_leg.transport.remote_addr,
                snapshot.a_leg.transport.transport,
                snapshot.a_leg.transport.connection_id,
                snapshot.a_leg_local_addr,
            )
        } else {
            match state.call_actors.get_call(call_id) {
                Some(call) => match call.winner.and_then(|i| call.b_legs.get(i)) {
                    Some(b) => (
                        b.transport.remote_addr,
                        b.transport.transport,
                        ConnectionId::default(),
                        b.transport.local_addr,
                    ),
                    None => {
                        warn!(call_id = %call_id, marker = marker_name, "B2BUA forwarded response: no winning B-leg");
                        return true;
                    }
                },
                None => return true,
            }
        };

        if is_a2b {
            if let Some((ref _b_cid, ref b_ftag)) = snapshot.b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &snapshot.a_leg.dialog.call_id,
                    b_ftag,
                    snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&snapshot.a_leg.dialog.local_tag),
                );
            }
            // RFC 3261 §8.2.6.2: echo the originator's request From/To verbatim.
            // The pseudo-leg captured the exact request headers at creation; that
            // is the precise thing this response is answering, so it beats
            // reconstructing from the A-leg INVITE / dialog (which can differ by a
            // port, param, or display name the peer never sent). Fall back to the
            // A-leg INVITE only if the capture is somehow absent.
            if let Some(ref from) = snapshot.b_leg_stored_from {
                message.headers.set("From", from.clone());
            } else if let Some(invite_arc) = &snapshot.a_leg_invite {
                if let Ok(invite) = invite_arc.lock() {
                    if let Some(from) = invite.headers.from() {
                        message.headers.set("From", from.clone());
                    }
                }
            }
            if let Some(ref to) = snapshot.b_leg_stored_to {
                message.headers.set("To", to.clone());
            } else if let Some(invite_arc) = &snapshot.a_leg_invite {
                if let Ok(invite) = invite_arc.lock() {
                    if let Some(to) = invite.headers.to() {
                        message.headers.set(
                            "To",
                            crate::b2bua::actor::ensure_tag(
                                to,
                                Some(&snapshot.a_leg.dialog.local_tag),
                            ),
                        );
                    }
                }
            }
        } else if let Some(call) = state.call_actors.get_call(call_id) {
            if let Some(winner) = call.winner.and_then(|i| call.b_legs.get(i)) {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &winner.dialog.call_id,
                    snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    &winner.dialog.local_tag,
                    winner.dialog.remote_tag.as_deref(),
                );
                // RFC 3261 §8.2.6.2: echo the far leg's request From/To verbatim
                // from the pseudo-leg capture (the exact NOTIFY/REFER this answers),
                // not the dialog URIs — those reconstruct From = far end / To =
                // siphon's B-leg identity but can carry a `:5060` (or param) the
                // peer omitted. Dialog reconstruction is the fallback only.
                if let Some(ref from) = snapshot.b_leg_stored_from {
                    message.headers.set("From", from.clone());
                } else if let Some(ref from_uri) = winner.dialog.remote_to_uri {
                    message.headers.set(
                        "From",
                        crate::b2bua::actor::ensure_tag(
                            from_uri,
                            winner.dialog.remote_tag.as_deref(),
                        ),
                    );
                }
                if let Some(ref to) = snapshot.b_leg_stored_to {
                    message.headers.set("To", to.clone());
                } else if let Some(ref to_uri) = winner.dialog.local_from_uri {
                    message.headers.set(
                        "To",
                        crate::b2bua::actor::ensure_tag(to_uri, Some(&winner.dialog.local_tag)),
                    );
                }
            }
        }

        // Restore the originator's Via and CSeq (RFC 3261 §8.2.6.2).
        message
            .headers
            .set_all("Via", snapshot.b_leg_stored_vias.clone());
        if let Some(ref cseq) = snapshot.b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }
        sanitize_b2bua_response(
            message,
            state,
            resp_transport,
            if is_a2b {
                snapshot.a_leg_local_addr
            } else {
                None
            },
            snapshot.a_leg_supports_100rel,
            call_id,
        );

        if (200..300).contains(&status_code) {
            if let Some(idx) = snapshot.b_leg_index {
                state
                    .call_actors
                    .set_b_leg_target_uri(call_id, idx, marker.done_target(direction));
            }
        } else if status_code >= 300 {
            if let Some(idx) = snapshot.b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
        }

        if is_a2b {
            send_message_from(
                message.clone(),
                resp_transport,
                resp_dest,
                resp_conn_id,
                resp_local_addr,
                state,
            );
        } else {
            send_b2bua_to_bleg(
                message.clone(),
                resp_transport,
                resp_dest,
                resp_local_addr,
                state,
            );
        }
        debug!(call_id = %call_id, status = status_code, marker = marker_name, direction, "B2BUA: relayed forwarded in-dialog response");
        return true;
    }

    false
}
