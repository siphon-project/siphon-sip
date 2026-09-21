//! An offer in the caller's PRACK after the caller has its 2xx (RFC 3262 §5,
//! RFC 3311).
//!
//! siphon's PRACK for a callee's reliable provisional waits for the caller's
//! PRACK of siphon's copy, but goes to the callee with the caller's 2xx when that
//! comes first ([`release_held_callee_pracks`]). A PRACK from the caller that
//! arrives after it, carrying an offer, has no PRACK of siphon's left to ride on.
//! The callee's dialog is confirmed by then, so siphon carries the offer to the
//! callee in an UPDATE on that dialog, and returns the callee's answer in the 200
//! to the caller's PRACK.
//!
//! An UPDATE, although RFC 3311 §5.1 recommends a re-INVITE on a confirmed
//! dialog: a re-INVITE may wait for the callee's user, and the caller's PRACK, a
//! non-INVITE request, has to be answered within its own transaction. An UPDATE
//! is answered at once, like the PRACK. It goes only to a callee that listed
//! UPDATE in the `Allow` of its 2xx (§4).
//!
//! A refusal leaves the session as it was (RFC 3311 §5.3), so the caller's PRACK
//! is refused the same way and the call carries on. RFC 3262 §3 has a PRACK
//! matching a provisional answered 2xx, but RFC 6337 §2.3 names a 488 to a PRACK
//! whose offer cannot be taken, after which the caller "may send again a PRACK
//! request without an offer"; siphon answers that one 200. What the callee
//! answered the UPDATE comes to on the caller's PRACK:
//!
//! | The callee's response to the UPDATE | The caller's PRACK |
//! |---|---|
//! | 2xx with an answer | 200 with the answer |
//! | 488, 606: the offer is not acceptable | 488 |
//! | 491: an offer of the callee's own crossed it | 491 |
//! | 500: the callee has an offer unanswered, with `Retry-After` | 500, with that `Retry-After` |
//! | 504: the answer needs the callee's user | 504 |
//! | 481, 408, or none within 64*T1: the dialog is gone (§5.3) | 500, and the call ends |
//! | anything else, or a 2xx without an answer | 500 |
//!
//! Before any of that the offer is refused without an UPDATE: 488 to a callee
//! that does not allow UPDATE, or when there is no answered callee to carry it to,
//! or the media engine refuses it; 491 while the caller still owes the answer to
//! the callee's offer in the 2xx (§5.2); 500 with a `Retry-After` while another
//! offer of the caller's is still with the callee.

use std::time::Instant;

use super::prack_bridge::{anchored_caller_offer, Anchoring};
use super::terminate::q850_reason;
use crate::b2bua::actor::{OfferVia, PendingPrackOffer, RequestSource};
use crate::dispatcher::*;

/// The Via branch prefix of an UPDATE siphon sends a callee for a late PRACK
/// offer. It extends [`PRACK_BRANCH_PREFIX`], so the callee's response reaches
/// [`handle_callee_prack_response`], which tells the two apart by the pending
/// offer's [`OfferVia`].
const UPDATE_BRANCH_PREFIX: &str = "z9hG4bK-prack-update-";

/// How a late PRACK offer the callee did not answer ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateOfferRefusal {
    /// The caller's PRACK gets this status and the call carries on.
    Refuse(u16),
    /// The callee's dialog is gone (RFC 3311 §5.3): the caller's PRACK gets 500
    /// and the call ends.
    EndCall,
}

/// What the callee's final response `status_code` to the UPDATE comes to, per the
/// table in the module documentation.
pub fn late_offer_refusal(status_code: u16) -> LateOfferRefusal {
    match status_code {
        408 | 481 => LateOfferRefusal::EndCall,
        488 | 606 => LateOfferRefusal::Refuse(488),
        491 => LateOfferRefusal::Refuse(491),
        504 => LateOfferRefusal::Refuse(504),
        _ => LateOfferRefusal::Refuse(500),
    }
}

/// The reason phrase siphon gives a status it refuses a PRACK's offer with.
pub fn prack_refusal_reason(status_code: u16) -> &'static str {
    match status_code {
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        504 => "Server Time-out",
        _ => "Server Internal Error",
    }
}

/// A `Retry-After` value between 0 and 10 seconds, as RFC 3311 §5.2 has a UAS
/// choose for a 500 to an offer that crosses one it has not answered.
fn random_retry_after() -> String {
    (uuid::Uuid::new_v4().as_bytes()[0] % 11).to_string()
}

/// Where the late offer goes, decided under the call's lock.
enum LateOfferRoute {
    /// In an UPDATE on the dialog of the answered callee at this index.
    Update(usize),
    Refuse {
        status: u16,
        retry_after: Option<String>,
        why: &'static str,
    },
}

/// Carry the offer in `caller_prack`, a PRACK that acknowledged siphon's reliable
/// provisional `a_leg_rseq` after the caller's 2xx, to the callee in an UPDATE.
///
/// The UPDATE goes to the media engine first on an anchored call, as a re-offer
/// from the caller's side, and gets siphon's `o=` and `s=` and the configured
/// attributes stripped. It is recorded as pending before it goes out, so the
/// callee's response never finds nothing waiting for it. One the transport
/// refuses is taken back, and the caller's PRACK refused 500, as a 503 from the
/// callee would have it.
pub fn carry_late_prack_offer(
    call_id: &str,
    caller_prack: &SipMessage,
    inbound: &InboundMessage,
    a_leg_rseq: u32,
    state: &DispatcherState,
) -> CallerPrackBridged {
    let refuse = |status: u16, retry_after: Option<String>, why: &str| {
        warn!(
            call_id = %call_id,
            status,
            "B2BUA: refusing the offer in the caller's PRACK after its 2xx: {why}"
        );
        CallerPrackBridged::Refuse {
            status,
            retry_after,
        }
    };
    let route = state
        .call_actors
        .get_call(call_id)
        .map(|call| {
            if call.delayed_offer_ack.as_ref().is_some_and(|held| !held.sent) {
                return LateOfferRoute::Refuse {
                    status: 491,
                    retry_after: None,
                    why: "the caller has not answered the callee's offer in the 2xx yet (RFC 3311 §5.2)",
                };
            }
            if call.prack_bridge.offer_pending() {
                return LateOfferRoute::Refuse {
                    status: 500,
                    retry_after: Some(random_retry_after()),
                    why: "another offer of the caller's is still with the callee (RFC 3311 §5.2)",
                };
            }
            let callee = call
                .winner
                .and_then(|index| call.b_legs.get(index).map(|leg| (index, leg)));
            match callee {
                // The Allow of the callee's 2xx, as the session timer negotiation
                // recorded it on the dialog.
                Some((index, leg)) if leg.dialog.peer_allows_update => {
                    LateOfferRoute::Update(index)
                }
                Some(_) => LateOfferRoute::Refuse {
                    status: 488,
                    retry_after: None,
                    why: "the callee does not allow UPDATE (RFC 3311 §4)",
                },
                None => LateOfferRoute::Refuse {
                    status: 488,
                    retry_after: None,
                    why: "there is no answered callee to carry it to",
                },
            }
        })
        .unwrap_or(LateOfferRoute::Refuse {
            status: 500,
            retry_after: None,
            why: "the call is gone",
        });
    let index = match route {
        LateOfferRoute::Update(index) => index,
        LateOfferRoute::Refuse {
            status,
            retry_after,
            why,
        } => return refuse(status, retry_after, why),
    };

    let content_type = caller_prack
        .headers
        .get("Content-Type")
        .or_else(|| caller_prack.headers.get("c"))
        .cloned()
        .unwrap_or_else(|| "application/sdp".to_string());
    let offer = match anchored_caller_offer(call_id, caller_prack, inbound, state) {
        Anchoring::NotAnchored => caller_prack.body.clone(),
        Anchoring::Rewritten(offer) => offer,
        Anchoring::Refused => {
            return refuse(488, None, "the media engine refused the offer");
        }
    };
    let Some(cseq) = state.call_actors.next_b_leg_local_cseq(call_id, index) else {
        return refuse(500, None, "the callee's leg is gone");
    };
    let source = RequestSource {
        transport: inbound.transport,
        remote_addr: inbound.remote_addr,
        connection_id: inbound.connection_id,
        local_addr: inbound.local_addr,
    };
    let built = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut guard| {
            let call = &mut *guard;
            let leg = call.b_legs.get_mut(index)?;
            let mut sdp = offer;
            let transport = leg.transport.transport;
            stamp_b_leg_origin(&mut sdp, &content_type, leg, &transport, state);
            let sent_offer = sdp_in_body(&content_type, &sdp);
            let mut update = build_b2bua_in_dialog_request(
                leg,
                state,
                Method::Update,
                cseq,
                &[],
                Some((content_type.as_str(), sdp)),
            )?;
            mark_update_branch(&mut update);
            let leg = leg.clone();
            call.prack_bridge.begin_offer(PendingPrackOffer {
                via: OfferVia::Update,
                caller_prack: caller_prack.clone(),
                source,
                a_leg_rseq,
                b_leg_call_id: leg.dialog.call_id.clone(),
                b_leg_cseq: cseq,
                b_leg_index: index,
                sent_offer,
                offer: caller_prack.body.clone(),
                sent_at: Instant::now(),
            });
            Some((update, leg))
        });
    let Some((update, leg)) = built else {
        return refuse(500, None, "the UPDATE to the callee could not be built");
    };
    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    debug!(
        call_id = %call_id,
        %destination,
        "B2BUA: the caller's PRACK carries an offer after its 2xx; carrying it to the callee in an UPDATE (RFC 3311)"
    );
    let b_leg_call_id = leg.dialog.call_id.clone();
    if !send_b2bua_to_bleg_checked(
        update,
        transport,
        destination,
        leg.transport.local_addr,
        state,
    ) {
        // Nothing reached the callee, so nothing will answer the offer. A
        // registration something else already took is that one's to finish.
        let withdrawn = state
            .call_actors
            .get_call_mut(call_id)
            .and_then(|mut call| call.prack_bridge.withdraw_offer(&b_leg_call_id, cseq));
        if withdrawn.is_some() {
            return refuse(500, None, "the transport refused the UPDATE to the callee");
        }
    }
    CallerPrackBridged::WaitForCallee
}

/// Give `update` a Via branch under [`UPDATE_BRANCH_PREFIX`].
fn mark_update_branch(update: &mut SipMessage) {
    let Some(via) = update.headers.get("Via").cloned() else {
        return;
    };
    if let Some((sent_by, _)) = via.split_once(";branch=") {
        update.headers.set(
            "Via",
            format!(
                "{sent_by};branch={UPDATE_BRANCH_PREFIX}{}",
                uuid::Uuid::new_v4().as_simple()
            ),
        );
    }
}

/// The callee answered the UPDATE carrying `pending` with a failure, or with
/// nothing siphon could pass on (`status_code` then names why): refuse the
/// caller's PRACK as the module documentation's table says, with the callee's
/// `retry_after` on a 500, and end the call when the callee's dialog is gone.
pub fn refuse_late_prack_offer(
    call_id: &str,
    pending: PendingPrackOffer,
    status_code: u16,
    retry_after: Option<String>,
    state: &DispatcherState,
) {
    let refusal = late_offer_refusal(status_code);
    let status = match refusal {
        LateOfferRefusal::Refuse(status) => status,
        LateOfferRefusal::EndCall => 500,
    };
    let reason =
        format!("SIP;cause={status_code};text=\"The UPDATE carrying the caller's offer failed\"");
    answer_caller_prack(
        call_id,
        &pending,
        status,
        retry_after.filter(|_| status == 500 && status_code == 500),
        state,
    );
    if refusal == LateOfferRefusal::EndCall {
        warn!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: the callee's dialog is gone for the UPDATE carrying the caller's offer (RFC 3311 §5.3); ending the call"
        );
        b2bua_terminate_call_inner(call_id, Some(&reason), "b2bua", state);
    } else {
        debug!(
            call_id = %call_id,
            callee_status = status_code,
            status,
            "B2BUA: the callee refused the UPDATE carrying the caller's offer; the session stays as it was (RFC 3311 §5.3)"
        );
    }
}

/// The callee answered the UPDATE 2xx, but the media engine refused its answer:
/// the callee's session has changed and the caller's cannot follow, so the
/// caller's PRACK is refused 500 and the call ends.
pub fn end_call_on_unrelayable_update_answer(
    call_id: &str,
    pending: PendingPrackOffer,
    state: &DispatcherState,
) {
    answer_caller_prack(call_id, &pending, 500, None, state);
    warn!(
        call_id = %call_id,
        "B2BUA: the media engine refused the callee's answer to the UPDATE carrying the caller's offer; ending the call"
    );
    b2bua_terminate_call_inner(
        call_id,
        Some(q850_reason!(47, "Media anchor failed")),
        "b2bua",
        state,
    );
}

/// End a call whose callee has left the UPDATE carrying the caller's offer
/// unanswered for 64*T1, as a 408 for it would (RFC 3311 §5.3).
pub fn end_call_on_overdue_update(call_id: &str, now: Instant, state: &DispatcherState) {
    let pending = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut call| {
            if call.teardown_claimed {
                return None;
            }
            call.prack_bridge.take_overdue_offer(now)
        });
    if let Some(pending) = pending {
        refuse_late_prack_offer(call_id, pending, 408, None, state);
    }
}

/// Answer the caller's PRACK of `pending` with `status`, kept so a
/// retransmission of that PRACK gets it again.
fn answer_caller_prack(
    call_id: &str,
    pending: &PendingPrackOffer,
    status: u16,
    retry_after: Option<String>,
    state: &DispatcherState,
) {
    let mut response = build_response(
        &pending.caller_prack,
        status,
        prack_refusal_reason(status),
        state.server_header.as_deref(),
        &[],
    );
    if let Some(retry_after) = retry_after {
        response.headers.set("Retry-After", retry_after);
    }
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        call.prack_bridge
            .record_answered(pending.a_leg_rseq, response.clone());
        let _no_2xx_waits = call.prack_bridge.finish_answering();
    }
    send_message_from(
        response,
        pending.source.transport,
        pending.source.remote_addr,
        pending.source.connection_id,
        Some(pending.source.local_addr),
        state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callees_refusal_of_the_update_maps_onto_the_callers_prack() {
        for (callee, caller) in [
            (488, LateOfferRefusal::Refuse(488)),
            (606, LateOfferRefusal::Refuse(488)),
            (491, LateOfferRefusal::Refuse(491)),
            (504, LateOfferRefusal::Refuse(504)),
            (500, LateOfferRefusal::Refuse(500)),
            (503, LateOfferRefusal::Refuse(500)),
            (403, LateOfferRefusal::Refuse(500)),
            (405, LateOfferRefusal::Refuse(500)),
            (200, LateOfferRefusal::Refuse(500)),
            (481, LateOfferRefusal::EndCall),
            (408, LateOfferRefusal::EndCall),
        ] {
            assert_eq!(late_offer_refusal(callee), caller, "callee {callee}");
        }
    }

    #[test]
    fn a_retry_after_for_crossing_offers_is_between_0_and_10_seconds() {
        for _ in 0..64 {
            let seconds: u8 = random_retry_after().parse().expect("a number");
            assert!(seconds <= 10);
        }
    }

    #[test]
    fn an_update_branch_is_told_by_the_prack_prefix() {
        let mut update = crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "UPDATE sip:callee@198.51.100.70:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-generated\r\n",
                "Call-ID: late@192.0.2.1\r\n",
                "CSeq: 3 UPDATE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("the fixture parses");
        mark_update_branch(&mut update);
        let via = update.headers.get("Via").cloned().unwrap_or_default();
        assert!(
            via.starts_with("SIP/2.0/UDP 192.0.2.1:5060;branch="),
            "{via}"
        );
        let branch = via.split(";branch=").nth(1).unwrap_or_default();
        assert!(branch.starts_with(PRACK_BRANCH_PREFIX), "{branch}");
        assert!(branch.starts_with(UPDATE_BRANCH_PREFIX), "{branch}");
    }
}
