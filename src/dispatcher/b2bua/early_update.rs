//! An UPDATE on a call nobody has answered (RFC 3311 §5, RFC 3312 §5).
//!
//! Before the 2xx the caller's dialog and the callee's are both early, and
//! either party may send an UPDATE (RFC 3311 §5.1). The precondition exchange
//! of RFC 3312 is the common case: the offerer sends its INVITE, gets the answer
//! in a reliable provisional, and once its resources are reserved sends an
//! UPDATE with a new offer carrying the updated current status, before the
//! callee alerts.
//!
//! * Without an offer the UPDATE changes nothing about the session. It is
//!   answered 200 on the dialog it arrived on and crosses nowhere.
//! * With an offer it crosses to the other party when the call's
//!   [`EarlyOfferState`](crate::b2bua::actor::EarlyOfferState) allows, relayed as
//!   an UPDATE after the answer is ([`handle_b2bua_update`]), on the early dialog
//!   of the one callee whose session the caller has.
//! * Otherwise it is refused with the status RFC 3311 §5.2 names, and the
//!   session stays as it was.
//!
//! What the other party answers the relayed UPDATE comes back as it is, except
//! where it speaks of that party's dialog alone:
//!
//! | The callee's response to the caller's UPDATE | The caller's UPDATE |
//! |---|---|
//! | 2xx with an answer | 2xx with the answer |
//! | 481, 408: the callee's early dialog is gone | 500 with a `Retry-After` |
//! | any other final response | the same |
//! | none before the callee's INVITE ends | 500 with a `Retry-After` |
//!
//! The caller's INVITE outlives a callee's early dialog: a script may dial
//! again, another branch may answer. A 481 or 408 relayed as it is, or an UPDATE
//! left unanswered, has the caller end its own dialog (RFC 3311 §5.3), so the
//! caller is asked to try again instead.

use crate::b2bua::actor::EarlyOffer;
use crate::dispatcher::*;

/// The marker of a tracking leg for an UPDATE relayed from the caller to the
/// callee.
const CALLER_UPDATE_IN_FLIGHT: &str = "update:a2b";

/// What an UPDATE on a call nobody has answered came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyUpdate {
    /// The call is not one whose INVITE is still pending between two parties:
    /// the UPDATE is handled as on any other call.
    NotEarly,
    /// Answered on the dialog it arrived on.
    Answered,
    /// Its offer crosses to the other party.
    Relay,
}

/// The reason phrase siphon gives a status it refuses an UPDATE with.
fn refusal_reason(status_code: u16) -> &'static str {
    match status_code {
        481 => "Call/Transaction Does Not Exist",
        491 => "Request Pending",
        _ => "Server Internal Error",
    }
}

/// Answer or admit `message`, an UPDATE on a call nobody has answered: from the
/// caller when `from_a_leg`, otherwise from the callee whose leg rides Via
/// `origin_branch` (`None` when the request named no early dialog siphon holds).
pub fn early_dialog_update(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    from_a_leg: bool,
    origin_branch: Option<&str>,
    state: &DispatcherState,
) -> EarlyUpdate {
    let carries_offer = !message.body.is_empty();
    let decided = state.call_actors.get_call(call_id).and_then(|call| {
        if !call.is_early_between_parties() {
            return None;
        }
        let origin = if from_a_leg {
            None
        } else {
            match origin_branch.and_then(|branch| call.find_b_leg_by_branch(branch)) {
                Some((index, _)) => Some(index),
                // On no early dialog of a callee's that siphon holds
                // (RFC 3261 §12.2.2).
                None => {
                    return Some(EarlyOffer::Refuse {
                        status: 481,
                        retry_after: false,
                        why: "the request names no early dialog of a callee's",
                    })
                }
            }
        };
        Some(if carries_offer {
            call.early_offer_state(origin).decide()
        } else {
            EarlyOffer::Relay
        })
    });
    let (status_code, retry_after) = match decided {
        None => return EarlyUpdate::NotEarly,
        Some(EarlyOffer::Relay) if carries_offer => return EarlyUpdate::Relay,
        Some(EarlyOffer::Relay) => (200, false),
        Some(EarlyOffer::Refuse {
            status,
            retry_after,
            why,
        }) => {
            info!(
                call_id = %call_id,
                status,
                from_a_leg,
                "B2BUA UPDATE on the early dialog refused: {why} (RFC 3311 §5.2)"
            );
            (status, retry_after)
        }
    };
    let reason = if status_code == 200 {
        "OK"
    } else {
        refusal_reason(status_code)
    };
    let mut response = build_response(
        message,
        status_code,
        reason,
        state.server_header.as_deref(),
        &[],
    );
    if retry_after {
        response.headers.set("Retry-After", random_retry_after());
    }
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    EarlyUpdate::Answered
}

/// Keep the `precondition` option tag on `relayed`, an UPDATE or its copy that
/// has had `Require` and `Supported` removed for the other leg, where `original`
/// listed it and `policy` passes preconditions end to end.
///
/// RFC 3312 §11: "An offerer MUST include this tag in the Require header field
/// if the offer contains one or more "mandatory" strength-tags", and in
/// `Supported` or `Require` otherwise. The offer in a relayed UPDATE is the
/// other party's, preconditions included, so under a policy that carried the
/// tag across on the INVITE it crosses on the UPDATE too. Every other tag names
/// something siphon negotiates per leg and stays off.
pub fn relay_precondition_tag(
    original: &SipHeaders,
    relayed: &mut SipHeaders,
    policy: &crate::b2bua::header_policy::ResolvedPolicy,
) {
    const PRECONDITION: &str = "precondition";
    if !policy.passes_end_to_end(PRECONDITION) {
        return;
    }
    for name in ["Require", "Supported"] {
        let listed = original
            .get_all(name)
            .into_iter()
            .flatten()
            .flat_map(|value| value.split(','))
            .any(|tag| tag.trim().eq_ignore_ascii_case(PRECONDITION));
        if listed {
            relayed.set(name, PRECONDITION.to_string());
        }
    }
}

/// The status the caller's UPDATE gets for the callee's final response
/// `status_code` to its relayed copy on the callee's early dialog, and whether
/// siphon adds a `Retry-After` of its own, per the table in the module
/// documentation. `None` relays the response as it is.
pub fn early_update_refusal_for_caller(status_code: u16) -> Option<(u16, bool)> {
    matches!(status_code, 408 | 481).then_some((500, true))
}

/// Answer every UPDATE of the caller's still with one of `ended`, callee legs
/// whose INVITE is over while the call goes on: 500 with a `Retry-After`. Those
/// callees no longer owe the UPDATE an answer the caller could use, and an
/// UPDATE left unanswered runs the caller's transaction out, which ends the
/// caller's dialog (RFC 3311 §5.3).
pub fn refuse_caller_updates_in_flight(call_id: &str, ended: &[&Leg], state: &DispatcherState) {
    if ended.is_empty() {
        return;
    }
    let orphaned = state.call_actors.get_call(call_id).map(|call| {
        let refusals: Vec<(String, SipMessage, Option<LegTransport>)> = call
            .b_legs
            .iter()
            .filter(|tracking| {
                tracking.dialog.target_uri.as_deref() == Some(CALLER_UPDATE_IN_FLIGHT)
                    && !tracking.stored_vias.is_empty()
                    && ended.iter().any(|leg| {
                        leg.dialog.call_id == tracking.dialog.call_id
                            && leg.dialog.local_tag == tracking.dialog.local_tag
                    })
            })
            .filter_map(|tracking| {
                let refusal = caller_update_refusal(tracking, &call.a_leg, state)?;
                Some((
                    tracking.branch.clone(),
                    refusal,
                    tracking.request_source.clone(),
                ))
            })
            .collect();
        (
            refusals,
            call.a_leg.transport.clone(),
            call.a_leg_local_addr,
        )
    });
    let Some((refusals, caller, caller_local_addr)) = orphaned else {
        return;
    };
    for (branch, refusal, source) in refusals {
        debug!(
            call_id = %call_id,
            "B2BUA: the callee's INVITE ended with the caller's UPDATE unanswered; refusing it 500 with a Retry-After"
        );
        state.call_actors.remove_b_leg_on(call_id, &branch);
        // To the hop the UPDATE came from (RFC 3261 §18.2.2), which need not be
        // the one the caller's INVITE did.
        let (transport, remote_addr, connection_id, local_addr) = match source {
            Some(source) => (
                source.transport,
                source.remote_addr,
                source.connection_id,
                source.local_addr,
            ),
            None => (
                caller.transport,
                caller.remote_addr,
                caller.connection_id,
                caller_local_addr,
            ),
        };
        send_message_from(
            refusal,
            transport,
            remote_addr,
            connection_id,
            local_addr,
            state,
        );
    }
}

/// The 500 with a `Retry-After` that answers the caller's UPDATE `tracking`
/// relayed, built from what the tracking leg kept of it (RFC 3261 §8.2.6.2).
fn caller_update_refusal(
    tracking: &Leg,
    a_leg: &Leg,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let mut builder = SipMessageBuilder::new().response(500, refusal_reason(500).to_string());
    for via in &tracking.stored_vias {
        builder = builder.via(via.clone());
    }
    builder = builder
        .from(tracking.stored_from.clone()?)
        .to(tracking.stored_to.clone()?)
        .call_id(a_leg.dialog.call_id.clone())
        .cseq(tracking.stored_cseq.clone()?)
        .header("Retry-After", random_retry_after());
    if let Some(server) = state.server_header.as_deref() {
        builder = builder.header("Server", server.to_string());
    }
    match builder.content_length(0).build() {
        Ok(response) => Some(response),
        Err(error) => {
            warn!("B2BUA: failed to build the refusal of an UPDATE in flight: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_callee_dialog_that_is_gone_asks_the_caller_to_try_again() {
        assert_eq!(early_update_refusal_for_caller(481), Some((500, true)));
        assert_eq!(early_update_refusal_for_caller(408), Some((500, true)));
    }

    #[test]
    fn any_other_response_of_the_callees_is_relayed_as_it_is() {
        for status_code in [200, 400, 405, 488, 491, 500, 504, 606] {
            assert_eq!(early_update_refusal_for_caller(status_code), None);
        }
    }

    fn headers(lines: &[(&str, &str)]) -> SipHeaders {
        let mut headers = SipHeaders::new();
        for (name, value) in lines {
            headers.add(name, value.to_string());
        }
        headers
    }

    fn policy(name: &str) -> crate::b2bua::header_policy::ResolvedPolicy {
        let presets = crate::b2bua::header_policy::builtin_presets();
        crate::b2bua::header_policy::ResolvedPolicy::from_preset(Arc::clone(
            presets.get(name).expect("a built-in preset"),
        ))
    }

    #[test]
    fn the_precondition_tag_crosses_under_a_policy_that_passes_it_end_to_end() {
        let original = headers(&[
            ("Require", "100rel, Precondition"),
            ("Supported", "timer"),
            ("Supported", "precondition, replaces"),
        ]);
        let mut relayed = SipHeaders::new();
        relay_precondition_tag(
            &original,
            &mut relayed,
            &policy("ims-intra-trust-domain@2026"),
        );
        assert_eq!(
            relayed.get("Require").map(String::as_str),
            Some("precondition")
        );
        assert_eq!(
            relayed.get("Supported").map(String::as_str),
            Some("precondition")
        );
    }

    #[test]
    fn the_precondition_tag_stays_off_where_it_was_not_listed_or_is_not_passed() {
        let original = headers(&[("Require", "100rel"), ("Supported", "precondition")]);
        let mut relayed = SipHeaders::new();
        relay_precondition_tag(
            &original,
            &mut relayed,
            &policy("ims-intra-trust-domain@2026"),
        );
        assert_eq!(relayed.get("Require"), None);
        assert_eq!(
            relayed.get("Supported").map(String::as_str),
            Some("precondition")
        );

        let mut relayed = SipHeaders::new();
        relay_precondition_tag(&original, &mut relayed, &policy("transparent-b2bua@2026"));
        assert_eq!(relayed.get("Require"), None);
        assert_eq!(relayed.get("Supported"), None);
    }

    #[test]
    fn a_refusal_carries_the_reason_phrase_of_its_status() {
        assert_eq!(refusal_reason(491), "Request Pending");
        assert_eq!(refusal_reason(500), "Server Internal Error");
        assert_eq!(refusal_reason(481), "Call/Transaction Does Not Exist");
    }
}
