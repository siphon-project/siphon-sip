//! A REFER whose transfer the controlling application carries out itself.
//!
//! `accept_refer` in its other modes has siphon do the transferring: it dials
//! the target as a new leg, or relays the REFER to the far end. Here siphon
//! does neither. It answers `202 Accepted`, opens the implicit subscription
//! with the first sipfrag NOTIFY (RFC 3515 §2.4.4) and stops; the application
//! moves the parties with its other verbs and then says how that went with
//! `complete_refer`, which siphon turns into the NOTIFY that ends the
//! subscription.
//!
//! What is kept in between is one record per call, and it is deliberately not
//! a `ReferSubscription` on the call. Those drive the leg replacement: one
//! with no target has no deadline, holds off every `replace_peer` — a verb the
//! application may well use to carry the transfer out — and is the first match
//! the replacement's completion and failure paths would find.

use crate::dispatcher::*;

/// How long an application has to report, when `accept_refer` names no
/// `timeout`.
pub const CONTROLLER_REFER_DEFAULT_SECS: u32 = 60;

/// The longest an application may ask for. The bound RFC 3261 §16.6 gives an
/// INVITE that never completes (Timer C), for the same reason: the referrer is
/// waiting on a subscription that has to end by something.
pub const CONTROLLER_REFER_MAX_SECS: u32 = 180;

/// A REFER subscription whose outcome the application reports.
pub struct ControllerRefer {
    /// Whether the referrer is the call's A-leg: the dialog the NOTIFYs go on.
    pub referrer_on_a_leg: bool,
    /// The subscription's `id`: the REFER's CSeq number (RFC 3515 §2.4.6).
    pub event_id: u32,
    /// When the sweep ends the subscription for an application that has not.
    pub deadline: std::time::Instant,
}

/// Per-call store of REFER subscriptions awaiting their application's report,
/// keyed by the `CallActor` id — not a SIP Call-ID, which a call's A-leg
/// changes when another party takes its place.
///
/// New per-call state: every entry leaves on `complete_refer`, on the
/// referrer's BYE, or on its deadline, so the store drains back to baseline
/// under a completed workload (the classic never-evicted-per-call-entry leak).
/// The deadline is also the backstop for a call that ends any other way: the
/// sweep drops an entry whose call is gone without sending anything, so a
/// teardown that never passes through here cannot strand one for longer than
/// [`CONTROLLER_REFER_MAX_SECS`]. Covered by the co-located steady-state leak
/// test `controller_refer_store_drains_to_baseline`.
#[derive(Default)]
pub struct ControllerReferStore {
    pub entries: DashMap<String, ControllerRefer>,
}

impl ControllerReferStore {
    /// Open a subscription for a call. `false` (dropping `record`) when one is
    /// already open: a call carries one at a time, and replacing it would
    /// leave the first referrer with a subscription nothing ever ends.
    /// Race-safe via the map entry API.
    pub fn insert(&self, call_id: &str, record: ControllerRefer) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.entries.entry(call_id.to_string()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(record);
                true
            }
        }
    }

    /// The referrer's leg and subscription `id` of the call's open
    /// subscription, if it has one. Asked for every REFER on a controlled
    /// call, so it stays cheap when nothing is open — the steady state.
    pub fn open_for(&self, call_id: &str) -> Option<(bool, u32)> {
        if self.entries.is_empty() {
            return None;
        }
        self.entries
            .get(call_id)
            .map(|record| (record.referrer_on_a_leg, record.event_id))
    }

    /// Remove + return the call's subscription (the `complete_refer` path).
    pub fn take(&self, call_id: &str) -> Option<ControllerRefer> {
        self.entries.remove(call_id).map(|(_, record)| record)
    }

    /// Remove + return the call's subscription when its referrer is the given
    /// leg (the BYE path). Asked for every BYE, so it stays cheap when nothing
    /// is open.
    pub fn take_for_leg(&self, call_id: &str, on_a_leg: bool) -> Option<ControllerRefer> {
        if self.entries.is_empty() {
            return None;
        }
        self.entries
            .remove_if(call_id, |_, record| record.referrer_on_a_leg == on_a_leg)
            .map(|(_, record)| record)
    }

    /// Drain every subscription whose deadline has passed, with its call.
    pub fn take_expired(&self, now: std::time::Instant) -> Vec<(String, ControllerRefer)> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.value().deadline <= now)
            .map(|entry| entry.key().clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key))
            .collect()
    }

    /// The number of open subscriptions (leak-test accessor).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Why a controller-mode `accept_refer` or a `complete_refer` did nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerReferRefusal {
    /// No REFER is awaiting a decision on the call.
    NoPendingRefer,
    /// There is no such call.
    Gone,
    /// The referrer's leg has left the call.
    ReferrerGone,
    /// The call already has a subscription awaiting its report.
    TransferOpen,
    /// The call has no subscription awaiting a report.
    NoTransferPending,
}

impl ControllerReferRefusal {
    /// The machine-readable reason a refusal carries in its details.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoPendingRefer => "no_pending_refer",
            Self::Gone => "call_gone",
            Self::ReferrerGone => "referrer_gone",
            Self::TransferOpen => "transfer_in_progress",
            Self::NoTransferPending => "no_transfer_pending",
        }
    }
}

impl std::fmt::Display for ControllerReferRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPendingRefer => write!(formatter, "no pending transfer for this call"),
            Self::Gone => write!(formatter, "call is gone"),
            Self::ReferrerGone => write!(
                formatter,
                "the referrer's leg has left the call, so there is no dialog to report on — report with complete_refer before releasing the referrer"
            ),
            Self::TransferOpen => write!(
                formatter,
                "a transfer accepted in mode \"controller\" is still awaiting its complete_refer on this call — the REFER was answered 491"
            ),
            Self::NoTransferPending => write!(
                formatter,
                "no transfer is awaiting a report on this call — it was already completed, its deadline passed, its referrer hung up, or none was accepted in mode \"controller\""
            ),
        }
    }
}

/// Accept the REFER pending on the call behind `sip_call_id` for its
/// application to carry out: `202 Accepted`, the first NOTIFY (sipfrag `100
/// Trying`), a subscription record, and nothing dialled.
///
/// `timeout_secs` is how long the application has to report with
/// `complete_refer` before the sweep ends the subscription for it; the value
/// used — the default when `None`, never more than
/// [`CONTROLLER_REFER_MAX_SECS`] — is returned and is what the NOTIFY
/// advertises as the subscription's `expires`.
pub fn b2bua_accept_refer_controller_with_state(
    state: &DispatcherState,
    sip_call_id: &str,
    timeout_secs: Option<u32>,
) -> Result<u32, ControllerReferRefusal> {
    let pending =
        take_held_refer(state, sip_call_id).ok_or(ControllerReferRefusal::NoPendingRefer)?;
    let Some(call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        // The call ended between the REFER and the decision. The REFER is
        // still owed an answer (RFC 3515 §2.4.2).
        warn!(%sip_call_id, "control plane: accept_refer (controller) — call gone before the decision, 481");
        b2bua_refer_send_final(
            &pending.inbound,
            &pending.message,
            481,
            "Call/Transaction Does Not Exist",
            state,
        );
        return Err(ControllerReferRefusal::Gone);
    };

    let Some(referrer_on_a_leg) = held_referrer_leg(&pending, &call_id, state) else {
        return Err(ControllerReferRefusal::ReferrerGone);
    };

    let expires = timeout_secs
        .unwrap_or(CONTROLLER_REFER_DEFAULT_SECS)
        .clamp(1, CONTROLLER_REFER_MAX_SECS);
    let event_id = refer_subscription_id(&pending.message);
    // Recorded before the 202 goes out: the referrer may send another REFER
    // the moment it has it, and that one has to find this one open.
    let opened = state.controller_refers.insert(
        &call_id,
        ControllerRefer {
            referrer_on_a_leg,
            event_id,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(expires.into()),
        },
    );
    if !opened {
        warn!(call_id = %call_id, "control plane: accept_refer (controller) — a transfer is already awaiting its report on this call, 491");
        b2bua_refer_send_final(
            &pending.inbound,
            &pending.message,
            491,
            "Request Pending",
            state,
        );
        return Err(ControllerReferRefusal::TransferOpen);
    }

    let notified = send_refer_accepted(
        &pending.inbound,
        &pending.message,
        &call_id,
        referrer_on_a_leg,
        event_id,
        expires,
        state,
    );
    if notified {
        info!(
            call_id = %call_id,
            referrer_on_a_leg,
            target = %pending.refer_to.uri,
            expires,
            "B2BUA REFER: accepted for its controller to carry out — 202 + NOTIFY 100 Trying, nothing dialled"
        );
    } else {
        // The 202 is out; the leg it came from is not on the call any more.
        // The record stays so the report, or the deadline, can clear it.
        warn!(
            call_id = %call_id,
            "B2BUA REFER: accepted for its controller, but the referrer's leg is gone — 202 sent, no NOTIFY"
        );
    }
    Ok(expires)
}

/// The reason phrase a report carries when the application names none.
fn default_report_reason(code: u16) -> String {
    match crate::b2bua::transfer::transfer_result_from_response(code) {
        crate::b2bua::transfer::TransferState::Failed { reason, .. } => reason,
        _ => "OK".to_string(),
    }
}

/// Report how the transfer the application carried out went, ending the
/// subscription opened by [`b2bua_accept_refer_controller_with_state`]: a
/// sipfrag NOTIFY of `code` with `Subscription-State: terminated`. A 2xx tells
/// the referrer the transfer succeeded, anything else that it failed.
///
/// `reason` is the sipfrag's reason phrase, used as given; without one it is
/// the phrase siphon reports that status with elsewhere.
///
/// Touches nothing but the subscription: no leg is promoted, released or
/// re-pointed, and no call state changes. Moving the parties is what the
/// application did with its other verbs before calling this.
pub fn b2bua_complete_refer_with_state(
    state: &DispatcherState,
    sip_call_id: &str,
    code: u16,
    reason: Option<&str>,
) -> Result<(), ControllerReferRefusal> {
    let call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(ControllerReferRefusal::Gone)?;
    // Taken before the send, so a second report finds nothing to end.
    let record = state
        .controller_refers
        .take(&call_id)
        .ok_or(ControllerReferRefusal::NoTransferPending)?;
    let reason = reason.map_or_else(|| default_report_reason(code), str::to_string);
    let Some(notify) = build_refer_final_notify(
        &call_id,
        record.referrer_on_a_leg,
        record.event_id,
        code,
        &reason,
        state,
    ) else {
        warn!(
            call_id = %call_id,
            code,
            "control plane: complete_refer — the referrer's leg is gone, nothing to report on"
        );
        return Err(ControllerReferRefusal::ReferrerGone);
    };
    send_message_from(
        notify.message,
        notify.transport,
        notify.destination,
        notify.connection_id,
        notify.local_addr,
        state,
    );
    info!(
        call_id = %call_id,
        code,
        %reason,
        referrer_on_a_leg = record.referrer_on_a_leg,
        "B2BUA REFER: controller reported the transfer — terminating NOTIFY sent"
    );
    Ok(())
}

/// The status siphon reports to the referrer for an application that did not
/// report in time.
const UNREPORTED_TRANSFER_STATUS: (u16, &str) = (503, "Service Unavailable");

/// End every subscription whose application did not report in time: a sipfrag
/// `503 Service Unavailable` NOTIFY, so the referrer is told the transfer did
/// not happen rather than left waiting on it, and `TransferTimedOut` to the
/// application, which would otherwise never learn that siphon reported for
/// it. A record whose call is gone is dropped with nothing sent — there is
/// no dialog left to say it in, and no channel to say it on. Driven from the
/// 500 ms maintenance tick.
pub fn check_controller_refer_timeouts(state: &DispatcherState) {
    let bus = crate::control::ControlBus::global();
    expire_controller_refers(bus.as_deref(), state);
}

/// [`check_controller_refer_timeouts`] with the control plane named.
pub fn expire_controller_refers(bus: Option<&crate::control::ControlBus>, state: &DispatcherState) {
    let (code, reason) = UNREPORTED_TRANSFER_STATUS;
    for (call_id, record) in state
        .controller_refers
        .take_expired(std::time::Instant::now())
    {
        // The Call-ID the call's channel is bound to: the A-leg's.
        let Some(sip_call_id) = state
            .call_actors
            .get_call(&call_id)
            .map(|call| call.a_leg.dialog.call_id.clone())
        else {
            debug!(call_id = %call_id, "control plane: a transfer awaiting its report outlived its call — dropped");
            continue;
        };
        let notify = build_refer_final_notify(
            &call_id,
            record.referrer_on_a_leg,
            record.event_id,
            code,
            reason,
            state,
        );
        // What the referrer was told, or `None` when its leg has left a call
        // that goes on: the application is owed the news either way.
        let reported = notify.is_some().then_some(code);
        match notify {
            Some(notify) => {
                warn!(
                    call_id = %call_id,
                    "control plane: no complete_refer before the deadline — reporting the transfer failed ({code})"
                );
                send_message_from(
                    notify.message,
                    notify.transport,
                    notify.destination,
                    notify.connection_id,
                    notify.local_addr,
                    state,
                );
            }
            None => warn!(
                call_id = %call_id,
                "control plane: no complete_refer before the deadline, and the referrer's leg is gone — nothing to report it in"
            ),
        }
        if let Some(bus) = bus {
            bus.forward_transfer_timed_out(&sip_call_id, record.referrer_on_a_leg, reported);
        }
    }
}

/// The party on one leg of a call hung up: if it was the referrer of a
/// subscription awaiting its application's report, the subscription went with
/// its dialog. Nothing is sent — a NOTIFY would arrive in a dialog that is
/// over.
pub fn controller_refer_referrer_left(state: &DispatcherState, call_id: &str, from_a_leg: bool) {
    if state
        .controller_refers
        .take_for_leg(call_id, from_a_leg)
        .is_some()
    {
        debug!(
            call_id = %call_id,
            referrer_on_a_leg = from_a_leg,
            "control plane: the referrer hung up before its transfer was reported — subscription dropped"
        );
    }
}

/// Answer a REFER that arrives while the call has a subscription awaiting its
/// application's report. Returns whether it was answered.
///
/// A retransmission of the REFER that opened the subscription — its 202 was
/// lost — is answered 202 again. Any other is a second transfer on a call
/// still carrying out its first, and is refused `491 Request Pending` (RFC
/// 3261 §21.4.27): the referrer may try again once the first is reported.
pub fn answer_refer_during_controller_transfer(
    inbound: &InboundMessage,
    message: &SipMessage,
    referrer: &Referrer<'_>,
    state: &DispatcherState,
) -> bool {
    let Some((referrer_on_a_leg, event_id)) = state.controller_refers.open_for(referrer.call_id)
    else {
        return false;
    };
    if referrer_on_a_leg == referrer.from_a_leg && event_id == refer_subscription_id(message) {
        debug!(call_id = %referrer.call_id, "B2BUA REFER: retransmit of a REFER its controller is carrying out — 202 again");
        let leg = state
            .call_actors
            .clone_leg(referrer.call_id, referrer.from_a_leg);
        send_message_from(
            build_refer_accepted(message, leg.as_ref(), state),
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        return true;
    }
    warn!(
        call_id = %referrer.call_id,
        "B2BUA REFER: a transfer on this call is still awaiting its controller's report — 491"
    );
    b2bua_refer_send_final(inbound, message, 491, "Request Pending", state);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_names_its_reason() {
        for (refusal, reason) in [
            (ControllerReferRefusal::NoPendingRefer, "no_pending_refer"),
            (ControllerReferRefusal::Gone, "call_gone"),
            (ControllerReferRefusal::ReferrerGone, "referrer_gone"),
            (ControllerReferRefusal::TransferOpen, "transfer_in_progress"),
            (
                ControllerReferRefusal::NoTransferPending,
                "no_transfer_pending",
            ),
        ] {
            assert_eq!(refusal.reason(), reason);
            assert!(!refusal.to_string().is_empty());
        }
        assert!(ControllerReferRefusal::ReferrerGone
            .to_string()
            .contains("before releasing the referrer"));
    }

    #[test]
    fn a_report_without_a_reason_uses_the_phrase_for_its_status() {
        assert_eq!(default_report_reason(200), "OK");
        assert_eq!(default_report_reason(202), "OK");
        assert_eq!(default_report_reason(486), "Busy Here");
        assert_eq!(default_report_reason(603), "Decline");
        // A status the table does not list still gets a phrase.
        assert_eq!(default_report_reason(499), "Error");
    }
}
