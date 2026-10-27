//! A re-INVITE siphon sends one party of a call because a script asked:
//! `b2bua.reoffer()`.
//!
//! A script that changes what siphon tells a party about the session has to be
//! able to say so without that party asking first: RFC 7866 has the recording
//! side report a recording state that changed on its own (a cap reached, an
//! error) to a record-aware party in a new offer, `a=record` on the session in
//! force. The re-INVITE goes on that party's own dialog, through the tracked
//! path every siphon-originated re-INVITE takes: its 2xx is ACKed and makes the
//! offer the session in force, the media engine where the call is anchored is
//! not involved (the offer is not one it made), and the other party is told
//! nothing. Its final status is
//! handed back so a crossing offer's 491 (RFC 3261 §14.1) can be retried.

use crate::dispatcher::*;

/// Why a re-offer was not sent.
#[derive(Debug, PartialEq, Eq)]
pub enum ReofferRefusal {
    /// No call with that Call-ID, or the dispatcher is not running.
    NotFound,
    /// The party has no dialog yet, or has not ACKed its 2xx: a new INVITE may
    /// not start until the first one is done (RFC 3261 §14.1).
    NotEstablished,
    /// No offer was given and siphon has sent the party no session to repeat.
    NoSession,
}

impl std::fmt::Display for ReofferRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(formatter, "not_found: no such call"),
            Self::NotEstablished => write!(
                formatter,
                "invalid_state: the party's dialog is not established"
            ),
            Self::NoSession => write!(
                formatter,
                "invalid_state: no offer given and no session in force toward the party"
            ),
        }
    }
}

/// What became of a re-offer.
pub enum Reoffered {
    /// On its way: its Via branch, and where its final status arrives.
    Sent {
        branch: String,
        status: tokio::sync::oneshot::Receiver<u16>,
    },
    /// An INVITE toward the party is already in progress, so this one was not
    /// sent; a script reads it as the 491 the party would have answered.
    Crossing,
}

fn pending_reoffers() -> &'static dashmap::DashMap<String, tokio::sync::oneshot::Sender<u16>> {
    static PENDING: std::sync::OnceLock<
        dashmap::DashMap<String, tokio::sync::oneshot::Sender<u16>>,
    > = std::sync::OnceLock::new();
    PENDING.get_or_init(dashmap::DashMap::new)
}

/// Re-offer one party of the call `sip_call_id`: the caller (`on_a_leg`) or the
/// answered callee, with `sdp`, or the session in force toward it when `None`.
/// siphon puts its own `o=` on it at the dialog's next version (RFC 3264 §8).
pub fn b2bua_reoffer(
    sip_call_id: &str,
    on_a_leg: bool,
    sdp: Option<Vec<u8>>,
) -> Result<Reoffered, ReofferRefusal> {
    let control = B2BUA_CONTROL.get().ok_or(ReofferRefusal::NotFound)?;
    let internal_call_id = control
        .state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(ReofferRefusal::NotFound)?;
    let _enter = control.runtime.enter();
    reoffer_leg(&control.state, &internal_call_id, on_a_leg, sdp)
}

/// [`b2bua_reoffer`] on a known call, for the dispatcher's own callers and
/// tests.
pub fn reoffer_leg(
    state: &DispatcherState,
    internal_call_id: &str,
    on_a_leg: bool,
    sdp: Option<Vec<u8>>,
) -> Result<Reoffered, ReofferRefusal> {
    let leg = state
        .call_actors
        .clone_leg(internal_call_id, on_a_leg)
        .ok_or(if on_a_leg {
            ReofferRefusal::NotFound
        } else {
            ReofferRefusal::NotEstablished
        })?;
    if !leg.initial_acked {
        return Err(ReofferRefusal::NotEstablished);
    }
    let offer = sdp
        .filter(|sdp| !sdp.is_empty())
        .or(leg.dialog.last_sent_sdp)
        .ok_or(ReofferRefusal::NoSession)?;
    // Test-and-set, as a relayed re-INVITE does: one INVITE toward a party at a
    // time. Cleared by the final response, or below when nothing went out.
    if state
        .call_actors
        .set_pending_reinvite(internal_call_id, on_a_leg, true)
    {
        return Ok(Reoffered::Crossing);
    }
    let tracking = if on_a_leg {
        "reinvite:b2a"
    } else {
        "reinvite:a2b"
    };
    let (sender, status) = tokio::sync::oneshot::channel();
    let mut sent_branch = None;
    let sent = b2bua_send_reinvite_on_leg_then(
        internal_call_id,
        on_a_leg,
        offer,
        tracking,
        |branch| {
            // Recorded before the send, so a fast response finds it.
            pending_reoffers().insert(branch.to_string(), sender);
            sent_branch = Some(branch.to_string());
        },
        state,
    );
    match (sent, sent_branch) {
        (true, Some(branch)) => {
            debug!(call_id = %internal_call_id, %branch, on_a_leg, "B2BUA: sent a script re-offer");
            Ok(Reoffered::Sent { branch, status })
        }
        (_, branch) => {
            if let Some(branch) = branch {
                pending_reoffers().remove(&branch);
            }
            state
                .call_actors
                .set_pending_reinvite(internal_call_id, on_a_leg, false);
            Err(ReofferRefusal::NotEstablished)
        }
    }
}

/// The session in force toward one party of the call `sip_call_id`: the
/// description siphon last sent the caller (`on_a_leg`) or the answered callee.
/// `None` when there is no such call or party, or siphon has sent it none.
pub fn b2bua_session_sdp(sip_call_id: &str, on_a_leg: bool) -> Option<Vec<u8>> {
    let control = B2BUA_CONTROL.get()?;
    let internal_call_id = control.state.call_actors.find_by_sip_call_id(sip_call_id)?;
    control
        .state
        .call_actors
        .clone_leg(&internal_call_id, on_a_leg)
        .and_then(|leg| leg.dialog.last_sent_sdp)
}

/// Whether the re-INVITE on `branch` is a script's re-offer still waiting for
/// its final response. Its offer is the session in force with what the script
/// changed, which no media engine made, so the answer to it is not sent to one:
/// the engine has no re-offer outstanding to take it against.
pub fn is_script_reoffer(branch: &str) -> bool {
    pending_reoffers().contains_key(branch)
}

/// Stop waiting for the re-offer sent on `branch` (the script gave up on it).
/// The INVITE transaction itself runs on; its response is handled as any other.
pub fn forget_reoffer(branch: &str) {
    pending_reoffers().remove(branch);
}

/// Hand the final status of the re-INVITE sent on `branch` to the script that
/// sent it, if one did.
pub fn settle_reoffer(branch: &str, status_code: u16) {
    if status_code < 200 {
        return;
    }
    if let Some((_, sender)) = pending_reoffers().remove(branch) {
        let _ = sender.send(status_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_final_status_reaches_the_waiting_script_once() {
        let (sender, mut status) = tokio::sync::oneshot::channel();
        pending_reoffers().insert("z9hG4bK-reoffer-test-1".to_string(), sender);
        settle_reoffer("z9hG4bK-reoffer-test-1", 180);
        assert!(status.try_recv().is_err(), "a provisional settles nothing");
        settle_reoffer("z9hG4bK-reoffer-test-1", 491);
        assert_eq!(status.try_recv(), Ok(491));
        assert!(!pending_reoffers().contains_key("z9hG4bK-reoffer-test-1"));
    }

    #[test]
    fn a_forgotten_reoffer_is_settled_into_nothing() {
        let (sender, mut status) = tokio::sync::oneshot::channel();
        pending_reoffers().insert("z9hG4bK-reoffer-test-2".to_string(), sender);
        forget_reoffer("z9hG4bK-reoffer-test-2");
        settle_reoffer("z9hG4bK-reoffer-test-2", 200);
        assert!(status.try_recv().is_err());
    }

    #[test]
    fn a_refusal_says_what_it_is() {
        assert!(ReofferRefusal::NotFound
            .to_string()
            .starts_with("not_found"));
        assert!(ReofferRefusal::NotEstablished
            .to_string()
            .starts_with("invalid_state"));
        assert!(ReofferRefusal::NoSession
            .to_string()
            .contains("no session in force"));
    }
}
