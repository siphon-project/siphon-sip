//! Taking a merged party off a hold nobody holds any more.
//!
//! A handset holds a call before it merges it: its `sendonly` re-INVITE is
//! relayed, and the far party answers `recvonly` and stops sending. The merge
//! then replaces the handset's dialog (RFC 3891) and seats the far party in
//! place, with no SIP to it, so the session in force toward it is still the
//! hold. It would hear the room and never be heard. A focus that dialled the
//! party in fresh would have offered `sendrecv` (RFC 4579 §5.5); seating it in
//! place ends in the same media state through one re-INVITE on its dialog: the
//! session in force with only the direction changed, at the next `o=` version.
//!
//! The re-INVITE goes through the path a script's `b2bua.reoffer` takes: its 2xx
//! is ACKed and makes the offer the session in force, so later session refreshes
//! offer `sendrecv` too, and the media engine is not involved, which a seat
//! needs, since it takes no offer/answer. The party's answer decides: one that
//! holds the room itself (`recvonly`, `inactive`) stays as it chose. A refusal or
//! a timeout leaves the seat as it was and is logged; the merge itself has
//! already happened.
//!
//! The far party's session timer was kept alive by the refreshes of the leg the
//! merge ended. siphon takes the refresh over ([`take_over_session_refresh`]) so
//! the merged call does not run out of session.

use crate::dispatcher::*;
use crate::media::direction::{effective_direction, sendrecv_offer};
use crate::media::sdp::SdpBody;

/// What became of the re-INVITE that took a merged party off hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeOutcome {
    /// The party answered sending and receiving.
    Resumed,
    /// The party answered holding the room itself, which is its choice.
    HeldByParty(&'static str),
    /// The party answered at another address, port or codec, which a seat
    /// cannot follow.
    Moved,
    /// The party refused it, or never answered (a Timer B 408).
    Refused(u16),
}

/// Re-INVITE the far party of the adopted call `call_id`, now its one leg in the
/// A-leg slot, off a hold siphon's side put it on. Nothing is sent when the
/// session in force toward it already receives. The re-INVITE goes out before
/// this returns; its outcome is logged when it arrives.
///
/// siphon becomes the far party's session refresher first
/// ([`take_over_session_refresh`]), so the re-INVITE carries the session timer
/// and its 2xx is the first refresh.
pub fn resume_held_far_party(state: &DispatcherState, call_id: &str) {
    let Some(leg) = state.call_actors.clone_leg(call_id, true) else {
        return;
    };
    let resume = leg.dialog.last_sent_sdp.as_deref().and_then(sendrecv_offer);
    take_over_session_refresh(state, call_id, resume.is_some());
    let Some(offer) = resume else {
        return;
    };
    let answered_before = leg.last_sdp;
    let (branch, status) = match reoffer_leg(state, call_id, true, Some(offer)) {
        Ok(Reoffered::Sent { branch, status }) => (branch, status),
        Ok(Reoffered::Crossing) => {
            warn!(call_id = %call_id, "b2bua.adopt_replaced: the far party was merged on hold, and an INVITE toward it is in progress — not resuming it");
            return;
        }
        Err(refusal) => {
            warn!(call_id = %call_id, "b2bua.adopt_replaced: the far party was merged on hold and could not be resumed: {refusal}");
            return;
        }
    };
    info!(call_id = %call_id, "b2bua.adopt_replaced: the far party was merged on hold — re-INVITEd sendrecv");
    let call_actors = Arc::clone(&state.call_actors);
    // Timer B ends the transaction with a 408 first; the margin only covers a
    // call that ended before any final response reached its waiter.
    let deadline =
        state.b2bua_retransmits.timeout_for(&Method::Invite) + std::time::Duration::from_secs(1);
    let call_id = call_id.to_string();
    tokio::spawn(async move {
        let status = match tokio::time::timeout(deadline, status).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => return,
            Err(_) => {
                forget_reoffer(&branch);
                refresh_at_once(&call_actors, &call_id);
                warn!(call_id = %call_id, "b2bua.adopt_replaced: the far party's resume got no final response — it stays on hold");
                return;
            }
        };
        let answered = call_actors
            .clone_leg(&call_id, true)
            .and_then(|leg| leg.last_sdp);
        let outcome = resume_outcome(status, answered_before.as_deref(), answered.as_deref());
        log_resume_outcome(&call_id, &outcome);
        if matches!(outcome, ResumeOutcome::Refused(_)) {
            refresh_at_once(&call_actors, &call_id);
        }
    });
}

/// The interval siphon asks for on a merged call's dialog where it has no timer
/// of its own to go by: RFC 4028 §4's recommended 1800 seconds.
const ADOPTED_SESSION_INTERVAL: u32 = 1800;

/// Make siphon the session refresher on the dialog of the adopted call
/// `call_id`, its far party's, for the rest of the call (RFC 4028).
///
/// That dialog was refreshed by the party on the leg the merge just ended,
/// whose refreshes siphon relayed. Nobody is left to send them, so the far party
/// would end the call when its session runs out. A dialog whose timer siphon ran
/// keeps its interval and last refresh, with siphon refreshing it at half the
/// interval. On a call that runs no timer of its own, siphon knows neither, so
/// it installs one and refreshes at once, asking to be the refresher; the 2xx
/// sets the real interval and refresher. `resuming` says a resume re-INVITE is
/// about to go out: it carries the timer and is that first refresh, so no
/// refresh is made due to cross it.
pub fn take_over_session_refresh(state: &DispatcherState, call_id: &str, resuming: bool) {
    if state
        .call_actors
        .update_leg_session_timer(call_id, true, |timer| timer.siphon_refreshes = true)
    {
        debug!(call_id = %call_id, "b2bua.adopt_replaced: siphon refreshes the far party's session from here on");
        return;
    }
    let (interval, min_se) = match session_timer_policy(state, call_id) {
        Some(policy) => (policy.session_expires, policy.min_se),
        None => state
            .session_timer_config
            .as_ref()
            .map(|config| (config.session_expires, config.min_se))
            .unwrap_or((
                ADOPTED_SESSION_INTERVAL,
                crate::b2bua::session_timer::MIN_SESSION_INTERVAL,
            )),
    };
    let now = std::time::Instant::now();
    let mut timer = crate::b2bua::actor::SessionTimerState::new(interval, true, min_se, now);
    if !resuming {
        timer.retry_at = Some(now);
    }
    state
        .call_actors
        .set_leg_session_timer(call_id, true, Some(timer));
    debug!(call_id = %call_id, interval, "b2bua.adopt_replaced: siphon took over the far party's session refresh");
}

/// Have the next sweep refresh the adopted call `call_id` at once: its resume,
/// which was to be the first refresh, did not refresh the session.
fn refresh_at_once(call_actors: &CallActorStore, call_id: &str) {
    call_actors.update_leg_session_timer(call_id, true, |timer| {
        timer.retry_at = Some(std::time::Instant::now());
    });
}

/// Whether the call `call_id` is an adopted call already seated in a room. Its
/// media is the seat's, which takes no offer/answer.
pub fn is_seated_adoption(state: &DispatcherState, call_id: &str) -> bool {
    state.call_actors.get_call(call_id).is_some_and(|call| {
        call.adoption
            .as_ref()
            .is_some_and(|adoption| adoption.seated)
    })
}

/// Judge a resume by its final `status` and the party's description before it
/// (`before`) and after it (`after`): its own SDP, not siphon's.
pub fn resume_outcome(status: u16, before: Option<&[u8]>, after: Option<&[u8]>) -> ResumeOutcome {
    if !(200..300).contains(&status) {
        return ResumeOutcome::Refused(status);
    }
    let parse = |bytes: &[u8]| std::str::from_utf8(bytes).ok().map(SdpBody::parse);
    let (before, after) = (before.and_then(parse), after.and_then(parse));
    if let (Some(before), Some(after)) = (&before, &after) {
        if media_moved(before, after) {
            return ResumeOutcome::Moved;
        }
    }
    match after.as_ref().and_then(effective_direction) {
        Some(direction @ ("recvonly" | "inactive")) => ResumeOutcome::HeldByParty(direction),
        _ => ResumeOutcome::Resumed,
    }
}

/// Whether `after` puts a stream somewhere `before` did not: another
/// connection address, port or first codec.
fn media_moved(before: &SdpBody, after: &SdpBody) -> bool {
    if before.media_sections.len() != after.media_sections.len() {
        return true;
    }
    let address = |session: &SdpBody, index: usize| {
        session.media_sections[index]
            .connection()
            .or_else(|| session.connection())
            .map(str::to_string)
    };
    (0..before.media_sections.len()).any(|index| {
        let (was, now) = (&before.media_sections[index], &after.media_sections[index]);
        now.port != 0
            && (was.port != now.port
                || was.formats.first() != now.formats.first()
                || address(before, index) != address(after, index))
    })
}

fn log_resume_outcome(call_id: &str, outcome: &ResumeOutcome) {
    match outcome {
        ResumeOutcome::Resumed => {
            info!(call_id = %call_id, "b2bua.adopt_replaced: the far party is off hold in the room")
        }
        ResumeOutcome::HeldByParty(direction) => {
            info!(call_id = %call_id, direction, "b2bua.adopt_replaced: the far party answered the resume holding the room itself — left as it chose")
        }
        ResumeOutcome::Moved => {
            warn!(call_id = %call_id, "b2bua.adopt_replaced: the far party answered the resume at another address, port or codec, which its seat cannot follow")
        }
        ResumeOutcome::Refused(status) => {
            warn!(call_id = %call_id, status, "b2bua.adopt_replaced: the far party refused the resume — it stays on hold, still seated")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(connection: &str, port: u16, formats: &str, direction: &str) -> Vec<u8> {
        format!(
            "v=0\r\no=- 9 2 IN IP4 198.51.100.77\r\ns=-\r\nc=IN IP4 {connection}\r\nt=0 0\r\nm=audio {port} RTP/AVP {formats}\r\n{direction}"
        )
        .into_bytes()
    }

    #[test]
    fn a_2xx_answering_sendrecv_in_the_same_place_is_a_resume() {
        let before = answer("198.51.100.77", 30000, "0 101", "a=recvonly\r\n");
        let after = answer("198.51.100.77", 30000, "0 101", "a=sendrecv\r\n");
        assert_eq!(
            resume_outcome(200, Some(&before), Some(&after)),
            ResumeOutcome::Resumed
        );
        assert_eq!(
            resume_outcome(
                200,
                Some(&before),
                Some(&answer("198.51.100.77", 30000, "0", ""))
            ),
            ResumeOutcome::Resumed,
            "no attribute is sendrecv"
        );
    }

    #[test]
    fn a_party_answering_recvonly_or_inactive_holds_the_room_itself() {
        let before = answer("198.51.100.77", 30000, "0", "a=recvonly\r\n");
        for direction in ["recvonly", "inactive"] {
            let after = answer("198.51.100.77", 30000, "0", &format!("a={direction}\r\n"));
            assert_eq!(
                resume_outcome(200, Some(&before), Some(&after)),
                ResumeOutcome::HeldByParty(direction)
            );
        }
    }

    #[test]
    fn an_answer_at_another_address_port_or_codec_cannot_be_followed() {
        let before = answer("198.51.100.77", 30000, "0", "a=recvonly\r\n");
        for after in [
            answer("198.51.100.78", 30000, "0", ""),
            answer("198.51.100.77", 30002, "0", ""),
            answer("198.51.100.77", 30000, "8", ""),
        ] {
            assert_eq!(
                resume_outcome(200, Some(&before), Some(&after)),
                ResumeOutcome::Moved,
                "{}",
                String::from_utf8_lossy(&after)
            );
        }
    }

    #[test]
    fn a_failure_or_a_timeout_is_a_refusal() {
        let before = answer("198.51.100.77", 30000, "0", "a=recvonly\r\n");
        for status in [408, 488, 491, 500] {
            assert_eq!(
                resume_outcome(status, Some(&before), Some(&before)),
                ResumeOutcome::Refused(status)
            );
        }
    }

    #[test]
    fn the_outcomes_that_need_an_operator_are_warned() {
        let warned = |outcome: ResumeOutcome| {
            let log = crate::log_capture::LogBuffer::default();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(log.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                log_resume_outcome("call-1", &outcome)
            });
            log.rendered().contains("WARN")
        };
        assert!(warned(ResumeOutcome::Refused(408)));
        assert!(warned(ResumeOutcome::Moved));
        assert!(!warned(ResumeOutcome::Resumed));
        assert!(!warned(ResumeOutcome::HeldByParty("recvonly")));
    }
}
