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
//! handed back, after the retries RFC 3261 §14.1 gives a crossing offer's 491
//! ([`settle_reoffer_through_glare`]).
//!
//! The script may send a body of its own beside the offer, as a part of a
//! `multipart/*` body (RFC 5621 §3), and headers ([`check_reoffer_headers`]):
//! a service that changes something about a call that is not its media (its
//! priority, say) tells the party so in a re-INVITE of the session in force.
//!
//! On a call the media engine answered itself, the engine is the far side of
//! the party's session, and the party's answer to the session in force is its
//! description from then on: where it differs from the one it had, the engine
//! is given it ([`hand_reoffer_answer_to_engine`]). A re-offer with an SDP of
//! the script's own is not the engine's session, and its answer is not sent
//! there.

use crate::b2bua::reoffer::AnswerExtras;
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
    /// The script's `multipart/*` body could not take the SDP part.
    BadBody(String),
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
            Self::BadBody(why) => write!(formatter, "bad_request: {why}"),
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

/// A re-offer whose INVITE has no final response yet.
///
/// It is kept until that response, whether or not the script still waits for
/// it: a 2xx that comes after the script's `timeout_ms` is ACKed and takes
/// effect like any other, so what the response path needs to know of the
/// re-offer has to outlive the wait. A call that ends with one still open
/// takes it along ([`sweep_ended_reoffers`]).
struct PendingReoffer {
    /// Where the script waits for the status, until it stops waiting.
    status: Option<tokio::sync::oneshot::Sender<u16>>,
    /// Whether it offered the session in force as it was, so the party's
    /// answer describes media the engine holds.
    session_in_force: bool,
    /// The call it is on, and whether on the caller's dialog.
    call_id: String,
    on_a_leg: bool,
    /// The call store that holds `call_id`: the table is process-wide, and a
    /// sweep may only call a re-offer ended by looking in its own store.
    store: usize,
}

/// Identity of the call store of `state`, for [`PendingReoffer::store`].
fn store_identity(state: &DispatcherState) -> usize {
    Arc::as_ptr(&state.call_actors) as usize
}

fn pending_reoffers() -> &'static dashmap::DashMap<String, PendingReoffer> {
    static PENDING: std::sync::OnceLock<dashmap::DashMap<String, PendingReoffer>> =
        std::sync::OnceLock::new();
    PENDING.get_or_init(dashmap::DashMap::new)
}

/// The headers siphon writes on a re-INVITE it sends in a dialog, and why a
/// script may not: compared by [`crate::sip::headers::same_header_name`], so a
/// compact form is refused like its long name.
const REQUEST_OWNED: &[(&str, &str)] = &[
    ("Via", "names siphon's transaction (RFC 3261 §8.1.1.7)"),
    (
        "From",
        "is the dialog's local identity (RFC 3261 §12.2.1.1)",
    ),
    ("To", "is the dialog's remote identity (RFC 3261 §12.2.1.1)"),
    ("Call-ID", "is the dialog's (RFC 3261 §12.2.1.1)"),
    ("CSeq", "is numbered on the dialog (RFC 3261 §12.2.1.1)"),
    ("Max-Forwards", "is set by siphon (RFC 3261 §8.1.1.6)"),
    (
        "Contact",
        "is the dialog's local target siphon advertises (RFC 3261 §12.2.1.1)",
    ),
    ("Route", "is the dialog's route set (RFC 3261 §12.2.1.1)"),
    ("Record-Route", "is a proxy's to add"),
    ("Content-Length", "is computed from the body"),
    (
        "Content-Type",
        "goes with the body: pass content_type= instead",
    ),
    (
        "Require",
        "carries the option tags siphon negotiates on the dialog",
    ),
    (
        "Supported",
        "carries the option tags siphon negotiates on the dialog",
    ),
    (
        "Session-Expires",
        "is the session timer siphon runs on the dialog (RFC 4028 §7.4)",
    ),
    (
        "Min-SE",
        "is the session timer siphon runs on the dialog (RFC 4028 §7.4)",
    ),
    ("RAck", "is a PRACK header (RFC 3262 §7.2)"),
    ("RSeq", "is a response header (RFC 3262 §7.1)"),
    ("User-Agent", "is siphon's configured identity"),
];

/// Check the headers a script asked to add to a re-INVITE it sends. `Err`
/// names the first one refused and why: a header siphon writes on the
/// request, a name that is not a header field name, or a value with a line
/// break or NUL.
pub fn check_reoffer_headers(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        crate::b2bua::uas_headers::check_syntax(name, value)?;
        if let Some((_, reason)) = REQUEST_OWNED
            .iter()
            .find(|(owned, _)| crate::sip::headers::same_header_name(owned, name))
        {
            return Err(format!(
                "{name} cannot be set by a script on a re-INVITE siphon sends: it {reason}"
            ));
        }
    }
    Ok(())
}

/// Re-offer one party of the call `sip_call_id`: the caller (`on_a_leg`) or the
/// answered callee, with `sdp`, or the session in force toward it when `None`,
/// and with what the script sends beside the offer in `extras`: a body of its
/// own, as a part of a multipart body with the SDP, and headers
/// ([`check_reoffer_headers`] is the caller's to have run). siphon puts its
/// own `o=` on `sdp`; the session in force keeps the `o=` it was sent with.
/// Either goes out at the dialog's next `o=` version (RFC 3264 §8).
///
/// The re-INVITE is sent before this returns, or refused. What is returned
/// waits for its final status, through the retries a `491` gets
/// ([`settle_reoffer_through_glare`]), for no longer than `timeout`.
pub fn b2bua_reoffer(
    sip_call_id: &str,
    on_a_leg: bool,
    sdp: Option<Vec<u8>>,
    extras: AnswerExtras,
    timeout: std::time::Duration,
) -> Result<impl std::future::Future<Output = Option<u16>> + Send + 'static, ReofferRefusal> {
    let control = B2BUA_CONTROL.get().ok_or(ReofferRefusal::NotFound)?;
    let internal_call_id = control
        .state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(ReofferRefusal::NotFound)?;
    // siphon generated the Call-ID of the callee's dialog, and of the
    // caller's on a call it placed itself: the longer wait of RFC 3261 §14.1.
    let owns_call_id = !on_a_leg
        || control
            .state
            .call_actors
            .get_call(&internal_call_id)
            .is_some_and(|call| call.originated);
    let send = move || {
        let _enter = control.runtime.enter();
        reoffer_leg_with(
            &control.state,
            &internal_call_id,
            on_a_leg,
            sdp.clone(),
            &extras,
        )
    };
    let first = send()?;
    Ok(settle_reoffer_through_glare(
        first,
        send,
        owns_call_id,
        timeout,
    ))
}

/// [`b2bua_reoffer`] on a known call, for the dispatcher's own callers and
/// tests.
pub fn reoffer_leg(
    state: &DispatcherState,
    internal_call_id: &str,
    on_a_leg: bool,
    sdp: Option<Vec<u8>>,
) -> Result<Reoffered, ReofferRefusal> {
    reoffer_leg_with(
        state,
        internal_call_id,
        on_a_leg,
        sdp,
        &AnswerExtras::default(),
    )
}

/// [`reoffer_leg`] with what the script sends beside the offer.
pub fn reoffer_leg_with(
    state: &DispatcherState,
    internal_call_id: &str,
    on_a_leg: bool,
    sdp: Option<Vec<u8>>,
    extras: &AnswerExtras,
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
    let script_sdp = sdp.filter(|sdp| !sdp.is_empty());
    let session_in_force = script_sdp.is_none();
    let offer = script_sdp
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
    let sent = b2bua_send_script_reinvite(
        internal_call_id,
        on_a_leg,
        offer,
        session_in_force,
        extras,
        tracking,
        |branch| {
            // Recorded before the send, so a fast response finds it.
            pending_reoffers().insert(
                branch.to_string(),
                PendingReoffer {
                    status: Some(sender),
                    session_in_force,
                    call_id: internal_call_id.to_string(),
                    on_a_leg,
                    store: store_identity(state),
                },
            );
            sent_branch = Some(branch.to_string());
        },
        state,
    );
    match (sent, sent_branch) {
        (Ok(true), Some(branch)) => {
            debug!(call_id = %internal_call_id, %branch, on_a_leg, "B2BUA: sent a script re-offer");
            Ok(Reoffered::Sent { branch, status })
        }
        (sent, branch) => {
            if let Some(branch) = branch {
                pending_reoffers().remove(&branch);
            }
            state
                .call_actors
                .set_pending_reinvite(internal_call_id, on_a_leg, false);
            Err(match sent {
                Err(why) => ReofferRefusal::BadBody(why),
                Ok(_) => ReofferRefusal::NotEstablished,
            })
        }
    }
}

/// How many times a re-offer answered `491` is sent again.
pub const GLARE_RETRIES: u32 = 3;

/// The wait before a re-INVITE answered `491 Request Pending` is tried again
/// (RFC 3261 §14.1, timer T): a random 2.1 to 4 seconds in units of 10 ms
/// when siphon generated the dialog's Call-ID, and 0 to 2 seconds when the
/// other party did, so the two sides of a glare do not collide again.
pub fn glare_retry_delay(owns_call_id: bool) -> std::time::Duration {
    let random = uuid::Uuid::new_v4().as_u128();
    let units = if owns_call_id {
        210 + (random % 191) as u64
    } else {
        (random % 201) as u64
    };
    std::time::Duration::from_millis(units * 10)
}

/// Wait for the final status of the re-offer `first`, sending it again with
/// `again` after the wait of [`glare_retry_delay`] each time it is answered
/// `491` (by the party, or here because an INVITE toward the party was in
/// progress), up to [`GLARE_RETRIES`] times and for no longer than `timeout`
/// in all.
///
/// Returns the final status, which is `491` when the glare outlasted the
/// retries or the time left, and `None` when no final response came in time
/// (the waiter is then forgotten; the INVITE transaction runs on to its own
/// end). A re-offer that can no longer be sent (the call ended meanwhile)
/// leaves the `491` it was answered.
pub async fn settle_reoffer_through_glare(
    first: Reoffered,
    mut again: impl FnMut() -> Result<Reoffered, ReofferRefusal>,
    owns_call_id: bool,
    timeout: std::time::Duration,
) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempt = first;
    let mut retries = 0;
    loop {
        let status = match attempt {
            Reoffered::Crossing => 491,
            Reoffered::Sent { branch, status } => {
                match tokio::time::timeout_at(deadline, status).await {
                    Ok(Ok(code)) => code,
                    _ => {
                        forget_reoffer(&branch);
                        return None;
                    }
                }
            }
        };
        if status != 491 || retries == GLARE_RETRIES {
            return Some(status);
        }
        let delay = glare_retry_delay(owns_call_id);
        if tokio::time::Instant::now() + delay >= deadline {
            return Some(status);
        }
        tokio::time::sleep(delay).await;
        retries += 1;
        attempt = match again() {
            Ok(next) => next,
            Err(refusal) => {
                debug!("B2BUA: a re-offer answered 491 is not sent again: {refusal}");
                return Some(status);
            }
        };
    }
}

/// The 2xx to a script's re-offer of the session in force, on the caller's
/// dialog of the call `call_id`: `answer` is the party's description from now
/// on, and `previous` the one it had.
///
/// Where the media engine is the far side of that party's session (a call it
/// answered itself), an answer that changes the party's media (an address, a
/// port, a direction, a key) is given to the engine the way the party's own
/// re-offer is, as the description to answer (`answer_local`). An answer that
/// repeats what the party had tells the engine nothing new and is not sent.
/// A re-offer that carried the script's own SDP is not the engine's session,
/// and neither is one on a session that relays to a second party.
///
/// A conference seat has no verb that takes a new description: an answer
/// that changes the party's media there is logged, and the seat keeps the
/// media it had.
pub fn hand_reoffer_answer_to_engine(
    call_id: &str,
    branch: &str,
    a_sip_call_id: &str,
    answer: &[u8],
    previous: Option<&[u8]>,
    answered_from: std::net::IpAddr,
    state: &DispatcherState,
) {
    if !pending_reoffers()
        .get(branch)
        .is_some_and(|pending| pending.session_in_force)
    {
        return;
    }
    // Anything but the `o=` line, whose version a party may advance on an
    // unchanged description (RFC 3264 §8): a codec parameter or an RTCP
    // address is the engine's to know as much as an RTP address is.
    let but_origin = |sdp: &[u8]| -> Vec<Vec<u8>> {
        sdp.split(|byte| *byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty() && !line.starts_with(b"o="))
            .map(<[u8]>::to_vec)
            .collect()
    };
    if previous.is_some_and(|previous| but_origin(previous) == but_origin(answer)) {
        return;
    }
    let (Some(rtpengine_set), Some(media_sessions), Some(profiles)) = (
        state.rtpengine_set.as_ref(),
        state.rtpengine_sessions.as_ref(),
        state.rtpengine_profiles.as_ref(),
    ) else {
        return;
    };
    let Some(session) = media_sessions.get(a_sip_call_id) else {
        if crate::rtpengine::MediaBackend::conference_seat(a_sip_call_id).is_some() {
            warn!(
                call_id = %call_id,
                "B2BUA: the answer to a script re-offer changes the media of a conference seat, \
                 which takes no new description: the seat keeps the media it had"
            );
        }
        return;
    };
    // A session that relays to a second party is not the engine's to answer
    // for one side of.
    if session.to_tag.is_some() {
        return;
    }
    let (Some(profile), Some(offer_tag)) =
        (profiles.get(&session.profile), session.offer_tag(true))
    else {
        warn!(call_id = %call_id, "B2BUA: the answer to a script re-offer cannot be named to the media engine (no profile or offerer tag)");
        return;
    };
    let mut flags = profile.answer.clone();
    session
        .party_ingress(true)
        .stamp_ingress(&mut flags, profiles, answered_from);
    flags.stamp_sip_call_id(a_sip_call_id);
    match crate::script::blocking::block_on_released(rtpengine_set.answer_local(
        session.rtpengine_id(),
        offer_tag,
        &String::from_utf8_lossy(answer),
        &flags,
    )) {
        Ok(_) => {
            debug!(call_id = %call_id, "B2BUA: gave the media engine the answer to a script re-offer")
        }
        // A 2xx cannot be refused (RFC 3261 §13.2.2.4): the dialog has the
        // answer, and the engine keeps the description it had.
        Err(error) => {
            error!(call_id = %call_id, "B2BUA: the media engine refused the answer to a script re-offer: {error}")
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
/// The INVITE transaction itself runs on, and its final response is handled
/// as that of the script's re-offer it still is.
pub fn forget_reoffer(branch: &str) {
    if let Some(mut pending) = pending_reoffers().get_mut(branch) {
        pending.status = None;
    }
}

/// Whether a re-INVITE a script had siphon send on the dialog of `call_id`
/// (the caller's when `on_a_leg`) has no final response yet.
pub fn script_reoffer_in_progress(call_id: &str, on_a_leg: bool) -> bool {
    pending_reoffers()
        .iter()
        .any(|pending| pending.on_a_leg == on_a_leg && pending.call_id == call_id)
}

/// Drop the re-offers of calls that ended before their INVITE got a final
/// response: nothing will settle them. Run with the periodic sweeps.
pub fn sweep_ended_reoffers(state: &DispatcherState) {
    let store = store_identity(state);
    pending_reoffers().retain(|_, pending| {
        pending.store != store || state.call_actors.get_call(&pending.call_id).is_some()
    });
}

/// Hand the final status of the re-INVITE sent on `branch` to the script that
/// sent it, if one did.
pub fn settle_reoffer(branch: &str, status_code: u16) {
    if status_code < 200 {
        return;
    }
    if let Some((_, pending)) = pending_reoffers().remove(branch) {
        if let Some(status) = pending.status {
            let _ = status.send(status_code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(branch: &str) -> tokio::sync::oneshot::Receiver<u16> {
        let (status, receiver) = tokio::sync::oneshot::channel();
        pending_reoffers().insert(
            branch.to_string(),
            PendingReoffer {
                status: Some(status),
                session_in_force: false,
                call_id: format!("call-of-{branch}"),
                on_a_leg: true,
                store: 0,
            },
        );
        receiver
    }

    #[test]
    fn the_headers_siphon_writes_on_a_reinvite_are_refused_and_others_pass() {
        let header = |name: &str| vec![(name.to_string(), "x".to_string())];
        for owned in [
            "Via",
            "From",
            "To",
            "Call-ID",
            "CSeq",
            "Max-Forwards",
            "Contact",
            "Route",
            "Record-Route",
            "Content-Length",
            "Content-Type",
            "Require",
            "Supported",
            "Session-Expires",
            "Min-SE",
            "RAck",
            "RSeq",
            "User-Agent",
            // Compact forms (RFC 3261 §7.3.3).
            "v",
            "i",
            "m",
            "l",
            "c",
            "k",
            "x",
        ] {
            let refused = check_reoffer_headers(&header(owned)).expect_err(owned);
            assert!(refused.contains(owned), "{owned}: {refused}");
        }
        assert_eq!(
            check_reoffer_headers(&[
                ("Resource-Priority".to_string(), "mcpttp.5".to_string()),
                (
                    "P-Asserted-Identity".to_string(),
                    "<sip:group@example.com>".to_string()
                ),
            ]),
            Ok(())
        );
        assert!(check_reoffer_headers(&header("Not A Name")).is_err());
        assert!(
            check_reoffer_headers(&[("X-Split".to_string(), "one\r\nVia: two".to_string())])
                .is_err()
        );
    }

    /// RFC 3261 §14.1: 2.1 to 4 s for the owner of the Call-ID and 0 to 2 s
    /// for the other side, in units of 10 ms.
    #[test]
    fn the_glare_wait_is_in_the_range_of_each_side() {
        let (mut owner_spread, mut other_spread) = (
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        for _ in 0..2000 {
            let owner = glare_retry_delay(true).as_millis();
            assert!((2100..=4000).contains(&owner), "{owner}");
            assert_eq!(owner % 10, 0);
            owner_spread.insert(owner);
            let other = glare_retry_delay(false).as_millis();
            assert!(other <= 2000, "{other}");
            assert_eq!(other % 10, 0);
            other_spread.insert(other);
        }
        assert!(owner_spread.len() > 50 && other_spread.len() > 50, "random");
    }

    #[tokio::test(start_paused = true)]
    async fn a_491_is_sent_again_after_the_wait_until_it_is_answered() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = std::sync::Arc::clone(&attempts);
        let started = tokio::time::Instant::now();
        let status = settle_reoffer_through_glare(
            Reoffered::Crossing,
            move || {
                let attempt = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let branch = format!("z9hG4bK-glare-retry-{attempt}");
                let receiver = waiting(&branch);
                // The party answers 491 once more, then accepts.
                settle_reoffer(&branch, if attempt == 0 { 491 } else { 200 });
                Ok(Reoffered::Sent {
                    branch,
                    status: receiver,
                })
            },
            false,
            std::time::Duration::from_secs(32),
        )
        .await;
        assert_eq!(status, Some(200));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(started.elapsed() <= std::time::Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn a_glare_that_outlasts_the_retries_or_the_time_is_reported_491() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = std::sync::Arc::clone(&attempts);
        let status = settle_reoffer_through_glare(
            Reoffered::Crossing,
            move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Reoffered::Crossing)
            },
            true,
            std::time::Duration::from_secs(60),
        )
        .await;
        assert_eq!(status, Some(491));
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            GLARE_RETRIES
        );

        // No time for the wait: the 491 is the status, and nothing is sent.
        let status = settle_reoffer_through_glare(
            Reoffered::Crossing,
            || panic!("not sent again"),
            true,
            std::time::Duration::from_millis(2000),
        )
        .await;
        assert_eq!(status, Some(491));

        // The call ended during the wait.
        let status = settle_reoffer_through_glare(
            Reoffered::Crossing,
            || Err(ReofferRefusal::NotFound),
            false,
            std::time::Duration::from_secs(32),
        )
        .await;
        assert_eq!(status, Some(491));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reoffer_nobody_answers_in_time_is_forgotten() {
        let receiver = waiting("z9hG4bK-glare-timeout");
        let status = settle_reoffer_through_glare(
            Reoffered::Sent {
                branch: "z9hG4bK-glare-timeout".to_string(),
                status: receiver,
            },
            || panic!("not sent again"),
            false,
            std::time::Duration::from_millis(500),
        )
        .await;
        assert_eq!(status, None);
        // The INVITE is still in progress, as the script's re-offer it is.
        assert!(is_script_reoffer("z9hG4bK-glare-timeout"));
        assert!(script_reoffer_in_progress(
            "call-of-z9hG4bK-glare-timeout",
            true
        ));
        assert!(!script_reoffer_in_progress(
            "call-of-z9hG4bK-glare-timeout",
            false
        ));
        settle_reoffer("z9hG4bK-glare-timeout", 200);
        assert!(!is_script_reoffer("z9hG4bK-glare-timeout"));
        assert!(!script_reoffer_in_progress(
            "call-of-z9hG4bK-glare-timeout",
            true
        ));
    }

    #[test]
    fn a_final_status_reaches_the_waiting_script_once() {
        let mut status = waiting("z9hG4bK-reoffer-test-1");
        settle_reoffer("z9hG4bK-reoffer-test-1", 180);
        assert!(status.try_recv().is_err(), "a provisional settles nothing");
        settle_reoffer("z9hG4bK-reoffer-test-1", 491);
        assert_eq!(status.try_recv(), Ok(491));
        assert!(!pending_reoffers().contains_key("z9hG4bK-reoffer-test-1"));
    }

    #[test]
    fn a_forgotten_reoffer_is_settled_into_nothing() {
        let mut status = waiting("z9hG4bK-reoffer-test-2");
        forget_reoffer("z9hG4bK-reoffer-test-2");
        settle_reoffer("z9hG4bK-reoffer-test-2", 200);
        assert!(status.try_recv().is_err());
        assert!(!is_script_reoffer("z9hG4bK-reoffer-test-2"));
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
        assert!(ReofferRefusal::BadBody("no boundary".to_string())
            .to_string()
            .starts_with("bad_request: no boundary"));
    }
}
