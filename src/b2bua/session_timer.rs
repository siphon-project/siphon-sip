//! RFC 4028 session timer negotiation for one dialog of a B2BUA call.
//!
//! siphon holds a session timer per dialog, not per call. On the dialog of the
//! INVITE siphon sent it is the UAC (§7), on the dialog of the INVITE siphon
//! answered it is the UAS (§9), and the two dialogs negotiate their session
//! interval and refresher independently. The `refresher` parameter names a role
//! in the transaction that set it, so the same `refresher=uac` means siphon on one
//! side and the other party on the other.
//!
//! Everything here is pure: header values in, timer state and header values out.

use std::time::{Duration, Instant};

use crate::config::SessionRefresher;
use crate::sip::headers::session_timer::{parse_min_se, parse_session_expires};
use crate::sip::headers::SipHeaders;

use super::actor::{RefreshInFlight, SessionTimerState};

/// RFC 4028 §4, §5: no session interval is shorter than 90 seconds, and a request
/// without `Min-SE` has a minimum of 90 seconds.
pub const MIN_SESSION_INTERVAL: u32 = 90;

/// RFC 4028 §10: the side that does not refresh sends its BYE ahead of the
/// session expiration by the smaller of 32 seconds and a third of the interval.
const BYE_AHEAD_OF_EXPIRATION: Duration = Duration::from_secs(32);

/// What siphon wants from the session timer of a call, from `call.session_timer()`
/// or the `session_timer:` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimerPolicy {
    /// The session interval siphon asks for, in seconds.
    pub session_expires: u32,
    /// The smallest session interval siphon accepts, in seconds.
    pub min_se: u32,
    /// Who siphon would have refresh each dialog, where the negotiation leaves it
    /// the choice: the UAC of each dialog, the UAS of each, or siphon on both.
    pub preference: SessionRefresher,
}

impl SessionTimerPolicy {
    /// Whether siphon would refresh a dialog it is the UAC of: under `uac` and
    /// `b2bua`, not under `uas`.
    pub fn prefers_refreshing_as_uac(&self) -> bool {
        !matches!(self.preference, SessionRefresher::Uas)
    }

    /// Whether siphon would refresh a dialog it is the UAS of: under `uas` and
    /// `b2bua`, not under `uac`.
    pub fn prefers_refreshing_as_uas(&self) -> bool {
        !matches!(self.preference, SessionRefresher::Uac)
    }

    /// The session interval siphon asks for: never below the `Min-SE` it sends
    /// beside it (RFC 4028 §7.1).
    pub fn requested_interval(&self) -> u32 {
        self.session_expires.max(self.min_se)
    }

    /// The `Session-Expires` of an initial INVITE siphon sends as the UAC (RFC 4028
    /// §7.1). `refresher=uac` when siphon prefers to refresh the dialog. Otherwise
    /// the parameter is left out: §7.1 gives a UAC `uac` or nothing, and nothing
    /// hands the choice to the UAS.
    pub fn uac_request_value(&self) -> String {
        let interval = self.requested_interval();
        if self.prefers_refreshing_as_uac() {
            format!("{interval};refresher=uac")
        } else {
            interval.to_string()
        }
    }
}

/// The RFC 4028 session timer a script or a controller runs on one call, over the
/// `session_timer:` block: `call.session_timer()`,
/// `b2bua.originate(session_timer={...})` and the control plane's `originate`
/// `args.session_timer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimerOverride {
    pub session_expires: u32,
    pub min_se: u32,
    /// Who siphon would have refresh each dialog, where the negotiation leaves
    /// it the choice.
    pub refresher: SessionRefresher,
}

impl SessionTimerOverride {
    /// A session timer with `refresher` by name: `uac`, `uas` or `b2bua`, in any
    /// case. The error says what was given.
    pub fn named(session_expires: u32, min_se: u32, refresher: &str) -> Result<Self, String> {
        let Some(preference) = SessionRefresher::from_name(refresher) else {
            return Err(format!(
                "refresher must be \"uac\", \"uas\" or \"b2bua\", not {refresher:?}"
            ));
        };
        Ok(Self {
            session_expires,
            min_se,
            refresher: preference,
        })
    }
}

/// One field of a session timer given as a map, `{expires, min_se, refresher}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTimerField {
    /// `expires`: the session interval, in seconds.
    Expires,
    /// `min_se`: the smallest session interval siphon accepts, in seconds.
    MinSe,
    /// `refresher`: `uac`, `uas` or `b2bua`.
    Refresher,
}

impl SessionTimerField {
    /// The field called `key`. The error names the fields there are and the key
    /// that was given.
    pub fn named(key: &str) -> Result<Self, String> {
        match key {
            "expires" => Ok(Self::Expires),
            "min_se" => Ok(Self::MinSe),
            "refresher" => Ok(Self::Refresher),
            other => Err(format!(
                "session_timer takes expires, min_se and refresher, not {other:?}"
            )),
        }
    }
}

/// A session timer given field by field, each one left out defaulting as in
/// `call.session_timer()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionTimerFields {
    pub expires: Option<u32>,
    pub min_se: Option<u32>,
    pub refresher: Option<String>,
}

impl SessionTimerFields {
    /// The session interval of a timer that names none, in seconds.
    pub const DEFAULT_EXPIRES: u32 = 1800;
    /// The `Min-SE` of a timer that names none, in seconds.
    pub const DEFAULT_MIN_SE: u32 = MIN_SESSION_INTERVAL;
    /// The refresher of a timer that names none.
    pub const DEFAULT_REFRESHER: &'static str = "b2bua";

    /// The session timer these fields give, or why they give none.
    pub fn build(self) -> Result<SessionTimerOverride, String> {
        SessionTimerOverride::named(
            self.expires.unwrap_or(Self::DEFAULT_EXPIRES),
            self.min_se.unwrap_or(Self::DEFAULT_MIN_SE),
            self.refresher.as_deref().unwrap_or(Self::DEFAULT_REFRESHER),
        )
    }
}

/// How siphon, the UAS of a session refresh request, answers its request for a
/// session timer (RFC 4028 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UasAnswer {
    /// The session interval the 2xx carries, in seconds.
    pub session_expires: u32,
    /// Whether the 2xx names siphon, the UAS, the refresher.
    pub siphon_refreshes: bool,
    /// Whether the UAC supports the extension: `timer` in its `Supported`.
    pub uac_supports_timer: bool,
    /// The `Min-SE` of the request, or 90 seconds without one.
    pub request_min_se: u32,
}

/// Decide the session timer siphon's 2xx gives a request siphon answers as the
/// UAS (RFC 4028 §9), or `None` for no session timer on the dialog. `current` is
/// the timer the dialog already runs, `None` for the INVITE that sets it up.
///
/// A request for a session timer is honoured at an interval siphon may shorten to
/// its own but never lengthens, and never below the request's `Min-SE`. Table 2
/// picks the refresher: a UAC that does not support the extension cannot refresh,
/// so siphon does; a refresher the UAC chose stands; and where the UAC left the
/// choice, the dialog keeps the refresher it has (§7.4), or on a new dialog
/// siphon's preference decides. A request that asks for no session timer gets one
/// where the UAC supports the extension, where the dialog already runs one, or
/// where siphon would refresh itself.
pub fn answer_as_uas(
    request: &SipHeaders,
    policy: &SessionTimerPolicy,
    current: Option<&SessionTimerState>,
) -> Option<UasAnswer> {
    let uac_supports_timer = lists_timer(request, "Supported") || lists_timer(request, "Require");
    let request_min_se = parse_min_se(request)
        .map(|min_se| min_se.delta_seconds)
        .unwrap_or(MIN_SESSION_INTERVAL);
    let left_to_siphon = current.map_or(policy.prefers_refreshing_as_uas(), |timer| {
        timer.siphon_refreshes
    });
    let own_interval = current.map_or(policy.requested_interval(), |timer| timer.session_expires);
    let (session_expires, siphon_refreshes) = match parse_session_expires(request) {
        Some(requested) => {
            let floor = request_min_se.min(requested.delta_seconds);
            let interval = requested.delta_seconds.min(own_interval).max(floor);
            let siphon_refreshes = if uac_supports_timer {
                match requested.refresher.as_deref() {
                    Some("uac") => false,
                    Some("uas") => true,
                    _ => left_to_siphon,
                }
            } else {
                true
            };
            (interval, siphon_refreshes)
        }
        None if uac_supports_timer => (own_interval.max(request_min_se), left_to_siphon),
        None if current.is_some() || policy.prefers_refreshing_as_uas() => {
            (own_interval.max(request_min_se), true)
        }
        None => return None,
    };
    Some(UasAnswer {
        session_expires,
        siphon_refreshes,
        uac_supports_timer,
        request_min_se,
    })
}

/// The `Min-SE` of the 422 (Session Interval Too Small) siphon refuses `request`
/// with, a session refresh request siphon is the UAS of, or `None` to take it
/// (RFC 4028 §9).
///
/// siphon refuses a request whose `Session-Expires` asks for less than its own
/// minimum, the policy's `min_se` and never under 90 seconds, and names that
/// minimum. It refuses only a UAC that supports the extension, which is the one
/// §9 lets a UAS send the 422 to and the one that can retry at the larger
/// interval. A request that asks for no interval, or at least the minimum, is
/// taken.
pub fn too_brief_session_interval(
    request: &SipHeaders,
    policy: &SessionTimerPolicy,
) -> Option<u32> {
    let requested = parse_session_expires(request)?.delta_seconds;
    let minimum = policy.min_se.max(MIN_SESSION_INTERVAL);
    let supports_timer = lists_timer(request, "Supported") || lists_timer(request, "Require");
    (supports_timer && requested < minimum).then_some(minimum)
}

/// The session timer headers of a session refresh request, everything
/// [`answer_as_uas`] reads: its `Session-Expires`, `Min-SE`, `Supported` and
/// `Require`.
pub fn session_refresh_request(request: &SipHeaders) -> SipHeaders {
    let mut kept = SipHeaders::new();
    for name in ["Session-Expires", "Min-SE", "Supported", "Require"] {
        if let Some(values) = request.get_all(name) {
            kept.set_all(name, values.clone());
        }
    }
    kept
}

impl UasAnswer {
    /// Put this answer on siphon's 2xx (RFC 4028 §9): `Session-Expires` with the
    /// refresher, replacing whatever the 2xx carried, and `timer` in `Supported`.
    /// `timer` goes in `Require` where the UAC refreshes, which §9 makes a MUST,
    /// and where siphon refreshes a UAC that supports the extension, a SHOULD. A
    /// UAC that does not support it is never required to.
    pub fn apply(&self, response: &mut SipHeaders) {
        let refresher = if self.siphon_refreshes { "uas" } else { "uac" };
        response.set(
            "Session-Expires",
            format!("{};refresher={refresher}", self.session_expires),
        );
        add_option_tag(response, "Supported", "timer");
        if self.uac_supports_timer {
            add_option_tag(response, "Require", "timer");
        } else {
            remove_option_tag(response, "Require", "timer");
        }
    }

    /// The session timer this answer leaves on the dialog, with `min_se` as the
    /// dialog's floor.
    pub fn timer(&self, min_se: u32, now: Instant) -> SessionTimerState {
        SessionTimerState::new(self.session_expires, self.siphon_refreshes, min_se, now)
    }
}

/// Take the session timer off a 2xx siphon answers without one: no
/// `Session-Expires`, and no `timer` in `Require`.
pub fn withdraw_from_answer(response: &mut SipHeaders) {
    response.remove("Session-Expires");
    remove_option_tag(response, "Require", "timer");
}

/// The session timer a 2xx gives the dialog of a request siphon sent as the UAC
/// (RFC 4028 §7.2), or `None` for no session timer.
///
/// `refresher=uac` names siphon. A 2xx without a `Session-Expires` turns the timer
/// off, unless siphon's request asked for one: siphon still wants it and refreshes
/// itself at the interval it asked for. `requested` is that interval. A 2xx that
/// carries a `Session-Expires` without the `refresher` §7.2 says it has is taken as
/// naming siphon, since an extra refresh costs a re-INVITE and a missing one costs
/// the call.
pub fn uac_session_timer(
    response: &SipHeaders,
    requested: Option<u32>,
    min_se: u32,
    now: Instant,
) -> Option<SessionTimerState> {
    match parse_session_expires(response) {
        Some(answer) => Some(SessionTimerState::new(
            answer.delta_seconds,
            answer.refresher.as_deref() != Some("uas"),
            min_se,
            now,
        )),
        None => requested.map(|interval| SessionTimerState::new(interval, true, min_se, now)),
    }
}

/// The session timer the 2xx siphon sent gives the dialog of a request siphon
/// answered as the UAS (RFC 4028 §9), or `None` when that 2xx carried no
/// `Session-Expires`. `refresher=uas` names siphon; a missing parameter is taken
/// as naming siphon, as on [`uac_session_timer`].
pub fn uas_session_timer(
    response: &SipHeaders,
    min_se: u32,
    now: Instant,
) -> Option<SessionTimerState> {
    parse_session_expires(response).map(|answer| {
        SessionTimerState::new(
            answer.delta_seconds,
            answer.refresher.as_deref() != Some("uac"),
            min_se,
            now,
        )
    })
}

/// The `Min-SE` a message carries, in seconds.
pub fn min_se_of(headers: &SipHeaders) -> Option<u32> {
    parse_min_se(headers).map(|min_se| min_se.delta_seconds)
}

/// The session interval a request's `Session-Expires` asks for, in seconds.
pub fn requested_interval_of(headers: &SipHeaders) -> Option<u32> {
    parse_session_expires(headers).map(|requested| requested.delta_seconds)
}

/// Whether a message's `Allow` lists UPDATE (RFC 3311), which RFC 4028 §7.4
/// takes as the peer supporting it.
pub fn allows_update(headers: &SipHeaders) -> bool {
    headers.get_all("Allow").is_some_and(|values| {
        values
            .iter()
            .flat_map(|value| value.split(','))
            .any(|method| method.trim().eq_ignore_ascii_case("UPDATE"))
    })
}

/// What a dialog's session timer asks of siphon at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTimerDue {
    /// Nothing yet.
    Nothing,
    /// siphon is the refresher and the refresh is due.
    Refresh,
    /// The session ran out, or siphon's refresh got no response: end the call.
    Expire,
}

impl SessionTimerState {
    /// A session just negotiated or refreshed at `now`. An interval below 90
    /// seconds, which no `Min-SE` allows (RFC 4028 §4), is taken as 90.
    pub fn new(session_expires: u32, siphon_refreshes: bool, min_se: u32, now: Instant) -> Self {
        Self {
            session_expires: session_expires.max(MIN_SESSION_INTERVAL),
            siphon_refreshes,
            min_se: min_se.max(MIN_SESSION_INTERVAL),
            last_refresh: now,
            refresh_in_flight: None,
            retry_at: None,
        }
    }

    /// When the session expires: the last refresh plus the session interval.
    pub fn expires_at(&self) -> Instant {
        self.last_refresh + Duration::from_secs(u64::from(self.session_expires))
    }

    /// The `Session-Expires` interval of a refresh siphon sends (RFC 4028 §7.4):
    /// the current interval, and at least the dialog's `Min-SE`.
    pub fn refresh_interval(&self) -> u32 {
        self.session_expires.max(self.min_se)
    }

    /// What this dialog's session timer asks of siphon at `now`.
    ///
    /// Where siphon refreshes, the refresh is due at half the interval (RFC 4028
    /// §7.2), or at the retry time a refused refresh set. A refresh still without
    /// a final response after `transaction_timeout` (64·T1) has timed out, and
    /// §10 ends the session; so does reaching the expiration with no 2xx. Where
    /// the other side refreshes, siphon ends the session slightly before it
    /// expires (§10).
    pub fn due(&self, now: Instant, transaction_timeout: Duration) -> SessionTimerDue {
        let expires_at = self.expires_at();
        if !self.siphon_refreshes {
            let interval = Duration::from_secs(u64::from(self.session_expires));
            let ahead = BYE_AHEAD_OF_EXPIRATION.min(interval / 3);
            return if now + ahead >= expires_at {
                SessionTimerDue::Expire
            } else {
                SessionTimerDue::Nothing
            };
        }
        if now >= expires_at {
            return SessionTimerDue::Expire;
        }
        if let Some(in_flight) = &self.refresh_in_flight {
            return if now.saturating_duration_since(in_flight.sent_at) >= transaction_timeout {
                SessionTimerDue::Expire
            } else {
                SessionTimerDue::Nothing
            };
        }
        let half = Duration::from_secs(u64::from(self.session_expires)) / 2;
        let refresh_at = self.retry_at.unwrap_or(self.last_refresh + half);
        if now >= refresh_at {
            SessionTimerDue::Refresh
        } else {
            SessionTimerDue::Nothing
        }
    }

    /// siphon sent a refresh on `branch` asking for `session_expires`. Sending it
    /// does not refresh anything: only its 2xx does (RFC 4028 §10).
    pub fn refresh_sent(&mut self, branch: String, session_expires: u32, now: Instant) {
        self.refresh_in_flight = Some(RefreshInFlight {
            branch,
            sent_at: now,
            session_expires,
        });
        self.retry_at = None;
    }

    /// Whether `branch` is the refresh siphon has out on this dialog.
    pub fn is_refresh(&self, branch: &str) -> bool {
        self.refresh_in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.branch == branch)
    }

    /// siphon's refresh drew a final response other than a 2xx, 408, 481 or 422.
    /// RFC 4028 §10 has the refresher retry without retrying continuously: the
    /// next attempt waits half of what is left of the session.
    pub fn refresh_refused(&mut self, now: Instant) {
        self.refresh_in_flight = None;
        let remaining = self.expires_at().saturating_duration_since(now);
        self.retry_at = Some(now + remaining / 2);
    }

    /// siphon's refresh drew a 422 naming `min_se` (RFC 4028 §7.3, §10): the
    /// dialog's floor rises and the refresh is retried at once, still before the
    /// unchanged expiration.
    pub fn refresh_too_brief(&mut self, min_se: u32, now: Instant) {
        self.raise_min_se(min_se);
        self.refresh_in_flight = None;
        self.retry_at = Some(now);
    }

    /// Raise the dialog's `Min-SE` to `min_se` (RFC 4028 §7.4: the largest one
    /// received in a 422 or a session refresh request on the dialog).
    pub fn raise_min_se(&mut self, min_se: u32) {
        self.min_se = self.min_se.max(min_se);
    }
}

/// Whether a header lists the `timer` option tag.
fn lists_timer(headers: &SipHeaders, name: &str) -> bool {
    headers.get_all(name).is_some_and(|values| {
        values
            .iter()
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("timer"))
    })
}

/// Add `tag` to an option-tag header unless it already lists it, merging it into
/// the first value rather than adding a second header line.
fn add_option_tag(headers: &mut SipHeaders, name: &str, tag: &str) {
    let mut values = headers.get_all(name).cloned().unwrap_or_default();
    let listed = values
        .iter()
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(tag));
    if listed {
        return;
    }
    match values.first_mut() {
        Some(first) if !first.trim().is_empty() => first.push_str(&format!(",{tag}")),
        Some(first) => *first = tag.to_string(),
        None => values.push(tag.to_string()),
    }
    headers.set_all(name, values);
}

/// Remove `tag` from an option-tag header, dropping the header when nothing else
/// is left in it.
fn remove_option_tag(headers: &mut SipHeaders, name: &str, tag: &str) {
    let Some(values) = headers.get_all(name).cloned() else {
        return;
    };
    let kept: Vec<String> = values
        .iter()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty() && !token.eq_ignore_ascii_case(tag))
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|value| !value.is_empty())
        .collect();
    if kept.is_empty() {
        headers.remove(name);
    } else {
        headers.set_all(name, kept);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> SipHeaders {
        let mut headers = SipHeaders::new();
        for (name, value) in pairs {
            headers.add(name, value.to_string());
        }
        headers
    }

    fn policy(session_expires: u32, preference: SessionRefresher) -> SessionTimerPolicy {
        SessionTimerPolicy {
            session_expires,
            min_se: 90,
            preference,
        }
    }

    /// RFC 4028 §9 Table 2, row by row, with siphon's preference deciding only
    /// the row where the UAC supports the extension and names no refresher.
    #[test]
    fn the_uas_refresher_follows_table_2() {
        /// A request's headers, siphon's preference, and whether siphon refreshes.
        type Case = (
            &'static [(&'static str, &'static str)],
            SessionRefresher,
            bool,
        );
        let cases: [Case; 8] = [
            // UAC does not support the extension, no refresher: uas.
            (&[("Session-Expires", "1800")], SessionRefresher::Uac, true),
            // UAC supports it, no refresher: siphon's preference.
            (
                &[("Supported", "timer"), ("Session-Expires", "1800")],
                SessionRefresher::Uac,
                false,
            ),
            (
                &[("Supported", "timer"), ("Session-Expires", "1800")],
                SessionRefresher::Uas,
                true,
            ),
            (
                &[("Supported", "timer"), ("Session-Expires", "1800")],
                SessionRefresher::B2bua,
                true,
            ),
            // UAC supports it and chose: the choice stands whatever siphon prefers.
            (
                &[
                    ("Supported", "timer"),
                    ("Session-Expires", "1800;refresher=uac"),
                ],
                SessionRefresher::B2bua,
                false,
            ),
            (
                &[
                    ("Supported", "timer"),
                    ("Session-Expires", "1800;refresher=uas"),
                ],
                SessionRefresher::Uac,
                true,
            ),
            // Require: timer also says the UAC supports the extension.
            (
                &[
                    ("Require", "timer"),
                    ("Session-Expires", "1800;refresher=uac"),
                ],
                SessionRefresher::Uas,
                false,
            ),
            // A token that merely contains the word is not the option tag.
            (
                &[
                    ("Supported", "timers"),
                    ("Session-Expires", "1800;refresher=uac"),
                ],
                SessionRefresher::Uac,
                true,
            ),
        ];
        for (request, preference, siphon_refreshes) in cases {
            let answer = answer_as_uas(&headers(request), &policy(1800, preference), None)
                .unwrap_or_else(|| panic!("no answer for {request:?}"));
            assert_eq!(
                answer.siphon_refreshes, siphon_refreshes,
                "{request:?} under {preference:?}"
            );
        }
    }

    /// RFC 4028 §9: the UAS may shorten the interval but never lengthens it and
    /// never goes below the request's Min-SE.
    #[test]
    fn the_uas_interval_is_shortened_never_lengthened_and_never_below_min_se() {
        let interval = |request: &[(&str, &str)], configured: u32| {
            answer_as_uas(
                &headers(request),
                &policy(configured, SessionRefresher::Uac),
                None,
            )
            .map(|answer| answer.session_expires)
        };
        assert_eq!(interval(&[("Session-Expires", "1800")], 900), Some(900));
        assert_eq!(interval(&[("Session-Expires", "600")], 900), Some(600));
        assert_eq!(
            interval(&[("Session-Expires", "1800"), ("Min-SE", "1200")], 900),
            Some(1200)
        );
        // A caller that supports timers and asks for none gets siphon's interval,
        // raised to its Min-SE.
        assert_eq!(
            interval(&[("Supported", "timer"), ("Min-SE", "1200")], 900),
            Some(1200)
        );
    }

    #[test]
    fn a_session_timer_takes_a_refresher_by_name_in_any_case_and_refuses_others() {
        assert_eq!(
            SessionTimerOverride::named(900, 120, "UAC"),
            Ok(SessionTimerOverride {
                session_expires: 900,
                min_se: 120,
                refresher: SessionRefresher::Uac,
            })
        );
        let error = SessionTimerOverride::named(1800, 90, "sometimes")
            .expect_err("a refresher siphon cannot negotiate");
        assert!(
            error.contains("refresher") && error.contains("sometimes"),
            "{error}"
        );
    }

    #[test]
    fn a_session_timer_given_field_by_field_defaults_what_it_leaves_out() {
        assert_eq!(
            SessionTimerFields::default().build(),
            Ok(SessionTimerOverride {
                session_expires: 1800,
                min_se: 90,
                refresher: SessionRefresher::B2bua,
            })
        );
        let fields = SessionTimerFields {
            expires: Some(90),
            min_se: None,
            refresher: Some("uas".to_string()),
        };
        assert_eq!(
            fields.build(),
            Ok(SessionTimerOverride {
                session_expires: 90,
                min_se: 90,
                refresher: SessionRefresher::Uas,
            })
        );
        assert_eq!(
            SessionTimerField::named("min_se"),
            Ok(SessionTimerField::MinSe)
        );
        let error = SessionTimerField::named("interval").expect_err("a field no timer has");
        assert!(
            error.contains("session_timer") && error.contains("interval"),
            "{error}"
        );
    }

    /// RFC 4028 §9: a UAC that supports the extension and asks for less than
    /// siphon's minimum is refused with that minimum, never under 90 seconds. One
    /// that does not support it, one asking for the minimum, and one asking for no
    /// interval are taken.
    #[test]
    fn only_a_supporting_uac_asking_below_the_minimum_is_too_brief() {
        let minimum_300 = SessionTimerPolicy {
            session_expires: 1800,
            min_se: 300,
            preference: SessionRefresher::Uac,
        };
        let refused = |request: &[(&str, &str)], policy: &SessionTimerPolicy| {
            too_brief_session_interval(&headers(request), policy)
        };
        assert_eq!(
            refused(
                &[("Supported", "timer"), ("Session-Expires", "120")],
                &minimum_300
            ),
            Some(300)
        );
        assert_eq!(
            refused(
                &[
                    ("Require", "timer"),
                    ("Session-Expires", "299;refresher=uac")
                ],
                &minimum_300
            ),
            Some(300)
        );
        assert_eq!(
            refused(
                &[("Supported", "timer"), ("Session-Expires", "300")],
                &minimum_300
            ),
            None
        );
        assert_eq!(refused(&[("Session-Expires", "120")], &minimum_300), None);
        assert_eq!(refused(&[("Supported", "timer")], &minimum_300), None);

        let below_the_floor = SessionTimerPolicy {
            session_expires: 1800,
            min_se: 30,
            preference: SessionRefresher::Uac,
        };
        assert_eq!(
            refused(
                &[("Supported", "timer"), ("Session-Expires", "60")],
                &below_the_floor
            ),
            Some(MIN_SESSION_INTERVAL)
        );
    }

    /// A request asking for no session timer from a UAC that does not support the
    /// extension gets one only where siphon would refresh the dialog itself.
    #[test]
    fn a_uac_without_timer_support_gets_a_timer_only_where_siphon_refreshes() {
        assert_eq!(
            answer_as_uas(&headers(&[]), &policy(900, SessionRefresher::Uac), None),
            None
        );
        let answer = answer_as_uas(&headers(&[]), &policy(900, SessionRefresher::B2bua), None)
            .expect("siphon refreshes");
        assert!(answer.siphon_refreshes);
        assert!(!answer.uac_supports_timer);
    }

    /// A refresh on a dialog that already runs a session timer keeps it: where the
    /// UAC leaves the refresher to siphon the role stays where it is (RFC 4028
    /// §7.4) at the dialog's interval, and a UAC without timer support that asks
    /// for none leaves siphon refreshing (Table 2), whatever siphon's preference.
    #[test]
    fn a_dialog_that_runs_a_timer_keeps_its_interval_and_refresher() {
        let now = Instant::now();
        let peer_refreshes = SessionTimerState::new(600, false, 90, now);

        let answer = answer_as_uas(
            &headers(&[("Supported", "timer")]),
            &policy(1800, SessionRefresher::B2bua),
            Some(&peer_refreshes),
        )
        .expect("the dialog keeps its timer");
        assert_eq!(
            (answer.session_expires, answer.siphon_refreshes),
            (600, false)
        );

        let answer = answer_as_uas(
            &headers(&[]),
            &policy(1800, SessionRefresher::Uac),
            Some(&peer_refreshes),
        )
        .expect("the dialog keeps its timer");
        assert_eq!(
            (answer.session_expires, answer.siphon_refreshes),
            (600, true)
        );
    }

    #[test]
    fn the_uas_answer_replaces_the_session_expires_and_requires_timer_only_of_a_supporting_uac() {
        let mut response = headers(&[
            ("Session-Expires", "1800;refresher=uac"),
            ("Require", "timer,100rel"),
            ("Supported", "replaces"),
        ]);
        UasAnswer {
            session_expires: 900,
            siphon_refreshes: true,
            uac_supports_timer: false,
            request_min_se: 90,
        }
        .apply(&mut response);
        assert_eq!(
            response.get("Session-Expires").map(String::as_str),
            Some("900;refresher=uas")
        );
        assert_eq!(
            response.get_all("Require").cloned(),
            Some(vec!["100rel".to_string()])
        );
        assert_eq!(
            response.get_all("Supported").cloned(),
            Some(vec!["replaces,timer".to_string()])
        );

        let mut response = headers(&[]);
        UasAnswer {
            session_expires: 600,
            siphon_refreshes: false,
            uac_supports_timer: true,
            request_min_se: 90,
        }
        .apply(&mut response);
        assert_eq!(
            response.get("Session-Expires").map(String::as_str),
            Some("600;refresher=uac")
        );
        assert_eq!(
            response.get_all("Require").cloned(),
            Some(vec!["timer".to_string()])
        );

        let mut response = headers(&[
            ("Session-Expires", "1800;refresher=uac"),
            ("Require", "timer"),
        ]);
        withdraw_from_answer(&mut response);
        assert!(response.get("Session-Expires").is_none());
        assert!(response.get("Require").is_none());
    }

    /// RFC 4028 §7.1: a UAC may ask for `uac` or leave the refresher out.
    #[test]
    fn the_uac_request_names_siphon_or_leaves_the_choice_to_the_uas() {
        assert_eq!(
            policy(1800, SessionRefresher::Uac).uac_request_value(),
            "1800;refresher=uac"
        );
        assert_eq!(
            policy(1800, SessionRefresher::B2bua).uac_request_value(),
            "1800;refresher=uac"
        );
        assert_eq!(
            policy(1800, SessionRefresher::Uas).uac_request_value(),
            "1800"
        );
        let floor = SessionTimerPolicy {
            session_expires: 60,
            min_se: 120,
            preference: SessionRefresher::Uac,
        };
        assert_eq!(floor.uac_request_value(), "120;refresher=uac");
    }

    /// RFC 4028 §7.2: `refresher=uac` in the 2xx names siphon, `uas` the peer, and a
    /// 2xx without Session-Expires leaves a timer only where siphon asked for one.
    #[test]
    fn the_uac_timer_follows_the_2xx() {
        let now = Instant::now();
        let timer = |response: &[(&str, &str)], requested| {
            uac_session_timer(&headers(response), requested, 90, now)
                .map(|timer| (timer.session_expires, timer.siphon_refreshes))
        };
        assert_eq!(
            timer(&[("Session-Expires", "900;refresher=uac")], Some(1800)),
            Some((900, true))
        );
        assert_eq!(
            timer(&[("Session-Expires", "900;refresher=uas")], Some(1800)),
            Some((900, false))
        );
        assert_eq!(
            timer(&[("Session-Expires", "900")], None),
            Some((900, true))
        );
        assert_eq!(timer(&[], Some(1800)), Some((1800, true)));
        assert_eq!(timer(&[], None), None);
    }

    /// RFC 4028 §9 from the other side: `uas` in a 2xx siphon sent names siphon.
    #[test]
    fn the_uas_timer_follows_the_2xx_siphon_sent() {
        let now = Instant::now();
        let timer = |response: &[(&str, &str)]| {
            uas_session_timer(&headers(response), 90, now)
                .map(|timer| (timer.session_expires, timer.siphon_refreshes))
        };
        assert_eq!(
            timer(&[("Session-Expires", "900;refresher=uas")]),
            Some((900, true))
        );
        assert_eq!(
            timer(&[("Session-Expires", "900;refresher=uac")]),
            Some((900, false))
        );
        assert_eq!(timer(&[]), None);
    }

    fn at(timer: &SessionTimerState, seconds: u64) -> Instant {
        timer.last_refresh + Duration::from_secs(seconds)
    }

    const TIMEOUT: Duration = Duration::from_secs(32);

    /// RFC 4028 §7.2, §10: siphon refreshes at half the interval and ends the
    /// session at the expiration without a 2xx.
    #[test]
    fn a_refresher_refreshes_at_half_the_interval_and_expires_without_a_2xx() {
        let mut timer = SessionTimerState::new(1800, true, 90, Instant::now());
        assert_eq!(
            timer.due(at(&timer, 899), TIMEOUT),
            SessionTimerDue::Nothing
        );
        assert_eq!(
            timer.due(at(&timer, 900), TIMEOUT),
            SessionTimerDue::Refresh
        );

        timer.refresh_sent("z9hG4bK-refresh".to_string(), 1800, at(&timer, 900));
        assert!(timer.is_refresh("z9hG4bK-refresh"));
        assert_eq!(
            timer.due(at(&timer, 920), TIMEOUT),
            SessionTimerDue::Nothing,
            "a refresh in flight is sent again"
        );
        assert_eq!(
            timer.due(at(&timer, 932), TIMEOUT),
            SessionTimerDue::Expire,
            "a refresh with no response after 64*T1 did not end the session"
        );
    }

    /// RFC 4028 §10: a refused refresh is retried, halfway to the expiration each
    /// time, and the session still ends at the expiration.
    #[test]
    fn a_refused_refresh_is_retried_halfway_to_the_expiration() {
        let mut timer = SessionTimerState::new(1800, true, 90, Instant::now());
        timer.refresh_sent("z9hG4bK-refresh".to_string(), 1800, at(&timer, 900));
        timer.refresh_refused(at(&timer, 900));
        assert_eq!(
            timer.due(at(&timer, 1349), TIMEOUT),
            SessionTimerDue::Nothing
        );
        assert_eq!(
            timer.due(at(&timer, 1350), TIMEOUT),
            SessionTimerDue::Refresh
        );
        timer.refresh_refused(at(&timer, 1350));
        assert_eq!(
            timer.due(at(&timer, 1575), TIMEOUT),
            SessionTimerDue::Refresh
        );
        assert_eq!(
            timer.due(at(&timer, 1800), TIMEOUT),
            SessionTimerDue::Expire
        );
    }

    #[test]
    fn a_422_to_a_refresh_raises_the_floor_and_retries_at_once() {
        let mut timer = SessionTimerState::new(90, true, 90, Instant::now());
        timer.refresh_sent("z9hG4bK-refresh".to_string(), 90, at(&timer, 45));
        timer.refresh_too_brief(1800, at(&timer, 46));
        assert_eq!(timer.refresh_interval(), 1800);
        assert_eq!(timer.due(at(&timer, 46), TIMEOUT), SessionTimerDue::Refresh);
    }

    /// RFC 4028 §10: the side that does not refresh ends the session ahead of the
    /// expiration by the smaller of 32 seconds and a third of the interval.
    #[test]
    fn a_non_refresher_ends_the_session_just_before_it_expires() {
        let timer = SessionTimerState::new(1800, false, 90, Instant::now());
        assert_eq!(
            timer.due(at(&timer, 1767), TIMEOUT),
            SessionTimerDue::Nothing
        );
        assert_eq!(
            timer.due(at(&timer, 1768), TIMEOUT),
            SessionTimerDue::Expire
        );
        let short = SessionTimerState::new(90, false, 90, Instant::now());
        assert_eq!(short.due(at(&short, 59), TIMEOUT), SessionTimerDue::Nothing);
        assert_eq!(short.due(at(&short, 60), TIMEOUT), SessionTimerDue::Expire);
    }

    #[test]
    fn allow_is_read_as_a_method_list() {
        assert!(allows_update(&headers(&[("Allow", "INVITE, ACK, UPDATE")])));
        assert!(allows_update(&headers(&[
            ("Allow", "INVITE"),
            ("Allow", "update")
        ])));
        assert!(!allows_update(&headers(&[("Allow", "INVITE, ACK, BYE")])));
        assert!(!allows_update(&headers(&[])));
    }
}
