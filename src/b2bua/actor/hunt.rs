//! When a hunt stops: the rule every sequential controller `dial` ends on,
//! whether its answer connects the caller or is bridged to one.
//!
//! A hunt tries its targets one at a time and moves on when one ends
//! unanswered. Two outcomes end it instead:
//!
//! * a 6xx. It says the callee is known and will not take the call anywhere
//!   (RFC 3261 §21.6). A proxy that gets one SHOULD CANCEL its pending
//!   branches and MUST NOT create new ones (§16.7 step 5), and a later target
//!   would only reach the same person again;
//! * any failure of a target that showed progress (a 101-199 from the far end,
//!   not the hop-by-hop 100) when that target does not set
//!   `reroute_after_progress`. A target that rang reached the callee, so its
//!   ring-out, busy or decline is the callee's answer, not a reason to ring
//!   them again through the next route to the same destination. A target
//!   that sets it, which is every target a controller did not say otherwise
//!   for, moves on as a hunt through phones does.
//!
//! One failure after progress still moves the hunt on: a `503 Service
//! Unavailable` carrying `Retry-After`. That is the element itself saying it
//! is overloaded or down for maintenance (RFC 3261 §21.5.4), which is the case
//! for the next of several redundant proxies or SBCs, not the callee's answer.
//! A target that failed without progress (no response at all, an INVITE the
//! transport would not take) has rung nobody, so it moves the hunt on too.

use super::*;
use crate::sip::message::SipMessage;

/// Whether a hunt ends on the target that just failed with `status_code`.
///
/// `progressed` is whether that target sent a 101-199, and
/// `reroute_after_progress` whether it moves on even so. `retry_elsewhere` is
/// whether the failure is a `503` carrying `Retry-After`
/// ([`is_retry_elsewhere`]), the one failure after progress that still moves
/// the hunt on. The one predicate both forms of a sequential `dial` use, so a
/// connecting dial and a bridging one cannot drift apart on when a hunt stops.
pub fn hunt_stops_at(
    status_code: u16,
    progressed: bool,
    reroute_after_progress: bool,
    retry_elsewhere: bool,
) -> bool {
    (600..=699).contains(&status_code)
        || (progressed && !reroute_after_progress && !retry_elsewhere)
}

/// Whether the final response `message` with `status_code` is a `503` carrying
/// `Retry-After`: the element that sent it is unavailable, not the callee
/// (RFC 3261 §21.5.4, §20.33).
pub fn is_retry_elsewhere(status_code: u16, message: &SipMessage) -> bool {
    status_code == 503 && message.headers.get("Retry-After").is_some()
}

impl CallActor {
    /// Whether the attempt in flight of a sequential controller `dial` ends
    /// the dial on `status_code` ([`hunt_stops_at`]). `false` for a call that
    /// is not hunting: an LCR or `route` sequence fails over on its reroute
    /// causes alone.
    pub fn hunt_stops_on(&self, status_code: u16, retry_elsewhere: bool) -> bool {
        self.route_sequence.as_ref().is_some_and(|sequence| {
            sequence.active.as_ref().is_some_and(|route| {
                route.hunt
                    && hunt_stops_at(
                        status_code,
                        sequence.active_progressed,
                        route.reroute_after_progress,
                        retry_elsewhere,
                    )
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_6xx_stops_a_hunt_whatever_the_target_did() {
        for status_code in [600, 603, 604, 606] {
            assert!(hunt_stops_at(status_code, false, true, false));
            assert!(hunt_stops_at(status_code, true, true, false));
            assert!(hunt_stops_at(status_code, false, false, false));
        }
    }

    #[test]
    fn a_target_that_showed_progress_stops_the_hunt_unless_it_reroutes_after_progress() {
        for status_code in [408, 480, 486, 487, 500, 503] {
            assert!(
                hunt_stops_at(status_code, true, false, false),
                "{status_code}"
            );
            assert!(
                !hunt_stops_at(status_code, true, true, false),
                "{status_code}"
            );
        }
    }

    #[test]
    fn a_503_with_retry_after_moves_the_hunt_on_even_after_progress() {
        assert!(!hunt_stops_at(503, true, false, true));
        // Without Retry-After it is the callee's side failing, after it rang.
        assert!(hunt_stops_at(503, true, false, false));
        // A 6xx is global whatever it carries.
        assert!(hunt_stops_at(603, true, false, true));
    }

    #[test]
    fn only_a_503_carrying_retry_after_is_a_retry_elsewhere() {
        let response = |status: &str, retry_after: bool| {
            let raw = format!(
                concat!(
                    "SIP/2.0 {status}\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-1\r\n",
                    "Call-ID: hunt@192.0.2.1\r\n",
                    "CSeq: 1 INVITE\r\n",
                    "{retry_after}",
                    "Content-Length: 0\r\n",
                    "\r\n",
                ),
                status = status,
                retry_after = if retry_after {
                    "Retry-After: 30\r\n"
                } else {
                    ""
                },
            );
            crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("a response")
        };
        assert!(is_retry_elsewhere(
            503,
            &response("503 Service Unavailable", true)
        ));
        assert!(!is_retry_elsewhere(
            503,
            &response("503 Service Unavailable", false)
        ));
        assert!(!is_retry_elsewhere(486, &response("486 Busy Here", true)));
    }

    #[test]
    fn a_target_that_showed_no_progress_moves_the_hunt_on() {
        for status_code in [408, 480, 486, 500, 503, 599] {
            assert!(
                !hunt_stops_at(status_code, false, false, false),
                "{status_code}"
            );
            assert!(
                !hunt_stops_at(status_code, false, true, false),
                "{status_code}"
            );
        }
    }
}
