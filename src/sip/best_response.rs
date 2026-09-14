//! Choosing the one final failure a request sends upstream — RFC 3261 §16.7
//! step 6.
//!
//! A proxy that forked, and a B2BUA that dialled or forked, collect a final
//! failure from every branch and send the caller exactly one. Step 6 says which:
//!
//! 1. Any 6xx wins: "It MUST choose from the 6xx class responses if any exist".
//! 2. Otherwise the **lowest** class present wins, so a 3xx beats a 4xx and a
//!    4xx beats a 5xx. A redirect or a client error says something about the
//!    request; a server error says something about one server.
//! 3. Within 4xx, the responses that tell the caller how to resubmit (401, 407,
//!    415, 420, 484) are preferred over the rest.
//! 4. Within 5xx, 503 ranks below every other code, because a 503 should not
//!    go upstream at all. When it is chosen anyway, a 500 goes in its place
//!    ([`upstream_status`]).
//!
//! Past those rules the RFC lets the element pick any response in the chosen
//! class, and the highest code wins.
//!
//! The proxy fork aggregator and the B2BUA call actor used to carry their own
//! copies of a 6xx > 5xx > 4xx > 3xx ranking, the reverse of step 6 below 6xx: a
//! branch answering `486 Busy Here` lost to a sibling's 5xx.

/// 4xx codes that tell the caller how to resubmit the request, which step 6
/// prefers when the 4xx class is chosen.
const RESUBMISSION_HINTS: [u16; 5] = [401, 407, 415, 420, 484];

/// Reason phrase of the 500 sent upstream in place of a chosen 503.
pub const SERVER_INTERNAL_ERROR: &str = "Server Internal Error";

/// Where one final failure ranks when choosing what goes upstream. Greater is
/// better. Only the ordering is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResponseRank {
    // Field order is the comparison order.
    class: u8,
    standing: u8,
    preferred: bool,
    status_code: u16,
}

impl ResponseRank {
    /// The rank of `status_code` on its own.
    pub fn of(status_code: u16) -> Self {
        Self::preferring(status_code, false)
    }

    /// The rank of `status_code`, where `preferred` decides between two
    /// responses the step 6 rules leave level, ahead of the highest-code
    /// tie-break.
    ///
    /// It never outranks the class, 6xx, resubmission or 503 rules: a
    /// preferred 503 still loses to a 486. The proxy uses it to put a peer's
    /// answer ahead of a response it synthesized for a branch itself.
    pub fn preferring(status_code: u16, preferred: bool) -> Self {
        let class = match status_code {
            600..=699 => 4,
            300..=399 => 3,
            400..=499 => 2,
            500..=599 => 1,
            _ => 0,
        };
        let standing = match status_code {
            503 => 0,
            code if RESUBMISSION_HINTS.contains(&code) => 2,
            _ => 1,
        };
        Self {
            class,
            standing,
            preferred,
            status_code,
        }
    }
}

/// The best of `status_codes` per RFC 3261 §16.7 step 6, or `None` when there
/// are none.
pub fn best_status(status_codes: impl IntoIterator<Item = u16>) -> Option<u16> {
    status_codes
        .into_iter()
        .max_by_key(|code| ResponseRank::of(*code))
}

/// The status a chosen failure goes upstream as: 500 for a 503 (RFC 3261 §16.7
/// step 6), the status itself otherwise.
///
/// A 503 means one downstream element is unavailable. Passed on, it tells the
/// caller the element in front of it is out of service (RFC 3261 §21.5.4), which
/// it is not.
pub fn upstream_status(status_code: u16) -> u16 {
    if status_code == 503 {
        500
    } else {
        status_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_6xx_wins_over_every_other_class() {
        assert_eq!(best_status([302, 401, 486, 500, 503, 603]), Some(603));
        assert_eq!(best_status([600, 302]), Some(600));
        // Within 6xx the highest code wins.
        assert_eq!(best_status([600, 604, 603]), Some(604));
    }

    #[test]
    fn a_4xx_beats_a_5xx() {
        assert_eq!(best_status([503, 486]), Some(486));
        assert_eq!(best_status([500, 404]), Some(404));
        assert_eq!(best_status([599, 400]), Some(400));
    }

    #[test]
    fn a_3xx_beats_a_4xx_and_a_5xx() {
        assert_eq!(best_status([486, 302]), Some(302));
        assert_eq!(best_status([500, 301]), Some(301));
    }

    #[test]
    fn resubmission_hints_are_preferred_within_4xx() {
        for hint in RESUBMISSION_HINTS {
            assert_eq!(
                best_status([486, hint, 488, 404]),
                Some(hint),
                "{hint} tells the caller how to resubmit"
            );
        }
        // Among the hints themselves the highest code wins.
        assert_eq!(best_status([401, 407]), Some(407));
        // A hint does not lift a 4xx over a 3xx: the class comes first.
        assert_eq!(best_status([401, 302]), Some(302));
    }

    #[test]
    fn a_503_ranks_below_every_other_5xx() {
        assert_eq!(best_status([503, 500]), Some(500));
        assert_eq!(best_status([503, 502]), Some(502));
        assert_eq!(best_status([504, 503]), Some(504));
    }

    #[test]
    fn a_503_that_is_all_there_is_goes_upstream_as_500() {
        let chosen = best_status([503, 503]);
        assert_eq!(chosen, Some(503));
        assert_eq!(chosen.map(upstream_status), Some(500));
    }

    #[test]
    fn only_a_503_is_replaced_upstream() {
        for code in [302, 401, 408, 486, 500, 502, 504, 603] {
            assert_eq!(upstream_status(code), code);
        }
        assert_eq!(upstream_status(503), 500);
    }

    #[test]
    fn the_highest_code_breaks_a_tie_within_a_class() {
        assert_eq!(best_status([480, 486]), Some(486));
        assert_eq!(best_status([486, 480]), Some(486));
        assert_eq!(best_status([404, 480]), Some(480));
    }

    /// RFC 3261 §16.8: a branch whose Timer C fires counts as a 408 in the
    /// response context, and competes like any other 4xx.
    #[test]
    fn a_timeout_408_competes_as_a_4xx() {
        assert_eq!(best_status([503, 408]), Some(408));
        assert_eq!(best_status([500, 408]), Some(408));
        assert_eq!(best_status([404, 408]), Some(408));
        assert_eq!(best_status([408, 486]), Some(486));
    }

    #[test]
    fn the_order_the_responses_arrived_in_does_not_matter() {
        let codes = [503, 486, 302, 401];
        let mut reversed = codes;
        reversed.reverse();
        assert_eq!(best_status(codes), best_status(reversed));
        assert_eq!(best_status(codes), Some(302));
    }

    #[test]
    fn no_responses_choose_nothing() {
        assert_eq!(best_status([]), None);
    }

    #[test]
    fn a_preference_only_breaks_ties_the_rules_leave_level() {
        // Level on class and standing: the preferred 404 beats the 408.
        assert!(ResponseRank::preferring(404, true) > ResponseRank::preferring(408, false));
        // It cannot cross a class...
        assert!(ResponseRank::preferring(503, true) < ResponseRank::preferring(486, false));
        assert!(ResponseRank::preferring(500, true) < ResponseRank::preferring(408, false));
        // ...or outrank a resubmission hint, or lift a 503 over another 5xx.
        assert!(ResponseRank::preferring(486, true) < ResponseRank::preferring(401, false));
        assert!(ResponseRank::preferring(503, true) < ResponseRank::preferring(500, false));
    }
}
