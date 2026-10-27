//! An in-dialog offer on a bridged call, as a script is shown it.
//!
//! A re-INVITE or an UPDATE from either party renegotiates the session the
//! B2BUA relays between them (RFC 3264 §8, RFC 3311). `@b2bua.on_reoffer` sees
//! the offer before it is relayed and may let it through, refuse it or answer
//! it itself, and `@b2bua.on_reoffer_answered` sees the final response the
//! offerer got. These are the facts both are given, and what the first one
//! decided.

use crate::media::direction::{classify, effective_direction, ReofferKind};
use crate::media::sdp::SdpBody;

/// An in-dialog offer, read once when it arrives.
#[derive(Debug, Clone)]
pub struct ReofferFacts {
    /// `"INVITE"` or `"UPDATE"`.
    pub method: &'static str,
    /// Whether the caller sent it.
    pub from_a_leg: bool,
    /// The offer as the party sent it, `None` for an offerless re-INVITE or an
    /// UPDATE without a body.
    pub offer: Option<String>,
    /// Which way the offer has media flow ([`effective_direction`]).
    pub direction: Option<&'static str>,
    /// Which way the description the party last gave on the dialog has it.
    pub previous_direction: Option<&'static str>,
    /// What the offer does to the session in force ([`classify`]).
    pub kind: ReofferKind,
    /// Whether it crossed between early dialogs, before the call was answered
    /// (an UPDATE, RFC 3311 §5.1).
    pub early: bool,
    /// The description siphon last sent the offering party: the session in
    /// force toward it (`Dialog::last_sent_sdp`), which an answer siphon gives
    /// here is built from. `None` before siphon has sent that party one.
    pub session: Option<String>,
}

impl ReofferFacts {
    /// Read the offer `offer` (the SDP of the request, if it has one) against
    /// `in_force`, the description the sending party last gave on its dialog.
    pub fn read(
        method: &'static str,
        from_a_leg: bool,
        offer: Option<&[u8]>,
        in_force: Option<&[u8]>,
        early: bool,
    ) -> Self {
        let parse = |sdp: &[u8]| SdpBody::parse(&String::from_utf8_lossy(sdp));
        let offered = offer.filter(|sdp| !sdp.is_empty()).map(parse);
        let previous = in_force.filter(|sdp| !sdp.is_empty()).map(parse);
        Self {
            method,
            from_a_leg,
            offer: offer
                .filter(|sdp| !sdp.is_empty())
                .map(|sdp| String::from_utf8_lossy(sdp).into_owned()),
            direction: offered.as_ref().and_then(effective_direction),
            previous_direction: previous.as_ref().and_then(effective_direction),
            kind: classify(offered.as_ref(), previous.as_ref()),
            early,
            session: None,
        }
    }

    /// `"a"` for the caller and `"b"` for the callee, the convention of
    /// `call.refer_side` and `ByeInitiator.side`.
    pub fn side(&self) -> &'static str {
        if self.from_a_leg {
            "a"
        } else {
            "b"
        }
    }
}

/// What `@b2bua.on_reoffer` decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ReofferDecision {
    /// Relay the offer to the other party, as without the hook.
    #[default]
    Relay,
    /// Refuse it with this final response. The session stays as it was
    /// (RFC 3261 §14.1).
    Refuse { code: u16, reason: String },
    /// Answer it here and relay nothing. `sdp` is the script's answer, or
    /// `None` to have siphon answer from the session in force toward the
    /// offerer (RFC 3264 §6).
    TakeOver { sdp: Option<String> },
}

/// The final response the offerer got, as `@b2bua.on_reoffer_answered` is
/// shown it.
#[derive(Debug, Clone)]
pub struct ReofferAnswer {
    pub status_code: u16,
    /// The SDP of the response, as the offerer was sent it.
    pub sdp: Option<String>,
    /// Whether siphon answered it rather than the other party.
    pub local: bool,
}

impl ReofferAnswer {
    /// `sdp`'s direction ([`effective_direction`]).
    pub fn direction(&self) -> Option<&'static str> {
        self.sdp
            .as_deref()
            .map(SdpBody::parse)
            .as_ref()
            .and_then(effective_direction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALKING: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

    fn held() -> Vec<u8> {
        [TALKING, b"a=sendonly\r\n"].concat()
    }

    #[test]
    fn a_hold_is_read_against_the_session_in_force() {
        let held = held();
        let facts = ReofferFacts::read("INVITE", true, Some(&held), Some(TALKING), false);
        assert_eq!(facts.kind, ReofferKind::Hold);
        assert_eq!(facts.direction, Some("sendonly"));
        assert_eq!(facts.previous_direction, Some("sendrecv"));
        assert_eq!(facts.side(), "a");
        assert_eq!(
            facts.offer.as_deref(),
            Some(String::from_utf8_lossy(&held).as_ref())
        );
    }

    #[test]
    fn an_offerless_request_has_no_offer_and_is_a_refresh() {
        let facts = ReofferFacts::read("INVITE", false, Some(b""), Some(TALKING), false);
        assert_eq!(facts.offer, None);
        assert_eq!(facts.direction, None);
        assert_eq!(facts.kind, ReofferKind::Refresh);
        assert_eq!(facts.side(), "b");
        let facts = ReofferFacts::read("UPDATE", false, None, None, true);
        assert_eq!(facts.previous_direction, None);
        assert!(facts.early);
    }

    #[test]
    fn the_answer_direction_is_read_off_its_sdp() {
        let answer = ReofferAnswer {
            status_code: 200,
            sdp: Some(String::from_utf8_lossy(&[TALKING, b"a=recvonly\r\n"].concat()).into_owned()),
            local: false,
        };
        assert_eq!(answer.direction(), Some("recvonly"));
        let refused = ReofferAnswer {
            status_code: 488,
            sdp: None,
            local: true,
        };
        assert_eq!(refused.direction(), None);
    }

    #[test]
    fn the_default_decision_relays() {
        assert_eq!(ReofferDecision::default(), ReofferDecision::Relay);
    }
}
