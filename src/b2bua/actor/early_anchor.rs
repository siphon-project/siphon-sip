//! The early answer siphon gave the caller itself, and the far leg it dials
//! behind it.

/// An SDP answer siphon sent the caller in its own 18x, kept so every later
/// response to the same INVITE repeats it.
///
/// RFC 3261 §13.2.1: the caller takes the first SDP it receives as the answer
/// and ignores SDP in later responses to the INVITE, and RFC 6337 §3.1.1 asks a
/// 2xx to repeat an answer previewed in an unreliable 18x exactly. Holds the SDP
/// text rather than engine flags, so the actor layer stays free of media types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyMediaAnchor {
    /// The SDP answer, exactly as the early response carried it.
    pub answer_sdp: String,
    /// The media profile the engine session was made with; empty when the
    /// answer is not an engine session.
    pub profile: String,
    /// Whether the answer is the media engine's own `answer_local` answer, the
    /// one shape a callee can still be connected behind (the engine re-points
    /// the media). A script's SDP from anywhere else cannot be.
    pub engine: bool,
    /// The far leg the engine bound behind the answer for a callee, while a
    /// dial is out or connected.
    pub far: Option<FarLeg>,
}

impl EarlyMediaAnchor {
    /// The media engine's own answer, made with `profile`.
    pub fn engine(answer_sdp: String, profile: String) -> Self {
        Self {
            answer_sdp,
            profile,
            engine: true,
            far: None,
        }
    }
}

/// The engine's far leg behind a caller's early answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FarLeg {
    /// The SDP offer the engine made for the far leg, which every B-leg INVITE
    /// of the dial carries.
    pub offer_sdp: Vec<u8>,
    /// The To tag of the callee whose SDP completed the far leg, once one has.
    pub answered_by: Option<String>,
}
