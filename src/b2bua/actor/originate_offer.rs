//! The engine allocation an originated leg's INVITE offered, for a leg siphon
//! places for a bridging `dial` with `offer: "early"`. Its accessors live with
//! the other dial-branch ones on the call store.

/// The engine allocation an originated leg's INVITE offered, for a leg siphon
/// places for a bridging `dial` with `offer: "early"`. Engine identifiers only,
/// so the actor layer stays free of media types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateOffer {
    /// The engine call-id the offer was allocated on, beside the caller's own
    /// session. It becomes the bridged pair's session when the leg is bridged.
    pub media_call_id: String,
    /// The engine tag of the party the offer was made for: the caller's, whose
    /// media description the engine was given.
    pub offerer_tag: String,
}
