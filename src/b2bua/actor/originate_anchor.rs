//! The media plan of an offerless originate, kept on the call until the
//! callee's 2xx brings the offer it is answered against. Its accessors live
//! with the other originate ones on the call store.

/// The media plan of an offerless originate, resolved when the callee's 2xx
/// arrives. Names a profile in the media registry rather than carrying resolved
/// engine flags: the profile's answer half is read at the 2xx, with the call's
/// own `media_flags` merged over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateAnchor {
    /// Media profile whose `answer` flags the local anchor uses.
    pub profile: String,
    /// Per-call WebSocket bridge URI (templated), overriding the profile's.
    pub ws_uri: Option<String>,
    /// This call's overrides of the profile's processing settings (the control
    /// verb's `media_flags`), already checked against the profile when the
    /// originate was placed. `None` runs the profile as it is.
    pub media_flags: Option<crate::rtpengine::media_flags::MediaFlags>,
}
