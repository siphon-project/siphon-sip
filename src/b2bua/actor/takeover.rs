//! A dialog takeover waiting on admission: what asked for it (an inbound
//! `Replaces`, or the script's `call.take_over()` for a header such as
//! `Target-Dialog`) and how it is to be carried out.

/// An inbound INVITE carrying a `Replaces` (RFC 3891) that matched a dialog this
/// node hosts, recorded on the new call while the INVITE is still being admitted.
///
/// The takeover is deliberately NOT performed at header-parse time. RFC 3891 §5
/// warns that a party who learns a dialog's identifiers can use `Replaces` to
/// hijack the call, so the request has to clear the same admission the script
/// applies to any other INVITE — `auth.require_proxy_digest()` in
/// `@b2bua.on_invite` — before siphon acts on it. This carries the resolved
/// match across that gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReplaces {
    /// The call whose dialog is being taken over.
    pub replaced_call_id: String,
    /// Which leg of that call the header named.
    pub replaced_on_a_leg: bool,
    /// The `early-only` flag (RFC 3891 §3) as it arrived.
    pub early_only: bool,
    /// What asked for the takeover.
    pub source: TakeoverSource,
    /// Whether the surviving party is re-INVITEd with the newcomer's offer.
    /// Always for a `Replaces`; a script's `call.take_over(reinvite=False)`
    /// leaves the survivor alone (TS 24.237 §12.3.5).
    pub reinvite_survivor: bool,
    /// Headers the script put on the `200` that answers the newcomer.
    pub answer_headers: Vec<(String, String)>,
}

impl PendingReplaces {
    /// A takeover an inbound `Replaces` header asked for: the survivor is
    /// always re-INVITEd, and the 200 carries nothing of the script's.
    pub fn from_replaces_header(
        replaced_call_id: String,
        replaced_on_a_leg: bool,
        early_only: bool,
    ) -> Self {
        Self {
            replaced_call_id,
            replaced_on_a_leg,
            early_only,
            source: TakeoverSource::ReplacesHeader,
            reinvite_survivor: true,
            answer_headers: Vec::new(),
        }
    }
}

/// What asked for a dialog takeover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverSource {
    /// An inbound INVITE's `Replaces` (RFC 3891), gated on
    /// `b2bua.accept_replaces`.
    ReplacesHeader,
    /// The script's `call.take_over(...)` in `@b2bua.on_invite`, for whatever
    /// header named the dialog (`Target-Dialog`, RFC 4538).
    Script,
}

impl TakeoverSource {
    /// The prefix of the takeover's log lines.
    pub fn label(self) -> &'static str {
        match self {
            TakeoverSource::ReplacesHeader => "B2BUA Replaces",
            TakeoverSource::Script => "B2BUA take_over",
        }
    }
}
