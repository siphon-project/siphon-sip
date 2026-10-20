//! What one `dial` target is, and the identity each branch presents.
//!
//! Split from [`control`](super::control) to keep that file inside its size
//! budget: these are the per-branch argument types of the `dial` verb and the
//! checks run on them before any branch is sent.

use crate::dispatcher::*;

/// One `dial` target: a URI to ring, or an AoR resolved against the registrar.
#[derive(Debug, Clone, Default)]
pub struct DialTarget {
    /// Request-URI for the B-leg.
    pub uri: String,
    /// Routing destination, when it differs from `uri` (a trunk, an outbound
    /// proxy). The R-URI keeps `uri`'s shape either way.
    pub next_hop: Option<String>,
    /// Captured inbound flow for a registered contact (RFC 5626 §5.3). The only
    /// way to reach a phone that registered over TCP, TLS or WebSocket behind
    /// NAT, which is why an AoR target resolves to one per contact.
    pub flow: Option<crate::script::api::registrar::PyFlow>,
    /// Route set for this branch, from the binding's Path (RFC 3327 §5.3).
    pub route: Vec<String>,
    /// Per-target headers, layered over the command's.
    pub headers: std::collections::HashMap<String, String>,
    /// Calling identity for this branch alone, overriding the dial's own.
    ///
    /// One dial can try two carriers that assigned different numbers, and the
    /// number a carrier will accept is a property of that carrier, not of the
    /// call. Without this a hunt across two trunks can only present one of
    /// them correctly, and the other challenges the INVITE and keeps
    /// challenging however correct the digest is.
    pub from: Option<String>,
    /// From display name for this branch alone. An empty string removes the
    /// caller's rather than presenting an empty one, as at dial level.
    pub from_display: Option<String>,
    /// Present `from` with siphon's own advertised address as its host
    /// (topology hiding), the way a connecting dial's B-leg presents the
    /// caller's `From`.
    ///
    /// Set by a bridge dial on a leg that presents the caller's own `From`:
    /// that host is whatever the caller's side put there, a carrier's address
    /// on a call in from a trunk, and is not the phone's to see. A `from` the
    /// dial or the target names keeps its host, which is pinned exactly as on
    /// a connecting dial.
    pub hide_from_host: bool,
    /// `P-Asserted-Identity` for this branch alone (RFC 3325 §9.1).
    pub p_asserted_identity: Option<String>,
    /// Calling-identity presentation for this branch alone (RFC 3323 §4.1).
    /// One carrier may be trusted with the real identity where another is not.
    pub privacy: Option<crate::sip::privacy::CallerIdPresentation>,
    /// Called party for this branch: the B-leg's `To` URI (RFC 3261 §8.1.1.2).
    ///
    /// Without it the B-leg keeps the caller's own `To` user at the target's
    /// authority, which is right for a forward and wrong for a divert: the
    /// R-URI names the new number while `To` still names the one the caller
    /// dialled, and a next hop that routes on `To` serves the call as one to
    /// the original number and can send it straight back. Per branch for the
    /// same reason `from` is: a hunt across two trunks can reach two numbers.
    pub to: Option<String>,
    /// Host siphon presents in its own `Contact` on this branch's leg, in place
    /// of the address it advertises on the leg's transport.
    ///
    /// The advertised address is one per transport, so without this every leg
    /// presents the same Contact host. A peer that identifies the tenant or
    /// account by the host of the Contact can then be served for one tenant
    /// per siphon. Only the host changes: port, transport and any user part
    /// stay what siphon advertises, so the in-dialog requests the peer sends to
    /// that Contact still reach the listener the INVITE left from (RFC 3261
    /// §12.1.2). The DNS for the host is the deployment's to point there.
    /// Validated and stored bracketed when it is an IPv6 address
    /// ([`checked_contact_host`]).
    pub contact_host: Option<String>,
    /// The registered AoR this target is a contact of, when it came from an
    /// `{aor}` target ([`dial_targets_for_aor`]). What the branch's events name
    /// as the AoR it was dialled for; `None` for a URI dialled as written.
    pub aor: Option<String>,
    /// Whether a sequential dial still moves on from this target once it has
    /// shown progress (a 101-199 from the far end). `None` is the verb's
    /// default, which is `true`: a hunt through phones moves on when a phone
    /// rings out or is busy.
    ///
    /// `Some(false)` makes this target's outcome the dial's once it has rung:
    /// its ring timeout, busy, decline or any other failure ends the dial and
    /// no later target is tried ([`crate::b2bua::actor::hunt_stops_at`]). For
    /// a hunt across several routes to the same destination, where the next
    /// target would ring the same person again. The field a `route` target
    /// has, pointing the same way (`false` keeps the call on a target that
    /// rang); on a `dial` it covers the target's final failures too, where a
    /// `route` carrier still fails over on its reroute causes, and its default
    /// is `true` rather than `false`. Ignored by a parallel dial, which has no
    /// next target to stop.
    pub reroute_after_progress: Option<bool>,
    /// Media profile for this branch alone, over the dial's own.
    ///
    /// The media a peer can take is a property of that peer, not of the call:
    /// a desk phone behind NAT needs a latching relay while a trunk asks for
    /// SDES-SRTP, and one ring can reach both. A branch naming a profile the
    /// others do not is offered an allocation of its own, and the branch that
    /// answers is answered through it (see `dial_media`).
    pub profile: Option<String>,
    /// When this branch's INVITE carries its SDP offer, over the dial's own.
    /// Only a bridging dial places its legs itself, so only it reads this.
    pub offer: Option<DialOffer>,
}

/// When a leg a bridging `dial` places carries its SDP offer.
///
/// Every leg of a bridging dial is a call siphon places itself, with no
/// caller's INVITE behind it to take an offer from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DialOffer {
    /// The INVITE goes out with no SDP: the callee offers in its 2xx and siphon
    /// answers in the ACK (RFC 3261 §13.2.1, RFC 3264 §5). What a bridging dial
    /// has always done.
    #[default]
    Delayed,
    /// The INVITE carries an offer the media engine allocated for the leg from
    /// the caller's media description, and the callee answers in its 2xx. For
    /// peers that refuse a delayed-offer INVITE.
    Early,
}

impl DialOffer {
    /// The offer mode named `text` (`early` / `delayed`).
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "early" => Some(Self::Early),
            "delayed" => Some(Self::Delayed),
            _ => None,
        }
    }

    /// The name the control plane uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delayed => "delayed",
            Self::Early => "early",
        }
    }
}

impl DialTarget {
    /// Whether this target, once it has rung, still moves a sequential dial on.
    pub fn reroutes_after_progress(&self) -> bool {
        self.reroute_after_progress.unwrap_or(true)
    }

    /// This branch's effective identity: its own where it names one, the
    /// dial's otherwise.
    ///
    /// Resolved per field rather than all-or-nothing, so a target naming only
    /// a `from` still inherits the dial's `privacy`. Same precedence as
    /// `headers`, which a target already layers over the command's.
    pub(super) fn shaping_over(&self, dial: &DialShaping) -> DialShaping {
        DialShaping {
            profile: self.profile.clone().or_else(|| dial.profile.clone()),
            from: self.from.clone().or_else(|| dial.from.clone()),
            from_display: self
                .from_display
                .clone()
                .or_else(|| dial.from_display.clone()),
            p_asserted_identity: self
                .p_asserted_identity
                .clone()
                .or_else(|| dial.p_asserted_identity.clone()),
            privacy: self.privacy.or(dial.privacy),
        }
    }
}

/// How a controller-issued `dial` presents itself and anchors its media.
///
/// Every field applies to the whole dial: each branch of a fork and each
/// attempt of a sequential hunt, not just the first one out.
#[derive(Debug, Clone, Default)]
pub struct DialShaping {
    /// Media profile to anchor both legs through. `None` passes the caller's
    /// own SDP to the phones and lets them negotiate with the caller directly.
    pub profile: Option<String>,
    /// Calling identity — the From URI (RFC 3261 §8.1.1.3).
    ///
    /// Without it a B-leg presents the caller's own From, which on a call out
    /// to a trunk is the internal extension. A carrier that looks its account
    /// up by the From user does not recognise that, so it challenges the INVITE
    /// and keeps challenging however correct the digest is.
    pub from: Option<String>,
    /// From display name. An empty string removes the caller's rather than
    /// presenting an empty one.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1). Injected
    /// after the header policy, so a preset that strips `P-*` at a trust
    /// boundary cannot silently drop an identity the controller named.
    pub p_asserted_identity: Option<String>,
    /// Calling-identity presentation (RFC 3323 §4.1 / TS 24.607). `Restricted`
    /// anonymises From and asserts `Privacy: id`, keeping the real identity in
    /// `P-Asserted-Identity` for the trusted next hop.
    pub privacy: Option<crate::sip::privacy::CallerIdPresentation>,
}

/// The `From` a dial's identity arguments shaped.
#[derive(Debug, Clone)]
pub(super) struct ShapedFrom {
    /// The whole header value, dialog tag included.
    pub(super) header: String,
    /// The host to pin, when `from` named one.
    pub(super) host: Option<String>,
}

/// Shape the dial template's `From` from `shaping`.
///
/// `From` is framework-managed on a B-leg — the builder swaps in a fresh dialog
/// tag and, for topology hiding, rewrites the host to siphon's own advertised
/// address — so it cannot be set with a plain header injection: one written
/// without its tag drops the mandatory dialog tag (RFC 3261 §8.1.1.3), and the
/// host would be overwritten after the fact anyway. This goes through
/// [`NameAddr`], which round-trips the tag, and reports the host to pin the way
/// `call.set_from_host()` pins it.
pub(super) fn apply_dial_identity(
    template: &mut SipMessage,
    shaping: &DialShaping,
) -> Result<Option<ShapedFrom>, String> {
    let shaped = shape_from(template, shaping)?;
    if let Some(shaped) = &shaped {
        crate::sip::privacy::present_calling_identity(template, shaped.header.clone());
    }
    Ok(shaped)
}

/// The `From` `shaping` presents over `template`'s own, or `None` when it names
/// no identity and the template's stands.
pub(super) fn shape_from(
    template: &SipMessage,
    shaping: &DialShaping,
) -> Result<Option<ShapedFrom>, String> {
    if shaping.from.is_none() && shaping.from_display.is_none() {
        return Ok(None);
    }
    let raw = template
        .headers
        .get("From")
        .or_else(|| template.headers.get("f"))
        .ok_or("the call has no From header to present an identity on")?;
    let mut nameaddr = crate::sip::headers::nameaddr::NameAddr::parse(raw)
        .map_err(|error| format!("cannot parse the call's From header: {error}"))?;
    let mut host = None;
    if let Some(from) = shaping.from.as_deref() {
        let uri = parse_uri_standalone(from)
            .map_err(|error| format!("dial from is not a SIP URI: {error}"))?;
        host = Some(uri.host.clone());
        nameaddr.uri = uri;
    }
    match shaping.from_display.as_deref() {
        Some(display) => {
            nameaddr.display_name = Some(display.to_string()).filter(|value| !value.is_empty());
        }
        // A display name is part of an identity. Keeping the caller's beside a
        // number the controller replaced would present "203" next to the
        // company's published number — the extension the `from` exists to hide.
        None if shaping.from.is_some() => nameaddr.display_name = None,
        None => {}
    }
    Ok(Some(ShapedFrom {
        header: nameaddr.to_string(),
        host,
    }))
}

/// The `From` each target presents where it names an identity of its own, in
/// target order, over the dial-shaped `template`.
///
/// A target's identity is shaped exactly as the dial's is — the whole URI with
/// its host pinned, the caller's display name dropped unless one is named —
/// resolved field by field over the dial's through
/// [`DialTarget::shaping_over`]. Every target is shaped before any branch is
/// sent, so an identity siphon cannot put on the wire refuses the dial before
/// anything rings rather than after the first phone already has.
pub(super) fn branch_identities(
    targets: &[DialTarget],
    template: &SipMessage,
    shaping: &DialShaping,
) -> Result<Vec<Option<ShapedFrom>>, String> {
    targets
        .iter()
        .map(|target| {
            if target.from.is_none() && target.from_display.is_none() {
                return Ok(None);
            }
            shape_from(template, &target.shaping_over(shaping))
        })
        .collect()
}

/// The `To` each target names as its called party, in target order, as the
/// header value its B-leg carries (`<uri>`, no tag: an out-of-dialog request
/// has none, RFC 3261 §8.1.1.2).
///
/// Every target is checked before any branch is sent, as its identity is, so a
/// `to` siphon cannot put on the wire refuses the dial before anything rings.
pub(super) fn branch_called_parties(targets: &[DialTarget]) -> Result<Vec<Option<String>>, String> {
    targets
        .iter()
        .map(|target| {
            target
                .to
                .as_deref()
                .map(|to| {
                    parse_uri_standalone(to)
                        .map(|uri| format!("<{uri}>"))
                        .map_err(|error| format!("dial target to is not a SIP URI: {error}"))
                })
                .transpose()
        })
        .collect()
}
