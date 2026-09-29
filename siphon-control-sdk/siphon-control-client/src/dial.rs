//! The typed `dial` surface: the target, the options and the result.
//!
//! Split from [`sip`](crate::sip) for the reason [`originate`](crate::originate)
//! is — that file is at its size budget — and kept together here because the
//! target type is the whole point of the verb.
//!
//! # Why the target is an enum
//!
//! The server accepts two things that read alike and do entirely different
//! things. A **URI** is dialed as written and resolved by DNS. An **AoR** is
//! resolved against the registrar and forked to *every* registered contact, each
//! branch over that contact's own captured flow — which is the only way to reach
//! a phone registered over TCP, TLS or WSS behind NAT, because such a contact is
//! reachable only on the connection it registered over.
//!
//! `"sip:204@pbx.example"` is a plausible spelling of both. As a loose string the
//! wrong one places a call that connects to nothing while every trace looks
//! healthy, so [`DialTarget`] makes the choice explicit at every call site.

use serde_json::json;

use siphon_control_proto::sip::{
    DialAnsweredPayload, DialBranchOutcome, DialBranchPayload, DialFailedPayload, SipEvent, SipVerb,
};

use crate::error::ControlError;
use crate::originate::OriginatePrivacy;
use crate::sip::{headers_to_json, Call, CallEvent};

/// One target of a [`Call::dial`] — a URI to dial as written, or an AoR to fork
/// to its registered contacts.
///
/// Build one with [`DialTarget::uri`], [`DialTarget::uri_via`] or
/// [`DialTarget::aor`]; there is deliberately no conversion from a bare string,
/// because a string alone does not say which of the two was meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialTarget {
    /// A request URI, dialed as written.
    Uri {
        /// The B-leg request URI.
        uri: String,
        /// Send the INVITE here instead of resolving `uri`; the R-URI keeps
        /// `uri`'s shape either way.
        next_hop: Option<String>,
        /// Headers injected on this branch's INVITE, over the command's.
        headers: Vec<(String, String)>,
        /// Calling identity for this branch alone, over the dial's.
        identity: TargetIdentity,
    },
    /// An address of record, forked to every contact registered against it.
    ///
    /// There is no `next_hop` here on purpose: each branch routes over its own
    /// binding's captured flow and Path route set, so a next hop for "the AoR"
    /// would have nothing to apply to. An AoR nobody has registered contributes
    /// no branch, and a `dial` whose targets all resolve to nothing answers
    /// `not_found`.
    Aor {
        /// The address of record to resolve against the registrar.
        aor: String,
        /// Headers injected on every branch the AoR expands to.
        headers: Vec<(String, String)>,
        /// Calling identity for every branch the AoR expands to, over the
        /// dial's.
        identity: TargetIdentity,
    },
}

/// The calling identity one dial target presents, overriding the dial's.
///
/// One dial can try two carriers that assigned different numbers, and the
/// number a carrier will accept is a property of that carrier, not of the call.
/// Each field falls back to the dial's own when this target does not name it,
/// the same precedence a target's headers already use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetIdentity {
    /// The From URI this branch presents (RFC 3261 §8.1.1.3).
    pub from: Option<String>,
    /// From display name. An empty string removes the caller's rather than
    /// presenting an empty one.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1).
    pub p_asserted_identity: Option<String>,
    /// Whether this carrier may be shown the calling identity (RFC 3323 §4.1).
    pub privacy: Option<OriginatePrivacy>,
}

impl DialTarget {
    /// A URI target, dialed as written and resolved by DNS.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self::Uri {
            uri: uri.into(),
            next_hop: None,
            headers: Vec::new(),
            identity: TargetIdentity::default(),
        }
    }

    /// A URI target sent to `next_hop` (a trunk, an outbound proxy) while the
    /// R-URI keeps `uri`'s shape.
    ///
    /// A constructor rather than a builder method, so it cannot be written
    /// against an [`DialTarget::Aor`] target, where the server would drop it.
    pub fn uri_via(uri: impl Into<String>, next_hop: impl Into<String>) -> Self {
        Self::Uri {
            uri: uri.into(),
            next_hop: Some(next_hop.into()),
            headers: Vec::new(),
            identity: TargetIdentity::default(),
        }
    }

    /// An AoR target: forked to every contact registered against it, each branch
    /// over that contact's own flow.
    pub fn aor(aor: impl Into<String>) -> Self {
        Self::Aor {
            aor: aor.into(),
            headers: Vec::new(),
            identity: TargetIdentity::default(),
        }
    }

    /// Add one header to this target's branch (or to every branch an AoR
    /// expands to).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        match &mut self {
            Self::Uri { headers, .. } | Self::Aor { headers, .. } => {
                headers.push((name.into(), value.into()));
            }
        }
        self
    }

    /// This target's own calling identity, mutable in place.
    fn identity_mut(&mut self) -> &mut TargetIdentity {
        match self {
            Self::Uri { identity, .. } | Self::Aor { identity, .. } => identity,
        }
    }

    /// Present this From on this branch alone, over the dial's own.
    ///
    /// For a hunt across carriers that assigned different numbers: the number
    /// a carrier accepts belongs to that carrier, and presenting another
    /// carrier's leaves it challenging the INVITE however correct the digest.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.identity_mut().from = Some(from.into());
        self
    }

    /// Present this From display name on this branch alone. An empty string
    /// removes the caller's rather than presenting an empty one.
    pub fn from_display(mut self, display: impl Into<String>) -> Self {
        self.identity_mut().from_display = Some(display.into());
        self
    }

    /// Assert this identity to this branch's next hop (RFC 3325 §9.1).
    pub fn p_asserted_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity_mut().p_asserted_identity = Some(identity.into());
        self
    }

    /// Whether this branch's carrier may be shown the calling identity.
    pub fn privacy(mut self, privacy: OriginatePrivacy) -> Self {
        self.identity_mut().privacy = Some(privacy);
        self
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        let (headers, identity) = match self {
            Self::Uri {
                uri,
                next_hop,
                headers,
                identity,
            } => {
                // A bare URI with no overrides is a plain string on the wire —
                // the shape the server's own examples use. An identity counts
                // as an override, or the carrier's own number would be
                // silently dropped on the way out.
                if next_hop.is_none()
                    && headers.is_empty()
                    && identity == &TargetIdentity::default()
                {
                    return json!(uri);
                }
                object.insert("uri".to_string(), json!(uri));
                if let Some(next_hop) = next_hop {
                    object.insert("next_hop".to_string(), json!(next_hop));
                }
                (headers, identity)
            }
            Self::Aor {
                aor,
                headers,
                identity,
            } => {
                object.insert("aor".to_string(), json!(aor));
                (headers, identity)
            }
        };
        if !headers.is_empty() {
            object.insert("headers".to_string(), headers_to_json(headers));
        }
        if let Some(from) = &identity.from {
            object.insert("from".to_string(), json!(from));
        }
        if let Some(display) = &identity.from_display {
            object.insert("from_display".to_string(), json!(display));
        }
        if let Some(asserted) = &identity.p_asserted_identity {
            object.insert("p_asserted_identity".to_string(), json!(asserted));
        }
        if let Some(privacy) = identity.privacy {
            object.insert("privacy".to_string(), json!(privacy.as_str()));
        }
        serde_json::Value::Object(object)
    }
}

/// How [`Call::dial`] tries its targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialStrategy {
    /// Ring every target at once; the first 2xx wins and the rest are CANCELled.
    Parallel,
    /// Try the targets in order, advancing on a failure or a ring timeout.
    Sequential,
}

impl DialStrategy {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            DialStrategy::Parallel => "parallel",
            DialStrategy::Sequential => "sequential",
        }
    }

    /// The strategy called `name`, in any case: `parallel` or `sequential`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "parallel" => Some(DialStrategy::Parallel),
            "sequential" => Some(DialStrategy::Sequential),
            _ => None,
        }
    }
}

/// The tone a [`DialOnAnswer::Bridge`] dial plays the caller while its phones
/// alert.
///
/// It starts on the first `180`-`183` from any phone (RFC 3960), not when the
/// dial starts, never talks over a prompt the app is still playing, and stops
/// before the bridge re-points the caller's media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ringback {
    /// The server's default tone (`ringback_eu`).
    Default,
    /// No ringback: the caller hears whatever the app leaves playing, its own
    /// tone or music on hold.
    Silent,
    /// A tone preset or cadence, anything `play {tone}` takes:
    /// `"ringback_eu"`, `"425/1000,0/4000*inf"`.
    Tone(String),
}

impl Ringback {
    /// Play this tone preset or cadence.
    pub fn tone(tone: impl Into<String>) -> Self {
        Self::Tone(tone.into())
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Ringback::Default => json!(true),
            Ringback::Silent => json!(false),
            Ringback::Tone(tone) => json!(tone),
        }
    }

    /// The ringback a bridge dial's reply echoes: the tone in force, or
    /// `false` for none.
    fn from_json(value: &serde_json::Value) -> Option<Self> {
        match value {
            serde_json::Value::Bool(true) => Some(Ringback::Default),
            serde_json::Value::Bool(false) => Some(Ringback::Silent),
            serde_json::Value::String(tone) => Some(Ringback::Tone(tone.clone())),
            _ => None,
        }
    }
}

/// What happens when a phone of a [`Call::dial`] picks up.
///
/// An enum rather than a flag plus a ringback, because the ringback only means
/// something to a bridge: the server refuses one on a connecting dial, and here
/// it cannot be written there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialOnAnswer {
    /// The phone's answer answers the caller: the ordinary dial, refused on a
    /// caller that is already answered.
    Connect,
    /// Ring phones for a caller the app already **answered** and anchored on
    /// the media engine (the end of every IVR flow: greeting, menu, then ring
    /// the department), and bridge the first phone to pick up to it.
    ///
    /// Each phone is a call siphon places itself, over its own flow and Path,
    /// and none of the caller's INVITE headers reach it. An answer is kept only
    /// once its phone is bridged: until `ChannelBridged` every other phone
    /// keeps ringing, and a phone whose bridge fails is hung up (its
    /// `DialBranchFailed` cause is `bridge_failed`) while the dial goes on.
    /// `DialAnswered` names the bridged phone and the channel siphon minted for
    /// it; `DialFailed` leaves the caller answered and owned.
    Bridge {
        /// The tone the caller hears while phones alert; `None` takes the
        /// server's default, `ringback_eu`.
        ringback: Option<Ringback>,
    },
}

impl DialOnAnswer {
    /// Bridge the phone that picks up, with the server's default ringback.
    pub fn bridge() -> Self {
        Self::Bridge { ringback: None }
    }

    /// Bridge the phone that picks up, playing this ringback meanwhile.
    pub fn bridge_with(ringback: Ringback) -> Self {
        Self::Bridge {
            ringback: Some(ringback),
        }
    }

    /// The wire token the server parses.
    pub const fn as_str(&self) -> &'static str {
        match self {
            DialOnAnswer::Connect => "connect",
            DialOnAnswer::Bridge { .. } => "bridge",
        }
    }
}

/// Optional shaping for [`Call::dial`]; every field left `None` takes the
/// server's own default rather than a copy of it pinned here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DialOptions {
    /// How to try the targets (`parallel` server-side when unset).
    pub strategy: Option<DialStrategy>,
    /// Ring timeout in seconds (30 server-side when unset, clamped to 1..=3600).
    pub timeout_secs: Option<u32>,
    /// Headers injected on every branch's INVITE, under each target's own.
    pub headers: Vec<(String, String)>,
    /// A configured media profile to anchor both legs through, so the caller
    /// and the phones never exchange media directly.
    ///
    /// What a carrier-delivered call to a ring group needs: the carrier hands
    /// over plain RTP at a routable address and every phone answers from an
    /// address on its own LAN, so without the relay in the middle the two ends
    /// cannot reach each other. `None` passes the caller's own SDP through.
    pub profile: Option<String>,
    /// The calling identity to present — the From URI (RFC 3261 §8.1.1.3).
    ///
    /// Without it a B-leg presents the caller's own From, which on a call out
    /// to a trunk is the internal extension. A carrier that looks its account
    /// up by the From user does not recognise that, so it challenges the INVITE
    /// and keeps challenging however correct the digest is. A header injected
    /// through [`DialOptions::header`] cannot do this: From is framework-managed
    /// on a B-leg and is rewritten after the fact.
    pub from: Option<String>,
    /// The From display name. Naming a `from` without one drops the caller's
    /// rather than presenting it beside a number that replaced it.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1). Reaches
    /// the wire after the header policy, so a preset that strips `P-*` at a
    /// trust boundary cannot silently drop it.
    pub p_asserted_identity: Option<String>,
    /// Whether the calling identity may be presented (RFC 3323 §4.1 /
    /// TS 24.607) — the same presentation [`crate::sip::OriginateOptions`]
    /// takes. `Restricted` anonymises From and asserts `Privacy: id`, keeping
    /// the real identity in `p_asserted_identity` for the trusted next hop.
    pub privacy: Option<OriginatePrivacy>,
    /// What happens when a phone picks up: connect the caller (the default) or
    /// bridge an already-answered caller to it.
    pub on_answer: Option<DialOnAnswer>,
}

impl DialOptions {
    /// Try the targets this way.
    pub fn strategy(mut self, strategy: DialStrategy) -> Self {
        self.strategy = Some(strategy);
        self
    }

    /// Ring for this many seconds before giving up on the dial.
    pub fn timeout(mut self, seconds: u32) -> Self {
        self.timeout_secs = Some(seconds);
        self
    }

    /// Add one header to every branch's INVITE.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Anchor both legs through this configured media profile.
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Present this URI as the calling identity instead of the caller's own.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Present this display name.
    pub fn from_display(mut self, display: impl Into<String>) -> Self {
        self.from_display = Some(display.into());
        self
    }

    /// Assert this identity to a trusted next hop (RFC 3325 §9.1).
    pub fn p_asserted_identity(mut self, identity: impl Into<String>) -> Self {
        self.p_asserted_identity = Some(identity.into());
        self
    }

    /// Present, or withhold, the calling identity.
    pub fn privacy(mut self, privacy: OriginatePrivacy) -> Self {
        self.privacy = Some(privacy);
        self
    }

    /// Decide what a phone's answer does.
    pub fn on_answer(mut self, on_answer: DialOnAnswer) -> Self {
        self.on_answer = Some(on_answer);
        self
    }

    fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        if let Some(strategy) = self.strategy {
            args.insert("strategy".to_string(), json!(strategy.as_str()));
        }
        if let Some(timeout) = self.timeout_secs {
            args.insert("timeout".to_string(), json!(timeout));
        }
        if !self.headers.is_empty() {
            args.insert("headers".to_string(), headers_to_json(&self.headers));
        }
        for (name, value) in [
            ("profile", &self.profile),
            ("from", &self.from),
            ("from_display", &self.from_display),
            ("p_asserted_identity", &self.p_asserted_identity),
        ] {
            if let Some(value) = value {
                args.insert(name.to_string(), json!(value));
            }
        }
        if let Some(privacy) = self.privacy {
            args.insert("privacy".to_string(), json!(privacy.as_str()));
        }
        if let Some(on_answer) = &self.on_answer {
            args.insert("on_answer".to_string(), json!(on_answer.as_str()));
            if let DialOnAnswer::Bridge {
                ringback: Some(ringback),
            } = on_answer
            {
                args.insert("ringback".to_string(), ringback.to_json());
            }
        }
    }
}

/// What the server answers an accepted [`Call::dial`] with: the INVITEs are on
/// the wire, nobody has answered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialing {
    /// The channel the targets are being rung for — still the caller's.
    pub channel: String,
    /// How many **branches** the server resolved, which an AoR expands: a single
    /// AoR target registered on three devices reports three.
    pub targets: Option<u64>,
    /// The strategy in force (the server's default when none was asked for).
    pub strategy: Option<String>,
    /// The ring timeout in force, in seconds.
    pub timeout_secs: Option<u32>,
    /// `bridge` for a [`DialOnAnswer::Bridge`] dial, `None` for a connecting
    /// one.
    pub on_answer: Option<String>,
    /// The id of the group of calls a bridge dial places, one per phone.
    pub group_id: Option<String>,
    /// How long a bridge dial rings as a whole, in seconds: `timeout` for a
    /// parallel dial, `timeout` times the number of phones for a sequential
    /// one.
    pub total_timeout_secs: Option<u32>,
    /// The ringback a bridge dial plays.
    pub ringback: Option<Ringback>,
    /// The phones a bridge dial rang at once, each named as its `DialBranch`
    /// event names it. Empty for a connecting dial, which reports its branches
    /// only as events.
    pub branches: Vec<DialBranchPayload>,
}

impl Call {
    /// Ring `targets` as B-legs while the caller stays **unanswered** and this
    /// application keeps the channel.
    ///
    /// The difference from [`Call::route`] is who holds the call afterwards.
    /// `route` hands it back to siphon, so the app gets `StasisEnd{reason:
    /// routed}` and loses it; there is then no way to say "ring the extension,
    /// and if nobody answers, voicemail" without answering the caller first —
    /// which starts billing before anyone picks up, records an unanswered call
    /// as answered, and denies the caller the callee's own ringback.
    ///
    /// Provisional responses and early media reach the caller as they do for a
    /// script's `call.fork`. The first 2xx answers the caller with the winner's
    /// SDP and the pair becomes an ordinary two-leg call, with this app still
    /// owning it. A failure or a timeout arrives as a `DialFailed` event with the
    /// caller still ringing and still parked, so nothing is forwarded to it and
    /// the app decides what happens next. Each branch is named as it is created
    /// ([`CallEvent::dial_branch`](crate::CallEvent::dial_branch)) and as it ends
    /// (`dial_branch_failed` / `dial_answered`), by its leg id and the SIP
    /// Call-ID its INVITE carries, and `DialFailed` lists them all.
    ///
    /// Each target is a [`DialTarget::Uri`] (dialed as written) or a
    /// [`DialTarget::Aor`] (forked to every registered contact over its own
    /// flow) — see [`DialTarget`] for why that distinction is load-bearing.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{Call, DialOptions, DialStrategy, DialTarget};
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// let dialing = call
    ///     .dial(
    ///         vec![
    ///             DialTarget::aor("sip:204@pbx.example"),
    ///             DialTarget::uri_via("sip:+15550177@trunk.example", "sip:192.0.2.9:5060"),
    ///         ],
    ///         DialOptions::default()
    ///             .strategy(DialStrategy::Sequential)
    ///             .timeout(20),
    ///     )
    ///     .await?;
    /// println!("ringing {:?} branches", dialing.targets);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Refusals are typed: `not_found` (the call is gone, or no target yielded a
    /// branch — an AoR nobody has registered), `invalid_state` (the call is
    /// already answered, which is what this verb exists to avoid),
    /// `bad_request` (an empty or malformed target list, an identity that is not
    /// a SIP URI, a privacy siphon does not recognise), `unsupported_verb` (a
    /// strategy siphon does not implement), `unavailable` (the media profile
    /// could not be allocated — nothing was sent and the caller stays parked).
    ///
    /// # Ringing phones for an answered caller
    ///
    /// With [`DialOnAnswer::Bridge`] the caller must instead already be answered
    /// and anchored on the media engine (`answer_anchored`), which is what lets
    /// the app play it a greeting and a menu first. The phones ring with the
    /// ringback, and the first to pick up is bridged to the caller.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{Call, DialOnAnswer, DialOptions, DialTarget, Ringback};
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// call.dial(
    ///     vec![DialTarget::aor("sip:204@pbx.example")],
    ///     DialOptions::default()
    ///         .timeout(20)
    ///         .on_answer(DialOnAnswer::bridge_with(Ringback::tone("ringback_eu"))),
    /// )
    /// .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Its refusals carry `error.details.reason`: `invalid_state` for a caller
    /// that is `not_answered`, `not_anchored`, `already_bridged` or has a
    /// `dial_in_progress`; `not_found` (`call_gone`) when the caller is gone.
    pub async fn dial(
        &self,
        targets: Vec<DialTarget>,
        options: DialOptions,
    ) -> Result<Dialing, ControlError> {
        let mut args = serde_json::Map::new();
        args.insert(
            "targets".to_string(),
            json!(targets.iter().map(DialTarget::to_json).collect::<Vec<_>>()),
        );
        options.insert_into(&mut args);

        let result = self
            .sip(SipVerb::Dial, serde_json::Value::Object(args))
            .await?;
        Ok(Dialing::from_reply(&result, self.channel_id()))
    }
}

impl Dialing {
    /// The typed reply, `channel` being the one the dial addressed.
    fn from_reply(result: &serde_json::Value, channel: &str) -> Self {
        Dialing {
            // The server echoes the channel back; fall back to the one addressed
            // rather than handing back an empty id.
            channel: string(result, "channel").unwrap_or_else(|| channel.to_string()),
            targets: result.get("targets").and_then(|value| value.as_u64()),
            strategy: string(result, "strategy"),
            timeout_secs: seconds(result, "timeout"),
            on_answer: string(result, "on_answer"),
            group_id: string(result, "group_id"),
            total_timeout_secs: seconds(result, "total_timeout"),
            ringback: result.get("ringback").and_then(Ringback::from_json),
            branches: branches(result),
        }
    }
}

fn string(result: &serde_json::Value, name: &str) -> Option<String> {
    result
        .get(name)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn seconds(result: &serde_json::Value, name: &str) -> Option<u32> {
    result
        .get(name)
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
}

/// The `branches` a group reply lists, each in the shape of a `DialBranch`
/// payload. A branch that does not parse is skipped rather than failing the
/// verb, whose INVITEs are already on the wire.
pub(crate) fn branches(result: &serde_json::Value) -> Vec<DialBranchPayload> {
    result
        .get("branches")
        .and_then(|value| value.as_array())
        .map(|branches| {
            branches
                .iter()
                .filter_map(|branch| serde_json::from_value(branch.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Typed views over the events a `dial` produces. Each branch it rings is its
/// own SIP dialog, on a Call-ID the server generated, so these are what tie a
/// leg back to the channel.
impl CallEvent {
    /// The typed [`DialBranchPayload`] when this is a [`SipEvent::DialBranch`]
    /// event, else `None`: a B-leg the `dial` just created, by the leg id its
    /// later events carry and the Call-ID its INVITE carries.
    pub fn dial_branch(&self) -> Option<DialBranchPayload> {
        if self.kind != SipEvent::DialBranch {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`DialBranchOutcome`] when this is a
    /// [`SipEvent::DialBranchFailed`] event, else `None`: one branch of the
    /// `dial` ended without answering, and why.
    pub fn dial_branch_failed(&self) -> Option<DialBranchOutcome> {
        if self.kind != SipEvent::DialBranchFailed {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`DialAnsweredPayload`] when this is a
    /// [`SipEvent::DialAnswered`] event, else `None`: the branch that answered.
    pub fn dial_answered(&self) -> Option<DialAnsweredPayload> {
        if self.kind != SipEvent::DialAnswered {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`DialFailedPayload`] when this is a [`SipEvent::DialFailed`]
    /// event, else `None`: nobody answered, with every branch and its outcome.
    pub fn dial_failed(&self) -> Option<DialFailedPayload> {
        if self.kind != SipEvent::DialFailed {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// Whether this event ends a `dial` — exactly one `DialAnswered` or
    /// `DialFailed` arrives per dial, so this is the signal to stop waiting.
    pub fn is_dial_final(&self) -> bool {
        matches!(self.kind, SipEvent::DialAnswered | SipEvent::DialFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use siphon_control_proto::sip::DialBranchCause;
    use siphon_control_proto::EventFrame;

    #[test]
    fn dial_events_parse_from_frames() {
        let frame = |event: &str, payload: serde_json::Value| {
            let frame = EventFrame::new(event, "ch1", "ivr-app", "call-uuid", "sip@host", payload);
            CallEvent {
                kind: frame.sip_kind(),
                payload: frame.payload.clone(),
                frame,
            }
        };

        let created = frame(
            "DialBranch",
            json!({
                "leg_id": "leg-1",
                "leg_sip_call_id": "b1@host",
                "target": "sip:204@example.com"
            }),
        );
        assert_eq!(created.kind, SipEvent::DialBranch);
        let payload = created.dial_branch().expect("branch payload");
        assert_eq!(payload.leg_id, "leg-1");
        assert_eq!(payload.leg_sip_call_id, "b1@host");
        assert!(!created.is_dial_final());
        assert!(created.dial_failed().is_none());

        let busy = frame(
            "DialBranchFailed",
            json!({
                "leg_id": "leg-1",
                "leg_sip_call_id": "b1@host",
                "target": "sip:204@example.com",
                "code": 486,
                "reason": "Busy Here",
                "cause": "rejected"
            }),
        );
        let payload = busy.dial_branch_failed().expect("branch outcome");
        assert_eq!(payload.code, 486);
        assert_eq!(payload.cause, DialBranchCause::Rejected);
        assert!(!busy.is_dial_final());

        let answered = frame(
            "DialAnswered",
            json!({
                "leg_id": "leg-2",
                "leg_sip_call_id": "b2@host",
                "target": "sip:205@example.com",
                "code": 200
            }),
        );
        let payload = answered.dial_answered().expect("answered payload");
        assert_eq!(payload.leg_sip_call_id, "b2@host");
        assert!(answered.is_dial_final());
        assert!(answered.dial_branch().is_none());

        let failed = frame(
            "DialFailed",
            json!({
                "code": 486,
                "reason": "Busy Here",
                "timed_out": false,
                "branches": [{
                    "leg_id": "leg-1",
                    "leg_sip_call_id": "b1@host",
                    "target": "sip:204@example.com",
                    "code": 486,
                    "reason": "Busy Here",
                    "cause": "rejected"
                }]
            }),
        );
        let payload = failed.dial_failed().expect("failed payload");
        assert_eq!(payload.branches.len(), 1);
        assert_eq!(payload.branches[0].leg_sip_call_id, "b1@host");
        assert!(failed.is_dial_final());
    }

    /// A target with no overrides stays a bare string, which is the shape the
    /// server's own examples use.
    #[test]
    fn a_plain_uri_target_is_a_bare_string() {
        assert_eq!(
            DialTarget::uri("sip:204@pbx.example").to_json(),
            json!("sip:204@pbx.example")
        );
    }

    /// An identity has to defeat that shortcut, or a carrier's own number is
    /// dropped on the way out and the branch presents the dial's instead —
    /// which is the number that carrier does not recognise.
    #[test]
    fn a_target_identity_is_carried_on_the_wire() {
        let target = DialTarget::uri("sip:+15550100@carrier-a.example")
            .from("sip:2025550111@carrier-a.example")
            .from_display("Support")
            .p_asserted_identity("sip:2025550111@carrier-a.example")
            .privacy(OriginatePrivacy::Restricted);

        let json = target.to_json();
        assert!(
            json.is_object(),
            "an identity must defeat the bare-string shortcut, got {json}"
        );
        assert_eq!(
            json.get("from").and_then(|v| v.as_str()),
            Some("sip:2025550111@carrier-a.example")
        );
        assert_eq!(
            json.get("from_display").and_then(|v| v.as_str()),
            Some("Support")
        );
        assert_eq!(
            json.get("p_asserted_identity").and_then(|v| v.as_str()),
            Some("sip:2025550111@carrier-a.example")
        );
        assert_eq!(
            json.get("privacy").and_then(|v| v.as_str()),
            Some(OriginatePrivacy::Restricted.as_str())
        );
    }

    fn wire(options: &DialOptions) -> serde_json::Value {
        let mut args = serde_json::Map::new();
        options.insert_into(&mut args);
        serde_json::Value::Object(args)
    }

    /// A connecting dial says nothing about `on_answer` unless asked, so a
    /// server that predates it reads the same arguments it always did.
    #[test]
    fn a_connecting_dial_sends_no_on_answer_and_no_ringback() {
        assert_eq!(wire(&DialOptions::default()), json!({}));
        assert_eq!(
            wire(&DialOptions::default().on_answer(DialOnAnswer::Connect)),
            json!({ "on_answer": "connect" })
        );
    }

    /// A bridge without a ringback leaves the server's default in force rather
    /// than pinning a copy of it here.
    #[test]
    fn a_bridge_dial_sends_on_answer_and_its_ringback() {
        assert_eq!(
            wire(&DialOptions::default().on_answer(DialOnAnswer::bridge())),
            json!({ "on_answer": "bridge" })
        );
        for (ringback, expected) in [
            (Ringback::Default, json!(true)),
            (Ringback::Silent, json!(false)),
            (
                Ringback::tone("425/1000,0/4000*inf"),
                json!("425/1000,0/4000*inf"),
            ),
        ] {
            assert_eq!(
                wire(&DialOptions::default().on_answer(DialOnAnswer::bridge_with(ringback))),
                json!({ "on_answer": "bridge", "ringback": expected })
            );
        }
    }

    #[test]
    fn a_bridge_dial_reply_names_its_group_and_phones() {
        let dialing = Dialing::from_reply(
            &json!({
                "channel": "ch_caller",
                "state": "dialing",
                "on_answer": "bridge",
                "group_id": "originate-group-1",
                "targets": 2,
                "strategy": "sequential",
                "timeout": 20,
                "total_timeout": 40,
                "ringback": "ringback_eu",
                "branches": [{
                    "leg_id": "leg-1",
                    "leg_sip_call_id": "b1@host",
                    "target": "sip:204@203.0.113.7:5060",
                    "aor": "sip:204@pbx.example"
                }]
            }),
            "ch_caller",
        );
        assert_eq!(dialing.on_answer.as_deref(), Some("bridge"));
        assert_eq!(dialing.group_id.as_deref(), Some("originate-group-1"));
        assert_eq!(dialing.timeout_secs, Some(20));
        assert_eq!(dialing.total_timeout_secs, Some(40));
        assert_eq!(dialing.ringback, Some(Ringback::tone("ringback_eu")));
        assert_eq!(dialing.branches.len(), 1);
        assert_eq!(
            dialing.branches[0].aor.as_deref(),
            Some("sip:204@pbx.example")
        );

        let silent = Dialing::from_reply(&json!({ "ringback": false }), "ch_caller");
        assert_eq!(silent.ringback, Some(Ringback::Silent));
        assert_eq!(silent.channel, "ch_caller");
    }

    /// A connecting dial's reply has none of the group fields.
    #[test]
    fn a_connecting_dial_reply_has_no_group() {
        let dialing = Dialing::from_reply(
            &json!({ "channel": "ch1", "state": "dialing", "targets": 3, "strategy": "parallel", "timeout": 30 }),
            "ch1",
        );
        assert_eq!(dialing.targets, Some(3));
        assert!(dialing.on_answer.is_none());
        assert!(dialing.group_id.is_none());
        assert!(dialing.ringback.is_none());
        assert!(dialing.branches.is_empty());
    }

    /// An AoR target carries its identity to every branch it expands to.
    #[test]
    fn an_aor_target_carries_its_identity() {
        let json = DialTarget::aor("sip:204@pbx.example")
            .from("sip:2025550100@pbx.example")
            .to_json();
        assert_eq!(
            json.get("aor").and_then(|v| v.as_str()),
            Some("sip:204@pbx.example")
        );
        assert_eq!(
            json.get("from").and_then(|v| v.as_str()),
            Some("sip:2025550100@pbx.example")
        );
    }
}
