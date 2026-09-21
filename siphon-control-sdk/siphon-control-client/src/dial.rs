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

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::originate::OriginatePrivacy;
use crate::sip::{headers_to_json, Call};

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
    },
}

impl DialTarget {
    /// A URI target, dialed as written and resolved by DNS.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self::Uri {
            uri: uri.into(),
            next_hop: None,
            headers: Vec::new(),
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
        }
    }

    /// An AoR target: forked to every contact registered against it, each branch
    /// over that contact's own flow.
    pub fn aor(aor: impl Into<String>) -> Self {
        Self::Aor {
            aor: aor.into(),
            headers: Vec::new(),
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

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        let headers = match self {
            Self::Uri {
                uri,
                next_hop,
                headers,
            } => {
                // A bare URI with no overrides is a plain string on the wire —
                // the shape the server's own examples use.
                if next_hop.is_none() && headers.is_empty() {
                    return json!(uri);
                }
                object.insert("uri".to_string(), json!(uri));
                if let Some(next_hop) = next_hop {
                    object.insert("next_hop".to_string(), json!(next_hop));
                }
                headers
            }
            Self::Aor { aor, headers } => {
                object.insert("aor".to_string(), json!(aor));
                headers
            }
        };
        if !headers.is_empty() {
            object.insert("headers".to_string(), headers_to_json(headers));
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
    /// the app decides what happens next.
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
        Ok(Dialing {
            // The server echoes the channel back; fall back to the one addressed
            // rather than handing back an empty id.
            channel: result
                .get("channel")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| self.channel_id().to_string()),
            targets: result.get("targets").and_then(|value| value.as_u64()),
            strategy: result
                .get("strategy")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            timeout_secs: result
                .get("timeout")
                .and_then(|value| value.as_u64())
                .and_then(|value| u32::try_from(value).ok()),
        })
    }
}
