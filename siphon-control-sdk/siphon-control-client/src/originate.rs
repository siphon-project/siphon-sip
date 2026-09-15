//! The typed `originate` surface: the media plan, the options and the result.
//!
//! Split from [`sip`](crate::sip) because it is self-contained and that file is
//! at its size budget — every other verb addresses a channel that already
//! exists, so `originate`'s arguments share nothing with them.

use serde_json::json;

use std::sync::Arc;

use siphon_control_proto::sip::SipVerb;
use siphon_control_proto::verbs::MODULE_SIP;

use crate::error::ControlError;
use crate::session::CommandTransport;
use crate::sip::headers_to_json;

/// The media plan for [`SipClient::originate`] — what the outbound INVITE
/// offers.
///
/// Required, and an enum, because the server requires exactly one plan and
/// rejects every combination of the raw `sdp` / `body` / `media` arguments that
/// names none or more than one. Expressed this way those errors are
/// unrepresentable rather than discovered at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginateMedia {
    /// Offerless INVITE: siphon anchors the leg on the media engine and
    /// synthesizes the offer, so the controller drives it with `play`, DTMF and
    /// recording without terminating audio itself.
    Anchor {
        /// Media profile to anchor with; `None` takes the server's default.
        profile: Option<String>,
        /// Per-call WebSocket bridge URI for the anchored leg.
        ws_uri: Option<String>,
    },
    /// Your own SDP offer. `application/sdp` by definition — pass
    /// [`OriginateMedia::Body`] for anything else.
    Sdp(String),
    /// Your own body with its own content type.
    Body {
        /// The body text.
        body: String,
        /// Its MIME type.
        content_type: String,
    },
}

impl OriginateMedia {
    /// Let siphon anchor the leg on the media engine's default profile.
    pub fn anchor() -> Self {
        Self::Anchor {
            profile: None,
            ws_uri: None,
        }
    }

    /// Anchor on a named media profile.
    pub fn anchor_with(profile: impl Into<String>) -> Self {
        Self::Anchor {
            profile: Some(profile.into()),
            ws_uri: None,
        }
    }

    /// Offer your own SDP.
    pub fn sdp(sdp: impl Into<String>) -> Self {
        Self::Sdp(sdp.into())
    }

    pub(crate) fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        match self {
            OriginateMedia::Anchor { profile, ws_uri } => {
                args.insert("media".to_string(), json!(true));
                if let Some(profile) = profile {
                    args.insert("profile".to_string(), json!(profile));
                }
                if let Some(ws_uri) = ws_uri {
                    args.insert("ws_uri".to_string(), json!(ws_uri));
                }
            }
            OriginateMedia::Sdp(sdp) => {
                args.insert("sdp".to_string(), json!(sdp));
            }
            OriginateMedia::Body { body, content_type } => {
                args.insert("body".to_string(), json!(body));
                args.insert("content_type".to_string(), json!(content_type));
            }
        }
    }
}

/// Caller identity and privacy for [`SipClient::originate`] (RFC 3323 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginatePrivacy {
    /// Present the calling identity.
    Allowed,
    /// Withhold it.
    Restricted,
}

impl OriginatePrivacy {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            OriginatePrivacy::Allowed => "allowed",
            OriginatePrivacy::Restricted => "restricted",
        }
    }
}

/// Who refreshes each dialog of an originated call where the RFC 4028 negotiation
/// leaves siphon the choice (§7.1): the UAC of each dialog, the UAS of each, or
/// siphon on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRefresher {
    /// The UAC of each dialog.
    Uac,
    /// The UAS of each dialog.
    Uas,
    /// siphon, on both dialogs.
    B2bua,
}

impl SessionRefresher {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionRefresher::Uac => "uac",
            SessionRefresher::Uas => "uas",
            SessionRefresher::B2bua => "b2bua",
        }
    }

    /// The refresher called `name`, in any case: `uac`, `uas` or `b2bua`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "uac" => Some(SessionRefresher::Uac),
            "uas" => Some(SessionRefresher::Uas),
            "b2bua" => Some(SessionRefresher::B2bua),
            _ => None,
        }
    }
}

/// The RFC 4028 session timer siphon runs on an originated call, over its
/// `session_timer:` block.
///
/// A field left `None` takes the server's default, as in the script API's
/// `call.session_timer()`: an interval of 1800 s, a `Min-SE` of 90 s, and
/// [`SessionRefresher::B2bua`]. The INVITE asks for the timer, the callee's 2xx
/// says who refreshes, and siphon refreshes the dialog or releases the call before
/// a session the callee let run out expires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionTimer {
    /// The session interval, in seconds.
    pub expires: Option<u32>,
    /// The smallest session interval siphon accepts, in seconds.
    pub min_se: Option<u32>,
    /// Who refreshes where the negotiation leaves siphon the choice.
    pub refresher: Option<SessionRefresher>,
}

impl SessionTimer {
    /// Ask for this session interval, in seconds.
    pub fn expires(mut self, seconds: u32) -> Self {
        self.expires = Some(seconds);
        self
    }

    /// Accept no session interval shorter than this, in seconds.
    pub fn min_se(mut self, seconds: u32) -> Self {
        self.min_se = Some(seconds);
        self
    }

    /// Prefer this refresher.
    pub fn refresher(mut self, refresher: SessionRefresher) -> Self {
        self.refresher = Some(refresher);
        self
    }

    /// The `session_timer` object the server parses, with only the fields set.
    pub(crate) fn to_json(self) -> serde_json::Value {
        let mut timer = serde_json::Map::new();
        if let Some(expires) = self.expires {
            timer.insert("expires".to_string(), json!(expires));
        }
        if let Some(min_se) = self.min_se {
            timer.insert("min_se".to_string(), json!(min_se));
        }
        if let Some(refresher) = self.refresher {
            timer.insert("refresher".to_string(), json!(refresher.as_str()));
        }
        serde_json::Value::Object(timer)
    }
}

/// Optional shaping for [`SipClient::originate`]; every field defaults to the
/// server's behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginateOptions {
    /// From-URI to place the call as.
    pub from: Option<String>,
    /// From display name.
    pub from_display: Option<String>,
    /// To display name.
    pub to_display: Option<String>,
    /// Route the INVITE here while keeping `to` as the R-URI.
    pub next_hop: Option<String>,
    /// P-Asserted-Identity to assert (RFC 3325).
    pub p_asserted_identity: Option<String>,
    /// Caller-identity presentation.
    pub privacy: Option<OriginatePrivacy>,
    /// Extra headers on the outbound INVITE.
    pub headers: Vec<(String, String)>,
    /// Ring timeout in seconds.
    pub timeout: Option<u64>,
    /// Control-loss policy for the created channel (`hangup` by default
    /// server-side).
    pub on_lost: Option<String>,
    /// Per-call variables carried on the channel.
    pub vars: Vec<(String, String)>,
    /// The RFC 4028 session timer to run on the call; `None` runs the one the
    /// server has configured, if any.
    pub session_timer: Option<SessionTimer>,
}

impl OriginateOptions {
    /// Place the call as this From-URI.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Route the INVITE to this next hop, keeping `to` as the R-URI.
    pub fn next_hop(mut self, next_hop: impl Into<String>) -> Self {
        self.next_hop = Some(next_hop.into());
        self
    }

    /// Assert this P-Asserted-Identity.
    pub fn p_asserted_identity(mut self, identity: impl Into<String>) -> Self {
        self.p_asserted_identity = Some(identity.into());
        self
    }

    /// Set the caller-identity presentation.
    pub fn privacy(mut self, privacy: OriginatePrivacy) -> Self {
        self.privacy = Some(privacy);
        self
    }

    /// Add one header to the outbound INVITE.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Ring for this many seconds before giving up.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout = Some(seconds);
        self
    }

    /// Add one channel variable.
    pub fn var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.push((key.into(), value.into()));
        self
    }

    /// Run this RFC 4028 session timer on the call.
    pub fn session_timer(mut self, timer: SessionTimer) -> Self {
        self.session_timer = Some(timer);
        self
    }

    pub(crate) fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        let mut put = |name: &str, value: &Option<String>| {
            if let Some(value) = value {
                args.insert(name.to_string(), json!(value));
            }
        };
        put("from", &self.from);
        put("from_display", &self.from_display);
        put("to_display", &self.to_display);
        put("next_hop", &self.next_hop);
        put("p_asserted_identity", &self.p_asserted_identity);
        put("on_lost", &self.on_lost);
        if let Some(privacy) = self.privacy {
            args.insert("privacy".to_string(), json!(privacy.as_str()));
        }
        if let Some(timeout) = self.timeout {
            args.insert("timeout".to_string(), json!(timeout));
        }
        if !self.headers.is_empty() {
            args.insert("headers".to_string(), headers_to_json(&self.headers));
        }
        if !self.vars.is_empty() {
            args.insert("vars".to_string(), headers_to_json(&self.vars));
        }
        if let Some(timer) = self.session_timer {
            args.insert("session_timer".to_string(), timer.to_json());
        }
    }
}

/// What the server answers an accepted `originate` with: the call is `calling`,
/// not answered — the answer arrives later as an event on the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Originated {
    /// The caller-supplied channel id the call is addressed by.
    pub channel: String,
    /// siphon's internal call id.
    pub call_id: Option<String>,
    /// The SIP Call-ID on the wire, for joining CDR / HEP.
    pub sip_call_id: Option<String>,
}

/// Build and send an `originate`, split from [`SipClient::originate`] so the
/// argument shaping is exercised against a recording transport.
///
/// That split is the point: `originate` has more optional arguments than every
/// other verb combined, and a field spelled wrong or dropped produces a call
/// that still connects — to the wrong party, without the asserted identity, or
/// with privacy quietly not applied.
pub(crate) async fn originate_on(
    transport: &Arc<dyn CommandTransport>,
    channel: &str,
    to: &str,
    media: OriginateMedia,
    options: OriginateOptions,
) -> Result<Originated, ControlError> {
    let mut args = serde_json::Map::new();
    args.insert("channel".to_string(), json!(channel));
    args.insert("to".to_string(), json!(to));
    media.insert_into(&mut args);
    options.insert_into(&mut args);

    let result = transport
        .command(
            Some(MODULE_SIP.to_string()),
            SipVerb::Originate.as_str().to_string(),
            serde_json::Value::Null,
            serde_json::Value::Object(args),
        )
        .await?;

    let string = |name: &str| {
        result
            .get(name)
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    Ok(Originated {
        // The server echoes the id back; fall back to the one we asked for
        // rather than inventing an empty channel a caller cannot address.
        channel: string("channel").unwrap_or_else(|| channel.to_string()),
        call_id: string("call_id"),
        sip_call_id: string("sip_call_id"),
    })
}
