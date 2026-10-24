//! The typed `originate` surface: the media plan, the options and the result.
//!
//! Split from [`sip`](crate::sip) because it is self-contained and that file is
//! at its size budget — every other verb addresses a channel that already
//! exists, so `originate`'s arguments share nothing with them.

use serde_json::json;

use std::sync::Arc;

use siphon_control_proto::sip::{DialBranchPayload, SipVerb};
use siphon_control_proto::verbs::MODULE_SIP;
use siphon_control_proto::{ControlErrorCode, EventFrame, FrameType};
use tokio::sync::mpsc;

use crate::dial::{branches, DialStrategy};
use crate::error::ControlError;
use crate::session::CommandTransport;
use crate::sip::{headers_to_json, Call, CallEvent, SipClient, SipFacade};

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
        /// Overrides of the profile's processing settings for this call,
        /// merged over its answer half when siphon answers the callee.
        media_flags: Option<siphon_control_proto::media_flags::MediaFlags>,
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
            media_flags: None,
        }
    }

    /// Anchor on a named media profile.
    pub fn anchor_with(profile: impl Into<String>) -> Self {
        Self::Anchor {
            profile: Some(profile.into()),
            ws_uri: None,
            media_flags: None,
        }
    }

    /// Anchor on `profile` (the server's default when `None`) with
    /// `media_flags` over its processing settings for this call only. Only an
    /// anchor plan takes them, which is why this is a constructor and not a
    /// setter an offer plan could be handed.
    pub fn anchor_with_flags(
        profile: Option<String>,
        media_flags: siphon_control_proto::media_flags::MediaFlags,
    ) -> Self {
        Self::Anchor {
            profile,
            ws_uri: None,
            media_flags: Some(media_flags),
        }
    }

    /// Offer your own SDP.
    pub fn sdp(sdp: impl Into<String>) -> Self {
        Self::Sdp(sdp.into())
    }

    pub(crate) fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        match self {
            OriginateMedia::Anchor {
                profile,
                ws_uri,
                media_flags,
            } => {
                args.insert("media".to_string(), json!(true));
                if let Some(profile) = profile {
                    args.insert("profile".to_string(), json!(profile));
                }
                if let Some(ws_uri) = ws_uri {
                    args.insert("ws_uri".to_string(), json!(ws_uri));
                }
                if let Some(media_flags) = media_flags {
                    args.insert("media_flags".to_string(), media_flags.to_json());
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
    /// Host of siphon's own Contact on the call (on every leg of an
    /// [`SipClient::originate_aor`]), in place of the address siphon
    /// advertises. See [`OriginateOptions::contact_host`].
    pub contact_host: Option<String>,
    /// User part of siphon's own Contact on the call (on every leg of an
    /// [`SipClient::originate_aor`]), which is otherwise userless. See
    /// [`OriginateOptions::contact_user`].
    pub contact_user: Option<String>,
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

    /// Present `host` as the host of siphon's own Contact on the call, in
    /// place of the address siphon advertises, for a peer that identifies the
    /// tenant or account by that host.
    ///
    /// Only the host changes: port, transport and user part stay siphon's own,
    /// so the callee's in-dialog requests still reach the listener that sent
    /// the INVITE, and every in-dialog request siphon sends on the call
    /// presents it too. A hostname, an IPv4 address or an IPv6 address; the
    /// server refuses anything else with `bad_request` before anything is
    /// sent.
    pub fn contact_host(mut self, host: impl Into<String>) -> Self {
        self.contact_host = Some(host.into());
        self
    }

    /// Present `user` as the user part of siphon's own Contact on the call,
    /// which is otherwise userless
    /// (`<sip:trunk-7@sbc.example.net:5061;transport=tls>`), for a peer that
    /// identifies the trunk or account by it.
    ///
    /// Only the user part changes, beside [`OriginateOptions::contact_host`]
    /// when both are named, and every in-dialog request siphon sends on the
    /// call presents it too. An RFC 3261 SIP URI user; the server refuses an
    /// empty or invalid one with `bad_request` before anything is sent.
    pub fn contact_user(mut self, user: impl Into<String>) -> Self {
        self.contact_user = Some(user.into());
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
        put("contact_host", &self.contact_host);
        put("contact_user", &self.contact_user);
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
pub(crate) struct Originated {
    /// The caller-supplied channel id the call is addressed by.
    pub channel: String,
    /// siphon's internal call id.
    pub call_id: Option<String>,
    /// The SIP Call-ID on the wire, for joining CDR / HEP.
    pub sip_call_id: Option<String>,
    /// The reply as the server sent it.
    pub reply: serde_json::Value,
}

/// How [`SipClient::originate_aor`] rings the phones registered at the AoR.
///
/// Separate from [`OriginateOptions`] because the server takes these beside
/// `aor` only and refuses them beside `to`; here they cannot be written there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AorRing {
    /// Every phone at once (`parallel`, the server's default), or one at a
    /// time in registration q-value order, moving on when one declines or
    /// rings out its own `timeout` (`sequential`).
    pub strategy: Option<DialStrategy>,
    /// How long the whole group rings, in seconds, before every phone still
    /// ringing is CANCELled. The server defaults it to `timeout` for a parallel
    /// group and to `timeout` times the number of phones for a sequential one;
    /// `0` is no bound.
    pub total_timeout_secs: Option<u64>,
}

impl AorRing {
    /// Ring the phones this way.
    pub fn strategy(mut self, strategy: DialStrategy) -> Self {
        self.strategy = Some(strategy);
        self
    }

    /// Bound the whole group to this many seconds.
    pub fn total_timeout(mut self, seconds: u64) -> Self {
        self.total_timeout_secs = Some(seconds);
        self
    }

    fn insert_into(self, args: &mut serde_json::Map<String, serde_json::Value>) {
        if let Some(strategy) = self.strategy {
            args.insert("strategy".to_string(), json!(strategy.as_str()));
        }
        if let Some(total_timeout) = self.total_timeout_secs {
            args.insert("total_timeout".to_string(), json!(total_timeout));
        }
    }
}

/// What the server answers an accepted `originate {aor}` with: every phone is
/// ringing, none has answered.
///
/// Until one does, the channel is bound to the group: its events carry
/// `group_id` as their `call_id` and `sip_call_id`, since no single dialog is
/// the call yet, and each phone's own Call-ID is in their payload. From
/// `DialAnswered` on, the channel is the winning phone's call.
#[derive(Debug, Clone)]
pub struct OriginatedGroup {
    /// The caller-supplied channel id the call is addressed by.
    pub channel: String,
    /// The placed call: its events (`DialBranch`, `DialAnswered`, then the
    /// winning phone's) and every verb on the channel.
    pub call: Call,
    /// The group's id, standing in for the call until a phone answers.
    pub group_id: Option<String>,
    /// The AoR as the registrar keys it.
    pub aor: Option<String>,
    /// The strategy in force.
    pub strategy: Option<String>,
    /// The group's bound in force, in seconds.
    pub total_timeout_secs: Option<u64>,
    /// The phones rung so far (all of them for a parallel group, the first for a
    /// sequential one), each named as its `DialBranch` event names it.
    pub branches: Vec<DialBranchPayload>,
}

impl SipClient {
    /// Place an outbound call under a caller-supplied channel id.
    ///
    /// The one verb that *creates* a channel rather than addressing one, which
    /// is why it lives here and not on [`Call`]. It returns as soon as the
    /// INVITE is on the wire — the call is `calling` — with the [`Call`] it
    /// placed: the answer, failure or timeout arrives on [`Call::next_event`],
    /// exactly as a handed-over call's does, and `hangup` CANCELs or BYEs it.
    ///
    /// siphon sends no `StasisStart` for a channel its controller created, so
    /// the channel is opened here before the command goes out (a fast 180 can
    /// overtake the reply). An id still live on this client is a `conflict`
    /// refused before anything is sent.
    ///
    /// The channel id is yours to choose so the call is addressable before it is
    /// answered (and before any server-assigned id could have reached you). A id
    /// already in use is a `conflict`, never silently reused.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{OriginateMedia, OriginateOptions, SipClient};
    /// # async fn example(client: &SipClient) -> Result<(), siphon_control_client::ControlError> {
    /// let call = client
    ///     .originate(
    ///         "wake-up-42",
    ///         "sip:1001@pbx.example",
    ///         OriginateMedia::anchor(),
    ///         OriginateOptions::default()
    ///             .from("sip:alarm@pbx.example")
    ///             .timeout(20),
    ///     )
    ///     .await?;
    /// println!("ringing on {}", call.channel_id());
    /// while let Some(event) = call.next_event().await {
    ///     println!("{:?}", event.kind);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn originate(
        &self,
        channel: &str,
        to: &str,
        media: OriginateMedia,
        options: OriginateOptions,
    ) -> Result<Call, ControlError> {
        place_on(
            &self.facade,
            &self.client.commander(),
            channel,
            to,
            media,
            options,
        )
        .await
    }

    /// Place an outbound call to every phone registered at `aor`, under a
    /// caller-supplied channel id; the first to answer becomes the channel's
    /// call.
    ///
    /// [`SipClient::originate`] resolves its `to` as written, which reaches
    /// nothing for a phone registered over TCP, TLS or WSS behind NAT (only the
    /// connection it registered over reaches it) or through an edge proxy (only
    /// its Path does). This rings each registered contact over its own flow and
    /// Path (RFC 5626 §5.3, RFC 3327 §5.3), as a `dial` to an AoR does, with
    /// every [`OriginateOptions`] applied to each phone's INVITE. Every other
    /// phone still ringing is CANCELled once one answers.
    ///
    /// An AoR with nobody registered is `not_found` with
    /// `error.details.reason == "no_contacts"`, and nothing goes on the wire.
    /// While the phones ring, `hangup` CANCELs every one of them and `drop` is
    /// refused (`invalid_state`), since their INVITEs are owed a CANCEL.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{AorRing, DialStrategy, OriginateMedia, OriginateOptions, SipClient};
    /// # async fn example(client: &SipClient) -> Result<(), siphon_control_client::ControlError> {
    /// let group = client
    ///     .originate_aor(
    ///         "wake-201",
    ///         "sip:201@pbx.example",
    ///         OriginateMedia::anchor(),
    ///         OriginateOptions::default().from("sip:reception@pbx.example").timeout(25),
    ///         AorRing::default().strategy(DialStrategy::Parallel),
    ///     )
    ///     .await?;
    /// println!("ringing {} phones", group.branches.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn originate_aor(
        &self,
        channel: &str,
        aor: &str,
        media: OriginateMedia,
        options: OriginateOptions,
        ring: AorRing,
    ) -> Result<OriginatedGroup, ControlError> {
        place_aor_on(
            &self.facade,
            &self.client.commander(),
            channel,
            aor,
            media,
            options,
            ring,
        )
        .await
    }
}

/// Open `channel` on the facade, send the originate, and hand back the call, or
/// close the channel again when the server refuses it.
pub(crate) async fn place_on(
    facade: &SipFacade,
    transport: &Arc<dyn CommandTransport>,
    channel: &str,
    to: &str,
    media: OriginateMedia,
    options: OriginateOptions,
) -> Result<Call, ControlError> {
    let events = facade
        .open_channel(channel)
        .ok_or_else(|| channel_in_use(channel))?;
    match originate_on(transport, channel, to, media, options).await {
        Ok(originated) => Ok(placed_call(
            transport,
            channel,
            originated.call_id,
            originated.sip_call_id,
            originated.reply,
            events,
        )),
        Err(error) => {
            facade.close_channel(channel);
            Err(error)
        }
    }
}

/// [`place_on`] for `originate {aor}`.
pub(crate) async fn place_aor_on(
    facade: &SipFacade,
    transport: &Arc<dyn CommandTransport>,
    channel: &str,
    aor: &str,
    media: OriginateMedia,
    options: OriginateOptions,
    ring: AorRing,
) -> Result<OriginatedGroup, ControlError> {
    let events = facade
        .open_channel(channel)
        .ok_or_else(|| channel_in_use(channel))?;
    let result = match originate_aor_on(transport, channel, aor, media, options, ring).await {
        Ok(result) => result,
        Err(error) => {
            facade.close_channel(channel);
            return Err(error);
        }
    };
    // Until a phone answers, the group stands in for the call, as its events say.
    let group_id = string(&result, "group_id");
    let call = placed_call(
        transport,
        channel,
        group_id.clone(),
        group_id.clone(),
        result.clone(),
        events,
    );
    Ok(OriginatedGroup {
        channel: string(&result, "channel").unwrap_or_else(|| channel.to_string()),
        call,
        group_id,
        aor: string(&result, "aor"),
        strategy: string(&result, "strategy"),
        total_timeout_secs: result.get("total_timeout").and_then(|value| value.as_u64()),
        branches: branches(&result),
    })
}

/// The [`Call`] for a channel this client placed: the ids from the reply, which
/// stands in for the `StasisStart` payload siphon never sends for it.
fn placed_call(
    transport: &Arc<dyn CommandTransport>,
    channel: &str,
    call_id: Option<String>,
    sip_call_id: Option<String>,
    reply: serde_json::Value,
    events: mpsc::UnboundedReceiver<CallEvent>,
) -> Call {
    let frame = EventFrame {
        frame_type: FrameType::Event,
        event: SipVerb::Originate.as_str().to_string(),
        channel: Some(channel.to_string()),
        app: None,
        call_id,
        sip_call_id,
        payload: reply,
    };
    Call::from_event(Arc::clone(transport), &frame, events, false)
}

fn channel_in_use(channel: &str) -> ControlError {
    ControlError::Command {
        code: ControlErrorCode::Conflict,
        message: format!("channel {channel} is already live on this client"),
    }
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

    let result = send(transport, args).await?;
    let text = |name: &str| string(&result, name);
    Ok(Originated {
        // The server echoes the id back; fall back to the one we asked for
        // rather than inventing an empty channel a caller cannot address.
        channel: text("channel").unwrap_or_else(|| channel.to_string()),
        call_id: text("call_id"),
        sip_call_id: text("sip_call_id"),
        reply: result,
    })
}

/// Build and send an `originate {aor}`: [`originate_on`] with `aor` in place of
/// `to`, which the server takes as mutually exclusive.
pub(crate) async fn originate_aor_on(
    transport: &Arc<dyn CommandTransport>,
    channel: &str,
    aor: &str,
    media: OriginateMedia,
    options: OriginateOptions,
    ring: AorRing,
) -> Result<serde_json::Value, ControlError> {
    let mut args = serde_json::Map::new();
    args.insert("channel".to_string(), json!(channel));
    args.insert("aor".to_string(), json!(aor));
    media.insert_into(&mut args);
    options.insert_into(&mut args);
    ring.insert_into(&mut args);

    send(transport, args).await
}

/// `originate` is module-level: it creates the channel, so it carries no
/// channel target for the substrate to resolve.
async fn send(
    transport: &Arc<dyn CommandTransport>,
    args: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, ControlError> {
    transport
        .command(
            Some(MODULE_SIP.to_string()),
            SipVerb::Originate.as_str().to_string(),
            serde_json::Value::Null,
            serde_json::Value::Object(args),
        )
        .await
}

fn string(result: &serde_json::Value, name: &str) -> Option<String> {
    result
        .get(name)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientEvent;
    use futures_util::future::BoxFuture;
    use siphon_control_proto::sip::SipEvent;
    use std::sync::Mutex;

    /// One command as sent: module, verb, target, args.
    type Sent = (Option<String>, String, serde_json::Value, serde_json::Value);

    /// Records the one command sent and answers it with a canned result.
    struct Recorder {
        sent: Mutex<Vec<Sent>>,
        result: serde_json::Value,
    }

    impl CommandTransport for Recorder {
        fn command(
            &self,
            module: Option<String>,
            verb: String,
            target: serde_json::Value,
            args: serde_json::Value,
        ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>> {
            self.sent.lock().unwrap().push((module, verb, target, args));
            let result = self.result.clone();
            Box::pin(async move { Ok(result) })
        }
    }

    fn group_result() -> serde_json::Value {
        json!({
            "channel": "wake-201",
            "group_id": "originate-group-1",
            "aor": "sip:201@example.com",
            "strategy": "sequential",
            "total_timeout": 50,
            "state": "calling",
            "branches": [{
                "leg_id": "leg-1",
                "leg_sip_call_id": "b1@host",
                "target": "sip:201@203.0.113.7:5060",
                "aor": "sip:201@example.com"
            }]
        })
    }

    /// Answers `originate` the way siphon can: the call's first event on the
    /// socket ahead of the reply, since the reply waits for the INVITE to go out
    /// and a fast 180 can overtake it.
    struct EarlyEvent {
        facade: Arc<SipFacade>,
        event: EventFrame,
        reply: Result<serde_json::Value, ControlError>,
    }

    impl CommandTransport for EarlyEvent {
        fn command(
            &self,
            _module: Option<String>,
            _verb: String,
            _target: serde_json::Value,
            _args: serde_json::Value,
        ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>> {
            let commander: Arc<dyn CommandTransport> = Arc::new(Recorder {
                sent: Mutex::new(Vec::new()),
                result: json!({}),
            });
            self.facade
                .handle_client_event(ClientEvent::Event(self.event.clone()), &commander);
            let reply = match &self.reply {
                Ok(result) => Ok(result.clone()),
                Err(_) => Err(ControlError::Command {
                    code: ControlErrorCode::NotFound,
                    message: "no route".to_string(),
                }),
            };
            Box::pin(async move { reply })
        }
    }

    fn placed_event(event: &str, payload: serde_json::Value) -> EventFrame {
        EventFrame::new(
            event,
            "out-1",
            "agent-app",
            "call-uuid",
            "sip@host",
            payload,
        )
    }

    fn deliver(facade: &SipFacade, frame: EventFrame) {
        let commander: Arc<dyn CommandTransport> = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({}),
        });
        facade.handle_client_event(ClientEvent::Event(frame), &commander);
    }

    /// A placed call hears its own outcome. siphon sends no `StasisStart` for a
    /// channel this client created, so without the channel opened up front every
    /// event for it, the answer included, had nowhere to go.
    #[tokio::test]
    async fn a_placed_call_hears_every_event_including_one_ahead_of_the_reply() {
        let facade = SipFacade::new();
        let transport: Arc<dyn CommandTransport> = Arc::new(EarlyEvent {
            facade: Arc::clone(&facade),
            event: placed_event(
                "ChannelStateChange",
                json!({"state": "ringing", "code": 180}),
            ),
            reply: Ok(json!({
                "channel": "out-1",
                "call_id": "call-uuid",
                "sip_call_id": "sip@host",
                "state": "calling",
            })),
        });

        let call = place_on(
            &facade,
            &transport,
            "out-1",
            "sip:1001@pbx.example",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
        )
        .await
        .expect("originate");

        assert_eq!(call.channel_id(), "out-1");
        assert_eq!(call.call_id(), Some("call-uuid"));
        assert_eq!(call.sip_call_id(), Some("sip@host"));
        assert!(!call.is_reattached());
        assert_eq!(call.payload()["state"], "calling");

        deliver(
            &facade,
            placed_event(
                "ChannelStateChange",
                json!({"state": "answered", "code": 200}),
            ),
        );
        deliver(&facade, placed_event("StasisEnd", json!({"reason": "bye"})));

        let ringing = call.next_event().await.expect("ringing");
        assert_eq!(ringing.kind, SipEvent::ChannelStateChange);
        assert_eq!(ringing.payload["state"], "ringing");
        let answered = call.next_event().await.expect("answered");
        assert_eq!(answered.payload["state"], "answered");
        let ended = call.next_event().await.expect("ended");
        assert_eq!(ended.kind, SipEvent::StasisEnd);
        // The channel is gone once it ends, so the stream ends with it.
        assert!(call.next_event().await.is_none());
    }

    /// A refused originate leaves nothing behind: the id is free to place again.
    #[tokio::test]
    async fn a_refused_originate_releases_its_channel() {
        let facade = SipFacade::new();
        let refusing: Arc<dyn CommandTransport> = Arc::new(EarlyEvent {
            facade: Arc::clone(&facade),
            event: placed_event("ChannelStateChange", json!({"state": "ringing"})),
            reply: Err(ControlError::Closed),
        });
        let error = place_on(
            &facade,
            &refusing,
            "out-1",
            "sip:1001@pbx.example",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
        )
        .await
        .expect_err("refused");
        assert_eq!(error.code(), Some(ControlErrorCode::NotFound));

        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({"channel": "out-1"}),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        place_on(
            &facade,
            &transport,
            "out-1",
            "sip:1001@pbx.example",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
        )
        .await
        .expect("the id is free again");
    }

    /// An id still live on this client is refused before anything is sent:
    /// taking it over would hand the live call's events to the new one.
    #[tokio::test]
    async fn a_channel_already_live_here_is_a_conflict_and_nothing_is_sent() {
        let facade = SipFacade::new();
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({"channel": "out-1"}),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        let _live = place_on(
            &facade,
            &transport,
            "out-1",
            "sip:1001@pbx.example",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
        )
        .await
        .expect("first");

        let error = place_on(
            &facade,
            &transport,
            "out-1",
            "sip:1002@pbx.example",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
        )
        .await
        .expect_err("second");
        assert_eq!(error.code(), Some(ControlErrorCode::Conflict));
        assert_eq!(recorder.sent.lock().unwrap().len(), 1);
    }

    /// An AoR originate hands back its call too, bound to the group until a
    /// phone answers.
    #[tokio::test]
    async fn an_aor_originate_hands_back_its_call() {
        let facade = SipFacade::new();
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: group_result(),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        let group = place_aor_on(
            &facade,
            &transport,
            "wake-201",
            "sip:201@example.com",
            OriginateMedia::anchor(),
            OriginateOptions::default(),
            AorRing::default(),
        )
        .await
        .expect("originate aor");

        assert_eq!(group.call.channel_id(), "wake-201");
        assert_eq!(group.call.payload()["group_id"], "originate-group-1");
        deliver(
            &facade,
            EventFrame::new(
                "DialAnswered",
                "wake-201",
                "agent-app",
                "originate-group-1",
                "originate-group-1",
                json!({}),
            ),
        );
        let answered = group.call.next_event().await.expect("answered");
        assert_eq!(answered.kind, SipEvent::DialAnswered);
    }

    /// `aor` replaces `to`: the server refuses an originate naming both, and one
    /// sent as `to` would be DNS-resolved and reach none of the phones.
    #[tokio::test]
    async fn originate_aor_sends_aor_in_place_of_to_with_its_ring_options() {
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: group_result(),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        let group = place_aor_on(
            &SipFacade::new(),
            &transport,
            "wake-201",
            "sip:201@example.com",
            OriginateMedia::anchor(),
            OriginateOptions::default()
                .from("sip:reception@example.com")
                .timeout(25)
                .contact_host("tenant-a.example.com"),
            AorRing::default()
                .strategy(DialStrategy::Sequential)
                .total_timeout(50),
        )
        .await
        .expect("originate aor");

        let (module, verb, target, args) = recorder.sent.lock().unwrap()[0].clone();
        assert_eq!(module.as_deref(), Some("sip"));
        assert_eq!(verb, "originate");
        assert_eq!(target, serde_json::Value::Null);
        assert_eq!(
            args,
            json!({
                "channel": "wake-201",
                "aor": "sip:201@example.com",
                "media": true,
                "from": "sip:reception@example.com",
                "timeout": 25,
                "contact_host": "tenant-a.example.com",
                "strategy": "sequential",
                "total_timeout": 50,
            })
        );

        assert_eq!(group.channel, "wake-201");
        assert_eq!(group.group_id.as_deref(), Some("originate-group-1"));
        assert_eq!(group.aor.as_deref(), Some("sip:201@example.com"));
        assert_eq!(group.strategy.as_deref(), Some("sequential"));
        assert_eq!(group.total_timeout_secs, Some(50));
        assert_eq!(group.branches.len(), 1);
        assert_eq!(group.branches[0].leg_sip_call_id, "b1@host");
    }

    /// A Contact host rides on a single originate as on an AoR one, and stays
    /// off the wire when it was not asked for.
    #[tokio::test]
    async fn originate_sends_the_contact_host_it_was_given() {
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({}),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        for contact_host in [Some("2001:db8::5"), None] {
            let mut options = OriginateOptions::default();
            if let Some(host) = contact_host {
                options = options.contact_host(host);
            }
            originate_on(
                &transport,
                "cb-1",
                "sip:+15550100@trunk.example",
                OriginateMedia::sdp("v=0\r\n"),
                options,
            )
            .await
            .expect("originate");
        }
        let sent = recorder.sent.lock().unwrap().clone();
        assert_eq!(sent[0].3["contact_host"], json!("2001:db8::5"));
        assert!(sent[1].3.get("contact_host").is_none());
    }

    /// A Contact user rides on a single originate alone or beside a Contact
    /// host, and stays off the wire when it was not asked for.
    #[tokio::test]
    async fn originate_sends_the_contact_user_it_was_given() {
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({}),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        for options in [
            OriginateOptions::default().contact_user("trunk-7"),
            OriginateOptions::default()
                .contact_host("sbc.example.net")
                .contact_user("trunk-7"),
            OriginateOptions::default(),
        ] {
            originate_on(
                &transport,
                "cb-1",
                "sip:+15550100@trunk.example",
                OriginateMedia::sdp("v=0\r\n"),
                options,
            )
            .await
            .expect("originate");
        }
        let sent = recorder.sent.lock().unwrap().clone();
        assert_eq!(sent[0].3["contact_user"], json!("trunk-7"));
        assert!(sent[0].3.get("contact_host").is_none());
        assert_eq!(sent[1].3["contact_host"], json!("sbc.example.net"));
        assert_eq!(sent[1].3["contact_user"], json!("trunk-7"));
        assert!(sent[2].3.get("contact_user").is_none());
    }

    /// An AoR originate carries the Contact user on the wire like a single one.
    #[tokio::test]
    async fn originate_aor_sends_the_contact_user() {
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: group_result(),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        place_aor_on(
            &SipFacade::new(),
            &transport,
            "wake-202",
            "sip:202@example.com",
            OriginateMedia::anchor(),
            OriginateOptions::default().contact_user("trunk-7"),
            AorRing::default(),
        )
        .await
        .expect("originate aor");
        let sent = recorder.sent.lock().unwrap().clone();
        assert_eq!(sent[0].3["aor"], json!("sip:202@example.com"));
        assert_eq!(sent[0].3["contact_user"], json!("trunk-7"));
    }

    /// Ring options left unset take the server's defaults rather than a copy.
    #[tokio::test]
    async fn originate_aor_omits_ring_options_it_was_not_given() {
        let recorder = Arc::new(Recorder {
            sent: Mutex::new(Vec::new()),
            result: json!({}),
        });
        let transport: Arc<dyn CommandTransport> = recorder.clone();
        let group = place_aor_on(
            &SipFacade::new(),
            &transport,
            "wake-201",
            "sip:201@example.com",
            OriginateMedia::sdp("v=0\r\n"),
            OriginateOptions::default(),
            AorRing::default(),
        )
        .await
        .expect("originate aor");

        let args = recorder.sent.lock().unwrap()[0].3.clone();
        assert!(args.get("to").is_none());
        assert!(args.get("strategy").is_none());
        assert!(args.get("total_timeout").is_none());
        // The id asked for stands in when the reply does not echo one.
        assert_eq!(group.channel, "wake-201");
        assert!(group.branches.is_empty());
    }
}
