//! `originate`: placing an outbound call under a caller-supplied channel id.

use std::collections::HashMap;
use std::sync::Arc;

use crate::b2bua::actor::DialBranch;
use crate::b2bua::session_timer::{SessionTimerField, SessionTimerFields, SessionTimerOverride};
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ControlBus;
use crate::control::AdapterCommand;
use crate::dispatcher::{
    OriginateError, OriginateGroupFailure, OriginateGroupSink, OriginateGroupSpec,
    OriginateGroupStrategy, OriginateGroupWinner, OriginateLegProgress, OriginateParams,
    PreparedOriginate,
};

use super::routing::parse_extra_headers;
use super::string_arg;

/// Where `originate` places its calls: the running B2BUA in production, a
/// test's own dispatcher when it drives the verb end to end.
pub(super) trait OriginatePlacer {
    /// Stage a call to one URI (`args.to`).
    fn prepare(&self, params: OriginateParams) -> Result<PreparedOriginate, OriginateError>;
    /// Send a staged call's INVITE.
    fn dial(&self, prepared: &PreparedOriginate) -> bool;
    /// Create a group ringing the contacts of an AoR (`args.aor`).
    fn create_group(
        &self,
        spec: OriginateGroupSpec,
        sink: Arc<dyn OriginateGroupSink>,
    ) -> Result<String, OriginateError>;
    /// Place a group's first legs.
    fn start_group(&self, group_id: &str) -> Result<Vec<DialBranch>, OriginateError>;
}

/// The running B2BUA, through its process-wide handle.
struct RunningB2bua;

impl OriginatePlacer for RunningB2bua {
    fn prepare(&self, params: OriginateParams) -> Result<PreparedOriginate, OriginateError> {
        crate::dispatcher::b2bua_originate_prepare(params)
    }

    fn dial(&self, prepared: &PreparedOriginate) -> bool {
        crate::dispatcher::b2bua_originate_dial(prepared)
    }

    fn create_group(
        &self,
        spec: OriginateGroupSpec,
        sink: Arc<dyn OriginateGroupSink>,
    ) -> Result<String, OriginateError> {
        crate::dispatcher::b2bua_originate_group_create(spec, sink)
    }

    fn start_group(&self, group_id: &str) -> Result<Vec<DialBranch>, OriginateError> {
        crate::dispatcher::b2bua_originate_group_start(group_id)
    }
}

/// `originate` — place an outbound call the controller owns from the moment it
/// is accepted.
///
/// **The channel id comes from the caller, never from siphon.** A controller
/// stages its per-call context — routing, media plan, its own state — keyed on
/// an id it chose *before* anything reaches the network; minting the id here and
/// returning it would force a round-trip that a well-built controller has
/// designed out, and would leave a window where the call exists and the
/// controller cannot name it. A collision with a live channel is a `conflict`,
/// never a silent re-point (which would strand the first call).
///
/// **Asynchronous by construction.** The reply is the *local* action — "the
/// INVITE is on the wire" — and returns before the callee has done anything.
/// Ringing (`ChannelStateChange`), answer (`ChannelStateChange{state:answered}`)
/// and hangup (`StasisEnd`, with the SIP cause) arrive later as events on the
/// supplied id. A synchronous originate that blocked to answer-or-timeout would
/// serialise this connection's whole command stream behind one ringing phone and
/// make ringback or a prompt during ring impossible.
///
/// The channel is registered **before** the INVITE is dialed (the two-phase
/// [`crate::dispatcher::b2bua_originate_prepare`] / `..._dial` split), so a
/// callee that answers instantly cannot beat its own `StasisStart`.
///
/// **`to` or `aor`.** `to` is one URI, resolved as written. `aor` rings every
/// phone registered at that AoR, each over the flow it registered on and the
/// Path its binding carries, the only way to reach one on TCP, TLS or WSS
/// behind NAT. Its legs are an originate group: the first phone to answer
/// becomes the channel's call and every other leg is CANCELled.
pub(super) fn originate(command: AdapterCommand) -> ControlResult {
    #[cfg(test)]
    {
        if let Some(rail) = staged::rail_for(&command.origin.app) {
            return originate_on(&rail.bus, command, rail.as_ref());
        }
    }
    let Some(bus) = ControlBus::global() else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "control plane is not installed",
        );
    };
    originate_with_bus(&bus, command)
}

/// [`originate`] with the bus injected, so the id-collision and ownership rules
/// are testable without a process-global control plane.
pub(super) fn originate_with_bus(
    bus: &std::sync::Arc<ControlBus>,
    command: AdapterCommand,
) -> ControlResult {
    originate_on(bus, command, &RunningB2bua)
}

/// [`originate_with_bus`] with the B2BUA rail injected as well: the running
/// B2BUA's in production, a test's own dispatcher when it drives the verb end
/// to end.
pub(super) fn originate_on(
    bus: &std::sync::Arc<ControlBus>,
    command: AdapterCommand,
    placer: &dyn OriginatePlacer,
) -> ControlResult {
    let args = &command.args;
    let Some(channel_id) = args.get("channel").and_then(|value| value.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "originate requires args.channel — the caller-supplied channel id this call is addressed by",
        );
    };
    if channel_id.trim().is_empty() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "originate args.channel must not be empty",
        );
    }
    let target = match parse_originate_target(args) {
        Ok(target) => target,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };

    let media = match parse_originate_media(args) {
        Ok(media) => media,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let privacy = match parse_privacy("originate", args.get("privacy")) {
        Ok(privacy) => privacy,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let session_timer = match parse_session_timer(args.get("session_timer")) {
        Ok(session_timer) => session_timer,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let headers = parse_extra_headers(args.get("headers"));
    let timeout_secs = args
        .get("timeout")
        .and_then(|value| value.as_u64())
        .unwrap_or(30) as u32;
    let vars: HashMap<String, String> = args
        .get("vars")
        .and_then(|value| value.as_object())
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let on_lost = args
        .get("on_lost")
        .and_then(|value| value.as_str())
        .unwrap_or("hangup")
        .to_string();
    // Refuse a policy siphon does not implement before anything is placed on
    // the wire: the control-loss path ends the call for everything that is not
    // `continue`, so accepting `fallback` here promised a re-dispatch and
    // delivered a hangup, on every call this controller placed.
    if let Some(refusal) = crate::config::unimplemented_on_lost(&on_lost) {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            format!("originate args.on_lost {refusal}"),
        );
    }

    if bus.channel_exists(channel_id) {
        return ControlResult::error(
            ControlErrorCode::Conflict,
            format!("channel '{channel_id}' is already in use — pick a different id"),
        );
    }
    // Resolve the owner up front: a channel with no live owner would be
    // unaddressable and would leak, so a command racing its own socket close
    // must fail before anything is placed on the wire.
    let Some(conn) = bus.connection_for_command(&command.origin.app, command.origin.conn_id) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "the commanding connection is gone — nothing would own the originated call",
        );
    };

    let params = crate::dispatcher::OriginateParams {
        to: String::new(),
        to_display: string_arg(args, "to_display"),
        from: string_arg(args, "from"),
        from_display: string_arg(args, "from_display"),
        next_hop: string_arg(args, "next_hop"),
        p_asserted_identity: string_arg(args, "p_asserted_identity"),
        privacy,
        headers,
        timeout_secs,
        media,
        session_timer,
    };

    let (to, group) = match target {
        OriginateTarget::Uri(to) => (to, None),
        OriginateTarget::Aor {
            aor,
            strategy,
            total_timeout_secs,
        } => (aor, Some((strategy, total_timeout_secs))),
    };
    if let Some((strategy, total_timeout_secs)) = group {
        return originate_aor(
            bus,
            placer,
            AorOriginate {
                channel_id,
                conn: &conn,
                aor: &to,
                params,
                strategy,
                total_timeout_secs,
                on_lost: &on_lost,
                vars,
            },
        );
    }
    let params = OriginateParams { to, ..params };

    let prepared = match placer.prepare(params) {
        Ok(prepared) => prepared,
        Err(error) => return originate_error(error),
    };

    // Own it before it rings: register under the caller's id, then dial.
    bus.register_channel(
        channel_id,
        &conn,
        &prepared.internal_call_id,
        &prepared.sip_call_id,
        &on_lost,
        vars,
    );
    if !placer.dial(&prepared) {
        bus.remove_channel(channel_id);
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "the originated call vanished before its INVITE could be sent",
        );
    }

    ControlResult::Ok(serde_json::json!({
        "channel": channel_id,
        "call_id": prepared.internal_call_id,
        "sip_call_id": prepared.sip_call_id,
        "state": "calling",
    }))
}

/// Who an `originate` calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OriginateTarget {
    /// `args.to`: one URI, resolved as written.
    Uri(String),
    /// `args.aor`: every phone registered at it, as an originate group.
    Aor {
        aor: String,
        strategy: OriginateGroupStrategy,
        /// `args.total_timeout`, when given: the group's own deadline.
        total_timeout_secs: Option<u32>,
    },
}

/// Parse who to call: exactly one of `args.to` and `args.aor`. `strategy` and
/// `total_timeout` shape how an AoR's phones are rung and mean nothing for one
/// URI, so they are refused beside `to` rather than ignored.
pub(super) fn parse_originate_target(args: &serde_json::Value) -> Result<OriginateTarget, String> {
    let text = |name: &str| -> Result<Option<String>, String> {
        match args.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
                Ok(Some(value.clone()))
            }
            Some(_) => Err(format!("originate args.{name} must be a non-empty string")),
        }
    };
    let to = text("to")?;
    let aor = text("aor")?;
    let strategy = text("strategy")?;
    let total_timeout = match args.get("total_timeout") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|seconds| u32::try_from(seconds).ok())
                .ok_or_else(|| {
                    "originate args.total_timeout must be a whole number of seconds".to_string()
                })?,
        ),
    };
    match (to, aor) {
        (Some(_), Some(_)) => Err(
            "originate takes args.to (one URI) or args.aor (every phone registered at it), not both"
                .to_string(),
        ),
        (None, None) => Err(
            "originate requires args.to (one URI) or args.aor (every phone registered at it)"
                .to_string(),
        ),
        (Some(to), None) => {
            if strategy.is_some() || total_timeout.is_some() {
                return Err(
                    "originate args.strategy and args.total_timeout apply to args.aor, not to a single args.to"
                        .to_string(),
                );
            }
            Ok(OriginateTarget::Uri(to))
        }
        (None, Some(aor)) => {
            let strategy = match strategy {
                None => OriginateGroupStrategy::Parallel,
                Some(name) => OriginateGroupStrategy::parse(&name).ok_or_else(|| {
                    format!(
                        "originate args.strategy must be \"parallel\" or \"sequential\", got '{name}'"
                    )
                })?,
            };
            Ok(OriginateTarget::Aor {
                aor,
                strategy,
                total_timeout_secs: total_timeout,
            })
        }
    }
}

/// An `originate {aor}`, parsed and owned by a live connection.
struct AorOriginate<'a> {
    channel_id: &'a str,
    conn: &'a Arc<crate::control::ConnHandle>,
    aor: &'a str,
    params: OriginateParams,
    strategy: OriginateGroupStrategy,
    total_timeout_secs: Option<u32>,
    on_lost: &'a str,
    vars: HashMap<String, String>,
}

/// The deadline of a whole group when the controller names none: one ring
/// timeout for a parallel group, whose legs ring together, and one per contact
/// for a sequential one, whose legs ring in turn. No ring timeout, no deadline.
pub(super) fn default_total_timeout(
    strategy: OriginateGroupStrategy,
    timeout_secs: u32,
    contacts: usize,
) -> u32 {
    match strategy {
        OriginateGroupStrategy::Parallel => timeout_secs,
        OriginateGroupStrategy::Sequential => {
            timeout_secs.saturating_mul(u32::try_from(contacts).unwrap_or(u32::MAX))
        }
    }
}

/// Ring every phone registered at an AoR under the controller's channel.
///
/// The channel is bound to the group while the phones ring, so a `hangup` of
/// it CANCELs every leg, and to the call of the phone that answers from then
/// on. An AoR with nobody registered is refused with nothing on the wire.
fn originate_aor(
    bus: &Arc<ControlBus>,
    placer: &dyn OriginatePlacer,
    request: AorOriginate<'_>,
) -> ControlResult {
    let targets = match crate::dispatcher::dial_targets_for_aor(request.aor) {
        Ok(targets) => targets,
        Err(error) => {
            return ControlResult::error_with_details(
                ControlErrorCode::NotFound,
                error.to_string(),
                serde_json::json!({
                    "verb": "originate",
                    "reason": "no_contacts",
                    "aor": request.aor,
                }),
            )
        }
    };
    // Every leg's To is the AoR as it is registered, however the controller
    // spelled it; each leg's Request-URI is its own contact.
    let registered = targets
        .iter()
        .find_map(|target| target.aor.clone())
        .unwrap_or_else(|| request.aor.to_string());
    let total_timeout_secs = request.total_timeout_secs.unwrap_or_else(|| {
        default_total_timeout(request.strategy, request.params.timeout_secs, targets.len())
    });
    let spec = OriginateGroupSpec {
        params: OriginateParams {
            to: registered.clone(),
            ..request.params
        },
        targets,
        strategy: request.strategy,
        total_timeout_secs,
        // `originate {aor}`: the first phone to answer is the call.
        answers: crate::dispatcher::OriginateGroupAnswers::First,
    };
    let sink = Arc::new(ChannelGroupSink {
        bus: Arc::clone(bus),
        channel_id: request.channel_id.to_string(),
    });
    let group_id = match placer.create_group(spec, sink) {
        Ok(group_id) => group_id,
        Err(error) => return originate_error(error),
    };

    // Own it before anything rings: the channel is bound to the group, whose
    // id stands in for the call until a phone answers.
    bus.register_channel(
        request.channel_id,
        request.conn,
        &group_id,
        &group_id,
        request.on_lost,
        request.vars,
    );
    let branches = match placer.start_group(&group_id) {
        Ok(branches) => branches,
        Err(error) => {
            bus.remove_channel(request.channel_id);
            return originate_error(error);
        }
    };

    ControlResult::Ok(serde_json::json!({
        "channel": request.channel_id,
        "group_id": group_id,
        "aor": registered,
        "strategy": request.strategy.as_str(),
        "total_timeout": total_timeout_secs,
        "branches": branches
            .iter()
            .map(crate::dispatcher::dial_branch_identity)
            .collect::<Vec<_>>(),
        "state": "calling",
    }))
}

/// Reports an originate group on the controller's channel.
///
/// Until a phone answers the channel is bound to the group: each leg is named
/// by `DialBranch` when its INVITE goes, `ChannelStateChange` reports each
/// leg's ringing or early media as a plain originate reports its one callee's
/// (with the leg named), and `DialBranchFailed` each leg that ends unanswered.
/// The phone that answers gets `DialAnswered`, and the channel is bound to its
/// call before the `ChannelStateChange{state:answered}` that follows. When no
/// phone answers, the channel ends with the `StasisEnd` a plain originate's
/// failure carries.
struct ChannelGroupSink {
    bus: Arc<ControlBus>,
    channel_id: String,
}

impl OriginateGroupSink for ChannelGroupSink {
    fn branch_created(&self, _group_id: &str, branch: &DialBranch) {
        self.bus.publish_channel_event(
            &self.channel_id,
            "DialBranch",
            crate::dispatcher::dial_branch_identity(branch),
        );
    }

    fn branch_progress(
        &self,
        _group_id: &str,
        branch: &DialBranch,
        progress: &OriginateLegProgress,
    ) {
        let mut payload = crate::dispatcher::dial_branch_identity(branch);
        if let Some(fields) = payload.as_object_mut() {
            fields.insert(
                "state".into(),
                if progress.early_media {
                    "progress"
                } else {
                    "ringing"
                }
                .into(),
            );
            fields.insert("code".into(), progress.code.into());
            fields.insert("early_media".into(), progress.early_media.into());
            fields.insert(
                "sdp".into(),
                progress
                    .sdp
                    .clone()
                    .map_or(serde_json::Value::Null, serde_json::Value::String),
            );
        }
        self.bus
            .publish_channel_event(&self.channel_id, "ChannelStateChange", payload);
    }

    fn branch_ended(&self, _group_id: &str, branch: &DialBranch) {
        self.bus.publish_channel_event(
            &self.channel_id,
            "DialBranchFailed",
            crate::dispatcher::dial_branch_summary(branch),
        );
    }

    fn answered(&self, winner: &OriginateGroupWinner) {
        self.bus.rebind_channel(
            &self.channel_id,
            &winner.internal_call_id,
            &winner.sip_call_id,
        );
        self.bus.publish_channel_event(
            &self.channel_id,
            "DialAnswered",
            crate::dispatcher::dial_answered_payload(&winner.branch),
        );
    }

    fn failed(&self, failure: &OriginateGroupFailure) {
        self.bus.on_call_terminated_with_cause(
            &failure.group_id,
            &failure.reason,
            Some(failure.code),
            Some(&failure.response),
        );
    }
}

/// Parse the media plan: exactly one of a controller-supplied offer
/// (`args.sdp`, or `args.body` with its own `args.content_type`) or
/// `args.media: true` (siphon anchors the leg on the media backend).
///
/// `args.sdp` is the shorthand — the body, carried as `application/sdp`.
/// `args.body` is the same slot with the type spelled out, for an INVITE whose
/// offer travels as one part of a `multipart/*` body (RFC 5621 §3) beside a
/// part SIP does not interpret. Either spelling has to carry an SDP offer; the
/// dispatcher refuses a body that does not.
///
/// Neither is a `bad_request` rather than a default, because an INVITE with no
/// offer and no plan to answer the callee's leaves its 2xx un-answerable
/// (RFC 3261 §13.2.2.4) — a connected call with no audio, which is the exact
/// hollow success this rail refuses to produce.
pub(super) fn parse_originate_media(
    args: &serde_json::Value,
) -> Result<crate::dispatcher::OriginateMedia, String> {
    let sdp = args.get("sdp").and_then(|value| value.as_str());
    let body = args.get("body").and_then(|value| value.as_str());
    let content_type = args.get("content_type").and_then(|value| value.as_str());
    let anchor = args
        .get("media")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if sdp.is_some() && body.is_some() {
        return Err(
            "originate takes either args.sdp (an SDP offer) or args.body (a body with its own args.content_type), not both"
                .to_string(),
        );
    }
    match (sdp.or(body), anchor) {
        (Some(_), true) => Err(
            "originate takes either your own offer (args.sdp / args.body) or args.media=true (siphon anchors the leg), not both"
                .to_string(),
        ),
        (Some(offer), false) if offer.trim().is_empty() => Err(format!(
            "originate {} must not be empty",
            if sdp.is_some() { "args.sdp" } else { "args.body" }
        )),
        (Some(_), false) if sdp.is_some() && content_type.is_some() => Err(
            "originate args.content_type goes with args.body — args.sdp is application/sdp by definition"
                .to_string(),
        ),
        (Some(offer), false) => Ok(crate::dispatcher::OriginateMedia::Offer {
            body: offer.as_bytes().to_vec(),
            content_type: content_type.unwrap_or("application/sdp").to_string(),
        }),
        (None, true) if content_type.is_some() => Err(
            "originate args.content_type needs args.body — args.media=true sends an offerless INVITE"
                .to_string(),
        ),
        (None, true) => Ok(crate::dispatcher::OriginateMedia::Anchor {
            profile: args
                .get("profile")
                .and_then(|value| value.as_str())
                .unwrap_or("rtp_passthrough")
                .to_string(),
            ws_uri: args
                .get("ws_uri")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
        }),
        (None, false) => Err(
            "originate requires a media plan: args.sdp / args.body (your own offer) or args.media=true (siphon anchors the leg)"
                .to_string(),
        ),
    }
}

/// Parse the optional `privacy` argument (RFC 3323 §4.1 / TS 24.607). An
/// unrecognised value is a typed error, never a silent "present the CLI" —
/// guessing at a privacy setting is how identities leak.
pub(super) fn parse_privacy(
    verb: &str,
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::sip::privacy::CallerIdPresentation>, String> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) => crate::sip::privacy::CallerIdPresentation::parse(text)
                .map(Some)
                .ok_or_else(|| {
                    format!(
                        "{verb} args.privacy must be \"allowed\" or \"restricted\", got '{text}'"
                    )
                }),
            None => Err(format!("{verb} args.privacy must be a string")),
        },
    }
}

/// Parse the optional `session_timer` argument: the RFC 4028 session timer to run
/// on the call over the `session_timer:` block, `{expires, min_se, refresher}`,
/// each key left out defaulting as in `call.session_timer()`.
///
/// Validated by the rules `call.session_timer()` and
/// `b2bua.originate(session_timer=...)` use ([`SessionTimerFields`]): a key no
/// timer has, a refresher that is not `uac`, `uas` or `b2bua`, or an interval
/// that is not a whole number of seconds is refused. Absent or `null` runs the
/// configured timer, if any.
pub(super) fn parse_session_timer(
    value: Option<&serde_json::Value>,
) -> Result<Option<SessionTimerOverride>, String> {
    let object = match value {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Object(object)) => object,
        Some(_) => {
            return Err(
                "originate args.session_timer must be an object: {expires, min_se, refresher}"
                    .to_string(),
            )
        }
    };
    let seconds = |key: &str, value: &serde_json::Value| {
        value
            .as_u64()
            .and_then(|seconds| u32::try_from(seconds).ok())
            .ok_or_else(|| {
                format!("originate args.session_timer.{key} must be a whole number of seconds")
            })
    };
    let mut fields = SessionTimerFields::default();
    for (key, value) in object {
        match SessionTimerField::named(key)
            .map_err(|message| format!("originate args.{message}"))?
        {
            SessionTimerField::Expires => fields.expires = Some(seconds(key, value)?),
            SessionTimerField::MinSe => fields.min_se = Some(seconds(key, value)?),
            SessionTimerField::Refresher => {
                let Some(refresher) = value.as_str() else {
                    return Err(
                        "originate args.session_timer.refresher must be a string".to_string()
                    );
                };
                fields.refresher = Some(refresher.to_string());
            }
        }
    }
    fields
        .build()
        .map(Some)
        .map_err(|message| format!("originate args.session_timer.{message}"))
}

/// Map an [`crate::dispatcher::OriginateError`] onto its own wire code, so a
/// caller can tell a bad URI from no route from a backend that cannot do it.
pub(super) fn originate_error(error: crate::dispatcher::OriginateError) -> ControlResult {
    use crate::dispatcher::OriginateError;
    let message = error.to_string();
    match error {
        // A malformed argument either way: the URI does not parse, or the body
        // is not one an INVITE can carry an offer in.
        OriginateError::InvalidUri { .. } | OriginateError::InvalidBody(_) => {
            ControlResult::error(ControlErrorCode::BadRequest, message)
        }
        // No reachable destination for the target: the request was well formed
        // and the resource simply is not there to be called.
        OriginateError::Unroutable(_) => ControlResult::error(ControlErrorCode::NotFound, message),
        OriginateError::Unsupported(_) => {
            ControlResult::error(ControlErrorCode::UnsupportedVerb, message)
        }
        OriginateError::Unavailable(_) | OriginateError::BuildFailed(_) => {
            ControlResult::error(ControlErrorCode::Unavailable, message)
        }
    }
}

/// The B2BUA rail a test hands `originate`, keyed by the app a command comes
/// from.
///
/// `originate` reaches the running B2BUA through its process-wide handle, which is
/// set once per process, and tests elsewhere rely on it being absent. A test that
/// drives the verb end to end, from the controller's frame through the command
/// consumer and the adapter's dispatch table, stages a dispatcher of its own here
/// under an app name of its own, and every other command takes the production
/// path.
#[cfg(test)]
pub(crate) mod staged {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    use crate::b2bua::actor::DialBranch;
    use crate::control::registry::ControlBus;
    use crate::dispatcher::{
        OriginateError, OriginateGroupSink, OriginateGroupSpec, OriginateParams, PreparedOriginate,
    };

    /// Stages an originate on the test's dispatcher.
    pub(crate) type Prepare =
        Box<dyn Fn(OriginateParams) -> Result<PreparedOriginate, OriginateError> + Send + Sync>;
    /// Sends a staged originate's INVITE.
    pub(crate) type Dial = Box<dyn Fn(&PreparedOriginate) -> bool + Send + Sync>;
    /// Creates an originate group on the test's dispatcher.
    pub(crate) type CreateGroup = Box<
        dyn Fn(OriginateGroupSpec, Arc<dyn OriginateGroupSink>) -> Result<String, OriginateError>
            + Send
            + Sync,
    >;
    /// Places an originate group's first legs.
    pub(crate) type StartGroup =
        Box<dyn Fn(&str) -> Result<Vec<DialBranch>, OriginateError> + Send + Sync>;

    /// Where an app's originates are placed, and the bus that owns their channels.
    pub(crate) struct OriginateRail {
        pub(crate) bus: Arc<ControlBus>,
        /// The dispatcher itself, for a `dial` that rings phones for an
        /// answered caller: it runs a task that outlives the command.
        pub(crate) dispatcher: Arc<dyn crate::dispatcher::DispatcherHandle>,
        pub(crate) prepare: Prepare,
        pub(crate) dial: Dial,
        pub(crate) create_group: CreateGroup,
        pub(crate) start_group: StartGroup,
    }

    impl super::OriginatePlacer for OriginateRail {
        fn prepare(&self, params: OriginateParams) -> Result<PreparedOriginate, OriginateError> {
            (self.prepare)(params)
        }

        fn dial(&self, prepared: &PreparedOriginate) -> bool {
            (self.dial)(prepared)
        }

        fn create_group(
            &self,
            spec: OriginateGroupSpec,
            sink: Arc<dyn OriginateGroupSink>,
        ) -> Result<String, OriginateError> {
            (self.create_group)(spec, sink)
        }

        fn start_group(&self, group_id: &str) -> Result<Vec<DialBranch>, OriginateError> {
            (self.start_group)(group_id)
        }
    }

    type Rails = Mutex<HashMap<String, Arc<OriginateRail>>>;

    fn rails() -> &'static Rails {
        static RAILS: OnceLock<Rails> = OnceLock::new();
        RAILS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Place every originate `app` sends on `rail`.
    pub(crate) fn stage(app: &str, rail: OriginateRail) {
        if let Ok(mut rails) = rails().lock() {
            rails.insert(app.to_string(), Arc::new(rail));
        }
    }

    /// The rail `app` was staged on, if any.
    pub(crate) fn rail_for(app: &str) -> Option<Arc<OriginateRail>> {
        rails()
            .lock()
            .ok()
            .and_then(|rails| rails.get(app).cloned())
    }
}
