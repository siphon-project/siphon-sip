//! `originate`: placing an outbound call under a caller-supplied channel id.

use std::collections::HashMap;

use crate::b2bua::session_timer::{SessionTimerField, SessionTimerFields, SessionTimerOverride};
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ControlBus;
use crate::control::AdapterCommand;
use crate::dispatcher::{OriginateError, OriginateParams, PreparedOriginate};

use super::routing::parse_extra_headers;
use super::string_arg;

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
pub(super) fn originate(command: AdapterCommand) -> ControlResult {
    #[cfg(test)]
    {
        if let Some(rail) = staged::rail_for(&command.origin.app) {
            return originate_on(
                &rail.bus,
                command,
                |params| (rail.prepare)(params),
                |prepared| (rail.dial)(prepared),
            );
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
    originate_on(
        bus,
        command,
        crate::dispatcher::b2bua_originate_prepare,
        crate::dispatcher::b2bua_originate_dial,
    )
}

/// [`originate_with_bus`] with the B2BUA rail injected as well: `prepare` stages
/// the call and `dial` sends its INVITE. The running B2BUA's in production, a
/// test's own dispatcher when it drives the verb end to end.
pub(super) fn originate_on(
    bus: &std::sync::Arc<ControlBus>,
    command: AdapterCommand,
    prepare: impl FnOnce(OriginateParams) -> Result<PreparedOriginate, OriginateError>,
    dial: impl FnOnce(&PreparedOriginate) -> bool,
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
    let Some(to) = args.get("to").and_then(|value| value.as_str()) else {
        return ControlResult::error(ControlErrorCode::BadRequest, "originate requires args.to");
    };

    let media = match parse_originate_media(args) {
        Ok(media) => media,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let privacy = match parse_privacy(args.get("privacy")) {
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
        to: to.to_string(),
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

    let prepared = match prepare(params) {
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
    if !dial(&prepared) {
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
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::sip::privacy::CallerIdPresentation>, String> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) => crate::sip::privacy::CallerIdPresentation::parse(text)
                .map(Some)
                .ok_or_else(|| {
                    format!("originate args.privacy must be \"allowed\" or \"restricted\", got '{text}'")
                }),
            None => Err("originate args.privacy must be a string".to_string()),
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

    use crate::control::registry::ControlBus;
    use crate::dispatcher::{OriginateError, OriginateParams, PreparedOriginate};

    /// Stages an originate on the test's dispatcher.
    pub(crate) type Prepare =
        Box<dyn Fn(OriginateParams) -> Result<PreparedOriginate, OriginateError> + Send + Sync>;
    /// Sends a staged originate's INVITE.
    pub(crate) type Dial = Box<dyn Fn(&PreparedOriginate) -> bool + Send + Sync>;

    /// Where an app's originates are placed, and the bus that owns their channels.
    pub(crate) struct OriginateRail {
        pub(crate) bus: Arc<ControlBus>,
        pub(crate) prepare: Prepare,
        pub(crate) dial: Dial,
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
