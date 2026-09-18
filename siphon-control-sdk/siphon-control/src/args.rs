//! Python arguments turned into the client's typed values: route targets, play
//! sources, header and variable dicts, the bridge hangup policy, and an
//! originate's media plan and session timer. Each refuses what the server would
//! refuse, before a frame goes out.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;

use siphon_control_client::proto::sip::PeerHangupPolicy;
use siphon_control_client::sip::{
    DialStrategy, DialTarget, OriginateMedia, PlaySource, RecordChannels, RecordDirection,
    RouteTarget, SessionRefresher, SessionTimer,
};

/// Extract one `route` target: a bare URI `str`, or a dict
/// `{uri, next_hop?, headers?, timeout?, reroute_after_progress?}`.
pub(crate) fn extract_route_target(item: &Bound<'_, PyAny>) -> PyResult<RouteTarget> {
    if let Ok(uri) = item.extract::<String>() {
        return Ok(RouteTarget::uri(uri));
    }
    let dict = item.cast::<pyo3::types::PyDict>().map_err(|_| {
        PyValueError::new_err(
            "each route target must be a URI str or a dict {uri, next_hop, headers, timeout}",
        )
    })?;
    let uri: String = match dict.get_item("uri")? {
        Some(value) => value.extract()?,
        None => {
            return Err(PyValueError::new_err(
                "route target dict requires a string 'uri'",
            ))
        }
    };
    let next_hop = match dict.get_item("next_hop")? {
        Some(value) if !value.is_none() => Some(value.extract::<String>()?),
        _ => None,
    };
    let headers = match dict.get_item("headers")? {
        Some(value) if !value.is_none() => extract_headers(&value)?,
        _ => Vec::new(),
    };
    let timeout_secs = match dict.get_item("timeout")? {
        Some(value) if !value.is_none() => Some(value.extract::<u32>()?),
        _ => None,
    };
    // A policy flag: anything but a real bool is refused, as the server refuses
    // it, rather than read as false and quietly left on the default rule.
    let reroute_after_progress = match dict.get_item("reroute_after_progress")? {
        Some(value) if !value.is_none() => value.extract::<bool>().map_err(|_| {
            PyTypeError::new_err("route target 'reroute_after_progress' must be a bool")
        })?,
        _ => false,
    };
    Ok(RouteTarget {
        uri,
        next_hop,
        headers,
        timeout_secs,
        reroute_after_progress,
    })
}

/// Extract the `targets` of a `dial` into typed targets, refusing every shape
/// that would place a different call than the one that was written down.
pub(crate) fn extract_dial_targets(items: &[Bound<'_, PyAny>]) -> PyResult<Vec<DialTarget>> {
    let mut targets = Vec::with_capacity(items.len());
    for item in items {
        targets.push(extract_dial_target(item)?);
    }
    Ok(targets)
}

/// Extract one `dial` target: a dict `{uri, next_hop?, headers?}` dialed as
/// written, or `{aor, headers?}` forked to every registered contact.
///
/// A bare string is refused although the server accepts one as a URI. The two
/// forms do entirely different things — an AoR forks to every contact over that
/// contact's own captured flow, the only way to reach a phone registered over
/// TCP, TLS or WSS behind NAT — and `"sip:204@pbx.example"` is a plausible
/// spelling of both, so the wrong one places a call that connects to nothing
/// while the trace looks healthy.
fn extract_dial_target(item: &Bound<'_, PyAny>) -> PyResult<DialTarget> {
    let Ok(dict) = item.cast::<pyo3::types::PyDict>() else {
        return Err(PyValueError::new_err(
            "each dial target must be a dict: {\"uri\": ...} to dial it as written, \
             or {\"aor\": ...} to fork to every registered contact over its own flow",
        ));
    };
    let uri = optional_string(dict, "uri")?;
    let aor = optional_string(dict, "aor")?;
    let next_hop = optional_string(dict, "next_hop")?;
    let headers = match dict.get_item("headers")? {
        Some(value) if !value.is_none() => extract_headers(&value)?,
        _ => Vec::new(),
    };

    let mut target = match (uri, aor) {
        (Some(_), Some(_)) => {
            return Err(PyValueError::new_err(
                "a dial target names \"uri\" or \"aor\", never both — siphon reads the \
                 aor and ignores the uri beside it",
            ))
        }
        (None, None) => {
            return Err(PyValueError::new_err(
                "a dial target requires a string \"uri\" or \"aor\"",
            ))
        }
        (Some(uri), None) => match next_hop {
            Some(next_hop) => DialTarget::uri_via(uri, next_hop),
            None => DialTarget::uri(uri),
        },
        (None, Some(aor)) => {
            if next_hop.is_some() {
                // Each branch of an AoR routes over its own binding's captured
                // flow, so the server has nothing to apply a next hop to and
                // drops it.
                return Err(PyValueError::new_err(
                    "an aor target takes no \"next_hop\": each of its branches routes \
                     over its own contact's captured flow",
                ));
            }
            DialTarget::aor(aor)
        }
    };
    for (name, value) in headers {
        target = target.header(name, value);
    }
    Ok(target)
}

/// Read an optional non-`None` string entry out of a dict.
fn optional_string(dict: &Bound<'_, pyo3::types::PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract()?)),
        _ => Ok(None),
    }
}

/// Parse `dial(strategy=...)`. Refused here rather than at the server, so a typo
/// raises before the caller's INVITEs go anywhere.
pub(crate) fn extract_dial_strategy(strategy: Option<String>) -> PyResult<Option<DialStrategy>> {
    match strategy {
        None => Ok(None),
        Some(name) => DialStrategy::from_name(&name).map(Some).ok_or_else(|| {
            PyValueError::new_err(format!(
                "dial strategy must be \"parallel\" or \"sequential\", not {name:?}"
            ))
        }),
    }
}

/// Parse `record_start(direction=...)`.
pub(crate) fn extract_record_direction(
    direction: Option<String>,
) -> PyResult<Option<RecordDirection>> {
    match direction {
        None => Ok(None),
        Some(name) => RecordDirection::from_name(&name).map(Some).ok_or_else(|| {
            PyValueError::new_err(format!(
                "record direction must be \"ingress\", \"egress\" or \"both\", not {name:?}"
            ))
        }),
    }
}

/// Parse `record_start(channels=...)`.
pub(crate) fn extract_record_channels(
    channels: Option<String>,
) -> PyResult<Option<RecordChannels>> {
    match channels {
        None => Ok(None),
        Some(name) => RecordChannels::from_name(&name).map(Some).ok_or_else(|| {
            PyValueError::new_err(format!(
                "record channels must be \"mono\" or \"stereo\", not {name:?}"
            ))
        }),
    }
}

/// Build a [`PlaySource`] from the mutually-exclusive `file` / `db_id` / `blob`
/// kwargs (exactly one must be set — mirrors the in-process `play_media`).
pub(crate) fn build_play_source(
    file: Option<String>,
    db_id: Option<u64>,
    blob: Option<Vec<u8>>,
) -> PyResult<PlaySource> {
    match (file, db_id, blob) {
        (Some(file), None, None) => Ok(PlaySource::file(file)),
        (None, Some(db_id), None) => Ok(PlaySource::db_id(db_id)),
        (None, None, Some(blob)) => Ok(PlaySource::blob(blob)),
        _ => Err(PyValueError::new_err(
            "play requires exactly one of file (str), db_id (int), or blob (bytes)",
        )),
    }
}

/// Parse the `on_peer_hangup` argument of `bridge`. Refused here rather than at
/// the server, so a typo raises before anything touches the two live calls.
pub(crate) fn parse_peer_hangup(policy: Option<String>) -> PyResult<Option<PeerHangupPolicy>> {
    match policy {
        None => Ok(None),
        Some(token) => PeerHangupPolicy::parse(&token).map(Some).ok_or_else(|| {
            PyValueError::new_err(format!(
                "on_peer_hangup must be \"hangup\" or \"hold\", got {token:?}"
            ))
        }),
    }
}

/// Extract a `{name: value}` header dict into ordered string pairs.
pub(crate) fn extract_headers(object: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    extract_string_pairs(object, "headers")
}

/// Extract a `{str: str}` dict named `what` into ordered string pairs.
pub(crate) fn extract_string_pairs(
    object: &Bound<'_, PyAny>,
    what: &str,
) -> PyResult<Vec<(String, String)>> {
    let dict = object
        .cast::<pyo3::types::PyDict>()
        .map_err(|_| PyValueError::new_err(format!("{what} must be a dict of str -> str")))?;
    let mut pairs = Vec::with_capacity(dict.len());
    for (key, value) in dict.iter() {
        pairs.push((key.extract::<String>()?, value.extract::<String>()?));
    }
    Ok(pairs)
}

/// The media plan of `client.originate(...)`: exactly one of `media=True`
/// (siphon anchors the leg, shaped by `profile` / `ws_uri`), `sdp` (your own
/// offer) or `body` with its `content_type`. Anything else raises `ValueError`
/// before a frame goes out, as the server would refuse it.
pub(crate) fn originate_media(
    media: bool,
    profile: Option<String>,
    ws_uri: Option<String>,
    sdp: Option<String>,
    body: Option<String>,
    content_type: Option<String>,
) -> PyResult<OriginateMedia> {
    let plan = match (media, sdp, body) {
        (true, None, None) if content_type.is_none() => {
            return Ok(OriginateMedia::Anchor { profile, ws_uri })
        }
        (false, Some(sdp), None) if content_type.is_none() => OriginateMedia::Sdp(sdp),
        (false, None, Some(body)) => OriginateMedia::Body {
            body,
            content_type: content_type.unwrap_or_else(|| "application/sdp".to_string()),
        },
        (false, None, None) => {
            return Err(PyValueError::new_err(
                "originate needs a media plan: media=True (siphon anchors the leg), sdp=... or body=...",
            ))
        }
        _ => {
            return Err(PyValueError::new_err(
                "originate takes exactly one media plan: media=True, sdp=... or body=... (content_type goes with body)",
            ))
        }
    };
    if profile.is_some() || ws_uri.is_some() {
        return Err(PyValueError::new_err(
            "originate profile and ws_uri go with media=True, where siphon anchors the leg",
        ));
    }
    Ok(plan)
}

/// `session_timer={"expires", "min_se", "refresher"}`, the dict the script API's
/// `b2bua.originate` takes, each key left out taking the server's default.
/// `ValueError` for another key or a refresher that is not `uac`, `uas` or
/// `b2bua`, `TypeError` for an interval that is not an int.
pub(crate) fn extract_session_timer(object: &Bound<'_, PyAny>) -> PyResult<SessionTimer> {
    let dict = object.cast::<pyo3::types::PyDict>().map_err(|_| {
        PyTypeError::new_err(
            "session_timer must be a dict: {\"expires\", \"min_se\", \"refresher\"}",
        )
    })?;
    let mut timer = SessionTimer::default();
    for (key, value) in dict.iter() {
        let key: String = key.extract()?;
        match key.as_str() {
            "expires" => timer.expires = Some(value.extract()?),
            "min_se" => timer.min_se = Some(value.extract()?),
            "refresher" => {
                let name: String = value.extract()?;
                let Some(refresher) = SessionRefresher::from_name(&name) else {
                    return Err(PyValueError::new_err(format!(
                        "session_timer refresher must be \"uac\", \"uas\" or \"b2bua\", not {name:?}"
                    )));
                };
                timer.refresher = Some(refresher);
            }
            other => {
                return Err(PyValueError::new_err(format!(
                    "session_timer takes expires, min_se and refresher, not {other:?}"
                )))
            }
        }
    }
    Ok(timer)
}
