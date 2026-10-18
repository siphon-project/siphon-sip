//! An INFO (RFC 6086) siphon sends in a call's dialog because a script asked:
//! `b2bua.send_info()`.
//!
//! An application package that carries requests in INFO (a media server
//! reporting an event to its controller, say) needs its own side of the
//! dialog to send them on. A request built outside the dialog would carry a
//! CSeq siphon does not know of, and siphon's next request on the dialog (its
//! BYE, a session refresh) could then be refused as out of order (RFC 3261
//! §12.2.2). This one takes its CSeq from the leg, goes to the remote target
//! through the route set (§12.2.1.1), is retransmitted on an unreliable
//! transport (§17.1.2.2), and its final response is handed back.

use crate::dispatcher::*;

/// Headers a script may not set on an INFO it sends: the ones that make it a
/// request in that dialog, which siphon writes.
const DIALOG_HEADERS: &[&str] = &[
    "call-id",
    "cseq",
    "from",
    "to",
    "via",
    "route",
    "max-forwards",
    "contact",
    "content-type",
    "content-length",
    "i",
    "f",
    "t",
    "v",
    "m",
    "c",
    "l",
];

/// Why an INFO was not sent.
#[derive(Debug, PartialEq, Eq)]
pub enum SendInfoRefusal {
    /// No call with that Call-ID, or the dispatcher is not running.
    NotFound,
    /// A header the dialog owns, or a value with a line break.
    BadHeader(String),
    /// The leg has no dialog to send in.
    NoDialog,
}

impl std::fmt::Display for SendInfoRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(formatter, "not_found: no such call"),
            Self::BadHeader(name) => write!(formatter, "bad_request: header {name} may not be set"),
            Self::NoDialog => write!(
                formatter,
                "invalid_state: the call has no dialog to send in"
            ),
        }
    }
}

/// The final response to a sent INFO: its status, reason phrase, and body
/// with its Content-Type (an application package answers a request in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoResponse {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

/// An INFO on its way: its Via branch, and where its final response arrives.
pub struct SentInfo {
    pub branch: String,
    pub response: tokio::sync::oneshot::Receiver<InfoResponse>,
}

fn pending_infos() -> &'static dashmap::DashMap<String, tokio::sync::oneshot::Sender<InfoResponse>>
{
    static PENDING: std::sync::OnceLock<
        dashmap::DashMap<String, tokio::sync::oneshot::Sender<InfoResponse>>,
    > = std::sync::OnceLock::new();
    PENDING.get_or_init(dashmap::DashMap::new)
}

/// Check the script's extra headers.
pub fn check_info_headers(headers: &[(String, String)]) -> Result<(), SendInfoRefusal> {
    for (name, value) in headers {
        let lowered = name.trim().to_ascii_lowercase();
        let bad_name = lowered.is_empty()
            || DIALOG_HEADERS.contains(&lowered.as_str())
            || !lowered
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&byte));
        let bad_value = value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0));
        if bad_name || bad_value {
            return Err(SendInfoRefusal::BadHeader(name.clone()));
        }
    }
    Ok(())
}

/// Send an INFO in a dialog of the call `sip_call_id`: the caller's
/// (`on_a_leg`; on a call siphon answered itself, its only dialog) or the
/// answered callee's. Returns the INFO's branch and the receiver of its final
/// response; a caller that stops waiting hands the branch to
/// [`forget_sent_info`].
pub fn b2bua_send_info(
    sip_call_id: &str,
    on_a_leg: bool,
    content_type: Option<&str>,
    body: Vec<u8>,
    headers: &[(String, String)],
) -> Result<SentInfo, SendInfoRefusal> {
    check_info_headers(headers)?;
    let control = B2BUA_CONTROL.get().ok_or(SendInfoRefusal::NotFound)?;
    let state = &control.state;
    let internal_call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(SendInfoRefusal::NotFound)?;
    let _enter = control.runtime.enter();
    send_info_on_leg(
        state,
        &internal_call_id,
        on_a_leg,
        content_type,
        body,
        headers,
    )
}

/// [`b2bua_send_info`] on a known call, for the dispatcher's own callers and
/// tests.
pub fn send_info_on_leg(
    state: &DispatcherState,
    internal_call_id: &str,
    on_a_leg: bool,
    content_type: Option<&str>,
    body: Vec<u8>,
    headers: &[(String, String)],
) -> Result<SentInfo, SendInfoRefusal> {
    let cseq = state
        .call_actors
        .reserve_leg_cseq(internal_call_id, on_a_leg)
        // A call without an answered callee has no callee dialog yet.
        .ok_or(if on_a_leg {
            SendInfoRefusal::NotFound
        } else {
            SendInfoRefusal::NoDialog
        })?;
    let leg = state
        .call_actors
        .clone_leg(internal_call_id, on_a_leg)
        .ok_or(SendInfoRefusal::NotFound)?;
    let extra: Vec<(&str, String)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.clone()))
        .collect();
    let body = match content_type {
        Some(content_type) => Some((content_type, body)),
        None if body.is_empty() => None,
        // A body says what it is (RFC 3261 §20.15).
        None => Some(("application/octet-stream", body)),
    };
    let info = build_b2bua_in_dialog_request(&leg, state, Method::Info, cseq, &extra, body)
        .ok_or(SendInfoRefusal::NoDialog)?;
    let branch = info
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
        .ok_or(SendInfoRefusal::NoDialog)?;
    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    // Recorded before the send, so a fast response finds it.
    let (sender, receiver) = tokio::sync::oneshot::channel();
    pending_infos().insert(branch.clone(), sender);
    let data = bytes::Bytes::from(info.to_bytes());
    arm_b2bua_retransmit(
        &info,
        &data,
        transport,
        destination,
        leg.transport.local_addr,
        state,
    );
    send_message_from(
        info,
        transport,
        destination,
        leg.transport.connection_id,
        leg.transport.local_addr,
        state,
    );
    debug!(call_id = %internal_call_id, %branch, cseq, "B2BUA: sent a script INFO");
    Ok(SentInfo {
        branch,
        response: receiver,
    })
}

/// Stop waiting for the response to the INFO sent on `branch` (the script gave
/// up on it).
pub fn forget_sent_info(branch: &str) {
    pending_infos().remove(branch);
}

/// Take a response to an INFO siphon sent for a script: a final one is handed
/// to the waiting script, a provisional is absorbed. False when the response
/// answers no such INFO.
pub fn take_sent_info_response(message: &SipMessage, status_code: u16) -> bool {
    let pending = pending_infos();
    if pending.is_empty() {
        return false;
    }
    let Some(branch) = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
    else {
        return false;
    };
    let is_info = message
        .headers
        .get("CSeq")
        .and_then(|raw| crate::sip::headers::cseq::CSeq::parse(raw).ok())
        .is_some_and(|cseq| cseq.method == Method::Info);
    if !is_info || !pending.contains_key(&branch) {
        return false;
    }
    if status_code < 200 {
        return true;
    }
    if let Some((_, sender)) = pending.remove(&branch) {
        let response = InfoResponse {
            status: status_code,
            reason: response_reason_phrase(message).to_string(),
            body: message.body.clone(),
            content_type: message
                .headers
                .get("Content-Type")
                .map(|value| value.to_string()),
        };
        // The script may have stopped waiting; the response is still taken.
        let _ = sender.send(response);
    }
    true
}
