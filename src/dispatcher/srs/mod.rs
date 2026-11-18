//! The SRS role (RFC 7866): recording sessions siphon terminates, offered to
//! it by a remote SRC.
//!
//! A recording session is a SIP dialog the SRC opens with an INVITE carrying
//! `Require: siprec`, a Contact with `+sip.src`, and a multipart body holding
//! the SDP offer and the recording metadata (RFC 7866 §6.1, §6.2). siphon is
//! the dialog's UAS: it answers each offered stream receive-only on a media
//! engine call of its own, records it, and follows the dialog through re-INVITE,
//! UPDATE, CANCEL and BYE.
//!
//! The SRS takes no server transaction from the transaction layer (it never
//! reaches `open_server_transaction`), so it does the UAS work itself, the way
//! the B2BUA does for its A-leg: 100 Trying at once, the 2xx retransmitted until
//! its ACK (RFC 3261 §13.3.1.4), a non-2xx kept for retransmitted INVITEs, and a
//! CANCEL answered against the INVITE it names (§9.2).

use super::*;

mod control;
mod events;
mod in_dialog;
mod invite;
mod media;
mod script;

#[cfg(test)]
pub(crate) use control::srs_control_verb_in;
#[cfg(test)]
pub(crate) use control::srs_media_target_in;
pub(crate) use control::{
    srs_control_verb, srs_media_target, srs_terminate_session, SrsMediaTarget, SRS_ACTOR_PREFIX,
};
pub(in crate::dispatcher) use events::srs_recording_finished;
pub(super) use in_dialog::{handle_srs_cancel, srs_unacked_answer_terminate};

/// Methods the SRS answers in a recording dialog (RFC 3261 §20.5).
const ALLOW: &str = "INVITE, ACK, BYE, CANCEL, UPDATE, OPTIONS";

/// Whether an INVITE's body is a SIPREC body: `multipart/mixed` carrying an
/// `application/rs-metadata+xml` part.
///
/// This is what routes an INVITE to the SRS. Whether it is a recording session
/// at all is [`carries_recording_session_markers`]: a body alone never is.
pub(super) fn is_siprec_invite(message: &SipMessage) -> bool {
    let content_type = match message.headers.get("Content-Type") {
        Some(content_type) => content_type,
        None => return false,
    };

    if !content_type
        .to_ascii_lowercase()
        .contains("multipart/mixed")
    {
        return false;
    }

    // Quick check: does the body contain the metadata content type?
    if message.body.is_empty() {
        return false;
    }
    let body_str = String::from_utf8_lossy(&message.body);
    body_str.contains("application/rs-metadata+xml")
}

/// RFC 7866 §6.2: the SRS "MUST only consider the SIP session as an RS when
/// both the "+sip.src" feature tag and "siprec" option tag are included in the
/// INVITE request": `siprec` in `Require`, `+sip.src` on the Contact.
fn carries_recording_session_markers(message: &SipMessage) -> bool {
    let requires_siprec = message
        .headers
        .get_all("Require")
        .into_iter()
        .flatten()
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("siprec"));
    let contact_is_src = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .is_some_and(|contact| contact_has_feature_tag(contact, "+sip.src"));
    requires_siprec && contact_is_src
}

/// Whether a Contact value carries the feature tag `tag` (RFC 3840 §9) among
/// its header parameters.
fn contact_has_feature_tag(contact: &str, tag: &str) -> bool {
    // In a name-addr the header parameters follow the `>`; in a bare
    // addr-spec everything after the first `;` is one (RFC 3261 §20.10).
    let parameters = match contact.rfind('>') {
        Some(end) => &contact[end + 1..],
        None => contact.split_once(';').map_or("", |(_, rest)| rest),
    };
    parameters.split(';').any(|parameter| {
        let name = parameter.split('=').next().unwrap_or_default().trim();
        name.eq_ignore_ascii_case(tag)
    })
}

/// The tag parameter of a From or To header.
fn tag_of(value: Option<&String>) -> Option<String> {
    let value = value?;
    let parameters = match value.rfind('>') {
        Some(end) => &value[end + 1..],
        None => value.as_str(),
    };
    parameters.split(';').find_map(|parameter| {
        let (name, tag) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("tag")
            .then(|| tag.trim().to_string())
    })
}

/// The top Via's branch.
fn branch_of(message: &SipMessage) -> Option<String> {
    super::inbound::top_via_branch(message).map(str::to_string)
}

/// Take a request off the general path when it is the SRS's: a SIPREC INVITE,
/// or any request on a recording dialog's Call-ID. Every one taken is answered.
/// Anything else is handed back for the rest of request handling.
pub(super) fn route_srs_request(
    inbound: InboundMessage,
    message: SipMessage,
    method: &str,
    srs_manager: &Arc<crate::srs::SrsManager>,
    state: &Arc<DispatcherState>,
) -> Option<(InboundMessage, SipMessage)> {
    let Some(call_id) = message.headers.call_id().cloned() else {
        return Some((inbound, message));
    };
    let held = srs_manager.is_srs_session(&call_id);
    let from_tag = tag_of(message.headers.from()).unwrap_or_default();
    let to_tag = tag_of(message.headers.to());

    if method == "INVITE" {
        let siprec = is_siprec_invite(&message);
        if !siprec && !held {
            return Some((inbound, message));
        }
        let branch = branch_of(&message).unwrap_or_default();
        // An INVITE already given a final non-2xx gets it again (RFC 3261
        // §17.2.1); the session it belonged to is gone.
        if to_tag.is_none() {
            if let Some(final_response) = state.completed_invites.get(&call_id, &branch) {
                send_outbound_from(
                    final_response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    state,
                );
                return None;
            }
        }
        match srs_manager.classify_invite(&call_id, &from_tag, to_tag.as_deref(), &branch) {
            crate::srs::InviteMatch::New if siprec => {
                invite::handle_initial_invite(inbound, message, Arc::clone(srs_manager), state);
            }
            crate::srs::InviteMatch::New => return Some((inbound, message)),
            crate::srs::InviteMatch::Retransmission => {
                invite::answer_retransmission(&inbound, &message, srs_manager, state);
            }
            crate::srs::InviteMatch::Merged => {
                // RFC 3261 §8.2.2.2: the same request arriving over another path.
                respond(&inbound, &message, 482, "Loop Detected", None, &[], state);
            }
            crate::srs::InviteMatch::CallIdInUse => {
                respond(&inbound, &message, 400, "Call-ID In Use", None, &[], state);
            }
            crate::srs::InviteMatch::InDialog => {
                in_dialog::handle_reinvite(inbound, message, Arc::clone(srs_manager), state);
            }
            crate::srs::InviteMatch::UnknownDialog if held => {
                respond_481(&inbound, &message, state);
            }
            crate::srs::InviteMatch::UnknownDialog => return Some((inbound, message)),
        }
        return None;
    }

    if !held {
        return Some((inbound, message));
    }
    // The ACK never gets here: the general ACK path absorbs it against the 2xx
    // it acknowledges (`absorb_b2bua_ack`), and drops a stray one.
    if method == "ACK" {
        return None;
    }
    let in_dialog = to_tag
        .as_deref()
        .is_some_and(|to_tag| srs_manager.in_dialog(&call_id, &from_tag, to_tag));
    if !in_dialog {
        respond_481(&inbound, &message, state);
        return None;
    }
    match method {
        "BYE" => in_dialog::handle_bye(inbound, message, call_id, Arc::clone(srs_manager), state),
        "UPDATE" => in_dialog::handle_update(inbound, message, Arc::clone(srs_manager), state),
        "OPTIONS" => respond(
            &inbound,
            &message,
            200,
            "OK",
            None,
            &[("Allow", ALLOW.to_string())],
            state,
        ),
        _ => respond(
            &inbound,
            &message,
            405,
            "Method Not Allowed",
            None,
            &[("Allow", ALLOW.to_string())],
            state,
        ),
    }
    None
}

/// Answer `request` with `code`, adding siphon's To-tag when given (every final
/// response in a dialog carries it, RFC 3261 §8.2.6.2) and `headers`.
fn build_srs_response(
    request: &SipMessage,
    code: u16,
    reason: &str,
    to_tag: Option<&str>,
    headers: &[(&str, String)],
    state: &DispatcherState,
) -> SipMessage {
    let mut response = build_response(
        request,
        code,
        reason,
        state.identity.load().server.as_deref(),
        &[],
    );
    if let (Some(to_tag), Some(to)) = (to_tag, request.headers.to()) {
        if tag_of(Some(to)).is_none() {
            response.headers.set("To", format!("{to};tag={to_tag}"));
        }
    }
    for (name, value) in headers {
        response.headers.add(name, value.clone());
    }
    response
}

/// Send a response to `request` back where it came from. A final non-2xx to
/// an INVITE is also kept for that INVITE's retransmissions (RFC 3261 §17.2.1).
fn respond(
    inbound: &InboundMessage,
    request: &SipMessage,
    code: u16,
    reason: &str,
    to_tag: Option<&str>,
    headers: &[(&str, String)],
    state: &DispatcherState,
) {
    let response = build_srs_response(request, code, reason, to_tag, headers, state);
    send_response(inbound, request, response, state);
}

/// Send `response` to the source of `request`, keeping a final non-2xx to an
/// initial INVITE for its retransmissions.
fn send_response(
    inbound: &InboundMessage,
    request: &SipMessage,
    response: SipMessage,
    state: &DispatcherState,
) {
    let code = response.status_code().unwrap_or_default();
    let initial_invite = request.method() == Some(&crate::sip::message::Method::Invite)
        && tag_of(request.headers.to()).is_none();
    if code >= 300 && initial_invite {
        if let (Some(call_id), Some(branch)) = (request.headers.call_id(), branch_of(request)) {
            state.completed_invites.remember(
                call_id,
                &branch,
                bytes::Bytes::from(response.to_bytes()),
            );
        }
    }
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

fn respond_481(inbound: &InboundMessage, request: &SipMessage, state: &DispatcherState) {
    respond(
        inbound,
        request,
        481,
        "Call/Transaction Does Not Exist",
        None,
        &[],
        state,
    );
}

/// The Contact siphon answers a recording dialog with: the address the INVITE
/// arrived on, as advertised, marked `+sip.srs` (RFC 7866 §6.2: the SRS "MUST
/// include the "+sip.srs" feature tag in the Contact URI").
fn srs_contact(inbound: &InboundMessage, state: &DispatcherState) -> String {
    format!(
        "<sip:srs@{}:{};transport={}>;+sip.srs",
        state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
        state.a_leg_advertised_port(Some(inbound.local_addr), &inbound.transport),
        inbound.transport.to_string().to_lowercase(),
    )
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    fn invite(require: Option<&str>, contact: &str) -> SipMessage {
        let mut raw = String::from(concat!(
            "INVITE sip:srs@192.0.2.1 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.20:5060;branch=z9hG4bK-m\r\n",
            "From: <sip:src@example.com>;tag=src-1\r\n",
            "To: <sip:srs@example.com>\r\n",
            "Call-ID: markers@198.51.100.20\r\n",
            "CSeq: 1 INVITE\r\n",
        ));
        if let Some(require) = require {
            raw.push_str(&format!("Require: {require}\r\n"));
        }
        raw.push_str(&format!("Contact: {contact}\r\nContent-Length: 0\r\n\r\n"));
        crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("parses")
    }

    #[test]
    fn both_markers_make_a_recording_session() {
        assert!(carries_recording_session_markers(&invite(
            Some("siprec"),
            "<sip:src@198.51.100.20>;+sip.src"
        )));
    }

    #[test]
    fn markers_are_matched_case_insensitively_among_others() {
        assert!(carries_recording_session_markers(&invite(
            Some("100rel, SIPREC"),
            "<sip:src@198.51.100.20>;expires=60;+SIP.SRC"
        )));
    }

    #[test]
    fn a_missing_marker_is_not_a_recording_session() {
        assert!(!carries_recording_session_markers(&invite(
            None,
            "<sip:src@198.51.100.20>;+sip.src"
        )));
        assert!(!carries_recording_session_markers(&invite(
            Some("siprec"),
            "<sip:src@198.51.100.20>"
        )));
        assert!(!carries_recording_session_markers(&invite(
            Some("siprecx"),
            "<sip:src@198.51.100.20>;+sip.src"
        )));
    }

    #[test]
    fn a_uri_parameter_is_not_the_feature_tag() {
        // Inside the angle brackets it belongs to the URI, not the Contact.
        assert!(!carries_recording_session_markers(&invite(
            Some("siprec"),
            "<sip:src@198.51.100.20;+sip.src>"
        )));
    }

    #[test]
    fn a_bare_contact_carries_its_parameters() {
        assert!(carries_recording_session_markers(&invite(
            Some("siprec"),
            "sip:src@198.51.100.20;+sip.src"
        )));
    }

    #[test]
    fn tags_are_read_from_header_parameters() {
        assert_eq!(
            tag_of(Some(&"<sip:a@example.com;tag=uri>;tag=hdr".to_string())).as_deref(),
            Some("hdr")
        );
        assert_eq!(tag_of(Some(&"<sip:a@example.com>".to_string())), None);
    }
}
