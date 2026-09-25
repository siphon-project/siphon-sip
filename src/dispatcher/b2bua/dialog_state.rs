//! Reporting the RFC 4235 dialog state of registered AoRs the B2BUA carries,
//! as the application-level `DialogStateChanged` event.
//!
//! Opt-in (`control.apps[].events: [dialog]`) and free when nobody opted in:
//! every entry point asks [`dialog_state_wanted`] first, and without a watch on
//! a call the later steps find nothing to do.
//!
//! ## Which AoR a leg belongs to
//!
//! A state is only worth reporting against the right phone, so a leg is watched
//! only when siphon can tell whose it is from what it observed, never from a
//! header a caller writes:
//!
//! - **A call a phone placed** (the A-leg): the From identity must name a
//!   registered AoR *and* a live binding of it must vouch for the request —
//!   the INVITE authenticated as the identity that registered it, or (for a
//!   binding with no authenticated identity to compare, or an INVITE that
//!   presented none) arrived from the address that REGISTER came from
//!   ([`Registrar::aor_placing_request`](crate::registrar::Registrar::aor_placing_request)).
//! - **A call siphon places to a phone** (a B-leg, or an `originate`): the AoR a
//!   controller's `{aor}` target resolved from, else the one AoR whose live
//!   binding has the Request-URI as its Contact
//!   ([`Registrar::aor_for_contact`](crate::registrar::Registrar::aor_for_contact)),
//!   which refuses a Contact two AoRs share.
//!
//! ## What is not covered
//!
//! INVITEs the **proxy** relays are not reported. A proxy keeps no dialog
//! state once the INVITE transaction is over, and it sees the BYE only when the
//! script Record-Routes and both ends honour the route set, so it could report
//! `confirmed` and then never report `terminated`. A dialog stuck in
//! `confirmed` is a phone shown busy forever, which is worse than no report.

use crate::b2bua::actor::{DialogDirection, DialogState, DialogWatch, DIALOG_EVENT_CLASS};
use crate::dispatcher::*;
use crate::sip::headers::nameaddr::NameAddr;

/// Whether any control application subscribed to `dialog` events. Fixed at
/// start-up; `false` without a control plane.
pub fn dialog_state_wanted() -> bool {
    crate::control::app_event_wanted(DIALOG_EVENT_CLASS)
}

/// The registrar the scripting API saves into, which is the one the phones
/// registered with.
fn registrar() -> Option<&'static Arc<crate::registrar::Registrar>> {
    crate::script::api::registrar_arc()
}

/// A From/To header value split into the URI and display name a dialog-info
/// `<identity>` carries.
fn identity_of(header: &str) -> (String, Option<String>) {
    match NameAddr::parse(header) {
        Ok(name_addr) => (name_addr.uri.to_string(), name_addr.display_name),
        Err(_) => (
            crate::b2bua::actor::extract_contact_uri(header)
                .split(';')
                .next()
                .unwrap_or_default()
                .to_string(),
            None,
        ),
    }
}

/// The AoR a From/To header value names.
fn aor_of(header: &str) -> String {
    crate::registrar::normalize_aor(&identity_of(header).0)
}

/// Watch the caller's leg of `call_id` when a registered phone placed the call.
///
/// Called once the call is going somewhere — routed, handed over or answered —
/// so a request refused at admission (a digest challenge, a policy reject) is
/// never shown as a call. `auth_user` is who the INVITE authenticated as, when
/// the script challenged it. The watch starts in whatever state siphon's own
/// responses already put the caller's dialog in.
pub fn watch_caller_dialog(call_id: &str, auth_user: Option<&str>, state: &DispatcherState) {
    if !dialog_state_wanted() {
        return;
    }
    let Some(registrar) = registrar() else {
        return;
    };
    let Some((from, to, source, leg_id, sip_call_id, phone_tag, siphon_tag, reached)) =
        state.call_actors.get_call(call_id).and_then(|call| {
            // A call siphon placed has no caller to watch; its callee is
            // watched as a recipient instead.
            if call.originated {
                return None;
            }
            Some((
                call.a_leg.stored_from.clone()?,
                call.a_leg.stored_to.clone().unwrap_or_default(),
                call.a_leg.transport.remote_addr,
                call.a_leg.id.0.clone(),
                call.a_leg.dialog.call_id.clone(),
                call.a_leg.dialog.remote_tag.clone(),
                call.a_leg.dialog.local_tag.clone(),
                call.caller_dialog_state,
            ))
        })
    else {
        return;
    };
    let Some(aor) = registrar.aor_placing_request(&aor_of(&from), auth_user, source) else {
        return;
    };
    let (remote_uri, remote_display_name) = identity_of(&to);
    state.call_actors.watch_dialog(
        call_id,
        DialogWatch {
            leg_id,
            aor,
            direction: DialogDirection::Initiator,
            call_id: sip_call_id,
            local_tag: phone_tag,
            // Siphon's To-tag is the phone's remote tag once a tagged response
            // carried it to the phone, and not before.
            remote_tag: (reached >= DialogState::Early).then_some(siphon_tag),
            remote_uri,
            remote_display_name,
            // siphon answers every INVITE with an untagged 100 the moment it
            // arrives, so the phone's dialog is proceeding at the least.
            state: reached.max(DialogState::Proceeding),
        },
    );
}

/// Watch a leg siphon is about to INVITE when it rings a registered AoR.
///
/// `invite` is the INVITE as it goes on the wire: its From is the identity the
/// phone is shown, which is the dialog's remote identity from the phone's side.
/// Called before the INVITE is sent, so no response can overtake the watch.
pub fn watch_callee_dialog(
    call_id: &str,
    leg: &Leg,
    target_uri: &str,
    invite: &SipMessage,
    state: &DispatcherState,
) {
    if !dialog_state_wanted() {
        return;
    }
    let dialled_for = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.control_dial_aor(target_uri));
    let Some(aor) = dialled_for
        .or_else(|| registrar().and_then(|registrar| registrar.aor_for_contact(target_uri)))
    else {
        return;
    };
    let (remote_uri, remote_display_name) = invite
        .headers
        .from()
        .map(|from| identity_of(from))
        .unwrap_or_default();
    state.call_actors.watch_dialog(
        call_id,
        DialogWatch {
            leg_id: leg.id.0.clone(),
            aor,
            direction: DialogDirection::Recipient,
            call_id: leg.dialog.call_id.clone(),
            // The phone's tag arrives with its first tagged response.
            local_tag: None,
            remote_tag: Some(leg.dialog.local_tag.clone()),
            remote_uri,
            remote_display_name,
            state: DialogState::Trying,
        },
    );
}

/// Watch the leg of a call siphon placed itself (`originate`) when its target
/// is a registered contact. The phone is the recipient.
pub fn watch_originated_dialog(call_id: &str, invite: &SipMessage, state: &DispatcherState) {
    if !dialog_state_wanted() {
        return;
    }
    let Some(registrar) = registrar() else {
        return;
    };
    let target = match &invite.start_line {
        StartLine::Request(request_line) => request_line.request_uri.to_string(),
        StartLine::Response(_) => return,
    };
    let Some(aor) = registrar.aor_for_contact(&target) else {
        return;
    };
    let Some((leg_id, sip_call_id, siphon_tag)) = state.call_actors.get_call(call_id).map(|call| {
        (
            call.a_leg.id.0.clone(),
            call.a_leg.dialog.call_id.clone(),
            call.a_leg.dialog.local_tag.clone(),
        )
    }) else {
        return;
    };
    let (remote_uri, remote_display_name) = invite
        .headers
        .from()
        .map(|from| identity_of(from))
        .unwrap_or_default();
    state.call_actors.watch_dialog(
        call_id,
        DialogWatch {
            leg_id,
            aor,
            direction: DialogDirection::Recipient,
            call_id: sip_call_id,
            local_tag: None,
            remote_tag: Some(siphon_tag),
            remote_uri,
            remote_display_name,
            state: DialogState::Trying,
        },
    );
}

/// The state a response to an INVITE moves its dialog to, with the To-tag it
/// carried. `None` for a final failure, which the caller reports once it knows
/// no retry keeps the leg alive, and for a response to anything but an INVITE.
fn state_of_invite_response(message: &SipMessage, status_code: u16) -> Option<DialogState> {
    let for_invite = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1))
        .is_some_and(|method| method.eq_ignore_ascii_case("INVITE"));
    if !for_invite {
        return None;
    }
    match status_code {
        100..=199 => Some(DialogState::of_provisional(
            crate::b2bua::actor::extract_to_tag(message).is_some(),
        )),
        200..=299 => Some(DialogState::Confirmed),
        _ => None,
    }
}

/// A B-leg sent `message`, a response to its INVITE: a provisional or 2xx moves
/// its watch.
pub fn observe_callee_response(
    call_id: &str,
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    if !dialog_state_wanted() {
        return;
    }
    let Some(dialog_state) = state_of_invite_response(message, status_code) else {
        return;
    };
    let tag = crate::b2bua::actor::extract_to_tag(message);
    state
        .call_actors
        .advance_dialog_by_via(call_id, branch, dialog_state, tag.as_deref());
}

/// The callee of a call siphon placed (`originate`) sent `message`.
pub fn observe_originated_response(
    call_id: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    if !dialog_state_wanted() {
        return;
    }
    let Some(dialog_state) = state_of_invite_response(message, status_code) else {
        return;
    };
    let Some(leg_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.id.0.clone())
    else {
        return;
    };
    let tag = crate::b2bua::actor::extract_to_tag(message);
    state
        .call_actors
        .advance_dialog(call_id, &leg_id, dialog_state, tag.as_deref());
}

/// The B-leg whose INVITE rides Via `branch` ended without an answer: a final
/// failure no retry saves, or an INVITE that never reached the transport.
pub fn callee_dialog_ended(call_id: &str, branch: &str, state: &DispatcherState) {
    if !dialog_state_wanted() {
        return;
    }
    state
        .call_actors
        .advance_dialog_by_via(call_id, branch, DialogState::Terminated, None);
}

/// siphon gave up on `legs` — CANCELled them — while the call goes on.
pub fn callee_dialogs_ended(call_id: &str, legs: &[Leg], state: &DispatcherState) {
    if legs.is_empty() || !dialog_state_wanted() {
        return;
    }
    state.call_actors.end_dialogs_of_legs(call_id, legs);
}

/// siphon sent the caller of `call_id` the responses in `messages`: a tagged
/// provisional makes the caller's dialog early, a 2xx confirms it.
pub fn observe_caller_responses(call_id: &str, messages: &[SipMessage], state: &DispatcherState) {
    if !dialog_state_wanted() {
        return;
    }
    for message in messages {
        let StartLine::Response(status) = &message.start_line else {
            continue;
        };
        let for_invite = message
            .headers
            .cseq()
            .and_then(|cseq| cseq.split_whitespace().nth(1))
            .is_some_and(|method| method.eq_ignore_ascii_case("INVITE"));
        if !for_invite {
            continue;
        }
        let has_to_tag = crate::b2bua::actor::extract_to_tag(message).is_some();
        state
            .call_actors
            .note_caller_response(call_id, status.status_code, has_to_tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_split_into_uri_and_display_name() {
        assert_eq!(
            identity_of("\"Front Desk\" <sip:201@example.com>;tag=abc"),
            (
                "sip:201@example.com".to_string(),
                Some("Front Desk".to_string())
            )
        );
        assert_eq!(
            identity_of("<sip:15550100077@example.com;user=phone>"),
            ("sip:15550100077@example.com;user=phone".to_string(), None)
        );
        assert_eq!(
            aor_of("<sip:201@example.com:5060>;tag=x"),
            "sip:201@example.com"
        );
    }

    fn response(status_line: &str, cseq: &str, to_tag: Option<&str>) -> SipMessage {
        let raw = format!(
            concat!(
                "SIP/2.0 {status}\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-x\r\n",
                "From: <sip:201@example.com>;tag=f\r\n",
                "To: <sip:202@example.com>{tag}\r\n",
                "Call-ID: c@192.0.2.1\r\n",
                "CSeq: {cseq}\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            status = status_line,
            tag = to_tag.map(|tag| format!(";tag={tag}")).unwrap_or_default(),
            cseq = cseq,
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("parses")
    }

    #[test]
    fn invite_responses_map_to_rfc_4235_states() {
        let cases = [
            ("100 Trying", None, Some(DialogState::Proceeding)),
            ("180 Ringing", None, Some(DialogState::Proceeding)),
            ("180 Ringing", Some("t"), Some(DialogState::Early)),
            ("183 Session Progress", Some("t"), Some(DialogState::Early)),
            ("200 OK", Some("t"), Some(DialogState::Confirmed)),
            ("486 Busy Here", Some("t"), None),
        ];
        for (status_line, tag, expected) in cases {
            let message = response(status_line, "1 INVITE", tag);
            let code = message.status_code().expect("a response");
            assert_eq!(
                state_of_invite_response(&message, code),
                expected,
                "{status_line} tag={tag:?}"
            );
        }
        let prack = response("200 OK", "2 PRACK", Some("t"));
        assert_eq!(state_of_invite_response(&prack, 200), None);
    }
}
