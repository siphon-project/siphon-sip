//! An inbound in-dialog INFO on a B2BUA call (RFC 6086).
//!
//! INFO was not one of the methods the B2BUA intercepted, so it took the proxy
//! path: a B2BUA script with no `@proxy.on_request` covering INFO got `405
//! Method Not Allowed`, and one with such a handler sent it to proxy routing
//! instead. Either way it was not relayed across a two-leg call and never
//! reached the control plane, so a peer that signals DTMF only as SIP INFO
//! (RFC 2976 / RFC 6086 `application/dtmf-relay`, which some handsets and
//! trunks still do) had its digits dropped.

use crate::dispatcher::*;

/// Handle an in-dialog INFO on a tracked B2BUA call.
///
/// On a two-leg call it is relayed to the other leg, like any other in-dialog
/// request. On a one-legged call siphon is the far party, so it is answered
/// here — and a DTMF payload is surfaced through the same path an RFC 4733
/// digit takes, so a script's `@rtpengine.on_dtmf` and a controller's
/// `ChannelDtmfReceived` see INFO digits without knowing where they came from.
pub fn handle_b2bua_info(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let Some(call_id) = state.call_actors.find_by_sip_call_id(&sip_call_id) else {
        // Raced a teardown after the dispatch gate matched.
        warn!(sip_call_id = %sip_call_id, "B2BUA INFO: no matching call — 481");
        respond(
            &inbound,
            &message,
            481,
            "Call/Transaction Does Not Exist",
            state,
        );
        return;
    };

    // Direction by dialog identity (RFC 3261 §12), never by source socket — a
    // peer may send this on a new connection.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA INFO: Call-ID matches no dialog leg — 481");
            respond(
                &inbound,
                &message,
                481,
                "Call/Transaction Does Not Exist",
                state,
            );
            return;
        }
    };

    let has_far_leg = state
        .call_actors
        .get_call(&call_id)
        .map(|call| call.winner.is_some())
        .unwrap_or(false);

    // A digit is surfaced whichever way the INFO goes: on a two-leg call the
    // far end still gets the INFO itself, and siphon reporting the digit as
    // well is what makes a controller's view the same on both shapes.
    if let Some((digit, duration_ms)) = parse_dtmf_payload(&message) {
        let leg_tag = state
            .call_actors
            .get_call(&call_id)
            .map(|call| {
                if from_a_leg {
                    call.a_leg.dialog.local_tag.clone()
                } else {
                    call.winner
                        .and_then(|index| call.b_legs.get(index))
                        .map(|leg| leg.dialog.local_tag.clone())
                        .unwrap_or_else(String::new)
                }
            })
            .unwrap_or_default();
        debug!(
            call_id = %call_id,
            digit = %digit,
            "B2BUA INFO: surfacing a DTMF digit"
        );
        // The fan-out is async (it may enter Python), and this path is the
        // synchronous SIP one — so hand it to the dispatcher runtime the same
        // way the imperative control entry points do.
        let event = crate::rtpengine::events::DtmfEvent {
            call_id: sip_call_id.clone(),
            from_tag: leg_tag,
            to_tag: None,
            digit,
            duration_ms,
            // No RTP tone to measure: INFO carries a duration at most, and
            // never a level. 0 dBm0 reads as "not reported" rather than as a
            // measurement siphon did not make.
            volume: 0,
            source: None,
        };
        if let Some(control) = B2BUA_CONTROL.get() {
            let state_for_event = Arc::clone(&control.state);
            control
                .runtime
                .spawn(dispatch_dtmf_event(state_for_event, event));
        } else {
            warn!(call_id = %call_id, "B2BUA INFO: no dispatcher handle — the digit was not surfaced");
        }
    }

    if has_far_leg {
        b2bua_forward_indialog_request(
            &inbound,
            &message,
            &call_id,
            from_a_leg,
            Method::Info,
            "info",
            state,
        );
        return;
    }

    // One-legged: siphon is the far party, so it answers. RFC 6086 §4.2.2 —
    // an INFO a UAS understood is a 200, with no body owed back.
    debug!(call_id = %call_id, "B2BUA INFO: answering on a one-legged call");
    respond(&inbound, &message, 200, "OK", state);
}

/// Send a plain response on the flow the request arrived on.
fn respond(
    inbound: &InboundMessage,
    message: &SipMessage,
    code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let response = build_response(message, code, reason, state.server_header.as_deref(), &[]);
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// Extract a DTMF digit and its duration from an INFO body.
///
/// Two body types are in the wild. `application/dtmf-relay` (the common one) is
/// a `Signal=<digit>` / `Duration=<ms>` pair; `application/dtmf` is the bare
/// digit. Anything else is not DTMF and is left alone — INFO carries plenty of
/// other payloads and inventing a digit from one would be worse than ignoring
/// it.
fn parse_dtmf_payload(message: &SipMessage) -> Option<(String, u32)> {
    let content_type = message
        .headers
        .get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&message.body);

    if content_type.contains("application/dtmf-relay") {
        let mut digit = None;
        let mut duration_ms = 0u32;
        for line in body.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "signal" => digit = normalise_digit(value.trim()),
                "duration" => duration_ms = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        return digit.map(|digit| (digit, duration_ms));
    }

    if content_type.contains("application/dtmf") {
        return normalise_digit(body.trim()).map(|digit| (digit, 0));
    }

    None
}

/// Accept the spellings a peer may use for a digit and reject anything else.
///
/// `10`/`11` are RFC 2833's numbering for `*` and `#`, which some devices put
/// in `Signal=`. A value that is not a single DTMF symbol is refused rather
/// than passed through, so a handler never sees a "digit" it cannot act on.
fn normalise_digit(value: &str) -> Option<String> {
    match value {
        "10" => return Some("*".to_string()),
        "11" => return Some("#".to_string()),
        _ => {}
    }
    let mut characters = value.chars();
    let (Some(first), None) = (characters.next(), characters.next()) else {
        return None;
    };
    let upper = first.to_ascii_uppercase();
    if first.is_ascii_digit() || upper == '*' || upper == '#' || ('A'..='D').contains(&upper) {
        Some(upper.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with(content_type: &str, body: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "INFO sip:bob@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
                "From: <sip:alice@example.com>;tag=a\r\n",
                "To: <sip:bob@example.com>;tag=b\r\n",
                "Call-ID: info-test\r\n",
                "CSeq: 2 INFO\r\n",
                "Content-Type: {}\r\n",
                "Content-Length: {}\r\n",
                "\r\n",
                "{}"
            ),
            content_type,
            body.len(),
            body
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the fixture should parse")
    }

    /// The common form, as a handset sends it.
    #[test]
    fn dtmf_relay_body_yields_the_digit_and_duration() {
        let message = info_with("application/dtmf-relay", "Signal=5\r\nDuration=160\r\n");
        assert_eq!(parse_dtmf_payload(&message), Some(("5".to_string(), 160)));
    }

    /// RFC 2833 numbering for the two symbols that are not digits.
    #[test]
    fn dtmf_relay_accepts_the_star_and_hash_encodings() {
        for (signal, expected) in [("10", "*"), ("11", "#"), ("*", "*"), ("#", "#")] {
            let message = info_with(
                "application/dtmf-relay",
                &format!("Signal={signal}\r\nDuration=100\r\n"),
            );
            assert_eq!(
                parse_dtmf_payload(&message),
                Some((expected.to_string(), 100)),
                "Signal={signal} should be {expected}"
            );
        }
    }

    /// The bare-digit form.
    #[test]
    fn dtmf_body_yields_the_digit() {
        let message = info_with("application/dtmf", "7");
        assert_eq!(parse_dtmf_payload(&message), Some(("7".to_string(), 0)));
    }

    /// INFO carries plenty that is not DTMF. Inventing a digit from a body
    /// that is not one would put a keypress into an IVR nobody made.
    #[test]
    fn a_non_dtmf_body_is_not_a_digit() {
        for (content_type, body) in [
            ("application/media_control+xml", "<?xml version=\"1.0\"?>"),
            ("application/dtmf-relay", "Duration=100\r\n"),
            ("application/dtmf-relay", "Signal=hello\r\n"),
            ("application/dtmf", "not-a-digit"),
            ("application/sdp", "v=0"),
        ] {
            assert_eq!(
                parse_dtmf_payload(&info_with(content_type, body)),
                None,
                "{content_type} / {body:?} is not a digit"
            );
        }
    }

    /// Case and the letter keys.
    #[test]
    fn letter_keys_are_upper_cased() {
        let message = info_with("application/dtmf-relay", "Signal=b\r\n");
        assert_eq!(parse_dtmf_payload(&message), Some(("B".to_string(), 0)));
    }
}
