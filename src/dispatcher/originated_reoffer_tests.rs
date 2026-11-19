//! `@b2bua.on_reoffer` on a leg the script placed with `b2bua.originate()`.
//!
//! siphon is the UAC of that dialog and the phone it called holds it alone, so
//! a re-INVITE from the phone has no other party to be relayed to. The script
//! is shown it as on any other call, and its refusal is what the phone gets,
//! with the body and `Warning` the script gave (RFC 3261 §14.2: the session in
//! force stays as it was).

use super::originate_test_harness::{drain, phone_response, phone_sends, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const PHONE: &str = "198.51.100.71:5060";
const PHONE_TAG: &str = "phone-tag";

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

const PHONE_SDP: &str = concat!(
    "v=0\r\n",
    "o=phone 1 1 IN IP4 198.51.100.71\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 42000 RTP/AVP 0\r\n",
);

/// The handler notes what it was shown in `builtins.originated_reoffer`, then
/// refuses the offer with a body and a `Warning`.
const SCRIPT: &str = concat!(
    "import builtins\n",
    "from siphon import b2bua\n",
    "\n",
    "builtins.originated_reoffer = []\n",
    "\n",
    "@b2bua.on_reoffer\n",
    "def on_reoffer(call, offer):\n",
    "    builtins.originated_reoffer.append(f\"{offer.method} {offer.side} {offer.kind}\")\n",
    "    offer.reject(403, \"Forbidden\", body=\"<mcpttinfo/>\",\n",
    "                 content_type=\"application/vnd.3gpp.mcptt-info+xml\",\n",
    "                 headers={\"Warning\": '399 mcx.example.com \"not allowed\"'})\n",
);

fn noted() -> Vec<String> {
    Python::attach(|python| {
        python
            .import("builtins")
            .and_then(|builtins| builtins.getattr("originated_reoffer"))
            .and_then(|notes| notes.extract())
            .expect("the script's notes")
    })
}

/// Place a leg to [`PHONE`] as `b2bua.originate()` does, and have the phone
/// answer it.
fn answered_leg() -> (TestDispatcher, PreparedOriginate) {
    let dispatcher = test_dispatcher_with_script(SCRIPT);
    let params = OriginateParams {
        to: format!("sip:callee@{PHONE}"),
        to_display: None,
        from: Some("sip:server@siphon.example.com".to_string()),
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
        privacy: None,
        headers: Vec::new(),
        timeout_secs: 30,
        media: OriginateMedia::Offer {
            body: OFFER.as_bytes().to_vec(),
            content_type: "application/sdp".to_string(),
        },
        session_timer: None,
    };
    let prepared =
        prepare_originate_with_route(&dispatcher.state, params, vec![format!("<sip:{PHONE};lr>")])
            .expect("the originate stages");
    dispatcher
        .state
        .call_actors
        .mark_script_originated(&prepared.internal_call_id);
    assert!(dial_originate(&dispatcher.state, &prepared));
    phone_sends(
        &dispatcher.state,
        socket(PHONE),
        &phone_response(
            &prepared.invite,
            200,
            "OK",
            PHONE_TAG,
            &format!("sip:callee@{PHONE}"),
            Some(PHONE_SDP),
        ),
    );
    let sent = drain(&dispatcher.udp);
    assert!(
        sent.iter().any(|frame| frame.is(Method::Ack)),
        "the 2xx is ACKed: {sent:?}"
    );
    (dispatcher, prepared)
}

/// The phone's re-INVITE on the dialog siphon's INVITE formed: its From is the
/// INVITE's To with the phone's tag, its To the INVITE's From.
fn phone_reinvite(invite: &SipMessage, sdp: &str) -> SipMessage {
    let header = |name: &str| invite.headers.get(name).cloned().expect("a header");
    let raw = format!(
        concat!(
            "INVITE sip:server@192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {phone};branch=z9hG4bK-phone-reinvite\r\n",
            "Max-Forwards: 70\r\n",
            "From: {to};tag={tag}\r\n",
            "To: {from}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:callee@{phone}>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        phone = PHONE,
        to = header("To"),
        tag = PHONE_TAG,
        from = header("From"),
        call_id = header("Call-ID"),
        length = sdp.len(),
        sdp = sdp,
    );
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("the re-INVITE parses")
}

fn final_to_phone(sent: &[Sent]) -> SipMessage {
    sent.iter()
        .find(|frame| {
            frame.destination == socket(PHONE)
                && frame.message.status_code().is_some_and(|code| code >= 200)
        })
        .map(|frame| frame.message.clone())
        .unwrap_or_else(|| panic!("the phone is answered: {sent:?}"))
}

/// A hold from the phone on a leg the script placed reaches `on_reoffer`, and
/// the script's refusal goes back with its body and `Warning`.
#[tokio::test(flavor = "multi_thread")]
async fn a_reoffer_on_an_originated_leg_is_shown_to_on_reoffer_and_refused_with_its_body() {
    let (dispatcher, prepared) = answered_leg();
    let reinvite = phone_reinvite(&prepared.invite, &format!("{PHONE_SDP}a=sendonly\r\n"));
    let arrived = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket("192.0.2.1:5060"),
        remote_addr: socket(PHONE),
        data: Bytes::from(reinvite.to_bytes()),
    };
    tokio::task::block_in_place(|| handle_b2bua_reinvite(arrived, reinvite, &dispatcher.state));

    assert_eq!(noted(), ["INVITE a hold"]);
    let refusal = final_to_phone(&drain(&dispatcher.udp));
    assert_eq!(refusal.status_code(), Some(403));
    assert_eq!(
        refusal.headers.get("Content-Type").map(String::as_str),
        Some("application/vnd.3gpp.mcptt-info+xml")
    );
    assert_eq!(String::from_utf8_lossy(&refusal.body), "<mcpttinfo/>");
    assert_eq!(
        refusal.headers.get("Warning").map(String::as_str),
        Some("399 mcx.example.com \"not allowed\"")
    );
}
