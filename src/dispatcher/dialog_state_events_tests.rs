//! `DialogStateChanged`: the RFC 4235 state of every dialog a registered AoR has
//! through the B2BUA, as siphon observed it on the wire.
//!
//! Driven through the dispatcher's own entry points on a test dispatcher: the
//! phone's INVITE through [`handle_b2bua_invite`], the controller's `dial`
//! through [`b2bua_dial_call_with_state`], responses through
//! [`handle_b2bua_response`], CANCEL and BYE through their handlers. Phones are
//! registered in the registrar the scripting API saves into, each test with AoRs
//! and Contacts of its own. Every Call-ID and tag an event names is checked
//! against the message that actually carried it, read back off the UDP egress.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::control::{app_event_capture, channel_event_capture};

/// A caller that is not a registered phone.
const OUTSIDE_CALLER: &str = "192.0.2.10:5060";
/// A callee that is not a registered phone.
const OUTSIDE_CALLEE: &str = "198.51.100.7:5060";

/// Register `aor` with one binding whose Contact is `sip:<user>@<address>`,
/// stored from `address` as the REGISTER's source, and start capturing its
/// dialog events.
fn register(aor: &str, address: &str) {
    let user = aor
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .expect("an AoR with a user part");
    let contact = parse_uri_standalone(&format!("sip:{user}@{address}")).expect("a contact URI");
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            contact,
            3600,
            1.0,
            format!("register-{aor}"),
            1,
            Some(address.parse().expect("a literal address")),
            Some(Transport::Udp),
        )
        .expect("the binding saves");
    app_event_capture::watch(aor);
}

/// The `DialogStateChanged` payloads published for `aor` since the last look.
fn dialog_events(aor: &str) -> Vec<serde_json::Value> {
    app_event_capture::take(aor)
        .into_iter()
        .filter(|(event, _)| event == "DialogStateChanged")
        .map(|(_, payload)| payload)
        .collect()
}

fn states(events: &[serde_json::Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| event["state"].as_str().expect("a state"))
        .collect()
}

fn text<'a>(payload: &'a serde_json::Value, field: &str) -> &'a str {
    payload[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string `{field}` in {payload}"))
}

/// One message siphon put on the wire.
struct Sent {
    destination: String,
    message: SipMessage,
}

/// Everything siphon has sent since the last look, the followers of an ordered
/// group included.
fn wire(dispatcher: &TestDispatcher) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination.to_string(),
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// The INVITEs among `sent`, by the address they went to.
fn invites(sent: &[Sent]) -> Vec<(String, SipMessage)> {
    sent.iter()
        .filter(|sent| sent.message.method() == Some(&Method::Invite))
        .map(|sent| (sent.destination.clone(), sent.message.clone()))
        .collect()
}

/// The response with `status_code` among `sent` that went to `address`.
fn response_to<'a>(sent: &'a [Sent], address: &str, status_code: u16) -> &'a SipMessage {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.status_code() == Some(status_code))
        .map(|sent| &sent.message)
        .unwrap_or_else(|| panic!("no {status_code} to {address}"))
}

fn header(message: &SipMessage, name: &str) -> String {
    message
        .headers
        .get(name)
        .map(|value| value.to_string())
        .unwrap_or_else(|| panic!("no {name} header"))
}

fn tag_of(value: &str) -> String {
    value
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("tag="))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no tag in {value}"))
}

fn uri_of(value: &str) -> String {
    crate::sip::headers::nameaddr::NameAddr::parse(value)
        .expect("a name-addr")
        .uri
        .to_string()
}

/// The response a phone at the far end of `invite` sends, tagged `to_tag`.
fn response_for(invite: &SipMessage, status_code: u16, reason: &str, to_tag: &str) -> SipMessage {
    let mut raw = format!("SIP/2.0 {status_code} {reason}\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str("Contact: <sip:phone@198.51.100.99:5060>\r\n");
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message_bytes(raw.as_bytes()).expect("the response parses")
}

/// The far end at `address` sends `status_code` for its `invite`.
fn responds(
    dispatcher: &TestDispatcher,
    call_id: &str,
    address: &str,
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
    to_tag: &str,
) {
    let mut response = response_for(invite, status_code, reason, to_tag);
    // Classifying a response waits on the leg actor with `block_on`, which a
    // runtime worker may only do outside its async context.
    let handled = tokio::task::block_in_place(|| {
        handle_b2bua_response(
            call_id,
            &top_via_branch(invite),
            &mut response,
            status_code,
            address.parse().expect("a literal address"),
            &dispatcher.state,
        )
    });
    assert!(handled, "the call was gone when the {status_code} arrived");
}

fn inbound(source: &str, raw: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: source.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
    }
}

/// A BYE from `source` in the dialog named by `from` (the sender's own
/// identity, tagged), `to` (the other end's, tagged) and `sip_call_id`.
fn bye(dispatcher: &TestDispatcher, source: &str, from: &str, to: &str, sip_call_id: &str) {
    let raw = format!(
        concat!(
            "BYE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-bye-{call}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call}\r\n",
            "CSeq: 9 BYE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        source = source,
        from = from,
        to = to,
        call = sip_call_id,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the BYE parses");
    tokio::task::block_in_place(|| {
        handle_b2bua_bye(inbound(source, &raw), message, &dispatcher.state)
    });
}

/// A script whose `@b2bua.on_invite` runs `routing`.
fn script(routing: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    {routing}\n",
        ),
        routing = routing,
    )
}

/// An INVITE from `from` (a full From header value, tagged) to `to`.
fn invite_raw(source: &str, sip_call_id: &str, from: &str, to: &str) -> String {
    format!(
        concat!(
            "INVITE {to_uri} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{call}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: <{to_uri}>\r\n",
            "Call-ID: {call}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:phone@{source}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        source = source,
        call = sip_call_id,
        from = from,
        to_uri = to,
    )
}

/// The caller at `source` places the call; returns the internal call id.
fn place_call(dispatcher: &TestDispatcher, source: &str, raw: &str) -> String {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let sip_call_id = header(&message, "Call-ID");
    tokio::task::block_in_place(|| {
        handle_b2bua_invite(inbound(source, raw), message, &dispatcher.state)
    });
    dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(&sip_call_id)
        .expect("the call exists")
}

/// A ring group of three registered phones, dialled by a controller as three
/// `{aor}` targets beside one raw URI: each member is reported ringing, the one
/// that answers confirmed and named by its AoR, and the others terminated the
/// moment siphon CANCELs them. The raw URI names no AoR and has no dialog
/// state reported for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_ring_group_reports_every_member_and_names_the_one_that_answers() {
    let members = [
        ("sip:2101@example.com", "198.51.100.21:5060"),
        ("sip:2102@example.com", "198.51.100.22:5060"),
        ("sip:2103@example.com", "198.51.100.23:5060"),
    ];
    for (aor, address) in members {
        register(aor, address);
    }

    let dispatcher = test_dispatcher();
    let sip_call_id = "ring-group@192.0.2.10";
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        sip_call_id.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-ring-group".to_string(),
        LegTransport {
            remote_addr: OUTSIDE_CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    let caller_invite = invite_raw(
        OUTSIDE_CALLER,
        sip_call_id,
        "\"Outside Line\" <sip:15550100042@example.com>;tag=caller-tag",
        "sip:2100@siphon.example.com",
    );
    dispatcher.state.call_actors.set_a_leg_invite(
        &call_id,
        Arc::new(Mutex::new(
            parse_sip_message_bytes(caller_invite.as_bytes()).expect("parses"),
        )),
    );
    channel_event_capture::watch(sip_call_id);

    let mut targets = Vec::new();
    for (aor, _) in members {
        targets.extend(dial_targets_for_aor(aor).expect("the member is registered"));
    }
    targets.push(DialTarget {
        uri: format!("sip:15550100077@{OUTSIDE_CALLEE}"),
        ..Default::default()
    });
    assert!(b2bua_dial_call_with_state(
        sip_call_id,
        targets,
        true,
        30,
        &[],
        &DialShaping::default(),
        &dispatcher.state,
    )
    .expect("the dial runs"));

    let sent = invites(&wire(&dispatcher));
    assert_eq!(sent.len(), 4, "every member and the raw URI rang");
    let invite_to = |address: &str| {
        sent.iter()
            .find(|(destination, _)| destination == address)
            .map(|(_, invite)| invite.clone())
            .unwrap_or_else(|| panic!("no INVITE to {address}"))
    };

    for (index, (aor, address)) in members.iter().enumerate() {
        let invite = invite_to(address);
        let events = dialog_events(aor);
        assert_eq!(states(&events), ["trying"], "{aor}: {events:?}");
        let trying = &events[0];
        assert_eq!(text(trying, "direction"), "recipient");
        assert_eq!(text(trying, "call_id"), header(&invite, "Call-ID"));
        assert_eq!(text(trying, "remote_tag"), tag_of(&header(&invite, "From")));
        assert!(
            trying["local_tag"].is_null(),
            "the phone has not tagged yet"
        );
        assert_eq!(
            trying["remote_identity"]["uri"],
            uri_of(&header(&invite, "From")),
            "the phone is shown the identity its INVITE presents"
        );
        responds(
            &dispatcher,
            &call_id,
            address,
            &invite,
            180,
            "Ringing",
            &format!("member-{index}"),
        );
    }
    for (index, (aor, _)) in members.iter().enumerate() {
        let events = dialog_events(aor);
        assert_eq!(states(&events), ["early"], "{aor}: {events:?}");
        assert_eq!(text(&events[0], "local_tag"), format!("member-{index}"));
    }

    // The second member answers.
    let (answering_aor, answering_address) = members[1];
    let answered_invite = invite_to(answering_address);
    responds(
        &dispatcher,
        &call_id,
        answering_address,
        &answered_invite,
        200,
        "OK",
        "member-1",
    );
    let confirmed = dialog_events(answering_aor);
    assert_eq!(states(&confirmed), ["confirmed"], "{confirmed:?}");
    assert_eq!(
        text(&confirmed[0], "call_id"),
        header(&answered_invite, "Call-ID")
    );
    for (aor, _) in [members[0], members[2]] {
        let events = dialog_events(aor);
        assert_eq!(states(&events), ["terminated"], "{aor}: {events:?}");
    }

    // The channel events name the AoR each branch was dialled for, and the one
    // that answered; the raw URI names none.
    let channel_events = channel_event_capture::take(sip_call_id);
    let answered: Vec<_> = channel_events
        .iter()
        .filter(|(event, _)| event == "DialAnswered")
        .collect();
    assert_eq!(answered.len(), 1, "{channel_events:?}");
    assert_eq!(text(&answered[0].1, "aor"), answering_aor);
    assert_eq!(
        text(&answered[0].1, "leg_id"),
        text(&confirmed[0], "leg_id"),
        "the dialog is the branch the controller was told of"
    );
    for (event, payload) in channel_events
        .iter()
        .filter(|(event, _)| event == "DialBranch" || event == "DialBranchFailed")
    {
        let target = text(payload, "target");
        match members.iter().find(|(_, address)| target.contains(address)) {
            Some((aor, _)) => assert_eq!(text(payload, "aor"), *aor, "{event}: {payload}"),
            None => assert!(payload.get("aor").is_none(), "{event}: {payload}"),
        }
    }

    // The answering member hangs up.
    bye(
        &dispatcher,
        answering_address,
        &format!("{};tag=member-1", header(&answered_invite, "To")),
        &header(&answered_invite, "From"),
        &header(&answered_invite, "Call-ID"),
    );
    assert_eq!(states(&dialog_events(answering_aor)), ["terminated"]);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// A call a registered phone places is reported from the phone's side: its own
/// Call-ID and From-tag, siphon's To-tag once a tagged response carried it, and
/// the party it called as the remote identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_the_phone_places_is_reported_as_initiator() {
    let (aor, phone) = ("sip:2201@example.com", "192.0.2.61:5060");
    register(aor, phone);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.dial(\"sip:15550100077@{OUTSIDE_CALLEE}\")"
    )));
    let sip_call_id = "phone-placed@192.0.2.61";
    let raw = invite_raw(
        phone,
        sip_call_id,
        "\"Front Desk\" <sip:2201@example.com>;tag=phone-tag",
        "sip:15550100077@example.com",
    );
    let call_id = place_call(&dispatcher, phone, &raw);

    let events = dialog_events(aor);
    assert_eq!(states(&events), ["proceeding"], "{events:?}");
    assert_eq!(text(&events[0], "direction"), "initiator");
    assert_eq!(text(&events[0], "call_id"), sip_call_id);
    assert_eq!(text(&events[0], "local_tag"), "phone-tag");
    assert!(events[0]["remote_tag"].is_null());
    assert_eq!(
        events[0]["remote_identity"]["uri"],
        "sip:15550100077@example.com"
    );

    let sent = wire(&dispatcher);
    let callee_invite = invites(&sent)
        .into_iter()
        .find(|(destination, _)| destination == OUTSIDE_CALLEE)
        .map(|(_, invite)| invite)
        .expect("the callee was dialled");
    responds(
        &dispatcher,
        &call_id,
        OUTSIDE_CALLEE,
        &callee_invite,
        180,
        "Ringing",
        "callee-tag",
    );
    let sent = wire(&dispatcher);
    let ringing = response_to(&sent, phone, 180);
    let events = dialog_events(aor);
    assert_eq!(states(&events), ["early"], "{events:?}");
    assert_eq!(
        text(&events[0], "remote_tag"),
        tag_of(&header(ringing, "To")),
        "the phone's remote tag is the To-tag siphon sent it"
    );

    responds(
        &dispatcher,
        &call_id,
        OUTSIDE_CALLEE,
        &callee_invite,
        200,
        "OK",
        "callee-tag",
    );
    let sent = wire(&dispatcher);
    let answer = response_to(&sent, phone, 200).clone();
    assert_eq!(states(&dialog_events(aor)), ["confirmed"]);

    // The phone hangs up.
    bye(
        &dispatcher,
        phone,
        &header(&answer, "From"),
        &header(&answer, "To"),
        sip_call_id,
    );
    assert_eq!(states(&dialog_events(aor)), ["terminated"]);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// A From header naming a registered phone, sent from anywhere but the address
/// that phone registered from, is not that phone's call: nothing is reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_from_header_alone_does_not_make_a_call_the_phones() {
    let (aor, phone) = ("sip:2202@example.com", "192.0.2.62:5060");
    register(aor, phone);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.dial(\"sip:15550100077@{OUTSIDE_CALLEE}\")"
    )));
    let elsewhere = "203.0.113.9:5060";
    let raw = invite_raw(
        elsewhere,
        "spoofed@203.0.113.9",
        "<sip:2202@example.com>;tag=spoofed-tag",
        "sip:15550100077@example.com",
    );
    let call_id = place_call(&dispatcher, elsewhere, &raw);
    assert!(
        !invites(&wire(&dispatcher)).is_empty(),
        "the call itself still goes through"
    );
    assert!(dialog_events(aor).is_empty());
    assert!(dispatcher
        .state
        .call_actors
        .dialog_watches(&call_id)
        .is_empty());
}

/// A registered phone calls another one straight at its Contact, and cancels
/// before it answers: both dialogs go from ringing to terminated, the callee
/// found by the Contact the INVITE was sent to.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_call_terminates_both_phones_dialogs() {
    let (caller_aor, caller) = ("sip:2301@example.com", "192.0.2.63:5060");
    let (callee_aor, callee) = ("sip:2302@example.com", "198.51.100.64:5060");
    register(caller_aor, caller);
    register(callee_aor, callee);
    let dispatcher =
        test_dispatcher_with_script(&script(&format!("call.dial(\"sip:2302@{callee}\")")));
    let sip_call_id = "cancelled@192.0.2.63";
    let raw = invite_raw(
        caller,
        sip_call_id,
        "<sip:2301@example.com>;tag=caller-phone-tag",
        "sip:2302@example.com",
    );
    let call_id = place_call(&dispatcher, caller, &raw);
    let callee_invite = invites(&wire(&dispatcher))
        .into_iter()
        .find(|(destination, _)| destination == callee)
        .map(|(_, invite)| invite)
        .expect("the callee was dialled");

    assert_eq!(states(&dialog_events(caller_aor)), ["proceeding"]);
    let callee_events = dialog_events(callee_aor);
    assert_eq!(states(&callee_events), ["trying"]);
    assert_eq!(
        text(&callee_events[0], "call_id"),
        header(&callee_invite, "Call-ID")
    );

    responds(
        &dispatcher,
        &call_id,
        callee,
        &callee_invite,
        180,
        "Ringing",
        "callee-phone-tag",
    );
    assert_eq!(states(&dialog_events(caller_aor)), ["early"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["early"]);
    let _ = wire(&dispatcher);

    let cancel_raw = format!(
        concat!(
            "CANCEL sip:2302@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:2301@example.com>;tag=caller-phone-tag\r\n",
            "To: <sip:2302@example.com>\r\n",
            "Call-ID: {call}\r\n",
            "CSeq: 1 CANCEL\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = caller,
        call = sip_call_id,
    );
    let cancel = parse_sip_message_bytes(cancel_raw.as_bytes()).expect("the CANCEL parses");
    tokio::task::block_in_place(|| {
        handle_b2bua_cancel(inbound(caller, &cancel_raw), cancel, &dispatcher.state)
    });

    assert!(
        wire(&dispatcher).iter().any(
            |sent| sent.destination == callee && sent.message.method() == Some(&Method::Cancel)
        ),
        "the callee's INVITE was CANCELled on the wire"
    );
    assert_eq!(states(&dialog_events(caller_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["terminated"]);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// A script forks to two registered phones and one declines: that phone's
/// dialog is terminated at once while the other goes on ringing, and then
/// answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_branch_terminates_while_the_other_rings_on() {
    let (busy_aor, busy) = ("sip:2401@example.com", "198.51.100.65:5060");
    let (free_aor, free) = ("sip:2402@example.com", "198.51.100.66:5060");
    register(busy_aor, busy);
    register(free_aor, free);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.fork([\"sip:2401@{busy}\", \"sip:2402@{free}\"])"
    )));
    let sip_call_id = "fork-busy@192.0.2.10";
    let raw = invite_raw(
        OUTSIDE_CALLER,
        sip_call_id,
        "<sip:15550100042@example.com>;tag=outside-tag",
        "sip:2400@siphon.example.com",
    );
    let call_id = place_call(&dispatcher, OUTSIDE_CALLER, &raw);
    let sent = invites(&wire(&dispatcher));
    let invite_to = |address: &str| {
        sent.iter()
            .find(|(destination, _)| destination == address)
            .map(|(_, invite)| invite.clone())
            .unwrap_or_else(|| panic!("no INVITE to {address}"))
    };
    let (busy_invite, free_invite) = (invite_to(busy), invite_to(free));
    assert_eq!(states(&dialog_events(busy_aor)), ["trying"]);
    assert_eq!(states(&dialog_events(free_aor)), ["trying"]);

    responds(
        &dispatcher,
        &call_id,
        free,
        &free_invite,
        180,
        "Ringing",
        "free-tag",
    );
    responds(
        &dispatcher,
        &call_id,
        busy,
        &busy_invite,
        486,
        "Busy Here",
        "busy-tag",
    );
    let busy_events = dialog_events(busy_aor);
    assert_eq!(states(&busy_events), ["terminated"], "{busy_events:?}");
    assert_eq!(
        text(&busy_events[0], "call_id"),
        header(&busy_invite, "Call-ID")
    );
    assert_eq!(states(&dialog_events(free_aor)), ["early"]);

    responds(
        &dispatcher,
        &call_id,
        free,
        &free_invite,
        200,
        "OK",
        "free-tag",
    );
    assert_eq!(states(&dialog_events(free_aor)), ["confirmed"]);
    assert!(dialog_events(busy_aor).is_empty(), "reported once");

    let sent = wire(&dispatcher);
    let answer = response_to(&sent, OUTSIDE_CALLER, 200).clone();
    bye(
        &dispatcher,
        OUTSIDE_CALLER,
        &header(&answer, "From"),
        &header(&answer, "To"),
        sip_call_id,
    );
    assert_eq!(states(&dialog_events(free_aor)), ["terminated"]);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// A call siphon places itself (`originate`) to a registered phone's Contact is
/// that phone's dialog, and the phone is its recipient.
#[tokio::test(flavor = "multi_thread")]
async fn an_originated_call_to_a_phone_is_reported_as_recipient() {
    let (aor, phone) = ("sip:2501@example.com", "198.51.100.67:5060");
    register(aor, phone);
    let dispatcher = test_dispatcher();
    let prepared = prepare_originate(
        &dispatcher.state,
        OriginateParams {
            to: format!("sip:2501@{phone}"),
            to_display: None,
            from: Some("sip:2500@example.com".to_string()),
            from_display: Some("Operator".to_string()),
            next_hop: None,
            p_asserted_identity: None,
            privacy: None,
            headers: Vec::new(),
            timeout_secs: 30,
            media: OriginateMedia::Offer {
                body: concat!(
                    "v=0\r\n",
                    "o=- 1 1 IN IP4 192.0.2.1\r\n",
                    "s=-\r\n",
                    "c=IN IP4 192.0.2.1\r\n",
                    "t=0 0\r\n",
                    "m=audio 40000 RTP/AVP 0\r\n",
                )
                .as_bytes()
                .to_vec(),
                content_type: "application/sdp".to_string(),
            },
            session_timer: None,
        },
    )
    .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));

    let invite = invites(&wire(&dispatcher))
        .into_iter()
        .find(|(destination, _)| destination == phone)
        .map(|(_, invite)| invite)
        .expect("the phone was dialled");
    let events = dialog_events(aor);
    assert_eq!(states(&events), ["trying"], "{events:?}");
    assert_eq!(text(&events[0], "direction"), "recipient");
    assert_eq!(text(&events[0], "call_id"), header(&invite, "Call-ID"));
    assert_eq!(events[0]["remote_identity"]["display_name"], "Operator");

    for (status_code, reason) in [(180, "Ringing"), (200, "OK")] {
        let response = response_for(&invite, status_code, reason, "phone-tag");
        handle_originated_call_response(
            &prepared.internal_call_id,
            &response,
            status_code,
            &dispatcher.state,
        );
    }
    let events = dialog_events(aor);
    assert_eq!(states(&events), ["early", "confirmed"], "{events:?}");
    assert_eq!(text(&events[1], "local_tag"), "phone-tag");

    dispatcher
        .state
        .call_actors
        .remove_call(&prepared.internal_call_id);
    assert_eq!(states(&dialog_events(aor)), ["terminated"]);
}

/// Steady state: every completed call a registered phone places ends with its
/// dialog terminated, and the call store — which is where each dialog's
/// tracking lives — drains back to its baseline after each one.
#[tokio::test(flavor = "multi_thread")]
async fn tracking_drains_to_baseline_after_complete_calls() {
    let (aor, phone) = ("sip:2601@example.com", "192.0.2.68:5060");
    register(aor, phone);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.dial(\"sip:15550100077@{OUTSIDE_CALLEE}\")"
    )));
    let baseline = dispatcher.state.call_actors.count();
    for round in 0..40 {
        let sip_call_id = format!("steady-{round}@192.0.2.68");
        let raw = invite_raw(
            phone,
            &sip_call_id,
            &format!("<sip:2601@example.com>;tag=steady-{round}"),
            "sip:15550100077@example.com",
        );
        let call_id = place_call(&dispatcher, phone, &raw);
        let callee_invite = invites(&wire(&dispatcher))
            .into_iter()
            .find(|(destination, _)| destination == OUTSIDE_CALLEE)
            .map(|(_, invite)| invite)
            .expect("the callee was dialled");
        responds(
            &dispatcher,
            &call_id,
            OUTSIDE_CALLEE,
            &callee_invite,
            200,
            "OK",
            "callee-tag",
        );
        let _ = wire(&dispatcher);
        // The callee hangs up.
        bye(
            &dispatcher,
            OUTSIDE_CALLEE,
            &format!("{};tag=callee-tag", header(&callee_invite, "To")),
            &header(&callee_invite, "From"),
            &header(&callee_invite, "Call-ID"),
        );
        let events = dialog_events(aor);
        assert_eq!(
            states(&events),
            ["proceeding", "confirmed", "terminated"],
            "round {round}: {events:?}"
        );
        assert_eq!(
            dispatcher.state.call_actors.count(),
            baseline,
            "round {round}: the call and its dialog tracking are released"
        );
        let _ = wire(&dispatcher);
    }
}

/// A registered phone rings out: when the ring timeout fires, the callee's
/// dialog and the calling phone's are both terminated.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_rings_out_terminates_both_phones_dialogs() {
    let (caller_aor, caller) = ("sip:2701@example.com", "192.0.2.71:5060");
    let (callee_aor, callee) = ("sip:2702@example.com", "198.51.100.72:5060");
    register(caller_aor, caller);
    register(callee_aor, callee);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.dial(\"sip:2702@{callee}\", timeout=5)"
    )));
    let raw = invite_raw(
        caller,
        "rings-out@192.0.2.71",
        "<sip:2701@example.com>;tag=ring-out-tag",
        "sip:2702@example.com",
    );
    let call_id = place_call(&dispatcher, caller, &raw);
    let callee_invite = invites(&wire(&dispatcher))
        .into_iter()
        .find(|(destination, _)| destination == callee)
        .map(|(_, invite)| invite)
        .expect("the callee was dialled");
    responds(
        &dispatcher,
        &call_id,
        callee,
        &callee_invite,
        180,
        "Ringing",
        "ringing-tag",
    );
    assert_eq!(states(&dialog_events(caller_aor)), ["proceeding", "early"]);
    assert_eq!(states(&dialog_events(callee_aor)), ["trying", "early"]);

    tokio::task::block_in_place(|| {
        check_b2bua_answer_timeouts_at(
            &dispatcher.state,
            std::time::Instant::now() + std::time::Duration::from_secs(31),
        )
    });
    let sent = wire(&dispatcher);
    assert!(
        sent.iter().any(
            |sent| sent.destination == callee && sent.message.method() == Some(&Method::Cancel)
        ),
        "the ring-out CANCELled the callee"
    );
    assert_eq!(states(&dialog_events(callee_aor)), ["terminated"]);
    assert_eq!(states(&dialog_events(caller_aor)), ["terminated"]);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// Two registered phones of a fork answer at once (RFC 3261 §16.7 glare): the
/// first 2xx wins, and the other phone — CANCELled when it lost, then ACKed and
/// BYEd for the 2xx it sent anyway — is reported terminated, never confirmed.
#[tokio::test(flavor = "multi_thread")]
async fn the_loser_of_an_answer_glare_is_never_shown_in_the_call() {
    let (winner_aor, winner) = ("sip:2801@example.com", "198.51.100.81:5060");
    let (loser_aor, loser) = ("sip:2802@example.com", "198.51.100.82:5060");
    register(winner_aor, winner);
    register(loser_aor, loser);
    let dispatcher = test_dispatcher_with_script(&script(&format!(
        "call.fork([\"sip:2801@{winner}\", \"sip:2802@{loser}\"])"
    )));
    let raw = invite_raw(
        OUTSIDE_CALLER,
        "glare@192.0.2.10",
        "<sip:15550100042@example.com>;tag=glare-caller",
        "sip:2800@siphon.example.com",
    );
    let call_id = place_call(&dispatcher, OUTSIDE_CALLER, &raw);
    let sent = invites(&wire(&dispatcher));
    let invite_to = |address: &str| {
        sent.iter()
            .find(|(destination, _)| destination == address)
            .map(|(_, invite)| invite.clone())
            .unwrap_or_else(|| panic!("no INVITE to {address}"))
    };
    let (winner_invite, loser_invite) = (invite_to(winner), invite_to(loser));

    responds(
        &dispatcher,
        &call_id,
        winner,
        &winner_invite,
        200,
        "OK",
        "won",
    );
    responds(
        &dispatcher,
        &call_id,
        loser,
        &loser_invite,
        200,
        "OK",
        "lost",
    );

    assert_eq!(states(&dialog_events(winner_aor)), ["trying", "confirmed"]);
    let loser_events = dialog_events(loser_aor);
    assert_eq!(
        states(&loser_events),
        ["trying", "terminated"],
        "{loser_events:?}"
    );
    assert!(
        wire(&dispatcher)
            .iter()
            .any(|sent| sent.destination == loser && sent.message.method() == Some(&Method::Bye)),
        "the loser's 2xx was released with a BYE"
    );
}
