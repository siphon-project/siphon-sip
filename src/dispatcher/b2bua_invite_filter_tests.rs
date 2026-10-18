//! `@b2bua.on_invite(request_uri=...)`: a process that is a B2BUA for some
//! INVITEs and a proxy for the rest.
//!
//! The script below takes the INVITEs for `sip:transfer@...` as B2BUA calls and
//! proxies every other one. Driven through the dispatcher's own entry points,
//! with what siphon puts on the UDP egress read back off the wire.

use super::proxy_dialog_state_tests::{
    header, headers, in_dialog, invite, invites_by_destination, knows_itself, response_to, Proxy,
    Sent,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const CALLER: &str = "192.0.2.91:5060";
const CALLEE: &str = "198.51.100.20:5060";
/// The callee's Contact. Its user part matches the B2BUA's filter, so a request
/// on the proxied dialog addresses a URI the filter matches.
const CALLEE_CONTACT: &str = "sip:transfer@198.51.100.20:5060";

const MIXED: &str = concat!(
    "from siphon import b2bua, proxy\n",
    "\n",
    "@b2bua.on_invite(request_uri=r\"^sip:transfer@example\\.com\")\n",
    "def take(call):\n",
    "    call.dial(\"sip:bob@198.51.100.30:5060\")\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    if request.in_dialog:\n",
    "        request.loose_route()\n",
    "        request.relay()\n",
    "        return\n",
    "    request.record_route()\n",
    "    request.fork([\"sip:bob@198.51.100.20:5060\"])\n",
);

fn mixed() -> Proxy {
    let mut dispatcher = test_dispatcher_with_script(MIXED);
    knows_itself(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

const CALLER_FROM: &str = "<sip:alice@example.com>;tag=caller-tag";

fn sent_to<'a>(wire: &'a [Sent], destination: &str) -> Vec<&'a SipMessage> {
    wire.iter()
        .filter(|sent| sent.destination == destination)
        .map(|sent| &sent.message)
        .collect()
}

fn describe(wire: &[Sent]) -> Vec<String> {
    wire.iter()
        .map(|sent| {
            format!(
                "{} {}",
                sent.destination,
                String::from_utf8_lossy(&sent.message.to_bytes())
            )
        })
        .collect()
}

/// A proxied INVITE answered by the callee: the INVITE the callee got and the
/// 200 OK it sent.
fn proxied_and_answered(proxy: &Proxy, call_id: &str) -> (SipMessage, SipMessage) {
    proxy.request(
        CALLER,
        &invite(CALLER, call_id, CALLER_FROM, "sip:bob@example.com"),
    );
    let wire = proxy.wire();
    let relayed = invites_by_destination(&wire)
        .into_iter()
        .find(|(destination, _)| destination == CALLEE)
        .map(|(_, message)| message)
        .unwrap_or_else(|| panic!("the INVITE was proxied: {:?}", describe(&wire)));
    let answer = response_to(&relayed, 200, "OK", "callee-tag", CALLEE_CONTACT, "");
    proxy.response(CALLEE, answer.clone());
    let wire = proxy.wire();
    assert!(
        sent_to(&wire, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200)),
        "the 200 OK reached the caller: {:?}",
        describe(&wire)
    );
    (relayed, answer)
}

/// The caller's in-dialog request on the proxied dialog, along its route set.
fn caller_in_dialog(method: &str, relayed: &SipMessage, answer: &SipMessage, cseq: u32) -> String {
    in_dialog(
        method,
        CALLEE_CONTACT,
        CALLER,
        CALLER_FROM,
        &header(answer, "To"),
        &header(relayed, "Call-ID"),
        &headers(answer, "Record-Route"),
        cseq,
    )
}

/// An INVITE no filter matches is proxied as in a script with no B2BUA
/// handlers, and so is the rest of its dialog: the ACK, a re-INVITE whose
/// Request-URI the filter would match, and the BYE. No B2BUA call is made.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_no_filter_matches_is_proxied_with_its_whole_dialog() {
    let proxy = mixed();
    let (relayed, answer) = proxied_and_answered(&proxy, "proxied-dialog@192.0.2.91");
    assert_eq!(proxy.state.call_actors.count(), 0, "no B2BUA call");

    proxy.request(CALLER, &caller_in_dialog("ACK", &relayed, &answer, 5));
    let wire = proxy.wire();
    assert!(
        sent_to(&wire, CALLEE)
            .iter()
            .any(|message| message.method() == Some(&Method::Ack)),
        "the 2xx ACK was proxied: {:?}",
        describe(&wire)
    );

    // In-dialog, to a Request-URI the B2BUA's filter matches: still the proxy's.
    proxy.request(CALLER, &caller_in_dialog("INVITE", &relayed, &answer, 6));
    let wire = proxy.wire();
    let reinvite = sent_to(&wire, CALLEE)
        .into_iter()
        .find(|message| message.method() == Some(&Method::Invite))
        .unwrap_or_else(|| panic!("the re-INVITE was proxied: {:?}", describe(&wire)))
        .clone();
    assert_eq!(header(&reinvite, "Call-ID"), header(&relayed, "Call-ID"));
    assert_eq!(proxy.state.call_actors.count(), 0, "no B2BUA call");
    proxy.response(
        CALLEE,
        response_to(&reinvite, 200, "OK", "callee-tag", CALLEE_CONTACT, ""),
    );
    let _ = proxy.wire();
    proxy.request(CALLER, &caller_in_dialog("ACK", &relayed, &answer, 6));
    let _ = proxy.wire();

    proxy.request(CALLER, &caller_in_dialog("BYE", &relayed, &answer, 7));
    let wire = proxy.wire();
    let bye = sent_to(&wire, CALLEE)
        .into_iter()
        .find(|message| message.method() == Some(&Method::Bye))
        .unwrap_or_else(|| panic!("the BYE was proxied: {:?}", describe(&wire)))
        .clone();
    proxy.response(
        CALLEE,
        response_to(&bye, 200, "OK", "callee-tag", CALLEE_CONTACT, ""),
    );
    let wire = proxy.wire();
    assert!(
        sent_to(&wire, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200)
                && header(message, "CSeq").ends_with("BYE")),
        "the BYE's 200 OK reached the caller: {:?}",
        describe(&wire)
    );
    assert_eq!(proxy.state.call_actors.count(), 0);
}

/// An INVITE a filter matches is a B2BUA call: the handler dials, and the
/// proxy handler never sees it.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_a_filter_matches_is_a_b2bua_call() {
    let proxy = mixed();
    proxy.request(
        CALLER,
        &invite(
            CALLER,
            "claimed@192.0.2.91",
            CALLER_FROM,
            "sip:transfer@example.com",
        ),
    );
    let wire = proxy.wire();
    assert_eq!(proxy.state.call_actors.count(), 1, "a B2BUA call");
    let invites = invites_by_destination(&wire);
    assert!(
        invites
            .iter()
            .any(|(destination, _)| destination == "198.51.100.30:5060"),
        "the B2BUA dialled its B-leg: {:?}",
        describe(&wire)
    );
    assert!(
        invites.iter().all(|(destination, _)| destination != CALLEE),
        "the proxy handler did not run: {:?}",
        describe(&wire)
    );
}

/// A CANCEL of a proxied INVITE in a process that also hosts B2BUA calls is
/// the proxy's, as in a script with no B2BUA handlers: the caller is answered
/// 200 and 487, the branch is CANCELled, and the callee's 487 is ACKed and not
/// forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn a_proxied_invite_is_cancelled_by_the_proxy() {
    let proxy = mixed();
    let call_id = "proxied-cancel@192.0.2.91";
    let raw_invite = invite(CALLER, call_id, CALLER_FROM, "sip:bob@example.com");
    proxy.request(CALLER, &raw_invite);
    let wire = proxy.wire();
    let relayed = invites_by_destination(&wire)
        .into_iter()
        .find(|(destination, _)| destination == CALLEE)
        .map(|(_, message)| message)
        .unwrap_or_else(|| panic!("the INVITE was proxied: {:?}", describe(&wire)));
    proxy.response(
        CALLEE,
        response_to(&relayed, 180, "Ringing", "callee-tag", CALLEE_CONTACT, ""),
    );
    let _ = proxy.wire();

    let cancel = raw_invite
        .replacen("INVITE sip:", "CANCEL sip:", 1)
        .replace("CSeq: 5 INVITE", "CSeq: 5 CANCEL");
    proxy.request(CALLER, &cancel);
    let wire = proxy.wire();
    let to_caller: Vec<_> = sent_to(&wire, CALLER)
        .iter()
        .filter_map(|message| message.status_code())
        .collect();
    assert_eq!(to_caller, [200, 487], "{:?}", describe(&wire));
    assert!(
        sent_to(&wire, CALLEE)
            .iter()
            .any(|message| message.method() == Some(&Method::Cancel)),
        "the CANCEL went downstream: {:?}",
        describe(&wire)
    );

    proxy.response(
        CALLEE,
        response_to(
            &relayed,
            487,
            "Request Terminated",
            "callee-tag",
            CALLEE_CONTACT,
            "",
        ),
    );
    let wire = proxy.wire();
    assert!(
        sent_to(&wire, CALLEE)
            .iter()
            .any(|message| message.method() == Some(&Method::Ack)),
        "the 487 is ACKed: {:?}",
        describe(&wire)
    );
    assert!(
        sent_to(&wire, CALLER).is_empty(),
        "the caller already has its 487: {:?}",
        describe(&wire)
    );
    assert_eq!(proxy.state.call_actors.count(), 0);
    assert!(
        proxy.state.completed_invites.is_empty(),
        "the proxy's own transaction answers a retransmitted INVITE"
    );
}

/// A rejection the proxy relays is not kept for the B2BUA's retransmission
/// handling: the proxy's INVITE server transaction has it.
#[tokio::test(flavor = "multi_thread")]
async fn a_proxied_rejection_is_not_kept_as_a_b2bua_final_response() {
    let proxy = mixed();
    proxy.request(
        CALLER,
        &invite(
            CALLER,
            "proxied-busy@192.0.2.91",
            CALLER_FROM,
            "sip:bob@example.com",
        ),
    );
    let wire = proxy.wire();
    let relayed = invites_by_destination(&wire)
        .into_iter()
        .find(|(destination, _)| destination == CALLEE)
        .map(|(_, message)| message)
        .unwrap_or_else(|| panic!("the INVITE was proxied: {:?}", describe(&wire)));
    proxy.response(
        CALLEE,
        response_to(&relayed, 486, "Busy Here", "callee-tag", CALLEE_CONTACT, ""),
    );
    let wire = proxy.wire();
    assert!(
        sent_to(&wire, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(486)),
        "the 486 reached the caller: {:?}",
        describe(&wire)
    );
    assert!(proxy.state.completed_invites.is_empty());
}
