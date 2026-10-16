//! The Contact a script names for a call siphon answers itself
//! (`call.answer(contact=…, contact_params=…)`, `call.progress(contact=…)`).
//!
//! A conference focus answers an INVITE to its factory URI with the URI of the
//! conference it created as its Contact, with the `isfocus` feature parameter
//! (RFC 4579 §5.1, §5.2). That Contact is the caller's remote target from then
//! on (RFC 3261 §12.1.2), so the caller's in-dialog requests are addressed to
//! the conference URI and still have to reach the call.
//!
//! Driven through the dispatcher's own send path and request entry point, with
//! what siphon sent read back off the UDP egress.

use std::sync::Arc;

use super::dial_bridge_test_harness::caller_invite;
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const FOCUS: &str = "<sip:conf-7@conf.example.com>;isfocus";

/// A script on the B2BUA path, so the dispatcher hands an in-dialog request to
/// the call it belongs to.
const B2BUA_SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    pass\n",
);

const SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

struct Focus {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    internal_call_id: String,
    invite: SipMessage,
    call_id: String,
}

/// A caller's INVITE, on the call siphon holds for it, not yet answered.
fn unanswered(call_id: &str) -> Focus {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(B2BUA_SCRIPT);
    let invite = caller_invite(call_id, CALLER);
    let mut leg = Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: socket(CALLER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.remote_contact = invite
        .headers
        .get("Contact")
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
    leg.dialog.local_from_uri = invite
        .headers
        .to()
        .map(|to| format!("{to};tag={}", leg.dialog.local_tag));
    leg.dialog.remote_to_uri = invite.headers.from().cloned();
    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    Focus {
        state: Arc::new(state),
        udp,
        internal_call_id,
        invite,
        call_id: call_id.to_string(),
    }
}

impl Focus {
    fn respond(&self, code: u16, reason: &str, final_response: bool) -> SipMessage {
        assert!(send_uas_response(
            &self.state,
            &self.internal_call_id,
            &self.invite,
            code,
            reason,
            Some(SDP.as_bytes().to_vec()),
            Some("application/sdp"),
            final_response,
            &[],
        ));
        let sent = drain(&self.udp);
        sent.into_iter()
            .find(|sent| sent.message.status_code() == Some(code))
            .unwrap_or_else(|| panic!("siphon sent the caller a {code}"))
            .message
    }

    /// The caller sends `method` in its dialog to `request_uri`, its remote
    /// target, through the dispatcher's entry point.
    fn caller_sends(
        &self,
        answer: &SipMessage,
        method: &str,
        cseq: &str,
        request_uri: &str,
    ) -> Vec<Sent> {
        let raw = format!(
            concat!(
                "{method} {ruri} SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}-{branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq}\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            method = method,
            ruri = request_uri,
            address = CALLER,
            branch = method.to_ascii_lowercase(),
            from = answer.headers.from().expect("a From"),
            to = answer.headers.to().expect("a To"),
            call_id = self.call_id,
            cseq = cseq,
        );
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: socket("192.0.2.1:5060"),
            remote_addr: socket(CALLER),
            data: Bytes::from(raw),
        };
        tokio::task::block_in_place(|| super::inbound::handle_inbound(inbound, &self.state));
        drain(&self.udp)
    }
}

fn contact(message: &SipMessage) -> String {
    message
        .headers
        .get("Contact")
        .cloned()
        .expect("the response has a Contact")
}

/// The focus's 2xx carries the conference URI with `isfocus` as its Contact,
/// where the caller that INVITEd the factory URI reads it (RFC 4579 §5.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_carries_the_contact_the_script_named() {
    let focus = unanswered("uas-contact-2xx@192.0.2.10");
    assert!(focus
        .state
        .call_actors
        .set_a_leg_local_contact(&focus.internal_call_id, FOCUS.to_string()));
    let answer = focus.respond(200, "OK", true);
    assert_eq!(contact(&answer), FOCUS);
}

/// So does an early-dialog provisional: the Contact is the dialog's.
#[tokio::test(flavor = "multi_thread")]
async fn an_18x_carries_the_contact_the_script_named() {
    let focus = unanswered("uas-contact-18x@192.0.2.10");
    assert!(focus
        .state
        .call_actors
        .set_a_leg_local_contact(&focus.internal_call_id, FOCUS.to_string()));
    let progress = focus.respond(183, "Session Progress", false);
    assert_eq!(contact(&progress), FOCUS);
    let answer = focus.respond(200, "OK", true);
    assert_eq!(contact(&answer), FOCUS, "the 2xx keeps the early dialog's");
}

/// Without one, siphon's own address, as before.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_script_contact_the_2xx_carries_siphons_address() {
    let focus = unanswered("uas-contact-none@192.0.2.10");
    let answer = focus.respond(200, "OK", true);
    assert_eq!(contact(&answer), "<sip:192.0.2.1:5060;transport=udp>");
}

/// The caller's BYE, sent to the conference URI it now holds as the remote
/// target, reaches the call and ends it.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_to_the_named_contact_reaches_the_call() {
    let focus = unanswered("uas-contact-bye@192.0.2.10");
    assert!(focus
        .state
        .call_actors
        .set_a_leg_local_contact(&focus.internal_call_id, FOCUS.to_string()));
    let answer = focus.respond(200, "OK", true);
    focus.caller_sends(&answer, "ACK", "1 ACK", "sip:conf-7@conf.example.com");
    let sent = focus.caller_sends(&answer, "BYE", "2 BYE", "sip:conf-7@conf.example.com");
    let statuses: Vec<_> = sent
        .iter()
        .filter(|sent| sent.destination == socket(CALLER))
        .filter_map(|sent| sent.message.status_code())
        .collect();
    assert_eq!(statuses, vec![200], "the BYE is answered in the dialog");
    assert!(
        focus
            .state
            .call_actors
            .get_call(&focus.internal_call_id)
            .is_none(),
        "the call is over"
    );
}
