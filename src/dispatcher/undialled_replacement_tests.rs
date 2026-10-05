//! A leg replacement none of whose targets could be dialled.
//!
//! An answered call between two registered phones, and a replacement of the
//! callee whose target resolves to nowhere: no INVITE reaches the transport.
//! Driven through the dispatcher's own entry points on a test dispatcher and
//! read off the UDP egress and the channel events published for the call.
//!
//! A REFER that was accepted is owed the NOTIFY that ends its subscription
//! (RFC 3515 §2.4.5) whether or not anything was dialled for it, and a
//! replacement that ended must not hold off the next one.

use super::dialog_state_events_tests::{header, inbound, wire, Sent};
use super::dialog_state_transfer_tests::{establish, in_dialog, sent_invite_to, Established};
use super::*;
use crate::b2bua::transfer::{ReplaceError, ReplacementOrigin};
use crate::control::channel_event_capture;

/// A target no INVITE can be sent to: not a URI siphon can resolve.
const NOWHERE: &str = "http://example.com/not-a-sip-target";

fn body(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

fn summaries(sent: &[Sent]) -> Vec<String> {
    sent.iter()
        .map(|sent| {
            let what = match (sent.message.method(), sent.message.status_code()) {
                (Some(method), _) => method.as_str().to_string(),
                (None, Some(status_code)) => status_code.to_string(),
                (None, None) => "?".to_string(),
            };
            format!("{what} {}", sent.destination)
        })
        .collect()
}

/// The callee sends a REFER naming `target`, which the call's script accepts
/// for siphon to dial.
fn callee_refers_to(call: &Established, target: &str, cseq: u32) {
    let (raw, message) = in_dialog(
        "REFER",
        call.b.1,
        &format!("{};tag=b-tag", header(&call.to_b, "To")),
        &header(&call.to_b, "From"),
        &header(&call.to_b, "Call-ID"),
        cseq,
        &format!("Refer-To: <{target}>\r\n"),
    );
    tokio::task::block_in_place(|| {
        handle_b2bua_refer(inbound(call.b.1, &raw), message, &call.dispatcher.state)
    });
}

/// The call's two original parties, no other leg, and no replacement open.
fn assert_intact(call: &Established) {
    let held = call
        .dispatcher
        .state
        .call_actors
        .get_call(&call.call_id())
        .expect("the call is kept");
    assert_eq!(held.state, CallState::Answered);
    assert_eq!(held.a_leg.dialog.call_id, call.a_call_id);
    assert_eq!(held.b_legs.len(), 1, "no target leg is left on the call");
    assert_eq!(
        held.winning_b_leg().map(|leg| leg.dialog.call_id.clone()),
        Some(header(&call.to_b, "Call-ID"))
    );
    assert!(
        held.refer_subscriptions.is_empty(),
        "the replacement is over"
    );
}

fn replace_callee(
    call: &Established,
    target: &str,
    dial: &ReplacementDial,
) -> Result<(), ReplaceError> {
    tokio::task::block_in_place(|| {
        b2bua_replace_peer_with_state(
            &call.dispatcher.state,
            &call.a_call_id,
            target,
            None,
            false,
            None,
            None,
            30,
            dial,
        )
    })
}

/// A REFER is accepted and its target cannot be dialled: the referrer gets the
/// `202`, the `100 Trying` NOTIFY, and then a NOTIFY ending the subscription
/// with a `503` sipfrag. Nobody is dialled, the call keeps both its parties,
/// the application hears one `ReplaceFailed`, and the call takes a replacement
/// afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_whose_target_cannot_be_dialled_is_notified_it_failed() {
    let call = establish(9500, "terminate");
    channel_event_capture::watch(&call.a_call_id);
    let _ = wire(&call.dispatcher);

    callee_refers_to(&call, NOWHERE, 2);
    let sent = wire(&call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [
            format!("202 {}", call.b.1),
            format!("NOTIFY {}", call.b.1),
            format!("NOTIFY {}", call.b.1),
        ],
        "the REFER is answered, the subscription opened and ended, and nobody dialled"
    );
    let trying = &sent[1].message;
    assert_eq!(header(trying, "Event"), "refer;id=2");
    assert!(header(trying, "Subscription-State").starts_with("active"));
    assert_eq!(body(trying), "SIP/2.0 100 Trying\r\n");
    let failed = &sent[2].message;
    assert_eq!(header(failed, "Call-ID"), header(&call.to_b, "Call-ID"));
    assert_eq!(header(failed, "Event"), "refer;id=2");
    assert_eq!(
        header(failed, "Subscription-State"),
        "terminated;reason=noresource"
    );
    assert_eq!(header(failed, "Content-Type"), "message/sipfrag");
    assert_eq!(body(failed), "SIP/2.0 503 Service Unavailable\r\n");

    let events = channel_event_capture::take(&call.a_call_id);
    assert_eq!(
        events
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["ReplaceFailed"]
    );
    assert_eq!(events[0].1["status"], 503);
    assert_eq!(events[0].1["call_kept"], true);
    assert_eq!(events[0].1["origin"], "refer");
    assert_intact(&call);

    // The call is as it was: a replacement of the same party is dialled.
    assert_eq!(
        replace_callee(&call, &call.c_uri(), &ReplacementDial::default()),
        Ok(())
    );
    let _ = sent_invite_to(&wire(&call.dispatcher), call.c.1);
}

/// `replace_peer` naming a target that cannot be dialled is refused, with
/// nothing sent and no event, and leaves no replacement behind: the next one
/// on the call is dialled, not refused as already in flight.
#[tokio::test(flavor = "multi_thread")]
async fn a_replacement_that_dials_nothing_does_not_hold_off_the_next() {
    let call = establish(9550, "terminate");
    channel_event_capture::watch(&call.a_call_id);
    let _ = wire(&call.dispatcher);

    assert_eq!(
        replace_callee(&call, NOWHERE, &ReplacementDial::default()),
        Err(ReplaceError::Unroutable {
            target: NOWHERE.to_string()
        })
    );
    assert!(
        wire(&call.dispatcher).is_empty(),
        "nobody subscribed, so nobody is notified"
    );
    assert!(
        channel_event_capture::take(&call.a_call_id).is_empty(),
        "the refusal is the verb's reply"
    );
    assert_intact(&call);

    assert_eq!(
        replace_callee(&call, &call.c_uri(), &ReplacementDial::default()),
        Ok(()),
        "the first replacement is over"
    );
    let _ = sent_invite_to(&wire(&call.dispatcher), call.c.1);
}

/// Several targets, none of which can be dialled, fail the replacement once.
#[tokio::test(flavor = "multi_thread")]
async fn several_targets_none_of_them_dialled_fail_the_replacement_once() {
    let call = establish(9600, "terminate");
    channel_event_capture::watch(&call.a_call_id);
    let call_id = call.call_id();
    let _ = wire(&call.dispatcher);

    let dial = ReplacementDial {
        also: vec![
            ReplacementContact {
                uri: "http://example.com/second".to_string(),
                ..Default::default()
            },
            ReplacementContact {
                uri: "http://example.com/third".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let dialled = tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &call_id,
            false,
            NOWHERE,
            None,
            None,
            None,
            None,
            None,
            7,
            ReplacementOrigin::Refer,
            30,
            &dial,
            &call.dispatcher.state,
        )
    });
    assert!(!dialled);
    let sent = wire(&call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [format!("NOTIFY {}", call.b.1)],
        "one terminating NOTIFY, however many targets there were"
    );
    assert_eq!(header(&sent[0].message, "Event"), "refer;id=7");
    assert_eq!(
        body(&sent[0].message),
        "SIP/2.0 503 Service Unavailable\r\n"
    );
    assert_eq!(channel_event_capture::take(&call.a_call_id).len(), 1);
    assert_intact(&call);
}

/// Of several targets, the ones that could be dialled carry on when another
/// could not: nothing is failed, and the one that answers is brought in.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_was_dialled_carries_on_when_another_was_not() {
    let call = establish(9650, "terminate");
    channel_event_capture::watch(&call.a_call_id);
    let call_id = call.call_id();
    let _ = wire(&call.dispatcher);

    let dial = ReplacementDial {
        also: vec![ReplacementContact {
            uri: call.c_uri(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let dialled = tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &call_id,
            false,
            NOWHERE,
            None,
            None,
            None,
            None,
            None,
            3,
            ReplacementOrigin::Refer,
            30,
            &dial,
            &call.dispatcher.state,
        )
    });
    assert!(dialled, "one INVITE reached the transport");
    let sent = wire(&call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [format!("INVITE {}", call.c.1)],
        "the target that resolves rings, and nothing is reported failed"
    );
    assert!(channel_event_capture::take(&call.a_call_id).is_empty());
    let open = call
        .dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .map(|held| {
            held.refer_subscriptions
                .iter()
                .map(|subscription| subscription.targets.len())
                .collect::<Vec<_>>()
        });
    assert_eq!(open, Some(vec![1]), "one replacement, one target ringing");

    // It answers, and the transfer completes as any other.
    let to_c = sent_invite_to(&sent, call.c.1);
    super::dialog_state_transfer_tests::respond(
        &call.dispatcher,
        &call_id,
        call.c.1,
        &to_c,
        super::dialog_state_transfer_tests::answer(&to_c, call.c.1, "c-tag"),
    );
    let sent = wire(&call.dispatcher);
    let notify = sent
        .iter()
        .find(|sent| sent.message.method() == Some(&Method::Notify))
        .expect("the terminating NOTIFY");
    assert_eq!(body(&notify.message), "SIP/2.0 200 OK\r\n");
    let events = channel_event_capture::take(&call.a_call_id);
    assert_eq!(
        events
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["PeerReplaced"]
    );
}
