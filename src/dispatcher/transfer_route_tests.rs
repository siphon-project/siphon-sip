//! The route set a transfer's new leg is sent through.
//!
//! An IMS application server sends the new leg of a transfer back through the
//! S-CSCF with the Route it was given (TS 24.229 §5.7.5), not to wherever the
//! target resolves. `replace_peer` and a siphon-terminated `accept_refer` carry a
//! `ReplacementDial::route` the way `dial` carries a target's `route`: it is the
//! first INVITE's Route headers, topmost first, and that INVITE goes to the
//! topmost entry unless `next_hop` pins it (RFC 3261 §8.1.2, §16.6 step 6). The
//! dialog's own route set is the 2xx's Record-Route (§12.1.2), never what the
//! INVITE was preloaded with.

use super::dialog_state_events_tests::{header, inbound, wire, Sent};
use super::dialog_state_transfer_tests::{
    answer, control_plane, establish, hang_up, in_dialog, respond, Established,
};
use super::*;
use crate::script::api::call::ReferMode;

const TOP_ENTRY: &str = "<sip:198.51.100.200:5080;lr;odi=4f1c>";
const SECOND_ENTRY: &str = "<sip:203.0.113.9:5090;lr>";
const TOP_ADDRESS: &str = "198.51.100.200:5080";
const PINNED_HOP: &str = "sip:203.0.113.77:5099";
const PINNED_ADDRESS: &str = "203.0.113.77:5099";

fn preloaded() -> ReplacementDial {
    ReplacementDial {
        route: vec![TOP_ENTRY.to_string(), SECOND_ENTRY.to_string()],
        ..Default::default()
    }
}

fn route_headers(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

fn request_uri(message: &SipMessage) -> String {
    match &message.start_line {
        StartLine::Request(request) => request.request_uri.to_string(),
        StartLine::Response(_) => panic!("a request"),
    }
}

/// `replace_peer` of the callee: the one INVITE `sent` holds, with where it went.
fn replace_callee(call: &Established, dial: &ReplacementDial, next_hop: Option<&str>) -> Sent {
    let _ = wire(&call.dispatcher);
    tokio::task::block_in_place(|| {
        b2bua_replace_peer_with_state(
            &call.dispatcher.state,
            &call.a_call_id,
            &call.c_uri(),
            next_hop,
            false,
            None,
            None,
            30,
            dial,
        )
    })
    .expect("the replacement is dialled");
    only_invite(wire(&call.dispatcher))
}

/// B refers the call to C and the application holds the REFER for a decision.
fn hold_refer(call: &Established) {
    let (bus, connection) = control_plane(&format!("transfer-route-{}", call.a_call_id));
    bus.register_channel(
        &format!("channel-{}", call.a_call_id),
        &connection,
        &call.call_id(),
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let _ = wire(&call.dispatcher);
    let (raw, message) = in_dialog(
        "REFER",
        call.b.1,
        &format!("{};tag=b-tag", header(&call.to_b, "To")),
        &header(&call.to_b, "From"),
        &header(&call.to_b, "Call-ID"),
        2,
        &format!("Refer-To: <{}>\r\n", call.c_uri()),
    );
    tokio::task::block_in_place(|| {
        handle_b2bua_refer_on(
            Some(bus.as_ref()),
            inbound(call.b.1, &raw),
            message,
            &call.dispatcher.state,
        )
    });
    let _ = wire(&call.dispatcher);
}

/// Accept the held REFER with `mode` (`None`: the configured default).
fn accept_held(
    call: &Established,
    mode: Option<ReferMode>,
    next_hop: Option<&str>,
    dial: &ReplacementDial,
) -> Result<bool, TransparentDialRefused> {
    tokio::task::block_in_place(|| {
        b2bua_accept_refer_with_state(
            &call.dispatcher.state,
            &call.a_call_id,
            None,
            next_hop.map(str::to_string),
            mode,
            None,
            None,
            dial,
        )
    })
}

/// B refers the call to C, the application holds the REFER and accepts it in
/// mode `terminate` with `dial`: the one INVITE that results.
fn accept_refer(call: &Established, dial: &ReplacementDial, next_hop: Option<&str>) -> Sent {
    hold_refer(call);
    assert_eq!(
        accept_held(call, Some(ReferMode::Terminate), next_hop, dial),
        Ok(true),
        "the held REFER was accepted"
    );
    only_invite(wire(&call.dispatcher))
}

fn only_invite(sent: Vec<Sent>) -> Sent {
    let mut found = sent
        .into_iter()
        .filter(|sent| sent.message.method() == Some(&Method::Invite))
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "exactly one INVITE: {}", found.len());
    found.remove(0)
}

/// Run `place` for both ways a transfer is placed, on a call of its own each.
fn each_verb(
    prefix: u32,
    check: impl Fn(&str, &Established, fn(&Established, &ReplacementDial, Option<&str>) -> Sent),
) {
    check(
        "replace_peer",
        &establish(prefix, "terminate"),
        replace_callee,
    );
    check(
        "accept_refer",
        &establish(prefix + 20, "terminate"),
        accept_refer,
    );
}

/// The new leg's INVITE carries the route set, topmost first, and goes to the
/// topmost entry: the Request-URI stays the target.
#[tokio::test(flavor = "multi_thread")]
async fn the_new_leg_carries_the_route_set_and_goes_to_its_topmost_entry() {
    each_verb(9700, |verb, call, place| {
        let sent = place(call, &preloaded(), None);
        assert_eq!(sent.destination, TOP_ADDRESS, "{verb}");
        assert_eq!(
            route_headers(&sent.message),
            [TOP_ENTRY, SECOND_ENTRY],
            "{verb}"
        );
        assert_eq!(request_uri(&sent.message), call.c_uri(), "{verb}");
    });
}

/// A `next_hop` pins where the INVITE goes; the route set still rides on it.
#[tokio::test(flavor = "multi_thread")]
async fn a_next_hop_pins_the_destination_and_the_route_set_stays() {
    each_verb(9760, |verb, call, place| {
        let sent = place(call, &preloaded(), Some(PINNED_HOP));
        assert_eq!(sent.destination, PINNED_ADDRESS, "{verb}");
        assert_eq!(
            route_headers(&sent.message),
            [TOP_ENTRY, SECOND_ENTRY],
            "{verb}"
        );
    });
}

/// Positive control: with no route set the leg is dialled as it was before the
/// key existed, to the target with no Route.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_route_set_the_new_leg_goes_to_the_target() {
    each_verb(9820, |verb, call, place| {
        let sent = place(call, &ReplacementDial::default(), None);
        assert_eq!(sent.destination, call.c.1, "{verb}");
        assert!(route_headers(&sent.message).is_empty(), "{verb}");
    });
}

/// The caller hangs up after the new leg answered: the BYE on the new leg.
fn bye_on_new_leg(call: &Established, to_c: &SipMessage, answer_with: SipMessage) -> Sent {
    respond(
        &call.dispatcher,
        &call.call_id(),
        call.c.1,
        to_c,
        answer_with,
    );
    let _ = wire(&call.dispatcher);
    hang_up(
        &call.dispatcher,
        call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&call.answer_to_a, "To"),
        &call.a_call_id,
    );
    let sent = wire(&call.dispatcher);
    let new_call_id = header(to_c, "Call-ID");
    sent.into_iter()
        .find(|sent| {
            sent.message.method() == Some(&Method::Bye)
                && header(&sent.message, "Call-ID") == new_call_id
        })
        .expect("a BYE on the new leg")
}

/// The dialog's route set is the 2xx's Record-Route, not the preloaded route:
/// the BYE follows the Record-Route and carries it alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_the_new_leg_follows_the_2xx_record_route() {
    const RECORD_ROUTE: &str = "<sip:198.51.100.210:5061;lr;state=new>";
    each_verb(9880, |verb, call, place| {
        let to_c = place(call, &preloaded(), None).message;
        let mut answered = answer(&to_c, call.c.1, "c-tag");
        answered
            .headers
            .set("Record-Route", RECORD_ROUTE.to_string());
        let bye = bye_on_new_leg(call, &to_c, answered);
        assert_eq!(bye.destination, "198.51.100.210:5061", "{verb}");
        assert_eq!(route_headers(&bye.message), [RECORD_ROUTE], "{verb}");
    });
}

/// With no Record-Route in the 2xx the leg has no route set, and its INVITE went
/// to a preloaded route first: the BYE is addressed to the Contact, the remote
/// target (RFC 3261 §12.2.1.1), and carries no Route, so the preloaded route was
/// not stored as the dialog's. (This pinned the INVITE's first hop as the BYE's
/// destination before proxy-first legs resolved the Contact.)
#[tokio::test(flavor = "multi_thread")]
async fn without_a_record_route_the_bye_goes_to_the_contact_with_no_route() {
    const CONTACT_ADDRESS: &str = "203.0.113.88:5099";
    each_verb(9940, |verb, call, place| {
        let to_c = place(call, &preloaded(), None).message;
        let mut answered = answer(&to_c, call.c.1, "c-tag");
        answered
            .headers
            .set("Contact", format!("<sip:phone@{CONTACT_ADDRESS}>"));
        let bye = bye_on_new_leg(call, &to_c, answered);
        assert_eq!(
            request_uri(&bye.message),
            format!("sip:phone@{CONTACT_ADDRESS}"),
            "{verb}"
        );
        assert!(route_headers(&bye.message).is_empty(), "{verb}");
        assert_eq!(bye.destination, CONTACT_ADDRESS, "{verb}");
    });
}

/// With `b2bua.default_refer_mode: transparent` and no `mode` named, the
/// transfer relays the REFER and dials nothing, so anything that shapes a dialled
/// leg is refused as it is for an explicit `"transparent"`, before the held REFER
/// is taken: it stays pending for the decision that follows.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_shaping_argument_is_refused_when_the_default_mode_is_transparent() {
    let mut call = establish(10000, "terminate");
    call.dispatcher.state.default_refer_mode = ReferMode::Transparent;
    hold_refer(&call);
    let shaped = [
        preloaded(),
        ReplacementDial {
            headers: vec![("X-Account".to_string(), "main".to_string())],
            ..Default::default()
        },
        ReplacementDial {
            aor: Some(call.c.0.to_string()),
            ..Default::default()
        },
        ReplacementDial {
            shaping: DialShaping {
                from: Some("sip:+15550100000@trunk.example.com".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
    ];
    for dial in &shaped {
        assert_eq!(
            accept_held(&call, None, None, dial),
            Err(TransparentDialRefused),
            "{dial:?}"
        );
    }
    assert!(
        wire(&call.dispatcher).is_empty(),
        "a refusal sends the referrer nothing"
    );
    // Nothing shaping a leg is accepted in the default mode, and an explicit
    // terminate takes the REFER that is still held.
    assert!(
        matches!(
            accept_held(&call, None, None, &ReplacementDial::default()),
            Ok(true)
        ),
        "the same REFER is still pending"
    );
}

/// A `Route` in `headers` is the route set's to say, not an injected header: it
/// cannot replace the Route headers the destination was chosen from.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_header_in_headers_does_not_replace_the_route_set() {
    each_verb(10060, |verb, call, place| {
        let dial = ReplacementDial {
            headers: vec![(
                "route".to_string(),
                "<sip:203.0.113.99:5099;lr>".to_string(),
            )],
            ..preloaded()
        };
        let sent = place(call, &dial, None);
        assert_eq!(sent.destination, TOP_ADDRESS, "{verb}");
        assert_eq!(
            route_headers(&sent.message),
            [TOP_ENTRY, SECOND_ENTRY],
            "{verb}"
        );
    });
}

/// The winning 2xx that carries no Record-Route leaves the dialog no route set
/// (RFC 3261 §12.1.2): a route set an early dialog's reliable provisional put on
/// the target leg does not survive it. (Main kept it on the transfer path, where
/// the ordinary answer path clears it.)
#[tokio::test(flavor = "multi_thread")]
async fn a_winning_2xx_with_no_record_route_clears_an_early_route_set() {
    each_verb(10120, |verb, call, place| {
        let to_c = place(call, &preloaded(), None).message;
        let branch = super::lcr_ring_timeout_tests::top_via_branch(&to_c);
        call.dispatcher
            .state
            .call_actors
            .get_call_mut(&call.call_id())
            .expect("the call")
            .find_b_leg_by_branch_mut(&branch)
            .expect("the target leg")
            .1
            .dialog
            .route_set = vec!["<sip:198.51.100.222:5099;lr>".to_string()];
        let answered = answer(&to_c, call.c.1, "c-tag");
        let bye = bye_on_new_leg(call, &to_c, answered);
        assert!(route_headers(&bye.message).is_empty(), "{verb}");
    });
}
