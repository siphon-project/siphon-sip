//! `route` on the target of the transfer verbs that place a new leg.
//!
//! `accept_refer` (mode `terminate`) and `replace_peer` take the route set a
//! `dial` target takes, in the same shape and under the same rules: a transfer's
//! new leg goes back through the proxy that gave the route, not to wherever the
//! target resolves. The key used to be dropped without a word.

use super::transfer::{accept_refer, accept_refer_command, parse_transfer_dial, replace_peer};
use super::*;
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;

fn channel() -> ChannelRef {
    ChannelRef {
        channel_id: "ch1".to_string(),
        call_actor_id: "call-uuid".to_string(),
        sip_call_id: "sipcid@host".to_string(),
        app: "ivr-app".to_string(),
    }
}

fn bad_request_message(result: &ControlResult) -> String {
    match result {
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            message,
            ..
        } => message.clone(),
        other => panic!("expected bad_request, got {other:?}"),
    }
}

fn refused_as_bad_request(verb: &str, args: &serde_json::Value) -> String {
    match parse_transfer_dial(verb, args) {
        Err(refusal) => bad_request_message(&refusal),
        Ok(_) => panic!("{verb} accepted {args}"),
    }
}

/// A `{uri, route}` target puts its route set on the dial, in order, for both
/// verbs; a target naming none, a `null` one, or a bare URI has none.
#[test]
fn a_uri_target_carries_its_route_set_into_the_replacement_dial() {
    for verb in ["accept_refer", "replace_peer"] {
        let transfer = parse_transfer_dial(
            verb,
            &serde_json::json!({
                "target": {
                    "uri": "sip:+15550100@ims.example.test",
                    "route": [
                        "<sip:term@scscf.example.test;lr;odi=4f1c>",
                        "<sip:198.51.100.51:5080;lr>",
                    ],
                },
            }),
        )
        .unwrap_or_else(|refusal| panic!("{verb} was refused: {refusal:?}"));
        assert_eq!(
            transfer.target.as_deref(),
            Some("sip:+15550100@ims.example.test")
        );
        assert_eq!(
            transfer.dial.route,
            [
                "<sip:term@scscf.example.test;lr;odi=4f1c>",
                "<sip:198.51.100.51:5080;lr>"
            ],
            "{verb}"
        );

        for bare in [
            serde_json::json!({ "target": { "uri": "sip:+15550100@ims.example.test" } }),
            serde_json::json!({ "target": { "uri": "sip:+15550100@ims.example.test", "route": null } }),
            serde_json::json!({ "target": { "uri": "sip:+15550100@ims.example.test", "route": [] } }),
            serde_json::json!({ "target": "sip:+15550100@ims.example.test" }),
        ] {
            let transfer = parse_transfer_dial(verb, &bare)
                .unwrap_or_else(|refusal| panic!("{bare} was refused: {refusal:?}"));
            assert!(transfer.dial.route.is_empty(), "{verb} {bare}");
        }
    }
}

/// A route set siphon cannot put on the wire is refused, not dropped: the new
/// leg sent without it goes somewhere else entirely.
#[test]
fn a_transfer_refuses_a_route_set_it_cannot_send() {
    for verb in ["accept_refer", "replace_peer"] {
        for route in [
            serde_json::json!("<sip:term@scscf.example.test;lr>"),
            serde_json::json!({ "0": "<sip:term@scscf.example.test;lr>" }),
            serde_json::json!(true),
            serde_json::json!([42]),
            serde_json::json!(["not a uri"]),
            // RFC 3261 §25.1: a Route entry is a name-addr.
            serde_json::json!(["sip:198.51.100.51:5080;lr"]),
            serde_json::json!(["<sip:a.example.test;lr>, <sip:b.example.test;lr>"]),
        ] {
            let message = refused_as_bad_request(
                verb,
                &serde_json::json!({
                    "target": { "uri": "sip:+15550100@ims.example.test", "route": route },
                }),
            );
            assert!(message.contains("route"), "{verb} {route}: {message}");
        }
    }
}

/// An AoR's contacts are reached over their own binding's Path, so a route set
/// beside one is refused rather than replacing or extending it. The positive
/// control is the same AoR without one.
#[test]
fn an_aor_target_refuses_a_route_set() {
    crate::script::api::test_registrar()
        .save(
            "sip:txroute1@siphon.example.com",
            crate::sip::parser::parse_uri_standalone("sip:txroute1@198.51.100.71:5060")
                .expect("a contact URI"),
            3600,
            1.0,
            "register-txroute1".to_string(),
            1,
        )
        .expect("the binding saves");
    for verb in ["accept_refer", "replace_peer"] {
        let message = refused_as_bad_request(
            verb,
            &serde_json::json!({
                "target": {
                    "aor": "sip:txroute1@siphon.example.com",
                    "route": ["<sip:term@scscf.example.test;lr>"],
                },
            }),
        );
        assert!(
            message.contains("route") && message.contains("Path"),
            "{verb}: {message}"
        );
        assert!(
            parse_transfer_dial(
                verb,
                &serde_json::json!({ "target": { "aor": "sip:txroute1@siphon.example.com" } }),
            )
            .is_ok(),
            "{verb}"
        );
    }
}

/// A transparent transfer relays the REFER and dials no leg, so a route set on
/// its target would be accepted and never used.
#[test]
fn a_transparent_transfer_refuses_a_route_set() {
    let result = accept_refer(
        &channel(),
        &serde_json::json!({
            "mode": "transparent",
            "target": { "uri": "sip:c@example.com", "route": ["<sip:term@scscf.example.test;lr>"] },
        }),
    );
    assert!(
        bad_request_message(&result).contains("transparent"),
        "{result:?}"
    );
}

/// `mode: "controller"` dials nothing: a target with a route inside it is
/// refused by the same rule that refuses the target.
#[test]
fn a_controller_transfer_refuses_a_target_with_a_route_set() {
    let result = accept_refer_command(
        &channel(),
        &AdapterCommand {
            verb: "accept_refer".to_string(),
            args: serde_json::json!({
                "mode": "controller",
                "target": { "uri": "sip:c@example.com", "route": ["<sip:term@scscf.example.test;lr>"] },
            }),
            target: ResolvedTarget::Channel(channel()),
            origin: crate::control::CommandOrigin {
                app: "ivr-app".to_string(),
                conn_id: 1,
            },
        },
    );
    match result {
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            details: Some(details),
            ..
        } => assert_eq!(details["argument"], "target"),
        other => panic!("expected a typed bad_request, got {other:?}"),
    }
}

/// A malformed route set is refused by the verbs themselves, before the call is
/// touched.
#[test]
fn the_transfer_verbs_refuse_a_malformed_route_set_as_bad_request() {
    let args = serde_json::json!({
        "target": { "uri": "sip:c@example.com", "route": "nope" },
    });
    assert!(bad_request_message(&replace_peer(&channel(), &args)).contains("route"));
    assert!(bad_request_message(&accept_refer(&channel(), &args)).contains("route"));
}

/// `Route` is framework-managed on a B-leg: a `headers` entry for it would
/// replace the validated route set after the destination was chosen from it. It
/// is refused, in any case, on the verb or on a target, for every verb that
/// places a leg.
#[test]
fn a_route_in_headers_is_refused_beside_the_route_set() {
    for verb in ["accept_refer", "replace_peer"] {
        for headers in [
            serde_json::json!({ "Route": "<sip:other.example.test;lr>" }),
            serde_json::json!({ "route": "<sip:other.example.test;lr>" }),
        ] {
            let message = refused_as_bad_request(
                verb,
                &serde_json::json!({
                    "target": {
                        "uri": "sip:+15550100@ims.example.test",
                        "route": ["<sip:term@scscf.example.test;lr>"],
                    },
                    "headers": headers,
                }),
            );
            assert!(message.contains("Route"), "{verb}: {message}");
        }
        // Positive control: another header is fine.
        assert!(parse_transfer_dial(
            verb,
            &serde_json::json!({
                "target": "sip:+15550100@ims.example.test",
                "headers": { "X-Account": "main" },
            }),
        )
        .is_ok());
    }
}

/// `dial` and `route` took a `Route` in `headers` as well, and replaced the
/// route set with it: refused for them too, on the verb and on a target.
#[test]
fn dial_and_route_refuse_a_route_in_headers() {
    let route = "<sip:other.example.test;lr>";
    for (verb, args) in [
        (
            "dial",
            serde_json::json!({ "targets": ["sip:201@example.com"], "headers": { "Route": route } }),
        ),
        (
            "dial",
            serde_json::json!({ "targets": [{ "uri": "sip:201@example.com", "headers": { "route": route } }] }),
        ),
        (
            "dial",
            serde_json::json!({ "targets": [{ "aor": "sip:nobody@pbx.example", "headers": { "Route": route } }] }),
        ),
        (
            "route",
            serde_json::json!({ "targets": ["sip:201@example.com"], "headers": { "Route": route } }),
        ),
        (
            "route",
            serde_json::json!({ "targets": [{ "uri": "sip:201@example.com", "headers": { "Route": route } }] }),
        ),
    ] {
        let result = sip_command_for(verb, args.clone());
        assert!(
            bad_request_message(&result).contains("Route"),
            "{verb} {args}: {result:?}"
        );
    }
}

fn sip_command_for(verb: &str, args: serde_json::Value) -> ControlResult {
    apply_sip(AdapterCommand {
        verb: verb.to_string(),
        args,
        target: ResolvedTarget::Channel(channel()),
        origin: crate::control::CommandOrigin {
            app: "ivr-app".to_string(),
            conn_id: 1,
        },
    })
}

/// RFC 3261 §20.34: a Route entry may carry a display name, and a quoted one
/// may hold a comma. One entry, accepted by `dial` and both transfer verbs; two
/// real entries in one string are still refused.
#[test]
fn a_route_entry_with_a_quoted_comma_is_one_entry() {
    use super::routing::parse_dial_target;
    for entry in [
        r#""Edge, west" <sip:198.51.100.51;lr>"#,
        r#""Say \"hi, there\"" <sip:198.51.100.51;lr>"#,
        "<sip:198.51.100.51;lr;x=a,b>",
    ] {
        let target =
            serde_json::json!({ "uri": "sip:+15550100@ims.example.test", "route": [entry] });
        let dialled = parse_dial_target(&target).unwrap_or_else(|error| panic!("{entry}: {error}"));
        assert_eq!(dialled[0].route, [entry], "dial");
        for verb in ["accept_refer", "replace_peer"] {
            let transfer = parse_transfer_dial(verb, &serde_json::json!({ "target": target }))
                .unwrap_or_else(|refusal| panic!("{verb} {entry}: {refusal:?}"));
            assert_eq!(transfer.dial.route, [entry], "{verb}");
        }
    }
    for two in [
        r#""A, B" <sip:a.example.test;lr>, <sip:b.example.test;lr>"#,
        "<sip:a.example.test;lr>, <sip:b.example.test;lr>",
    ] {
        let target = serde_json::json!({ "uri": "sip:+15550100@ims.example.test", "route": [two] });
        let error = parse_dial_target(&target).expect_err("two entries");
        assert!(error.contains("exactly one"), "{two}: {error}");
        assert!(
            refused_as_bad_request("replace_peer", &serde_json::json!({ "target": target }))
                .contains("exactly one")
        );
    }
}
