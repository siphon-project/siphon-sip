use super::*;
use crate::control::protocol::{ControlResult, EventFrame};

fn app_cfg(name: &str) -> ControlAppConfig {
    ControlAppConfig {
        name: name.to_string(),
        token: "tok".to_string(),
        per_call_connect: false,
        connect_url: None,
        on_lost: Some("hangup".to_string()),
        ca_file: None,
        events: Vec::new(),
    }
}

fn test_bus(depth: usize, policy: SlowConsumerPolicy) -> Arc<ControlBus> {
    let (command_tx, _command_rx) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![app_cfg("ivr-app")],
        depth,
        policy,
        10,
        3000,
    )
}

fn stasis_start(channel: &str, app: &str) -> EventFrame {
    EventFrame::new(
        "StasisStart",
        channel,
        app,
        "call-uuid",
        "sipcid",
        serde_json::json!({}),
    )
}

#[test]
fn authenticate_token_matches_configured_app() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    assert_eq!(bus.authenticate_token("tok").as_deref(), Some("ivr-app"));
    assert!(bus.authenticate_token("wrong").is_none());
    assert!(bus.authenticate_token("").is_none());
}

#[test]
fn register_and_pick_connection() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    assert_eq!(bus.app_count(), 0);
    let conn = bus.register_connection("ivr-app");
    assert_eq!(bus.app_count(), 1);
    assert_eq!(bus.app_connection_count("ivr-app"), 1);
    let picked = bus.pick_connection("ivr-app").unwrap();
    assert_eq!(picked.id, conn.id);
    assert!(bus.pick_connection("other-app").is_none());
}

#[test]
fn round_robin_pick_rotates() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let a = bus.register_connection("ivr-app");
    let b = bus.register_connection("ivr-app");
    let first = bus.pick_connection("ivr-app").unwrap().id;
    let second = bus.pick_connection("ivr-app").unwrap().id;
    assert_ne!(first, second);
    let mut ids = [first, second];
    ids.sort_unstable();
    let mut expected = [a.id, b.id];
    expected.sort_unstable();
    assert_eq!(ids, expected);
}

#[test]
fn offer_assigns_exactly_one_owner() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    let outcome = bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    assert_eq!(outcome, OfferOutcome::Assigned);
    assert_eq!(bus.channel_count(), 1);
    // Exactly one owner: the round-robin winner got the StasisStart.
    assert_eq!(conn.events.depth(), 1);
    match bus.owns("ch1", "ivr-app", conn.id) {
        Ownership::Owned(channel) => assert_eq!(channel.call_actor_id, "call-uuid"),
        other => panic!("expected owned, got {other:?}"),
    }
}

#[test]
fn offer_without_connection_reports_no_controller() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let outcome = bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    assert_eq!(outcome, OfferOutcome::NoController);
    assert_eq!(bus.channel_count(), 0);
}

#[test]
fn cross_app_target_is_forbidden() {
    let (command_tx, _rx) = flume::unbounded();
    let bus = ControlBus::new(
        command_tx,
        vec![app_cfg("ivr-app"), app_cfg("other")],
        16,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    );
    let owner = bus.register_connection("ivr-app");
    let intruder = bus.register_connection("other");
    bus.register_channel("ch1", &owner, "call", "sipcid", "hangup", HashMap::new());
    assert!(matches!(
        bus.owns("ch1", "ivr-app", owner.id),
        Ownership::Owned(_)
    ));
    assert_eq!(bus.owns("ch1", "other", intruder.id), Ownership::Forbidden);
    assert_eq!(bus.owns("nope", "ivr-app", owner.id), Ownership::Unknown);
}

#[tokio::test]
async fn cancel_while_parked_emits_stasis_end_and_drains() {
    // Models the teardown the CANCEL path (`handle_b2bua_cancel`) now runs
    // for a handed-over call the caller CANCELs before the controller acts:
    // control_notify_terminated → on_call_terminated. The owning app must be
    // told (StasisEnd) and every bus entry must drain — the leak the report
    // flagged (channel/app_calls/owner cleaned only on app disconnect).
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid@h",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    assert_eq!(bus.channel_count(), 1);
    assert_eq!(bus.owned_channels("ivr-app").len(), 1);

    // Caller CANCEL, keyed on the A-leg Call-ID.
    bus.on_call_terminated("sipcid@h", "cancelled");

    // The owning connection received StasisStart then StasisEnd(cancelled).
    let frames = conn.events.recv_many().await;
    let stasis_end = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
            _ => None,
        })
        .expect("owning app must receive StasisEnd on CANCEL");
    assert_eq!(stasis_end.payload["reason"], "cancelled");
    assert_eq!(stasis_end.channel.as_deref(), Some("ch1"));

    // Every per-call entry drained to baseline (no leak).
    assert_eq!(bus.channel_count(), 0, "channel leaked after CANCEL");
    assert!(
        bus.owned_channels("ivr-app").is_empty(),
        "app_calls leaked after CANCEL"
    );
}

#[tokio::test]
async fn release_channel_emits_stasis_end_routed_and_drains() {
    // The `route` return-control path: the controller hands the call back to
    // siphon. The owning app must be told (StasisEnd{reason:"routed"}) and the
    // bus must drain — but unlike a hangup, the underlying call lives on
    // (siphon dials the B-leg). Keyed by channel id (not sip_call_id).
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid@h",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    assert_eq!(bus.channel_count(), 1);
    assert_eq!(
        bus.channel_id_for_sip_call_id("sipcid@h").as_deref(),
        Some("ch1")
    );

    assert!(bus.release_channel("ch1", "routed"));

    let frames = conn.events.recv_many().await;
    let stasis_end = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
            _ => None,
        })
        .expect("owning app must receive StasisEnd on release");
    assert_eq!(stasis_end.payload["reason"], "routed");
    assert_eq!(stasis_end.channel.as_deref(), Some("ch1"));

    // Every per-call entry drained to baseline (no leak).
    assert_eq!(bus.channel_count(), 0, "channel leaked after release");
    assert!(
        bus.owned_channels("ivr-app").is_empty(),
        "app_calls leaked after release"
    );
    assert!(bus.channel_id_for_sip_call_id("sipcid@h").is_none());
    // Idempotent: a second release is a clean no-op.
    assert!(!bus.release_channel("ch1", "routed"));
}

/// Steady-state leak gate for the return-control (`route`) path: N cycles of
/// register-conn + offer-channel + release-channel → both maps drain to their
/// starting `len()`. The co-located analogue of `mem_leak_test.sh` gating
/// `siphon_proxy_dialog_sessions → 0`, for the release path specifically.
#[test]
fn release_channel_steady_state_drains_to_baseline() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    assert_eq!(bus.channel_count(), 0);

    for cycle in 0..5 {
        let mut conns = Vec::new();
        for index in 0..8 {
            let conn = bus.register_connection("ivr-app");
            let channel = format!("ch-{cycle}-{index}");
            bus.offer_channel(
                "ivr-app",
                &channel,
                &format!("call-{cycle}-{index}"),
                &format!("sip-{cycle}-{index}"),
                "hangup",
                HashMap::new(),
                serde_json::json!({}),
            );
            conns.push((conn, channel));
        }
        assert_eq!(bus.channel_count(), 8);

        for (conn, channel) in conns {
            // Return control to siphon (the call lives on) rather than hangup.
            assert!(bus.release_channel(&channel, "routed"));
            if let Some(fanout) = bus.apps.get(&conn.app) {
                fanout.remove(conn.id);
            }
            conn.events.close();
            bus.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
        }

        assert_eq!(bus.channel_count(), 0, "channels leaked on cycle {cycle}");
        assert_eq!(bus.app_count(), 0, "apps leaked on cycle {cycle}");
        assert!(
            bus.app_calls.is_empty(),
            "app_calls index leaked on cycle {cycle}"
        );
    }
}

#[tokio::test]
async fn forward_dtmf_pushes_event_to_owning_connection() {
    // An in-band DTMF digit on a controlled call reaches the owning
    // connection as a ChannelDtmfReceived event carrying the digit + tag,
    // additive to (never in place of) the @rtpengine.on_dtmf dispatch.
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid@h",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    assert_eq!(bus.channel_count(), 1);

    // The media call-id equals the SIP Call-ID for a control-anchored call.
    assert!(bus.forward_dtmf("sipcid@h", "5", 120, -8, "ftag-a"));

    let frames = conn.events.recv_many().await;
    let dtmf = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "ChannelDtmfReceived" => Some(event),
            _ => None,
        })
        .expect("owning app must receive ChannelDtmfReceived");
    assert_eq!(dtmf.channel.as_deref(), Some("ch1"));
    assert_eq!(dtmf.call_id.as_deref(), Some("call-uuid"));
    assert_eq!(dtmf.sip_call_id.as_deref(), Some("sipcid@h"));
    assert_eq!(dtmf.payload["digit"], "5");
    assert_eq!(dtmf.payload["duration_ms"], 120);
    assert_eq!(dtmf.payload["volume"], -8);
    assert_eq!(dtmf.payload["from_tag"], "ftag-a");

    // Additive: forwarding neither creates nor removes per-call state.
    assert_eq!(
        bus.channel_count(),
        1,
        "forward_dtmf must not touch channel state"
    );
    assert_eq!(bus.owned_channels("ivr-app").len(), 1);
}

#[test]
fn forward_dtmf_on_uncontrolled_call_is_clean_noop() {
    // A DTMF event for a call no control app owns must be a silent no-op —
    // no panic, no state change, nothing pushed.
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    assert!(!bus.forward_dtmf("unknown-cid", "1", 100, 0, "ftag"));
    assert_eq!(conn.events.depth(), 0, "no event for an uncontrolled call");
    assert_eq!(bus.channel_count(), 0);
}

#[tokio::test]
async fn forward_transfer_requested_pushes_event_to_owning_connection() {
    // An inbound REFER on a controlled call reaches the owning connection as a
    // TransferRequested event carrying the Refer-To target, embedded Replaces,
    // and the referring party's from_tag — the app owns the decision.
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid@h",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );

    let refer_to = crate::sip::headers::refer::ReferTo {
        uri: "sip:carol@example.com".to_string(),
        replaces: Some(crate::sip::headers::refer::Replaces {
            call_id: "xfer-dialog".to_string(),
            from_tag: "peer-ft".to_string(),
            to_tag: "peer-tt".to_string(),
            early_only: false,
        }),
    };
    assert!(bus.forward_transfer_requested("ch1", "sipcid@h", &refer_to, Some("alice-tag")));

    let frames = conn.events.recv_many().await;
    let transfer = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "TransferRequested" => Some(event),
            _ => None,
        })
        .expect("owning app must receive TransferRequested");
    assert_eq!(transfer.channel.as_deref(), Some("ch1"));
    assert_eq!(transfer.call_id.as_deref(), Some("call-uuid"));
    assert_eq!(transfer.sip_call_id.as_deref(), Some("sipcid@h"));
    assert_eq!(transfer.payload["refer_to"], "sip:carol@example.com");
    assert_eq!(transfer.payload["from_tag"], "alice-tag");
    assert_eq!(transfer.payload["replaces"]["call_id"], "xfer-dialog");
    assert_eq!(transfer.payload["replaces"]["to_tag"], "peer-tt");
    assert_eq!(transfer.payload["replaces"]["early_only"], false);

    // Emitting the event neither creates nor removes per-call state (the
    // pending REFER lives in the dispatcher's store, not here).
    assert_eq!(
        bus.channel_count(),
        1,
        "forward_transfer_requested must not touch channel state"
    );
}

#[test]
fn forward_transfer_requested_on_uncontrolled_call_is_clean_noop() {
    // A REFER for a call no control app owns is a silent no-op — nothing
    // pushed, no state change (the dispatcher then runs the Python path).
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    let refer_to = crate::sip::headers::refer::ReferTo {
        uri: "sip:carol@example.com".to_string(),
        replaces: None,
    };
    assert!(!bus.forward_transfer_requested("unknown-ch", "unknown-cid", &refer_to, None));
    assert_eq!(conn.events.depth(), 0, "no event for an uncontrolled call");
    assert_eq!(bus.channel_count(), 0);
}

// -----------------------------------------------------------------------
// Outbound-REFER verdicts (`TransferProgress` / `TransferCompleted` /
// `TransferFailed`) — the far-end outcome of the `refer` verb.
// -----------------------------------------------------------------------

/// Drain the transfer verdicts a connection received, as
/// `(event_name, stage, code, attempt)`.
async fn transfer_events(
    conn: &Arc<ConnHandle>,
) -> Vec<(String, String, Option<u64>, Option<u64>)> {
    conn.events
        .recv_many()
        .await
        .into_iter()
        .filter_map(|frame| match frame {
            OutboundFrame::Event(event)
                if event.event.starts_with("Transfer") && event.event != "TransferRequested" =>
            {
                Some((
                    event.event.clone(),
                    event.payload["stage"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    event.payload["code"].as_u64(),
                    event.payload["attempt"].as_u64(),
                ))
            }
            _ => None,
        })
        .collect()
}

fn controlled_bus() -> (Arc<ControlBus>, Arc<ConnHandle>) {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid@h",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    (bus, conn)
}

#[test]
fn transfer_stage_wire_tokens_event_names_and_terminality() {
    // The three event names an app subscribes to, and which stages are
    // terminal (exactly one terminal verdict per outbound REFER).
    let progress = [
        (TransferStage::Accepted, "accepted"),
        (TransferStage::Challenged, "challenged"),
        (TransferStage::Notify, "notify"),
    ];
    for (stage, token) in progress {
        assert_eq!(stage.as_str(), token);
        assert_eq!(stage.event_name(), "TransferProgress");
        assert!(!stage.is_terminal(), "{token} must not end the transfer");
    }
    assert_eq!(TransferStage::Transferred.as_str(), "transferred");
    assert_eq!(TransferStage::Transferred.event_name(), "TransferCompleted");
    assert!(TransferStage::Transferred.is_terminal());
    let failures = [
        (TransferStage::Refused, "refused"),
        (TransferStage::Rejected, "rejected"),
        (TransferStage::Unauthorized, "unauthorized"),
        (TransferStage::NoOutcome, "no_outcome"),
        (TransferStage::CallEnded, "call_ended"),
    ];
    for (stage, token) in failures {
        assert_eq!(stage.as_str(), token);
        assert_eq!(stage.event_name(), "TransferFailed");
        assert!(stage.is_terminal(), "{token} must end the transfer");
    }
}

#[test]
fn refer_2xx_is_accepted_for_processing_never_completion() {
    // RFC 3515 §2.4.4: a 2xx to a REFER says the referee took it on, not
    // that the transfer happened. Reporting it as TransferCompleted would
    // call every failed transfer a success — the whole point of the split.
    for status in [200, 202, 299] {
        let stage = TransferStage::from_refer_response(status, false);
        assert_eq!(stage, TransferStage::Accepted);
        assert_eq!(stage.event_name(), "TransferProgress");
        assert!(!stage.is_terminal());
    }
}

#[test]
fn refer_challenge_answered_is_progress_unanswered_is_failure() {
    // The same 401/407 status means two opposite things; only whether a
    // credentialed retry went out separates them.
    for status in [401, 407] {
        assert_eq!(
            TransferStage::from_refer_response(status, true),
            TransferStage::Challenged
        );
        assert_eq!(
            TransferStage::from_refer_response(status, false),
            TransferStage::Unauthorized
        );
    }
    // Anything else final is a plain refusal, retry flag or not.
    for status in [403, 404, 480, 603] {
        assert_eq!(
            TransferStage::from_refer_response(status, true),
            TransferStage::Rejected
        );
        assert_eq!(
            TransferStage::from_refer_response(status, false),
            TransferStage::Rejected
        );
    }
}

#[test]
fn notify_classification_covers_every_terminating_body() {
    // Terminating NOTIFY: the sipfrag status is the outcome.
    assert_eq!(
        TransferStage::from_notify(true, Some(200)),
        Some(TransferStage::Transferred)
    );
    assert_eq!(
        TransferStage::from_notify(true, Some(486)),
        Some(TransferStage::Refused)
    );
    // A terminating NOTIFY with no usable outcome is still terminal — it
    // must never read as success, and must never leave the app waiting.
    assert_eq!(
        TransferStage::from_notify(true, None),
        Some(TransferStage::NoOutcome)
    );
    assert_eq!(
        TransferStage::from_notify(true, Some(100)),
        Some(TransferStage::NoOutcome)
    );
    // Non-terminating: progress when readable, nothing to report otherwise.
    assert_eq!(
        TransferStage::from_notify(false, Some(180)),
        Some(TransferStage::Notify)
    );
    assert_eq!(TransferStage::from_notify(false, None), None);
}

#[test]
fn transfer_outcome_payload_shape() {
    let outcome = TransferOutcome::new(TransferStage::Challenged)
        .with_refer_to("sip:carol@example.net")
        .with_status(407, "Proxy Authentication Required")
        .with_attempt(2);
    let payload = outcome.payload();
    assert_eq!(payload["stage"], "challenged");
    assert_eq!(payload["refer_to"], "sip:carol@example.net");
    assert_eq!(payload["code"], 407);
    assert_eq!(payload["reason"], "Proxy Authentication Required");
    assert_eq!(payload["attempt"], 2);
    // An empty reason phrase (RFC 3261 §25.1 permits one) is omitted rather
    // than published as "".
    let bare = TransferOutcome::new(TransferStage::Rejected).with_status(603, "");
    assert!(bare.payload()["reason"].is_null());
    assert!(bare.payload()["refer_to"].is_null());
    assert!(bare.payload()["attempt"].is_null());
}

#[tokio::test]
async fn outbound_refer_accepted_then_progress_then_completed() {
    // The full happy path: the referee 202s the REFER (progress), NOTIFYs
    // 100 Trying (progress), then terminates the subscription with a
    // sipfrag 200 (RFC 3515 §2.4.4) — only THAT is the completion.
    let (bus, conn) = controlled_bus();
    let target = "sip:carol@example.net";

    assert!(bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(202, false))
            .with_refer_to(target)
            .with_status(202, "Accepted")
            .with_attempt(1),
    ));
    let notify = TransferStage::from_notify(false, Some(100)).expect("progress NOTIFY");
    assert!(bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(notify).with_status(100, "Trying"),
    ));
    let done = TransferStage::from_notify(true, Some(200)).expect("terminating NOTIFY");
    assert!(bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(done).with_status(200, "OK"),
    ));

    let events = transfer_events(&conn).await;
    assert_eq!(
        events
            .iter()
            .map(|(event, stage, ..)| (event.as_str(), stage.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("TransferProgress", "accepted"),
            ("TransferProgress", "notify"),
            ("TransferCompleted", "transferred"),
        ]
    );
    assert_eq!(events[0].2, Some(202));
    assert_eq!(events[0].3, Some(1));
    assert_eq!(events[2].2, Some(200));

    // The terminal verdict disarmed the teardown flush: no second, bogus
    // TransferFailed when the call later ends.
    bus.on_call_terminated("sipcid@h", "bye");
    assert!(transfer_events(&conn).await.is_empty());
}

#[tokio::test]
async fn outbound_refer_accepted_then_refused() {
    // Accepted for processing, then the referee reports the target refused
    // it. An app that stopped at the 202 would have called this a success.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(202, false))
            .with_refer_to("sip:carol@example.net")
            .with_status(202, "Accepted")
            .with_attempt(1),
    );
    let refused = TransferStage::from_notify(true, Some(486)).expect("terminating NOTIFY");
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(refused).with_status(486, "Busy Here"),
    );

    let events = transfer_events(&conn).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, "TransferProgress");
    assert_eq!(events[1].0, "TransferFailed");
    assert_eq!(events[1].1, "refused");
    assert_eq!(events[1].2, Some(486), "the sipfrag status must ride along");
}

#[tokio::test]
async fn outbound_refer_challenged_retried_then_completed() {
    // The carrier challenges, siphon answers with credentials, the retry is
    // accepted and the transfer completes. The challenge must read as
    // progress carrying the attempt number, not as a refusal.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(407, true))
            .with_refer_to("sip:carol@example.net")
            .with_status(407, "Proxy Authentication Required")
            .with_attempt(1),
    );
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(202, false))
            .with_refer_to("sip:carol@example.net")
            .with_status(202, "Accepted")
            .with_attempt(2),
    );
    let done = TransferStage::from_notify(true, Some(200)).expect("terminating NOTIFY");
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(done).with_status(200, "OK"),
    );

    let events = transfer_events(&conn).await;
    assert_eq!(
        events
            .iter()
            .map(|(event, stage, code, attempt)| (event.as_str(), stage.as_str(), *code, *attempt))
            .collect::<Vec<_>>(),
        vec![
            ("TransferProgress", "challenged", Some(407), Some(1)),
            ("TransferProgress", "accepted", Some(202), Some(2)),
            ("TransferCompleted", "transferred", Some(200), None),
        ]
    );
}

#[tokio::test]
async fn outbound_refer_unretryable_challenge_is_terminal_failure() {
    // Challenged with no way to answer (no credentials / unparseable
    // challenge / retry cap): terminal, and distinguishable from the
    // retried case by the event name + stage despite the identical status.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(407, false))
            .with_refer_to("sip:carol@example.net")
            .with_status(407, "Proxy Authentication Required")
            .with_attempt(3),
    );

    let events = transfer_events(&conn).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "TransferFailed");
    assert_eq!(events[0].1, "unauthorized");
    assert_eq!(events[0].2, Some(407));
    assert_eq!(events[0].3, Some(3), "the attempt count must ride along");

    // Terminal means terminal: the teardown flush was disarmed.
    bus.on_call_terminated("sipcid@h", "bye");
    assert!(transfer_events(&conn).await.is_empty());
}

#[tokio::test]
async fn outbound_refer_rejected_outright_is_terminal_failure() {
    // The referee refuses the REFER itself: the transfer never started.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::from_refer_response(603, false))
            .with_refer_to("sip:carol@example.net")
            .with_status(603, "Decline")
            .with_attempt(1),
    );
    let events = transfer_events(&conn).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        (events[0].0.as_str(), events[0].1.as_str()),
        ("TransferFailed", "rejected")
    );
    assert_eq!(events[0].2, Some(603));
}

#[tokio::test]
async fn outbound_refer_outstanding_at_teardown_reports_failed_before_stasis_end() {
    // A transfer that can never complete: the referee accepted the REFER,
    // then the call went away before any terminating NOTIFY. The implicit
    // subscription lives in the dialog (RFC 3515 §2.4.4), so no verdict can
    // ever arrive — the app must get a terminal one anyway, and it must
    // arrive before the StasisEnd that ends the stream.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::Accepted)
            .with_refer_to("sip:carol@example.net")
            .with_status(202, "Accepted")
            .with_attempt(1),
    );
    bus.on_call_terminated("sipcid@h", "bye");

    let names: Vec<String> = conn
        .events
        .recv_many()
        .await
        .into_iter()
        .filter_map(|frame| match frame {
            OutboundFrame::Event(event) => Some(event.event),
            _ => None,
        })
        .collect();
    let failed = names
        .iter()
        .position(|name| name == "TransferFailed")
        .expect("a transfer left pending by teardown must be reported failed");
    let ended = names
        .iter()
        .position(|name| name == "StasisEnd")
        .expect("StasisEnd still fires");
    assert!(
        failed < ended,
        "the verdict must precede StasisEnd: {names:?}"
    );
    // Everything drained — the flush marker lives on the channel entry.
    assert_eq!(bus.channel_count(), 0);
}

#[tokio::test]
async fn outbound_refer_outstanding_at_release_reports_failed() {
    // Same guarantee on the other channel-removal funnel: the controller
    // handed the call back to siphon (`route`) mid-transfer.
    let (bus, conn) = controlled_bus();
    bus.forward_transfer_outcome(
        "sipcid@h",
        &TransferOutcome::new(TransferStage::Accepted).with_refer_to("sip:carol@example.net"),
    );
    assert!(bus.release_channel("ch1", "routed"));

    let events = transfer_events(&conn).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].0, "TransferFailed");
    assert_eq!(events[1].1, "call_ended");
    assert_eq!(bus.channel_count(), 0);
}

#[test]
fn forward_transfer_outcome_on_uncontrolled_call_is_clean_noop() {
    // A transfer verdict for a call no control app owns: silent no-op, no
    // panic, no state (the in-process transfer path is unaffected).
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    assert!(!bus.forward_transfer_outcome(
        "unknown-cid",
        &TransferOutcome::new(TransferStage::Transferred).with_status(200, "OK"),
    ));
    assert_eq!(conn.events.depth(), 0, "no event for an uncontrolled call");
    assert_eq!(bus.channel_count(), 0);
}

#[test]
fn outbound_transfer_marker_drains_to_baseline() {
    // Steady-state leak gate for the one piece of per-call state this adds:
    // N transfers armed and torn down leave the channel map at baseline.
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    assert_eq!(bus.channel_count(), 0);
    for cycle in 0..5 {
        let conn = bus.register_connection("ivr-app");
        for index in 0..8 {
            let channel = format!("ch-{cycle}-{index}");
            let sip_call_id = format!("sip-{cycle}-{index}");
            bus.register_channel(
                &channel,
                &conn,
                &format!("call-{cycle}-{index}"),
                &sip_call_id,
                "hangup",
                HashMap::new(),
            );
            // Arm (non-terminal), then end the call without a verdict.
            bus.forward_transfer_outcome(
                &sip_call_id,
                &TransferOutcome::new(TransferStage::Accepted).with_refer_to("sip:c@example.net"),
            );
            bus.on_call_terminated(&sip_call_id, "bye");
        }
        assert_eq!(bus.channel_count(), 0, "channels leaked on cycle {cycle}");
        if let Some(fanout) = bus.apps.get(&conn.app) {
            fanout.remove(conn.id);
        }
        conn.events.close();
        bus.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
    }
    assert!(bus.app_calls.is_empty(), "app_calls index leaked");
}

#[test]
fn per_call_vars_get_set_and_drain() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel("ch1", &conn, "call", "sipcid", "hangup", HashMap::new());
    assert!(bus.set_var("ch1", "queue", "support"));
    assert_eq!(bus.get_var("ch1", "queue").as_deref(), Some("support"));
    assert!(!bus.set_var("nope", "k", "v"));
    bus.remove_channel("ch1");
    assert_eq!(bus.get_var("ch1", "queue"), None);
}

#[tokio::test]
async fn resync_enumerates_and_reattaches_owned_channels() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let first = bus.register_connection("ivr-app");
    bus.offer_channel(
        "ivr-app",
        "ch1",
        "call-uuid",
        "sipcid",
        "hangup",
        HashMap::new(),
        serde_json::json!({}),
    );
    // Owner disconnects; the channel is orphaned but not (yet) torn down.
    bus.unregister_connection(&first);
    assert_eq!(bus.channel_count(), 1);
    assert!(!bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app")));

    // A fresh connection of the same app resyncs and re-claims it.
    let second = bus.register_connection("ivr-app");
    let owned = bus.reattach(&second);
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].channel_id, "ch1");
    // Now events route to the reattached connection.
    assert!(bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app")));
    assert_eq!(second.events.depth(), 1);
}

#[tokio::test]
async fn ordering_events_and_replies_share_one_queue_in_order() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel("ch1", &conn, "call", "sipcid", "hangup", HashMap::new());
    // Interleave an event, a reply, an event — the single queue preserves
    // submission order for the call.
    bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app"));
    conn.events.push_reply(
        ControlResult::Ok(serde_json::json!({"ok": true})).into_reply("c-1".to_string()),
    );
    bus.publish_to_channel(
        "ch1",
        EventFrame::new(
            "StasisEnd",
            "ch1",
            "ivr-app",
            "call",
            "sipcid",
            serde_json::json!({}),
        ),
    );
    let drained = conn.events.recv_many().await;
    assert_eq!(drained.len(), 3);
    assert!(matches!(drained[0], OutboundFrame::Event(_)));
    assert!(matches!(drained[1], OutboundFrame::Reply(_)));
    assert!(matches!(drained[2], OutboundFrame::Event(_)));
}

#[tokio::test]
async fn reply_never_dropped_even_when_event_queue_full() {
    let queue = OutboundQueue::new(2, SlowConsumerPolicy::DropOldest);
    let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
    queue.try_push_event(event());
    queue.try_push_event(event());
    // Queue full of events; a reply must still get in (an event is dropped).
    queue.push_reply(ControlResult::Ok(serde_json::json!({})).into_reply("c-9".to_string()));
    let drained = queue.recv_many().await;
    assert!(drained
        .iter()
        .any(|frame| matches!(frame, OutboundFrame::Reply(_))));
    assert_eq!(queue.dropped_count(), 1);
}

/// Steady-state leak gate: N cycles of register-conn + offer-channel +
/// hangup + disconnect → both maps drain to their starting `len()`. The
/// co-located analogue of `mem_leak_test.sh` gating
/// `siphon_proxy_dialog_sessions → 0`.
#[test]
fn steady_state_drains_to_baseline() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    assert_eq!(bus.app_count(), 0);
    assert_eq!(bus.channel_count(), 0);

    for cycle in 0..5 {
        let mut conns = Vec::new();
        for index in 0..8 {
            let conn = bus.register_connection("ivr-app");
            let channel = format!("ch-{cycle}-{index}");
            let sip_call_id = format!("sip-{cycle}-{index}");
            bus.register_channel(
                &channel,
                &conn,
                &format!("call-{cycle}-{index}"),
                &sip_call_id,
                "hangup",
                HashMap::new(),
            );
            bus.publish_to_channel(&channel, stasis_start(&channel, "ivr-app"));
            conns.push((conn, channel, sip_call_id));
        }
        assert_eq!(bus.channel_count(), 8);
        assert_eq!(bus.app_connection_count("ivr-app"), 8);

        for (position, (conn, channel, sip_call_id)) in conns.into_iter().enumerate() {
            // Alternate the teardown trigger: half via a direct hangup
            // (remove_channel), half via the CANCEL/BYE path
            // (on_call_terminated by sip_call_id) — the latter is what the
            // report's leak fix restored on the CANCEL-while-parked path.
            if position % 2 == 0 {
                bus.remove_channel(&channel);
            } else {
                bus.on_call_terminated(&sip_call_id, "cancelled");
            }
            // Directly remove the fanout entry (no grace timer in a
            // non-tokio test context).
            if let Some(fanout) = bus.apps.get(&conn.app) {
                fanout.remove(conn.id);
            }
            conn.events.close();
            bus.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
        }

        assert_eq!(bus.channel_count(), 0, "channels leaked on cycle {cycle}");
        assert_eq!(bus.app_count(), 0, "apps leaked on cycle {cycle}");
        assert!(
            bus.app_calls.is_empty(),
            "app_calls index leaked on cycle {cycle}"
        );
    }
}

#[test]
fn event_queue_bounded_drop_oldest() {
    let queue = OutboundQueue::new(2, SlowConsumerPolicy::DropOldest);
    let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
    assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
    assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
    assert_eq!(queue.try_push_event(event()), PushOutcome::DroppedOldest);
    assert_eq!(queue.try_push_event(event()), PushOutcome::DroppedOldest);
    assert_eq!(queue.depth(), 2, "queue must stay bounded at capacity");
    assert_eq!(queue.dropped_count(), 2);
    assert!(!queue.disconnect_requested());
}

#[test]
fn event_queue_disconnect_policy_flags_slow_consumer() {
    let queue = OutboundQueue::new(1, SlowConsumerPolicy::Disconnect);
    let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
    assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
    assert_eq!(
        queue.try_push_event(event()),
        PushOutcome::OverflowDisconnect
    );
    assert!(queue.disconnect_requested());
    assert_eq!(queue.depth(), 1, "queue must stay bounded at capacity");
}

#[test]
fn publishing_never_blocks_a_stuck_consumer() {
    // A consumer that never drains: publishing must return immediately and
    // the queue must stay bounded rather than grow without limit.
    let bus = test_bus(4, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel("ch", &conn, "call", "sipcid", "hangup", HashMap::new());
    for _ in 0..1000 {
        bus.publish_to_channel("ch", stasis_start("ch", "ivr-app"));
    }
    assert_eq!(conn.events.depth(), 4);
    assert_eq!(conn.events.dropped_count(), 996);
}

// --- originate support -------------------------------------------------

#[test]
fn channel_exists_is_the_duplicate_id_gate() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    assert!(!bus.channel_exists("cb-1"));
    bus.register_channel(
        "cb-1",
        &conn,
        "call-uuid",
        "sipcid",
        "hangup",
        HashMap::new(),
    );
    assert!(bus.channel_exists("cb-1"));
    bus.remove_channel("cb-1");
    assert!(
        !bus.channel_exists("cb-1"),
        "the id must be free again after teardown"
    );
}

#[test]
fn connection_for_command_resolves_only_a_live_owner() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    assert_eq!(
        bus.connection_for_command("ivr-app", conn.id).map(|c| c.id),
        Some(conn.id)
    );
    assert!(bus
        .connection_for_command("ivr-app", conn.id + 99)
        .is_none());
    assert!(bus.connection_for_command("other-app", conn.id).is_none());
    bus.unregister_connection(&conn);
    assert!(
        bus.connection_for_command("ivr-app", conn.id).is_none(),
        "a closed connection must never be handed a new channel to own"
    );
}

#[test]
fn forward_channel_event_reaches_the_owner_by_sip_call_id() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel(
        "cb-1",
        &conn,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );

    assert!(bus.forward_channel_event(
        "sipcid@host",
        "ChannelStateChange",
        serde_json::json!({ "state": "ringing", "code": 180 }),
    ));
    let frames = futures_executor_block_on_recv(&conn);
    let event = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "ChannelStateChange" => Some(event),
            _ => None,
        })
        .expect("ChannelStateChange must be queued");
    assert_eq!(event.channel.as_deref(), Some("cb-1"));
    assert_eq!(event.sip_call_id.as_deref(), Some("sipcid@host"));
    assert_eq!(event.payload["state"], "ringing");

    // An uncontrolled call is a silent no-op, never a panic.
    assert!(!bus.forward_channel_event("nobody@host", "ChannelStateChange", serde_json::json!({})));
}

#[test]
fn stasis_end_carries_the_sip_cause_when_one_is_known() {
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel(
        "cb-1",
        &conn,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );

    bus.on_call_terminated_with_cause("sipcid@host", "rejected", Some(486), Some("Busy Here"));
    let frames = futures_executor_block_on_recv(&conn);
    let event = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
            _ => None,
        })
        .expect("StasisEnd must be queued");
    assert_eq!(event.payload["reason"], "rejected");
    assert_eq!(event.payload["code"], 486);
    assert_eq!(event.payload["response"], "Busy Here");
    assert!(
        !bus.channel_exists("cb-1"),
        "the channel must drain with the call"
    );
}

#[test]
fn stasis_end_without_a_cause_is_byte_identical_to_the_legacy_frame() {
    // Regression guard: adding the cause must not change the frame an
    // ordinary BYE-driven teardown emits.
    let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
    let conn = bus.register_connection("ivr-app");
    bus.register_channel(
        "cb-1",
        &conn,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );
    bus.on_call_terminated("sipcid@host", "bye");
    let frames = futures_executor_block_on_recv(&conn);
    let event = frames
        .iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
            _ => None,
        })
        .expect("StasisEnd must be queued");
    assert_eq!(event.payload, serde_json::json!({ "reason": "bye" }));
}

/// Drain a connection's queue without an async runtime: the queue is
/// already populated by the synchronous `try_push_event`, so one poll is
/// enough.
fn futures_executor_block_on_recv(conn: &Arc<ConnHandle>) -> Vec<OutboundFrame> {
    conn.events.close();
    let mut frames = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        frames = conn.events.recv_many().await;
    });
    frames
}
