//! Registration state on the control plane: the payloads, their `seq`, and the
//! `registrations` / `outbound_registrations` verbs end to end.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::*;
use crate::config::ControlAppConfig;
use crate::control::{app_event_capture, ControlAdapter, SlowConsumerPolicy};
use crate::registrant::{RegistrantCredentials, RegistrantEntry};
use crate::registrar::ContactKind;
use crate::sip::uri::SipUri;
use crate::transport::Transport;

fn binding(user: &str) -> Contact {
    Contact {
        uri: SipUri::new("203.0.113.40".to_string()).with_user(user.to_string()),
        q: 0.5,
        registered_at: Instant::now(),
        expires_secs: 600,
        call_id: "register-call@192.0.2.50".into(),
        cseq: 42,
        source_addr: Some("192.0.2.50:41000".parse().expect("an address")),
        source_transport: Some(Transport::Tcp),
        client_transport: Some(Transport::Tls),
        sip_instance: Some("<urn:uuid:00000000-0000-1000-8000-000000000001>".into()),
        reg_id: Some(1),
        path: vec!["<sip:edge.example.com;lr>".into()].into_boxed_slice(),
        pending: false,
        instance: None,
        flow_token: None,
        inbound_local_addr: None,
        inbound_connection_id: None,
        params: Vec::new(),
        kind: ContactKind::Ue,
        auth_user: None,
    }
}

#[test]
fn a_contact_says_where_its_register_came_from() {
    let contact = binding("alice");
    let payload = contact_payload(&contact);

    assert_eq!(payload["uri"], "sip:alice@203.0.113.40");
    assert_eq!(payload["q"], 0.5);
    assert!(payload["expires"]
        .as_u64()
        .is_some_and(|expires| expires <= 600));
    // The script's Contact.received, byte for byte.
    assert_eq!(
        payload["received"], "sip:192.0.2.50:41000;transport=tcp",
        "received is the source, not the NAT'd Contact"
    );
    assert_eq!(
        payload["received"].as_str(),
        contact.received_uri().as_deref()
    );
    assert_eq!(payload["transport"], "tcp");
    assert_eq!(payload["client_transport"], "tls");
    assert_eq!(
        payload["instance"],
        "<urn:uuid:00000000-0000-1000-8000-000000000001>"
    );
    assert_eq!(payload["reg_id"], 1);
    assert_eq!(
        payload["path"],
        serde_json::json!(["<sip:edge.example.com;lr>"])
    );
    assert_eq!(payload["call_id"], "register-call@192.0.2.50");
    assert_eq!(payload["cseq"], 42);
}

#[test]
fn a_contact_without_a_source_or_a_differing_front_omits_them() {
    let mut contact = binding("bob");
    contact.source_addr = None;
    contact.source_transport = None;
    contact.client_transport = None;
    contact.sip_instance = None;
    contact.reg_id = None;
    contact.path = Box::default();
    let payload = contact_payload(&contact);

    assert!(payload["received"].is_null());
    assert!(payload["transport"].is_null());
    assert!(payload["instance"].is_null());
    assert!(payload["reg_id"].is_null());
    assert_eq!(payload["path"], serde_json::json!([]));
    assert!(
        payload.get("client_transport").is_none(),
        "client_transport is only there when it differs from the hop"
    );

    let mut same = binding("carol");
    same.client_transport = same.source_transport;
    assert!(contact_payload(&same).get("client_transport").is_none());
}

fn save(registrar: &Registrar, aor: &str, user: &str) {
    registrar
        .save_with_source(
            aor,
            SipUri::new("203.0.113.41".to_string()).with_user(user.to_string()),
            3600,
            1.0,
            format!("call-{user}"),
            7,
            Some("192.0.2.51:5060".parse().expect("an address")),
            Some(Transport::Udp),
        )
        .expect("saved");
}

fn seqs(events: &[(String, Value)]) -> Vec<u64> {
    events
        .iter()
        .map(|(_, payload)| payload["seq"].as_u64().expect("a seq"))
        .collect()
}

#[test]
fn every_registration_changed_is_numbered_and_a_loss_leaves_a_gap() {
    let registrar = Registrar::default();
    let aor = "sip:seq-check@example.com";
    app_event_capture::watch(aor);
    save(&registrar, aor, "seq-check");

    publish_registration_change(&registrar, aor, "registered");
    publish_registration_change(&registrar, aor, "refreshed");
    skip_registration_events(5);
    publish_registration_change(&registrar, aor, "snapshot");

    let events = app_event_capture::take(aor);
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|(event, _)| event == "RegistrationChanged"));
    let numbers = seqs(&events);
    assert!(numbers[1] > numbers[0], "seq rises: {numbers:?}");
    assert!(
        numbers[2] >= numbers[1] + 6,
        "the five lost events leave a gap a controller can see: {numbers:?}"
    );
    let snapshot = &events[2].1;
    assert_eq!(snapshot["event"], "snapshot");
    assert_eq!(snapshot["aor"], aor);
    assert_eq!(
        snapshot["contacts"][0]["received"],
        "sip:192.0.2.51:5060;transport=udp"
    );
    assert_eq!(snapshot["contacts"][0]["call_id"], "call-seq-check");
    assert_eq!(snapshot["contacts"][0]["cseq"], 7);
}

#[test]
fn the_registrations_reply_is_current_to_its_seq() {
    let registrar = Registrar::default();
    let aor = "sip:reply-check@example.com";
    app_event_capture::watch(aor);
    save(&registrar, aor, "reply-check");
    publish_registration_change(&registrar, aor, "registered");
    let before = seqs(&app_event_capture::take(aor))[0];

    let reply = registrations_reply(&registrar, None, DEFAULT_PAGE_LIMIT);
    let mark = reply["seq"].as_u64().expect("a seq");
    assert!(
        mark >= before,
        "an event published before the reply is covered by it"
    );
    let registrations = reply["registrations"].as_array().expect("a list");
    assert_eq!(registrations.len(), 1);
    assert_eq!(registrations[0]["aor"], aor);
    assert_eq!(
        registrations[0]["contacts"][0]["received"],
        "sip:192.0.2.51:5060;transport=udp"
    );

    // A change after the reply is numbered above it, so the controller applies
    // it on top of the reply.
    registrar.remove_all(aor);
    publish_registration_change(&registrar, aor, "deregistered");
    let after = app_event_capture::take(aor);
    assert!(seqs(&after)[0] > mark);
    assert_eq!(after[0].1["contacts"], serde_json::json!([]));
    assert_eq!(
        registrations_reply(&registrar, None, DEFAULT_PAGE_LIMIT)["registrations"],
        serde_json::json!([]),
        "an AoR with no binding left is not in the set"
    );
}

fn registrant() -> RegistrantManager {
    RegistrantManager::new(
        3600,
        Duration::from_secs(60),
        Duration::from_secs(300),
        crate::config::IdentityHeaders::default().shared(),
    )
}

fn trunk(aor: &str) -> RegistrantEntry {
    RegistrantEntry::new(
        aor.to_string(),
        "sip:registrar.example.net".to_string(),
        "192.0.2.60:5060".parse().expect("an address"),
        Transport::Udp,
        RegistrantCredentials::password("trunk".to_string(), "secret".to_string(), None),
        3600,
        None,
    )
}

#[test]
fn a_registrant_change_carries_its_state_and_is_numbered() {
    let manager = registrant();
    let aor = "sip:trunk-state@example.net";
    app_event_capture::watch(aor);
    manager.add(trunk(aor));
    manager.handle_failure(aor, 503, None);

    publish_registrant_change(&manager, aor, "failed", Some(503));
    skip_registrant_events(2);
    publish_registrant_change(&manager, aor, "snapshot", None);
    manager.handle_success(aor, 600);
    publish_registrant_change(&manager, aor, "registered", None);

    let events = app_event_capture::take(aor);
    assert!(events.iter().all(|(event, _)| event == "RegistrantChanged"));
    let failed = &events[0].1;
    assert_eq!(failed["event"], "failed");
    assert_eq!(failed["registrar"], "sip:registrar.example.net");
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["failure_count"], 1);
    assert_eq!(failed["status_code"], 503);
    assert_eq!(failed["expires_in"], 0);
    let snapshot = &events[1].1;
    assert_eq!(snapshot["event"], "snapshot");
    assert_eq!(
        snapshot["status_code"], 503,
        "a snapshot of a failed trunk says why it failed"
    );
    let registered = &events[2].1;
    assert_eq!(registered["state"], "registered");
    assert!(registered["status_code"].is_null());
    assert!(registered["expires_in"]
        .as_u64()
        .is_some_and(|left| left > 0));
    let numbers = seqs(&events);
    assert!(numbers[1] >= numbers[0] + 3, "the lost events leave a gap");
    assert!(numbers[2] > numbers[1]);

    let reply = outbound_registrations_reply(&manager, None, DEFAULT_PAGE_LIMIT);
    assert!(reply["seq"].as_u64().is_some_and(|mark| mark >= numbers[2]));
    assert_eq!(reply["registrations"][0]["aor"], aor);
    assert_eq!(reply["registrations"][0]["state"], "registered");
}

#[test]
fn a_removed_trunk_reports_no_state() {
    let manager = registrant();
    let aor = "sip:trunk-removed@example.net";
    app_event_capture::watch(aor);
    publish_registrant_change(&manager, aor, "deregistered", None);
    let events = app_event_capture::take(aor);
    let payload = &events[0].1;
    assert!(payload["registrar"].is_null());
    assert!(payload["state"].is_null());
    assert_eq!(payload["failure_count"], 0);
}

#[test]
fn a_page_is_the_first_keys_past_after_in_order() {
    let keys = |names: &[&str]| {
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    };
    let all = keys(&["sip:d@x", "sip:a@x", "sip:c@x", "sip:b@x", "sip:e@x"]);

    let (first, next) = page(all.clone(), None, 2);
    assert_eq!(first, keys(&["sip:a@x", "sip:b@x"]));
    assert_eq!(next.as_deref(), Some("sip:b@x"));
    let (second, next) = page(all.clone(), next.as_deref(), 2);
    assert_eq!(second, keys(&["sip:c@x", "sip:d@x"]));
    let (last, next) = page(all.clone(), next.as_deref(), 2);
    assert_eq!(last, keys(&["sip:e@x"]));
    assert_eq!(next, None, "the last page names no next");

    let (exact, next) = page(keys(&["sip:b@x", "sip:a@x"]), None, 2);
    assert_eq!(exact, keys(&["sip:a@x", "sip:b@x"]));
    assert_eq!(next, None, "a page that holds the rest exactly is the last");
    assert_eq!(page(Vec::new(), None, 2), (Vec::new(), None));
}

#[test]
fn the_registrations_reply_pages_in_aor_order() {
    let registrar = Registrar::default();
    for user in ["page-c", "page-a", "page-b"] {
        save(&registrar, &format!("sip:{user}@example.com"), user);
    }
    let first = registrations_reply(&registrar, None, 2);
    let aors = |reply: &Value| -> Vec<String> {
        reply["registrations"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|entry| entry["aor"].as_str().expect("an aor").to_string())
            .collect()
    };
    assert_eq!(
        aors(&first),
        vec!["sip:page-a@example.com", "sip:page-b@example.com"]
    );
    assert_eq!(first["next"], "sip:page-b@example.com");
    let second = registrations_reply(&registrar, first["next"].as_str(), 2);
    assert_eq!(aors(&second), vec!["sip:page-c@example.com"]);
    assert!(second["next"].is_null());
}

// ---------------------------------------------------------------------------
// The verbs, through the control plane's own dispatch.
// ---------------------------------------------------------------------------

fn app(name: &str, events: &[&str]) -> ControlAppConfig {
    ControlAppConfig {
        name: name.to_string(),
        token: "tok".to_string(),
        per_call_connect: false,
        connect_url: None,
        on_lost: Some("hangup".to_string()),
        ca_file: None,
        events: events.iter().map(|class| class.to_string()).collect(),
    }
}

fn bus() -> Arc<ControlBus> {
    let (command_tx, _rx) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![
            app("dashboard", &["registration"]),
            app("trunks", &["outbound_registration"]),
            app("pbx", &[]),
        ],
        64,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    )
}

fn sip_only() -> HashMap<String, Arc<dyn ControlAdapter>> {
    let mut adapters: HashMap<String, Arc<dyn ControlAdapter>> = HashMap::new();
    adapters.insert(
        "sip".to_string(),
        Arc::new(super::super::sip_adapter::SipControlAdapter::new()),
    );
    adapters
}

async fn command(bus: &Arc<ControlBus>, app: &str, verb: &str) -> ControlResult {
    command_with(bus, app, verb, Value::Null).await
}

async fn command_with(bus: &Arc<ControlBus>, app: &str, verb: &str, args: Value) -> ControlResult {
    let conn = bus.register_connection(app);
    super::super::dispatch(
        bus,
        &sip_only(),
        app,
        conn.id,
        None,
        verb,
        Value::Null,
        args,
    )
    .await
}

/// Every entry of a state verb, page by page, as a controller reads it.
async fn every_page(bus: &Arc<ControlBus>, app: &str, verb: &str) -> Vec<Value> {
    let mut entries = Vec::new();
    let mut after = Value::Null;
    loop {
        let result = command_with(bus, app, verb, serde_json::json!({ "after": after })).await;
        let ControlResult::Ok(reply) = result else {
            panic!("expected a reply, got {result:?}");
        };
        assert!(reply["seq"].is_u64());
        entries.extend(
            reply["registrations"]
                .as_array()
                .expect("a list")
                .iter()
                .cloned(),
        );
        if reply["next"].is_null() {
            return entries;
        }
        after = reply["next"].clone();
    }
}

#[tokio::test]
async fn registrations_over_the_rail_returns_what_the_registrar_holds() {
    let bus = bus();
    let aor = "sip:over-the-rail@example.com";
    save(crate::script::api::test_registrar(), aor, "over-the-rail");

    let entry = every_page(&bus, "dashboard", "registrations")
        .await
        .into_iter()
        .find(|entry| entry["aor"] == aor)
        .expect("the AoR the registrar holds");
    assert_eq!(
        entry["contacts"][0]["received"],
        "sip:192.0.2.51:5060;transport=udp"
    );
    crate::script::api::test_registrar().remove_all(aor);
}

#[tokio::test]
async fn a_page_argument_that_names_no_page_is_a_bad_request() {
    let bus = bus();
    let conn = bus.register_connection("dashboard");
    for args in [
        serde_json::json!({ "limit": 0 }),
        serde_json::json!({ "limit": MAX_PAGE_LIMIT + 1 }),
        serde_json::json!({ "limit": "ten" }),
        serde_json::json!({ "after": 5 }),
    ] {
        let result = super::super::dispatch(
            &bus,
            &sip_only(),
            "dashboard",
            conn.id,
            None,
            "registrations",
            Value::Null,
            args.clone(),
        )
        .await;
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::BadRequest,
                    ..
                }
            ),
            "{args}: {result:?}"
        );
    }
}

#[tokio::test]
async fn the_state_verbs_need_the_class_subscribed() {
    let bus = bus();
    for (app, verb) in [
        ("pbx", "registrations"),
        ("trunks", "registrations"),
        ("pbx", "outbound_registrations"),
        ("dashboard", "outbound_registrations"),
    ] {
        let result = command(&bus, app, verb).await;
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::Forbidden,
                    ..
                }
            ),
            "{app} asking {verb}: {result:?}"
        );
    }
}

#[tokio::test]
async fn outbound_registrations_over_the_rail_returns_every_trunk() {
    let bus = bus();
    // The process-wide manager; this test's AoR is its own, so any other test
    // asking about a trunk of its own still finds none.
    let manager = Arc::new(registrant());
    crate::registrant::set_manager(Arc::clone(&manager));
    let manager = crate::registrant::manager().expect("a manager is installed");
    let aor = "sip:trunk-over-the-rail@example.net";
    manager.add(trunk(aor));
    manager.handle_failure(aor, 403, None);

    let entry = every_page(&bus, "trunks", "outbound_registrations")
        .await
        .into_iter()
        .find(|entry| entry["aor"] == aor)
        .expect("the trunk");
    assert_eq!(entry["state"], "failed");
    assert_eq!(entry["status_code"], 403);
    assert_eq!(entry["failure_count"], 1);
    manager.remove(aor);
}
