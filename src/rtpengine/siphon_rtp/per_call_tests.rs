use super::super::scope::CallScopes;
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::rtpengine::MediaBackend;

fn scope(name: &str) -> CallScope {
    CallScope::per_call(name).expect("a valid scope")
}

#[test]
fn a_scoped_key_is_never_a_call_id() {
    assert_eq!(scoped_key("call-1", None), "call-1");
    let key = scoped_key("call-1", Some(&scope("orig")));
    assert_eq!(key, "call-1\norig");
    assert_ne!(key, scoped_key("call-1", Some(&scope("term"))));
}

#[test]
fn a_per_call_scope_is_held_to_the_node_scopes_rules() {
    assert!(CallScope::per_call("orig-2_b").is_ok());
    for refused in ["", "has space", "semi;colon", &"x".repeat(65)] {
        let error = CallScope::per_call(refused).expect_err(refused);
        assert!(error.contains("scope="), "{error}");
    }
}

#[test]
fn a_named_scope_is_the_connections_and_the_names_are_bounded() {
    let scopes = CallScopes::new(None);
    let orig = serde_json::json!({"event": "media_timeout", "call_id": "c", "scope": "orig"});
    assert!(!scopes.accepts(&orig), "not named yet");
    scopes.name(&scope("orig")).expect("named");
    scopes.name(&scope("orig")).expect("naming again is free");
    assert!(scopes.accepts(&orig));
    assert_eq!(scopes.named_count(), 1);

    for index in 1..256 {
        scopes
            .name(&scope(&format!("s{index}")))
            .expect("under the cap");
    }
    let error = scopes
        .name(&scope("one-too-many"))
        .expect_err("over the cap");
    assert!(error.to_string().contains("256"), "{error}");
}

#[test]
fn a_node_info_without_the_feature_refuses_a_per_call_scope() {
    let node_info = |features: &[&str]| -> siphon_rtp_proto::CmdResult {
        serde_json::from_value(serde_json::json!({
            "result": "node_info",
            "node": {
                "node_id": "engine-1",
                "version": "0.13.0",
                "media_addresses": ["192.0.2.10"],
                "codecs": ["PCMU"],
                "features": features,
                "max_sessions": 0,
                "draining": false,
            },
        }))
        .expect("a node_info result")
    };
    assert!(super::require_scope_feature(node_info(&["scope"]), "scope=x").is_ok());
    let error = super::require_scope_feature(node_info(&["relay"]), "scope=\"orig\" was named")
        .expect_err("no scope feature");
    assert!(error.to_string().contains("0.13.0"), "{error}");
}

#[tokio::test]
async fn two_scopes_of_one_call_id_are_two_engine_calls() {
    let engine = NativeTestEngine::start().await;
    let backend = engine.backend();
    let flags = NgFlags::default();
    let (orig, term) = (scope("orig"), scope("term"));

    backend
        .offer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig offered");
    backend
        .offer_in(Some(&term), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("term offered");
    assert!(engine.holds_in(Some("orig"), "call-1"));
    assert!(engine.holds_in(Some("term"), "call-1"));
    assert!(!engine.holds("call-1"), "nothing anchored unscoped");
    assert_eq!(backend.active_sessions(), 2);

    backend
        .answer_in(Some(&term), "call-1", "tag-a", "tag-b", b"v=0\r\n", &flags)
        .await
        .expect("term answered on its own call");
    backend
        .reoffer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig re-offered on its own call");

    backend
        .delete_in(Some(&orig), "call-1", "tag-a")
        .await
        .expect("orig deleted");
    assert!(engine.holds_in(Some("term"), "call-1"), "term untouched");
    backend
        .delete_call_in(Some(&term), "call-1")
        .await
        .expect("term deleted by id");
    assert_eq!(engine.held_count(), 0);
    assert_eq!(backend.active_sessions(), 0);
}

#[tokio::test]
async fn a_node_scope_named_per_call_is_the_node_scope() {
    let engine = NativeTestEngine::start().await;
    let (event_tx, _event_rx) = tokio::sync::mpsc::channel(16);
    let set = SiphonRtpClientSet::with_scope(
        vec![(engine.address(), 2000, 1)],
        None,
        Some(scope("pcscf")),
        5_000,
        event_tx,
    )
    .expect("a set");
    let backend = MediaBackend::SiphonRtp(set);
    assert!(backend.is_node_scope(&scope("pcscf")));
    assert!(!backend.is_node_scope(&scope("orig")));
    backend
        .offer_in(None, "call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    assert!(engine.holds_in(Some("pcscf"), "call-1"));
}
