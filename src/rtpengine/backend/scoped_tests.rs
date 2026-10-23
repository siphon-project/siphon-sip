use super::*;
use crate::rtpengine::test_engine::TestEngine;

fn scope(name: &str) -> CallScope {
    CallScope::per_call(name).expect("a valid scope")
}

#[test]
fn a_scoped_leg_is_its_own_engine_call_id() {
    assert_eq!(engine_call_id("call-1", None), "call-1");
    assert_eq!(
        engine_call_id("call-1", Some(&scope("orig"))),
        "call-1;orig"
    );
    assert_ne!(
        engine_call_id("call-1", Some(&scope("orig"))),
        engine_call_id("call-1", Some(&scope("term")))
    );
}

#[tokio::test]
async fn rtpengine_addresses_each_scoped_leg_by_its_own_call_id() {
    let engine = TestEngine::start(false).await;
    let backend = engine.backend().await;
    let flags = NgFlags::default();
    let orig = scope("orig");
    assert!(!backend.is_node_scope(&orig), "rtpengine has no node scope");

    backend
        .offer_in(None, "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("unscoped offer");
    backend
        .offer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig offer");
    backend
        .reoffer_in(Some(&orig), "call-1", "tag-a", b"v=0\r\n", &flags)
        .await
        .expect("orig re-offer");
    backend
        .answer_in(Some(&orig), "call-1", "tag-a", "tag-b", b"v=0\r\n", &flags)
        .await
        .expect("orig answer");
    backend
        .delete_in(Some(&orig), "call-1", "tag-a")
        .await
        .expect("orig delete");
    backend
        .delete_call_in(Some(&orig), "call-1")
        .await
        .expect("orig delete by id");

    let sent: Vec<(String, Option<String>)> = engine
        .all_commands()
        .into_iter()
        .map(|command| (command.name, command.call_id))
        .collect();
    let named = |name: &str, call_id: &str| (name.to_string(), Some(call_id.to_string()));
    assert_eq!(
        sent,
        vec![
            named("offer", "call-1"),
            named("offer", "call-1;orig"),
            named("offer", "call-1;orig"),
            named("answer", "call-1;orig"),
            named("delete", "call-1;orig"),
            named("delete", "call-1;orig"),
        ]
    );
}
