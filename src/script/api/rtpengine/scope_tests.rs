//! `scope=` on `rtpengine.offer` / `answer` / `delete`, driven through the real
//! Python methods against the in-process engines of both backends.

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

use pyo3::types::PyDict;

use super::super::{PyRequest, PyRtpEngine};
use super::*;
use crate::config::{MediaProfileConfig, NgFlagsConfig};
use crate::rtpengine::profile::ProfileRegistry;
use crate::rtpengine::test_engine::TestEngine;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::script::api::call::PyCall;
use crate::sip::message::SipMessage;

const CALL_ID: &str = "uu-call-1@192.0.2.10";

const OFFER_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 20000 RTP/AVP 0\r\n",
);

const ANSWER_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP6 2001:db8::7\r\n",
    "s=-\r\n",
    "c=IN IP6 2001:db8::7\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
);

/// Profiles that pin each leg to one address family: the originating access
/// on IPv4, the terminating access on IPv6.
fn registry() -> Arc<ProfileRegistry> {
    let family = |family: &str| NgFlagsConfig {
        address_family: Some(family.to_string()),
        ..Default::default()
    };
    let mut custom = HashMap::new();
    for (name, family_name) in [("access_v4", "IP4"), ("access_v6", "IP6")] {
        custom.insert(
            name.to_string(),
            MediaProfileConfig {
                offer: family(family_name),
                answer: family(family_name),
            },
        );
    }
    Arc::new(ProfileRegistry::from_config(&custom))
}

fn parse(raw: &str) -> Arc<Mutex<SipMessage>> {
    Arc::new(Mutex::new(
        crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("a SIP message"),
    ))
}

/// The INVITE, as it reaches the proxy on each leg: same Call-ID, same tags.
fn invite() -> Arc<Mutex<SipMessage>> {
    parse(&format!(
        concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:alice@example.com>;tag=tag-a\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: {}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        CALL_ID,
        OFFER_SDP.len(),
        OFFER_SDP
    ))
}

/// The callee's 2xx, as it passes back through the proxy on each leg.
fn answer() -> Arc<Mutex<SipMessage>> {
    parse(&format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1\r\n",
            "From: <sip:alice@example.com>;tag=tag-a\r\n",
            "To: <sip:bob@example.com>;tag=tag-b\r\n",
            "Call-ID: {}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        CALL_ID,
        ANSWER_SDP.len(),
        ANSWER_SDP
    ))
}

fn bye() -> Arc<Mutex<SipMessage>> {
    parse(&format!(
        concat!(
            "BYE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-2\r\n",
            "From: <sip:alice@example.com>;tag=tag-a\r\n",
            "To: <sip:bob@example.com>;tag=tag-b\r\n",
            "Call-ID: {}\r\n",
            "CSeq: 2 BYE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        CALL_ID
    ))
}

/// One proxied call's whole media life, both legs anchored under their own
/// scope, then a BYE that names no scope.
const BOTH_LEGS: &str = "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    await engine.answer(reply_orig, scope='orig')
    await engine.answer(reply_term, scope='term')
    await engine.delete(bye)
";

/// Run `code`'s `run(engine, *messages)` the way a script handler awaits it.
async fn drive(namespace: PyRtpEngine, code: &'static str) -> PyResult<()> {
    tokio::task::spawn_blocking(move || {
        Python::attach(|python| {
            let engine = Bound::new(python, namespace)?;
            let request = |message: Arc<Mutex<SipMessage>>| {
                Bound::new(
                    python,
                    PyRequest::new(message, "udp".to_string(), "192.0.2.10".to_string(), 5060),
                )
                .map(Bound::into_any)
            };
            let reply = |message: Arc<Mutex<SipMessage>>| {
                Bound::new(python, PyReply::new(message)).map(Bound::into_any)
            };
            let code = CString::new(code).expect("no NUL");
            let globals = PyDict::new(python);
            python.run(code.as_c_str(), Some(&globals), None)?;
            let run = globals
                .get_item("run")?
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("no run"))?;
            let coroutine = run.call1((
                engine,
                request(invite())?,
                request(invite())?,
                reply(answer())?,
                reply(answer())?,
                request(bye())?,
            ))?;
            crate::script::engine::run_coroutine_value(python, &coroutine).map(|_| ())
        })
    })
    .await
    .expect("the handler thread")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rtpengine_anchors_each_leg_of_one_call_id_as_its_own_engine_call() {
    Python::initialize();
    let engine = TestEngine::start(false).await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend().await, Arc::clone(&sessions), registry());

    drive(namespace, BOTH_LEGS).await.expect("the call runs");

    let orig = format!("{CALL_ID};orig");
    let term = format!("{CALL_ID};term");
    let of = |name: &str| {
        engine
            .commands(name)
            .into_iter()
            .map(|command| (command.call_id.unwrap_or_default(), command.address_family))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        of("offer"),
        vec![
            (orig.clone(), Some("IP4".to_string())),
            (term.clone(), Some("IP6".to_string())),
        ]
    );
    // Each answer reuses the profile its own leg's offer recorded.
    assert_eq!(
        of("answer"),
        vec![
            (orig.clone(), Some("IP4".to_string())),
            (term.clone(), Some("IP6".to_string())),
        ]
    );
    // The BYE named no scope: the call's own (unscoped) id, then both legs,
    // in whichever order the scope stores yield them.
    let mut deleted: Vec<String> = of("delete").into_iter().map(|(id, _)| id).collect();
    assert_eq!(deleted.first().map(String::as_str), Some(CALL_ID));
    deleted.sort();
    let mut expected = vec![CALL_ID.to_string(), orig, term];
    expected.sort();
    assert_eq!(deleted, expected);
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.scoped_len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siphon_rtp_anchors_each_leg_of_one_call_id_under_its_own_scope() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(namespace, BOTH_LEGS).await.expect("the call runs");

    let of = |name: &str| {
        engine
            .commands(name)
            .into_iter()
            .map(|command| (command.call_id, command.scope, command.address_family))
            .collect::<Vec<_>>()
    };
    let leg = |scope: &str, family: &str| {
        (
            CALL_ID.to_string(),
            Some(scope.to_string()),
            Some(family.to_string()),
        )
    };
    assert_eq!(of("offer"), vec![leg("orig", "IP4"), leg("term", "IP6")]);
    assert_eq!(of("answer"), vec![leg("orig", "IP4"), leg("term", "IP6")]);
    assert!(
        engine
            .commands("answer")
            .iter()
            .all(|command| !command.refused),
        "each answer reached its own leg's engine call"
    );
    // The BYE named no scope: the unscoped call (none held) and both legs.
    let mut deletes: Vec<Option<String>> = engine
        .commands("delete")
        .into_iter()
        .map(|command| command.scope)
        .collect();
    deletes.sort();
    assert_eq!(
        deletes,
        vec![None, Some("orig".to_string()), Some("term".to_string())]
    );
    assert!(!engine.holds_in(Some("orig"), CALL_ID));
    assert!(!engine.holds_in(Some("term"), CALL_ID));
    assert_eq!(engine.held_count(), 0);
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.scoped_len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scoped_delete_ends_only_its_own_leg() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    await engine.delete(bye, scope='orig')
",
    )
    .await
    .expect("the call runs");

    assert!(!engine.holds_in(Some("orig"), CALL_ID));
    assert!(engine.holds_in(Some("term"), CALL_ID));
    assert_eq!(sessions.scoped_len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_scope_the_frames_carry_none() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4')
    await engine.answer(reply_orig)
    await engine.delete(bye)
",
    )
    .await
    .expect("the call runs");

    for name in ["offer", "answer", "delete"] {
        let commands = engine.commands(name);
        assert_eq!(commands.len(), 1, "{name}");
        assert_eq!(commands[0].scope, None, "{name}");
        assert_eq!(commands[0].call_id, CALL_ID, "{name}");
    }
    assert_eq!(engine.held_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_scope_or_a_b2bua_call_is_refused_before_the_engine() {
    Python::initialize();
    let engine = TestEngine::start(false).await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend().await, Arc::clone(&sessions), registry());

    let errors = tokio::task::spawn_blocking(move || {
        Python::attach(|python| {
            let engine = Bound::new(python, namespace).expect("namespace");
            let request = Bound::new(
                python,
                PyRequest::new(invite(), "udp".to_string(), "192.0.2.10".to_string(), 5060),
            )
            .expect("request");
            let call = Bound::new(
                python,
                PyCall::new(
                    "id-1".to_string(),
                    invite(),
                    "192.0.2.10".to_string(),
                    "udp".to_string(),
                ),
            )
            .expect("call");
            let refusal = |target: &Bound<'_, PyAny>, scope: &str| {
                let kwargs = PyDict::new(python);
                kwargs.set_item("scope", scope).expect("kwarg");
                engine
                    .call_method("offer", (target,), Some(&kwargs))
                    .err()
                    .map(|error| error.to_string())
            };
            [
                refusal(request.as_any(), ""),
                refusal(request.as_any(), "has space"),
                refusal(request.as_any(), &"x".repeat(65)),
                refusal(call.as_any(), "orig"),
            ]
        })
    })
    .await
    .expect("the handler thread");

    for error in &errors {
        let error = error.as_deref().expect("refused");
        assert!(error.contains("ValueError"), "{error}");
    }
    assert!(errors[3]
        .as_deref()
        .is_some_and(|error| error.contains("B2BUA")));
    assert!(
        engine.all_commands().is_empty(),
        "nothing reached the engine"
    );
}

/// Leak gate: the per-call media bookkeeping of scoped legs drains to its
/// baseline over many complete offer/answer/delete cycles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_leg_bookkeeping_drains_to_baseline() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    for _ in range(200):
        await engine.offer(invite_orig, profile='access_v4', scope='orig')
        await engine.offer(invite_term, profile='access_v6', scope='term')
        await engine.answer(reply_orig, scope='orig')
        await engine.answer(reply_term, scope='term')
        await engine.delete(bye)
",
    )
    .await
    .expect("the cycles run");

    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.scoped_len(), 0);
    assert_eq!(engine.held_count(), 0);
    assert_eq!(engine.commands("offer").len(), 400);
}

/// `delete_call` by Call-ID alone ends every leg under the scope it was
/// offered under; with a scope, only that leg.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_call_resolves_the_scopes_each_leg_was_offered_under() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    assert await engine.delete_call('uu-call-1@192.0.2.10', scope='orig')
    assert await engine.delete_call('uu-call-1@192.0.2.10')
    assert not await engine.delete_call('uu-call-1@192.0.2.10')
",
    )
    .await
    .expect("the releases run");

    assert_eq!(engine.held_count(), 0);
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.scoped_len(), 0);
}

/// The media verbs a script runs on each leg, after both legs are anchored.
const MEDIA_VERBS: &str = "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    await engine.play_media(invite_orig, file='/prompts/a.wav', scope='orig')
    await engine.play_dtmf(invite_term, '5', scope='term')
    await engine.silence_media(invite_orig, scope='orig')
    await engine.stop_media(invite_term, scope='term')
    await engine.subscribe_request('uu-call-1@192.0.2.10', 'tag-a', 'tag-s', scope='orig')
    await engine.unsubscribe('uu-call-1@192.0.2.10', 'tag-a', 'tag-s', scope='orig')
    await engine.delete(bye)
";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rtpengine_media_verbs_reach_the_leg_their_scope_names() {
    Python::initialize();
    let engine = TestEngine::start(false).await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend().await, Arc::clone(&sessions), registry());

    drive(namespace, MEDIA_VERBS).await.expect("the call runs");

    let orig = format!("{CALL_ID};orig");
    let term = format!("{CALL_ID};term");
    let verbs: Vec<(String, String)> = engine
        .all_commands()
        .into_iter()
        .filter(|command| !matches!(command.name.as_str(), "offer" | "answer" | "delete"))
        .map(|command| (command.name, command.call_id.unwrap_or_default()))
        .collect();
    let on = |name: &str, call_id: &str| (name.to_string(), call_id.to_string());
    assert_eq!(
        verbs,
        vec![
            on("play media", &orig),
            on("play DTMF", &term),
            on("silence media", &orig),
            on("stop media", &term),
            on("subscribe request", &orig),
            on("unsubscribe", &orig),
        ]
    );
    assert_eq!(sessions.scoped_len(), 0, "the BYE ended both legs");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siphon_rtp_media_verbs_reach_the_leg_their_scope_names() {
    Python::initialize();
    let engine = NativeTestEngine::start().await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend(), Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    await engine.play_media(invite_orig, tone='ringback_eu', wait=False, scope='orig')
    await engine.play_dtmf(invite_term, '5', scope='term')
    await engine.silence_media(invite_orig, scope='orig')
    await engine.stop_media(invite_term, scope='term')
    await engine.delete(bye)
",
    )
    .await
    .expect("the call runs");

    let on_leg = |name: &str| {
        engine
            .commands(name)
            .into_iter()
            .map(|command| (command.call_id, command.scope, command.refused))
            .collect::<Vec<_>>()
    };
    let leg = |scope: &str| (CALL_ID.to_string(), Some(scope.to_string()), false);
    assert_eq!(on_leg("play_media"), vec![leg("orig")]);
    assert_eq!(on_leg("stop_media"), vec![leg("term")]);
    assert_eq!(engine.held_count(), 0);
    assert_eq!(sessions.scoped_len(), 0);
}

/// No `scope=`: the one scoped leg when it is the only one, the node's call
/// (as before) once there are two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verb_without_a_scope_finds_the_only_scoped_leg_and_no_other() {
    Python::initialize();
    let engine = TestEngine::start(false).await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend().await, Arc::clone(&sessions), registry());

    drive(
        namespace,
        "\
async def run(engine, invite_orig, invite_term, reply_orig, reply_term, bye):
    await engine.offer(invite_orig, profile='access_v4', scope='orig')
    await engine.play_media(invite_orig, file='/prompts/a.wav')
    await engine.offer(invite_term, profile='access_v6', scope='term')
    await engine.play_media(invite_orig, file='/prompts/a.wav')
    await engine.delete(bye)
",
    )
    .await
    .expect("the call runs");

    let played: Vec<String> = engine
        .commands("play media")
        .into_iter()
        .map(|command| command.call_id.unwrap_or_default())
        .collect();
    assert_eq!(played, vec![format!("{CALL_ID};orig"), CALL_ID.to_string()]);
}

/// A B2BUA call's legs have Call-IDs of their own: a scope on a media verb
/// for one is refused before anything reaches the engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_media_verb_scope_on_a_b2bua_call_is_refused() {
    Python::initialize();
    let engine = TestEngine::start(false).await;
    let sessions = Arc::new(MediaSessionStore::new());
    let namespace = PyRtpEngine::new(engine.backend().await, Arc::clone(&sessions), registry());

    let errors = tokio::task::spawn_blocking(move || {
        Python::attach(|python| {
            let engine = Bound::new(python, namespace).expect("namespace");
            let call = Bound::new(
                python,
                PyCall::new(
                    "id-1".to_string(),
                    invite(),
                    "192.0.2.10".to_string(),
                    "udp".to_string(),
                ),
            )
            .expect("call");
            ["silence_media", "stop_media", "detach_ws_tee", "echo"]
                .into_iter()
                .map(|verb| {
                    let kwargs = PyDict::new(python);
                    kwargs.set_item("scope", "orig").expect("kwarg");
                    engine
                        .call_method(verb, (call.as_any(),), Some(&kwargs))
                        .err()
                        .map(|error| error.to_string())
                })
                .collect::<Vec<_>>()
        })
    })
    .await
    .expect("the handler thread");

    for error in &errors {
        let error = error.as_deref().expect("refused");
        assert!(
            error.contains("ValueError") && error.contains("B2BUA"),
            "{error}"
        );
    }
    assert!(engine.all_commands().is_empty());
}
