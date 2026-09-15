//! The control plane's `originate` verb with an RFC 4028 session timer, driven
//! the way a controller's command reaches it: the frame an SDK puts on the wire,
//! read by the listener's frame processing, routed by the command consumer to the
//! SIP adapter's dispatch table and its handler, and placed on a dispatcher.
//!
//! A verb lives in three places, the frame, the adapter's table and the handler,
//! and a test on the handler alone proves none of the others. These drive all
//! three and read the outcome off the wire and the dialog: the timer the INVITE
//! asks for, the refresher the callee's 2xx names, and the refresh siphon sends.

use std::collections::HashMap;
use std::sync::Arc;

use super::sdp_strip_tests::{endpoint_sdp, request_to, CALLEE, CALLEE_TAG, CALLEE_TARGET};
use super::session_timer_tests::{age, lists_option_tag, requests, sweep, timer_dispatcher, wire};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::control::sip_adapter::staged::{stage, OriginateRail};
use crate::control::{ConnHandle, ControlAdapter, ControlBus, OutboundFrame, SlowConsumerPolicy};

/// A controller connected to a control plane whose SIP adapter places its calls
/// on `dispatcher`.
struct Controller {
    bus: Arc<ControlBus>,
    connection: Arc<ConnHandle>,
    dispatcher: Arc<TestDispatcher>,
}

/// Connect a controller as `app`, a name no other test uses, to a control plane
/// running the real command consumer and SIP adapter, with `config` as the
/// dispatcher's `session_timer:` block.
fn controller(app: &str, config: Option<&str>) -> Controller {
    let dispatcher = Arc::new(timer_dispatcher(config));
    let (command_tx, command_rx) = flume::unbounded();
    let bus = ControlBus::new(
        command_tx,
        vec![crate::config::ControlAppConfig {
            name: app.to_string(),
            token: "token".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: None,
            ca_file: None,
            events: Vec::new(),
        }],
        64,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    );
    let staged_on = Arc::clone(&dispatcher);
    let dialled_on = Arc::clone(&dispatcher);
    stage(
        app,
        OriginateRail {
            bus: Arc::clone(&bus),
            prepare: Box::new(move |params| prepare_originate(&staged_on.state, params)),
            dial: Box::new(move |prepared| dial_originate(&dialled_on.state, prepared)),
        },
    );
    let mut adapters: HashMap<String, Arc<dyn ControlAdapter>> = HashMap::new();
    adapters.insert(
        "sip".to_string(),
        Arc::new(crate::control::sip_adapter::SipControlAdapter::new()),
    );
    tokio::spawn(crate::control::run_consumer(
        Arc::clone(&bus),
        Arc::new(adapters),
        command_rx,
    ));
    let connection = bus.register_connection(app);
    Controller {
        bus,
        connection,
        dispatcher,
    }
}

/// The `args` of an originate to the callee with its own offer, carrying
/// `session_timer` when there is one.
fn originate_args(channel: &str, session_timer: Option<serde_json::Value>) -> serde_json::Value {
    let mut args = serde_json::json!({
        "channel": channel,
        "to": CALLEE_TARGET,
        "sdp": endpoint_sdp("192.0.2.1"),
    });
    if let Some(session_timer) = session_timer {
        args["session_timer"] = session_timer;
    }
    args
}

/// Send `args` in the `originate` frame an SDK sends and return the reply frame
/// siphon queues for the controller, as JSON.
async fn originate(controller: &Controller, args: serde_json::Value) -> serde_json::Value {
    let frame = serde_json::json!({
        "id": "c-1",
        "type": "command",
        "module": "sip",
        "verb": "originate",
        "target": null,
        "args": args,
    });
    let mut said_hello = true;
    assert!(
        crate::control::listener::process_text(
            &frame.to_string(),
            &mut said_hello,
            &controller.connection,
            &controller.bus,
        )
        .await
    );
    let frames = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        controller.connection.events.recv_many(),
    )
    .await
    .expect("a reply to the originate");
    frames
        .into_iter()
        .find_map(|frame| match frame {
            OutboundFrame::Reply(reply) => serde_json::to_value(reply).ok(),
            OutboundFrame::Event(_) => None,
        })
        .expect("a reply frame")
}

/// The callee answers the originate's `invite` with a 200 carrying `headers` and
/// an answer.
fn callee_answers(
    controller: &Controller,
    call_id: &str,
    invite: &SipMessage,
    headers: &[(&str, &str)],
) {
    let mut answer = build_response(invite, 200, "OK", None, &[]);
    let to = invite.headers.to().cloned().expect("the INVITE has a To");
    answer.headers.set("To", format!("{to};tag={CALLEE_TAG}"));
    answer.headers.set("Contact", format!("<{CALLEE_TARGET}>"));
    for (name, value) in headers {
        answer.headers.set(name, value.to_string());
    }
    set_sdp_body(
        &mut answer,
        endpoint_sdp("198.51.100.20").into_bytes(),
        "application/sdp",
    );
    handle_originated_call_response(call_id, &answer, 200, &controller.dispatcher.state);
}

/// RFC 4028 §7.1, §7.2, §10: a controller's originate with `session_timer` asks
/// for that timer, and the call runs it exactly as one `b2bua.originate()` places:
/// the callee's 2xx names siphon the refresher, and siphon refreshes the dialog at
/// half the interval.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_originate_runs_the_session_timer_it_asks_for() {
    let controller = controller("dialer-session-timer", None);
    let _ = wire(&controller.dispatcher);

    let reply = originate(
        &controller,
        originate_args(
            "st-1",
            Some(serde_json::json!({ "expires": 90, "refresher": "uac" })),
        ),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let call_id = reply["result"]["call_id"]
        .as_str()
        .expect("the call id")
        .to_string();

    let invite = request_to(&wire(&controller.dispatcher), CALLEE, Method::Invite);
    assert_eq!(
        invite.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac")
    );
    assert_eq!(invite.headers.get("Min-SE").map(String::as_str), Some("90"));
    assert!(lists_option_tag(&invite, "Supported", "timer"));

    callee_answers(
        &controller,
        &call_id,
        &invite,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
    );
    let timer = controller
        .dispatcher
        .state
        .call_actors
        .leg_session_timer(&call_id, true)
        .expect("the dialog's session timer");
    assert_eq!((timer.session_expires, timer.siphon_refreshes), (90, true));

    age(&controller.dispatcher, &call_id, true, 46);
    let refreshes = requests(&sweep(&controller.dispatcher), CALLEE, Method::Invite);
    assert_eq!(refreshes.len(), 1, "siphon did not refresh the call");
    assert_eq!(refreshes[0].headers.call_id(), invite.headers.call_id());
    assert_eq!(
        refreshes[0]
            .headers
            .get("Session-Expires")
            .map(String::as_str),
        Some("90;refresher=uac")
    );
}

/// A controller's originate that names no session timer asks for the configured
/// one, or none, as it always has.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_originate_without_a_session_timer_runs_the_configured_one() {
    for (app, config, requested) in [
        ("dialer-no-session-timer", None, None),
        (
            "dialer-configured-session-timer",
            Some("session_expires: 1800\n"),
            Some("1800;refresher=uac"),
        ),
    ] {
        let controller = controller(app, config);
        let _ = wire(&controller.dispatcher);

        let reply = originate(&controller, originate_args("st-2", None)).await;
        assert_eq!(reply["status"], "ok", "{app}: {reply}");

        let invite = request_to(&wire(&controller.dispatcher), CALLEE, Method::Invite);
        assert_eq!(
            invite.headers.get("Session-Expires").map(String::as_str),
            requested,
            "{app}"
        );
    }
}

/// A session timer siphon cannot run is refused `bad_request` the way every other
/// argument the verb cannot use is, validated as `call.session_timer()` validates
/// it: a refresher that is not `uac`, `uas` or `b2bua`, a field no timer has, an
/// interval that is not a whole number of seconds, or a value that is not an
/// object. Nothing is placed and the channel id stays free.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_originate_with_a_session_timer_siphon_cannot_run_is_bad_request() {
    let refused = [
        serde_json::json!({ "refresher": "sometimes" }),
        serde_json::json!({ "interval": 90 }),
        serde_json::json!({ "expires": "90" }),
        serde_json::json!({ "min_se": -1 }),
        serde_json::json!({ "expires": 5_000_000_000_u64 }),
        serde_json::json!("90;refresher=uac"),
    ];
    for (index, session_timer) in refused.into_iter().enumerate() {
        let controller = controller(&format!("dialer-bad-session-timer-{index}"), None);
        let _ = wire(&controller.dispatcher);

        let reply = originate(
            &controller,
            originate_args("st-3", Some(session_timer.clone())),
        )
        .await;

        assert_eq!(reply["status"], "error", "{session_timer}: {reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{session_timer}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("session_timer")),
            "{session_timer}: {reply}"
        );
        assert!(
            requests(&wire(&controller.dispatcher), CALLEE, Method::Invite).is_empty(),
            "{session_timer}: a call was placed"
        );
        assert!(!controller.bus.channel_exists("st-3"), "{session_timer}");
    }
}
