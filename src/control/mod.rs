//! External remote-control plane (ARI/ESL-class) — protocol-agnostic substrate
//! + per-protocol adapters.
//!
//! An out-of-process application connects over a WebSocket (either inbound
//! persistent, or siphon dials it per handed-over call) and drives calls that a
//! Python `@b2bua.on_invite` handler explicitly hands over with
//! `call.handover("app")` (the ARI *Stasis* model). Calls not handed over cost
//! nothing.
//!
//! ## Substrate vs adapter
//!
//! The **substrate** ([`listener`], [`outbound`], [`registry`], [`protocol`])
//! owns the WebSocket transport, JSON envelope, auth, app registry, ownership,
//! event bus + backpressure, and command routing *by module*. It knows nothing
//! about SIP — it moves opaque `serde_json::Value` DTOs between apps and
//! adapters.
//!
//! An **adapter** ([`ControlAdapter`]) owns one protocol's resource model + maps
//! generic verbs onto its internal machinery. The SIP adapter
//! ([`sip_adapter`]) lives in core (and would move with SIP if extracted); other
//! protocols register their own via [`register_control_adapter`](crate::server::SiphonServer::register_control_adapter).
//!
//! ## I/O discipline (the load-bearing rule)
//!
//! Control-socket I/O is pure async tokio; event fan-out is `try_push` on a
//! bounded per-connection queue (never `.await`); command ingress is an
//! unbounded flume send then an awaited `oneshot`; and `apply` performs only the
//! bounded local action and returns immediately — a far-end outcome (the callee
//! answering / BYEing) arrives later as an event, never as the command reply.

pub mod listener;
pub mod outbound;
pub mod protocol;
pub mod registry;
pub mod sip_adapter;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::config::ControlConfig;

pub use protocol::{
    CommandFrame, ControlErrorCode, ControlResult, EventFrame, HelloArgs, ReplyFrame, ReplyStatus,
    PROTOCOL_VERSION, SUBPROTOCOL,
};
pub use registry::{
    ChannelRef, ConnHandle, ControlBus, ControlCommand, OfferOutcome, OutboundFrame, OutboundQueue,
    Ownership, PushOutcome, SlowConsumerPolicy,
};

/// Push an event to the control channel owning `sip_call_id`, if the call is
/// controlled. A no-op when the control plane is not installed. Signalling-path
/// helper — never blocks, never panics.
pub fn notify_channel_event(sip_call_id: &str, event: &str, payload: serde_json::Value) {
    if let Some(bus) = ControlBus::global() {
        bus.forward_channel_event(sip_call_id, event, payload);
    }
}

/// The resolved target of an adapter command. The substrate resolves + ownership
/// -checks a `{channel}` target before handing the command to the adapter, so an
/// adapter never sees a channel its connection does not own.
#[derive(Debug, Clone)]
pub enum ResolvedTarget {
    /// A channel the commanding connection owns.
    Channel(ChannelRef),
    /// No addressable resource (module-level verb).
    None,
}

/// The authenticated connection a command arrived on.
///
/// Carried alongside the resolved target because a verb that *creates* a
/// resource (`originate`) has no target to resolve ownership from and must
/// still register what it creates to exactly one owner — the connection that
/// asked for it. Server-authoritative: the substrate fills this in from the
/// authenticated socket, it is never read off the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOrigin {
    /// The application the connection authenticated as.
    pub app: String,
    /// The originating connection id.
    pub conn_id: u64,
}

/// A command handed to an adapter, with its target already resolved +
/// ownership-checked by the substrate. `verb`/`args` are opaque to the substrate.
#[derive(Debug, Clone)]
pub struct AdapterCommand {
    /// The verb to apply (adapter-defined).
    pub verb: String,
    /// The arguments (adapter-defined opaque JSON).
    pub args: serde_json::Value,
    /// The resolved, ownership-checked target.
    pub target: ResolvedTarget,
    /// The authenticated connection this command came in on.
    pub origin: CommandOrigin,
}

/// Introspection schema for one adapter (`describe`).
#[derive(Debug, Clone, Serialize)]
pub struct AdapterSchema {
    /// The routing key (`"sip"`, `"smpp"`, …).
    pub module: String,
    /// The verbs this adapter accepts.
    pub verbs: Vec<VerbSchema>,
    /// The events this adapter emits.
    pub events: Vec<String>,
}

/// One verb in an [`AdapterSchema`].
#[derive(Debug, Clone, Serialize)]
pub struct VerbSchema {
    /// The verb name.
    pub verb: String,
    /// A one-line human summary.
    pub summary: String,
}

/// A per-protocol control adapter. Implementors map generic verbs onto their
/// own machinery and (de)serialize their own `args`/`payload` — the substrate
/// never parses them.
pub trait ControlAdapter: Send + Sync {
    /// The routing key (`"sip"`, `"smpp"`, …).
    fn module(&self) -> &str;

    /// Apply one command's **local, bounded** action and return immediately.
    /// Must never wait on a far-end outcome (rule #4): the callee's answer / ACK
    /// / BYE-200 arrive later as events.
    fn apply<'a>(&'a self, command: AdapterCommand) -> BoxFuture<'a, ControlResult>;

    /// The adapter's verb/event schema (for `describe` + generated docs/SDKs).
    fn describe(&self) -> AdapterSchema;
}

/// Boot the control plane: build + install the [`ControlBus`], spawn the command
/// consumer, and start the inbound WebSocket listener (if `control.listen` is
/// set). Per-call-connect apps are dialed lazily at handover, so they need no
/// boot-time listener.
///
/// `extra_adapters` are the adapters registered by a host binary via
/// `SiphonServer::register_control_adapter`; the built-in SIP adapter is always
/// registered.
pub fn spawn_control_plane(config: &ControlConfig, extra_adapters: Vec<Arc<dyn ControlAdapter>>) {
    let mut adapters: HashMap<String, Arc<dyn ControlAdapter>> = HashMap::new();
    let sip: Arc<dyn ControlAdapter> = Arc::new(sip_adapter::SipControlAdapter::new());
    adapters.insert(sip.module().to_string(), sip);
    for adapter in extra_adapters {
        let module = adapter.module().to_string();
        if adapters.insert(module.clone(), adapter).is_some() {
            warn!(module = %module, "control plane: duplicate adapter module — later registration wins");
        }
    }

    let (command_tx, command_rx) = flume::unbounded();
    let policy = SlowConsumerPolicy::from_config(&config.limits.slow_consumer);
    let bus = ControlBus::new(
        command_tx,
        config.apps.clone(),
        config.limits.event_queue_depth,
        policy,
        config.limits.reattach_grace_secs,
        config.limits.handoff_deadline_ms,
    );
    if ControlBus::install(Arc::clone(&bus)).is_err() {
        warn!("control plane already installed — ignoring second boot");
        return;
    }

    let adapters = Arc::new(adapters);

    // Command consumer: routes each command to its adapter (or handles a
    // substrate verb) as a plain async task — zero blocking-pool slots.
    tokio::spawn(run_consumer(Arc::clone(&bus), Arc::clone(&adapters), command_rx));

    if let Some(listen) = config.listen.as_deref() {
        match listen.parse::<SocketAddr>() {
            Ok(addr) => {
                tokio::spawn(listener::serve(addr, Arc::clone(&bus)));
            }
            Err(error) => {
                error!(%listen, %error, "invalid control.listen address — inbound control disabled");
            }
        }
    }

    let modules: Vec<String> = adapters.keys().cloned().collect();
    info!(
        apps = config.apps.len(),
        listen = ?config.listen,
        ?modules,
        "control plane started"
    );
}

/// The command consumer. One task; each command is applied on its own spawned
/// task so a slow adapter for one command never head-of-line-blocks another.
async fn run_consumer(
    bus: Arc<ControlBus>,
    adapters: Arc<HashMap<String, Arc<dyn ControlAdapter>>>,
    command_rx: flume::Receiver<ControlCommand>,
) {
    while let Ok(command) = command_rx.recv_async().await {
        let bus = Arc::clone(&bus);
        let adapters = Arc::clone(&adapters);
        tokio::spawn(async move {
            let ControlCommand {
                app,
                conn_id,
                module,
                verb,
                target,
                args,
                response_tx,
                ..
            } = command;
            let result = dispatch(&bus, &adapters, &app, conn_id, module.as_deref(), &verb, target, args).await;
            let _ = response_tx.send(result);
        });
    }
}

/// Route one command: substrate verbs (`resync`/`describe`/`set_var`/`get_var`)
/// are handled here; everything else routes to the adapter named by `module`
/// after the target is resolved + ownership-checked.
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    bus: &Arc<ControlBus>,
    adapters: &HashMap<String, Arc<dyn ControlAdapter>>,
    app: &str,
    conn_id: u64,
    module: Option<&str>,
    verb: &str,
    target: serde_json::Value,
    args: serde_json::Value,
) -> ControlResult {
    match verb {
        "resync" => {
            let owned = bus.resync(app, conn_id);
            let channels: Vec<serde_json::Value> = owned
                .into_iter()
                .map(|channel| channel_snapshot(bus, &channel))
                .collect();
            return ControlResult::Ok(serde_json::json!({ "channels": channels }));
        }
        "describe" => {
            let schemas: Vec<AdapterSchema> = adapters.values().map(|a| a.describe()).collect();
            return match serde_json::to_value(&schemas) {
                Ok(value) => ControlResult::Ok(serde_json::json!({ "adapters": value })),
                Err(error) => ControlResult::error(
                    ControlErrorCode::Unavailable,
                    format!("failed to serialize schema: {error}"),
                ),
            };
        }
        "set_var" | "get_var" => {
            let channel_id = match target.get("channel").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => {
                    return ControlResult::error(
                        ControlErrorCode::BadRequest,
                        "set_var/get_var require target.channel",
                    );
                }
            };
            match bus.owns(&channel_id, app, conn_id) {
                Ownership::Unknown => {
                    return ControlResult::error(ControlErrorCode::NotFound, "no such channel");
                }
                Ownership::Forbidden => {
                    return ControlResult::error(
                        ControlErrorCode::Forbidden,
                        "channel owned by another app",
                    );
                }
                Ownership::Owned(_) => {}
            }
            if verb == "set_var" {
                let key = args.get("key").and_then(|v| v.as_str());
                let value = args.get("value").and_then(|v| v.as_str());
                return match (key, value) {
                    (Some(key), Some(value)) => {
                        bus.set_var(&channel_id, key, value);
                        ControlResult::Ok(serde_json::json!({ "channel": channel_id, "key": key }))
                    }
                    _ => ControlResult::error(
                        ControlErrorCode::BadRequest,
                        "set_var requires args.key and args.value",
                    ),
                };
            } else {
                let key = match args.get("key").and_then(|v| v.as_str()) {
                    Some(key) => key,
                    None => {
                        return ControlResult::error(
                            ControlErrorCode::BadRequest,
                            "get_var requires args.key",
                        );
                    }
                };
                let value = bus.get_var(&channel_id, key);
                return ControlResult::Ok(serde_json::json!({ "channel": channel_id, "key": key, "value": value }));
            }
        }
        _ => {}
    }

    // Adapter verb: route by module. Default to the sole adapter when a single
    // one is registered and the client omitted `module`.
    let module_name = match module {
        Some(name) => name.to_string(),
        None if adapters.len() == 1 => adapters.keys().next().cloned().unwrap_or_default(),
        None => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "command is missing a 'module' (adapter routing key)",
            );
        }
    };
    let adapter = match adapters.get(&module_name) {
        Some(adapter) => adapter,
        None => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("unknown module '{module_name}'"),
            );
        }
    };

    // Resolve + ownership-check a channel target when present.
    let resolved = match target.get("channel").and_then(|v| v.as_str()) {
        Some(channel_id) => match bus.owns(channel_id, app, conn_id) {
            Ownership::Owned(channel) => ResolvedTarget::Channel(channel),
            Ownership::Forbidden => {
                return ControlResult::error(
                    ControlErrorCode::Forbidden,
                    "channel owned by another app",
                );
            }
            Ownership::Unknown => {
                return ControlResult::error(
                    ControlErrorCode::NotFound,
                    "no such channel (already gone?)",
                );
            }
        },
        None => ResolvedTarget::None,
    };

    adapter
        .apply(AdapterCommand {
            verb: verb.to_string(),
            args,
            target: resolved,
            origin: CommandOrigin {
                app: app.to_string(),
                conn_id,
            },
        })
        .await
}

/// Build a resync channel snapshot (ids + current state + vars).
fn channel_snapshot(bus: &Arc<ControlBus>, channel: &ChannelRef) -> serde_json::Value {
    let state = crate::b2bua::actor::global_call_store()
        .and_then(|store| store.get_call(&channel.call_actor_id).map(|call| call_state_str(&call.state)))
        .unwrap_or("gone");
    serde_json::json!({
        "channel": channel.channel_id,
        "call_id": channel.call_actor_id,
        "sip_call_id": channel.sip_call_id,
        "state": state,
        "vars": bus.vars(&channel.channel_id),
    })
}

/// Render a `CallState` to the wire string the control app sees.
fn call_state_str(state: &crate::b2bua::actor::CallState) -> &'static str {
    match state {
        crate::b2bua::actor::CallState::Calling => "calling",
        crate::b2bua::actor::CallState::Ringing => "ringing",
        crate::b2bua::actor::CallState::Answered => "answered",
        crate::b2bua::actor::CallState::Terminated => "terminated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlAppConfig;

    fn app_cfg(name: &str) -> ControlAppConfig {
        ControlAppConfig {
            name: name.to_string(),
            token: "tok".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: Some("hangup".to_string()),
        }
    }

    fn sip_only() -> HashMap<String, Arc<dyn ControlAdapter>> {
        let mut adapters: HashMap<String, Arc<dyn ControlAdapter>> = HashMap::new();
        adapters.insert("sip".to_string(), Arc::new(sip_adapter::SipControlAdapter::new()));
        adapters
    }

    fn bus_with_channel() -> (Arc<ControlBus>, Arc<ConnHandle>) {
        let (command_tx, _rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![app_cfg("ivr-app"), app_cfg("other")],
            64,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch1", &conn, "call-uuid", "sipcid@h", "hangup", Default::default());
        (bus, conn)
    }

    #[tokio::test]
    async fn describe_lists_registered_adapters() {
        let (bus, conn) = bus_with_channel();
        let result = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            None,
            "describe",
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
        .await;
        match result {
            ControlResult::Ok(value) => {
                let adapters = value["adapters"].as_array().unwrap();
                assert!(adapters.iter().any(|a| a["module"] == "sip"));
            }
            other => panic!("expected ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_var_then_get_var_roundtrips_with_ownership() {
        let (bus, conn) = bus_with_channel();
        let set = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            None,
            "set_var",
            serde_json::json!({ "channel": "ch1" }),
            serde_json::json!({ "key": "queue", "value": "support" }),
        )
        .await;
        assert!(matches!(set, ControlResult::Ok(_)));

        let get = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            None,
            "get_var",
            serde_json::json!({ "channel": "ch1" }),
            serde_json::json!({ "key": "queue" }),
        )
        .await;
        match get {
            ControlResult::Ok(value) => assert_eq!(value["value"], "support"),
            other => panic!("expected ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cross_app_target_is_forbidden() {
        let (bus, _conn) = bus_with_channel();
        let intruder = bus.register_connection("other");
        let result = dispatch(
            &bus,
            &sip_only(),
            "other",
            intruder.id,
            Some("sip"),
            "answer",
            serde_json::json!({ "channel": "ch1" }),
            serde_json::json!({ "code": 200 }),
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::Forbidden, .. }
        ));
    }

    #[tokio::test]
    async fn unknown_channel_is_not_found() {
        let (bus, conn) = bus_with_channel();
        let result = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            Some("sip"),
            "answer",
            serde_json::json!({ "channel": "nope" }),
            serde_json::json!({ "code": 200 }),
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
        ));
    }

    #[tokio::test]
    async fn unknown_module_is_bad_request() {
        let (bus, conn) = bus_with_channel();
        let result = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            Some("smpp"),
            "submit_sm",
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[tokio::test]
    async fn resync_enumerates_owned_channels() {
        let (bus, conn) = bus_with_channel();
        let result = dispatch(
            &bus,
            &sip_only(),
            "ivr-app",
            conn.id,
            None,
            "resync",
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
        .await;
        match result {
            ControlResult::Ok(value) => {
                let channels = value["channels"].as_array().unwrap();
                assert_eq!(channels.len(), 1);
                assert_eq!(channels[0]["channel"], "ch1");
                assert_eq!(channels[0]["sip_call_id"], "sipcid@h");
            }
            other => panic!("expected ok, got {other:?}"),
        }
    }
}
