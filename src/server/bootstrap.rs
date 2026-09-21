//! What `SiphonServer::run_async` builds before it starts serving:
//! logging, the registrar backend, the gateway, lawful intercept, Diameter,
//! charging, outbound registration, and the transport plumbing each listener
//! needs.
//!
//! Separate from the builder so each one is a `fn(&Config) -> Component` a
//! test can call, rather than a section of a 2,200-line function that only
//! runs as part of starting a server.

use super::*;

pub(super) fn init_logging(
    log_config: &crate::config::LogConfig,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use crate::config::{LogFormat, LogLevel};
    use event_clock::{EventClock, SharedTime};
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = match log_config.level {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        tracing_subscriber::EnvFilter::new(level)
    });

    let is_json = log_config.format == LogFormat::Json;

    let console_layer = if is_json {
        tracing_subscriber::fmt::layer()
            .json()
            .with_timer(SharedTime)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_timer(SharedTime)
            .boxed()
    };

    let (file_layer, guard) = if let Some(ref path) = log_config.file {
        let file = crate::file_sink::open_append(path).unwrap_or_else(|error| {
            eprintln!("Failed to open log file {path}: {error}");
            std::process::exit(1);
        });
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let layer = if is_json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(SharedTime)
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_timer(SharedTime)
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        };

        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    // EventClock precedes both `fmt` layers deliberately: `Layered` dispatches
    // an event to the layer added first, so this is what makes the console and
    // the file render the same instant instead of timing the event twice.
    //
    // The tail layer is installed unconditionally but is inert until
    // `log_tail::enable()` runs (admin config, later in startup): its
    // `on_event` is one relaxed atomic load in that state. Installing it here
    // rather than conditionally keeps the subscriber a single static shape —
    // and `EnvFilter` above it means the tail can only ever see what
    // `log.level` already admits.
    tracing_subscriber::registry()
        .with(env_filter)
        .with(EventClock)
        .with(crate::log_tail::LogTailLayer)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}

/// Compute the per-process identity tag from config + environment, then
/// stamp it onto the registrar so subsequent `save()`s carry it.
///
/// Resolution order for `instance_id`:
///   1. ``server.instance_id`` from siphon.yaml (env-expanded by serde_yaml_ng).
///   2. The ``HOSTNAME`` environment variable (Linux default).
///   3. Literal ``"siphon"`` as a last-resort fallback.
///
/// `instance_epoch` is always a fresh UUID v4 generated at startup so two
/// runs of the same logical replica are distinguishable.
/// Start following a `registrant.backend` source, when one is configured.
///
/// Runs after the static `entries` are loaded, so the first reconcile sees them
/// and leaves them alone — a source owns only the entries it created itself.
fn init_registrant_source(
    manager: &Arc<crate::registrant::RegistrantManager>,
    config: &Config,
    registrant_config: &crate::config::RegistrantYamlConfig,
) {
    use crate::config::RegistrantBackendType;
    use crate::registrant::source::{DatabaseSource, HttpSource, RegistrantSource};

    let source = match registrant_config.backend {
        RegistrantBackendType::Static => return,
        RegistrantBackendType::Database => {
            // Config load refuses `database` without the block, so this is
            // unreachable; log rather than panic if it ever is not.
            let Some(database) = registrant_config.database.clone() else {
                error!("registrant.backend: database without a `registrant.database` block");
                return;
            };
            RegistrantSource::Database(DatabaseSource::new(database, instance_id(config)))
        }
        RegistrantBackendType::Http => {
            let Some(http) = registrant_config.http.clone() else {
                error!("registrant.backend: http without a `registrant.http` block");
                return;
            };
            match HttpSource::new(http) {
                Ok(source) => RegistrantSource::Http(source),
                Err(error) => {
                    error!(%error, "cannot build the registrant HTTP source");
                    return;
                }
            }
        }
    };

    let source = Arc::new(source);
    crate::registrant::source::set_source(Arc::clone(&source));
    let loop_manager = Arc::clone(manager);
    tokio::spawn(async move {
        crate::registrant::source::reconcile_loop(loop_manager, source).await;
    });
}

/// This process's identity tag.
///
/// Resolution order: `server.instance_id` from siphon.yaml, then the `HOSTNAME`
/// environment variable, then the literal `"siphon"`. Shared by the registrar's
/// binding identity and the registrant source's `$1` binding, so a deployment
/// that shards trunks by node uses the same name in both places.
pub(super) fn instance_id(config: &Config) -> String {
    config
        .server
        .as_ref()
        .and_then(|server| server.instance_id.clone())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "siphon".to_string())
}

pub(super) fn init_registrar_identity(config: &Config) {
    use crate::registrar::InstanceIdentity;
    use crate::script::api::registrar_arc;

    let registrar = match registrar_arc() {
        Some(r) => r,
        None => return,
    };

    let id = instance_id(config);
    let epoch = uuid::Uuid::new_v4().to_string();

    info!(instance_id = %id, instance_epoch = %epoch, "registrar instance identity");
    registrar.set_instance_identity(InstanceIdentity { id, epoch });
}

pub(super) async fn init_registrar_backend(config: &Config) {
    use crate::config::RegistrarBackendType;
    use crate::registrar::backend;
    use crate::script::api::registrar_arc;

    let registrar = match registrar_arc() {
        Some(r) => r,
        None => return,
    };

    match config.registrar.backend {
        RegistrarBackendType::Redis => {
            let redis_cfg = match &config.registrar.redis {
                Some(redis_cfg) => redis_cfg,
                None => {
                    error!("registrar backend is redis but no redis config provided");
                    return;
                }
            };
            let redis_config = backend::RedisBackendConfig {
                url: redis_cfg.url.clone(),
                urls: Vec::new(),
                key_prefix: redis_cfg.key_prefix.clone(),
                shard_count: 0,
                ttl_slack_secs: redis_cfg.ttl_slack_secs as u64,
            };
            match backend::RedisBackend::connect(redis_config).await {
                Ok(redis_backend) => {
                    match backend::restore_from_backend(&redis_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.registrations_active.set(aors as i64);
                            }
                            info!(aors, contacts, "restored contacts from Redis backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Redis backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(redis_backend));

                    // --- iFC profile persistence (shares the same Redis instance) ---
                    init_ifc_redis_backend(&redis_cfg.url, config).await;
                }
                Err(err) => {
                    error!(%err, "failed to connect to Redis registrar backend");
                }
            }
        }
        RegistrarBackendType::Postgres => {
            let pg_config = match &config.registrar.postgres {
                Some(cfg) => backend::PostgresBackendConfig {
                    url: cfg.url.clone(),
                    urls: Vec::new(),
                    table: cfg.table.clone(),
                    shard_count: 0,
                },
                None => {
                    error!("registrar backend is postgres but no postgres config provided");
                    return;
                }
            };
            match backend::PostgresBackend::connect(pg_config).await {
                Ok(pg_backend) => {
                    match backend::restore_from_backend(&pg_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.registrations_active.set(aors as i64);
                            }
                            info!(aors, contacts, "restored contacts from Postgres backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Postgres backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(pg_backend));
                }
                Err(err) => {
                    error!(%err, "failed to connect to Postgres registrar backend");
                }
            }
        }
        RegistrarBackendType::Memory | RegistrarBackendType::Python => {}
    }
}

/// Stand-in when the `redis-backend` feature is off.
///
/// The registrar's own Redis backend already has a stub for this build, so the
/// `RegistrarBackendType::Redis` arm still compiles and runs; without one here
/// it did not, and `cargo build --no-default-features` failed outright. Same
/// contract as `sctp` and `ui`: the config still parses and the feature is
/// skipped with a loud warning rather than silently doing nothing.
#[cfg(not(feature = "redis-backend"))]
pub(super) async fn init_ifc_redis_backend(_redis_url: &str, _config: &Config) {
    warn!(
        "iFC profile persistence needs the redis-backend cargo feature, which this binary \
         was built without — profiles stay in memory and are lost on restart"
    );
}

/// Initialize iFC Redis persistence — restore profiles and wire the backend writer.
///
/// Called from `init_registrar_backend` when the registrar uses a Redis backend,
/// reusing the same Redis instance for iFC profile storage.
#[cfg(feature = "redis-backend")]
pub(super) async fn init_ifc_redis_backend(redis_url: &str, config: &Config) {
    use crate::script::api::ifc_store_arc;

    let ifc_store = match ifc_store_arc() {
        Some(store) => store,
        None => return,
    };

    let ifc_key_prefix = config
        .isc
        .as_ref()
        .map(|isc| isc.ifc_key_prefix.clone())
        .unwrap_or_else(|| "siphon:ifc:".to_owned());

    let client = match redis::Client::open(redis_url) {
        Ok(client) => client,
        Err(error) => {
            error!(%error, "failed to open Redis client for iFC backend");
            return;
        }
    };

    let mut connection = match client.get_multiplexed_async_connection().await {
        Ok(connection) => connection,
        Err(error) => {
            error!(%error, "failed to connect to Redis for iFC backend");
            return;
        }
    };

    // Restore iFC profiles from Redis.
    match crate::ifc::restore_ifc_profiles(&mut connection, &ifc_key_prefix, ifc_store).await {
        Ok((profiles, ifcs)) => {
            if profiles > 0 {
                info!(profiles, ifcs, "restored iFC profiles from Redis");
            }
        }
        Err(error) => {
            error!(error, "failed to restore iFC profiles from Redis");
        }
    }

    // Wire the backend writer for ongoing persistence.
    let writer = crate::ifc::spawn_ifc_backend_writer(connection, ifc_key_prefix);
    ifc_store.set_backend_writer(writer);
    info!("iFC Redis backend writer initialized");
}

pub(super) async fn init_gateway(config: &Config) -> Option<Arc<DispatcherManager>> {
    use crate::gateway::{
        extract_address_from_uri, resolve_address, Algorithm, Destination, DispatcherGroup,
        ProbeConfig,
    };

    let gateway_config = config.gateway.as_ref()?;

    let manager = Arc::new(DispatcherManager::new());

    for group_config in &gateway_config.groups {
        let algorithm = Algorithm::from_str(&group_config.algorithm).unwrap_or_else(|| {
            warn!(
                algorithm = %group_config.algorithm,
                group = %group_config.name,
                "unknown algorithm, defaulting to weighted"
            );
            Algorithm::Weighted
        });

        let mut destinations = Vec::new();
        for dest_config in &group_config.destinations {
            let address_str = dest_config
                .address
                .clone()
                .unwrap_or_else(|| extract_address_from_uri(&dest_config.uri));

            let address = match resolve_address(&address_str) {
                Ok(addr) => addr,
                Err(error) => {
                    error!(
                        address = %address_str,
                        uri = %dest_config.uri,
                        error = %error,
                        "cannot resolve gateway destination address, skipping"
                    );
                    continue;
                }
            };
            // Derive transport from config field, or from URI ;transport= param
            let transport_type = match dest_config.effective_transport().as_str() {
                "tcp" => transport::Transport::Tcp,
                "tls" => transport::Transport::Tls,
                _ => transport::Transport::Udp,
            };
            // Store original hostname string for DNS re-resolution on failure
            let is_hostname = address_str.parse::<std::net::SocketAddr>().is_err();
            let mut dest = Destination::new(
                dest_config.uri.clone(),
                address,
                transport_type,
                dest_config.weight,
                dest_config.priority,
            )
            .with_attrs(dest_config.attrs.clone());
            if is_hostname {
                dest = dest.with_address_str(address_str.clone());
            }
            if let Some(ref aor) = dest_config.registers {
                dest = dest.with_registration(aor.clone(), dest_config.require_registration);
            } else if dest_config.require_registration {
                error!(
                    uri = %dest_config.uri,
                    group = %group_config.name,
                    "require_registration needs a `registers` AoR to gate on, skipping destination"
                );
                continue;
            }
            if let Some(ref auth) = dest_config.auth {
                match crate::auth::StoredSecret::from_config(
                    auth.password.as_deref(),
                    auth.ha1.as_deref(),
                    &auth.ha1_algorithm,
                ) {
                    Ok(secret) => {
                        dest = dest.with_credentials(crate::auth::StoredCredentials {
                            username: auth.username.clone(),
                            secret,
                        });
                    }
                    Err(error) => {
                        // Skip the destination rather than the credential: a
                        // gateway that challenges and is dialled without one
                        // fails every call, which is harder to read than a
                        // destination that is plainly absent.
                        error!(
                            uri = %dest_config.uri,
                            group = %group_config.name,
                            %error,
                            "invalid gateway destination credentials, skipping destination"
                        );
                        continue;
                    }
                }
            }
            destinations.push(dest);
        }

        let probe = ProbeConfig {
            enabled: group_config.probe.enabled,
            interval: std::time::Duration::from_secs(group_config.probe.interval_secs as u64),
            failure_threshold: group_config.probe.failure_threshold,
            from_user: group_config.probe.from_user.clone(),
            from_domain: group_config.probe.from_domain.clone(),
        };

        // Static source CIDR membership (for from_gateway) — peers that source
        // SIP from a whole published subnet, not only their FQDN-resolved IPs.
        let source_networks: Vec<ipnet::IpNet> = group_config
            .source_networks
            .iter()
            .filter_map(|spec| {
                let parsed = crate::gateway::parse_source_network(spec);
                if parsed.is_none() {
                    warn!(
                        group = %group_config.name,
                        entry = %spec,
                        "ignoring invalid gateway source_networks entry (not a CIDR or IP)"
                    );
                }
                parsed
            })
            .collect();

        manager.add_group(
            DispatcherGroup::new(group_config.name.clone(), algorithm, destinations)
                .with_probe_config(probe)
                .with_source_networks(source_networks)
                .with_reroute_causes(group_config.reroute_causes.clone())
                .from_yaml(),
        );
    }

    // Inject gateway Python API before script loads
    pyo3::Python::attach(|python| {
        let py_gateway = crate::script::api::gateway::PyGateway::new(Arc::clone(&manager));
        if let Err(error) = crate::script::api::set_gateway_singleton(python, py_gateway) {
            error!("failed to store gateway singleton: {error}");
        } else {
            info!("gateway registered for injection");
        }
    });

    // Store the Rust-side manager Arc so `request.from_gateway` /
    // `call.from_gateway` can test source membership without a Python
    // round-trip (points at the same manager as the Python singleton).
    crate::script::api::set_gateway_manager(Arc::clone(&manager));
    init_gateway_source(&manager, config, gateway_config).await;

    Some(manager)
}

/// Start following a `gateway.backend` source, when one is configured.
///
/// Runs after the `gateway.groups` are built, so the first reconcile sees them
/// and leaves them alone — a source owns only the groups it created itself.
///
/// **Awaits a first read before returning**, retrying on a short backoff within
/// a bounded budget, and only then spawns the poll loop. The loop used to do
/// its own first fetch, so a node bound its listeners and began answering calls
/// while the carriers were still being read — or, when the controller was down,
/// with no carriers at all and a single `warn` to say so. The "keep the current
/// set" rule that makes a failed poll harmless on a running node has nothing to
/// keep at start-up.
///
/// The budget is bounded rather than open-ended: a node that cannot reach its
/// controller still has to come up to answer a health probe, serve the
/// last-success gauge that is the alert, and accept the admin refresh a
/// recovering controller pushes at it.
async fn init_gateway_source(
    manager: &Arc<crate::gateway::DispatcherManager>,
    config: &Config,
    gateway_config: &crate::config::GatewayConfig,
) {
    use crate::config::GatewayBackendType;
    use crate::gateway::source::{DatabaseSource, GatewaySource, HttpSource};

    let source = match gateway_config.backend {
        GatewayBackendType::Static => return,
        GatewayBackendType::Database => {
            // Config load refuses `database` without the block, so this is
            // unreachable; log rather than panic if it ever is not.
            let Some(database) = gateway_config.database.clone() else {
                error!("gateway.backend: database without a `gateway.database` block");
                return;
            };
            GatewaySource::Database(DatabaseSource::new(database, instance_id(config)))
        }
        GatewayBackendType::Http => {
            let Some(http) = gateway_config.http.clone() else {
                error!("gateway.backend: http without a `gateway.http` block");
                return;
            };
            match HttpSource::new(http) {
                Ok(source) => GatewaySource::Http(source),
                Err(error) => {
                    error!(%error, "cannot build the gateway HTTP source");
                    return;
                }
            }
        }
    };

    let source = Arc::new(source);
    crate::gateway::source::set_source(Arc::clone(&source));

    // Read it once before the listeners take traffic, carrying the attempt's
    // failure streak into the loop so a node that came up against a dead
    // controller does not restart its escalation from scratch.
    let mut health =
        crate::source_health::SourceHealth::new(crate::source_health::SourceKind::Gateway);
    crate::gateway::source::reconcile_at_startup(manager, &source, &mut health).await;

    let loop_manager = Arc::clone(manager);
    tokio::spawn(async move {
        crate::gateway::source::reconcile_loop(loop_manager, source, health).await;
    });
}

/// Cloned LiManager handle that survives `init_li` so `spawn_li_tasks` can
/// hand the X3 manager into it once X3 has been constructed.
pub(super) static LI_MANAGER: std::sync::OnceLock<crate::li::LiManager> =
    std::sync::OnceLock::new();

/// The lawful-intercept subsystem, if `lawful_intercept.enabled` is set.
///
/// The dispatcher takes a clone at construction so it can match every message
/// against the provisioned warrants without reaching through a global on the
/// hot path.
pub fn li_manager() -> Option<crate::li::LiManager> {
    LI_MANAGER.get().cloned()
}

pub(super) fn init_li(config: &Config) -> Option<LiState> {
    let li_config = config.lawful_intercept.as_ref()?;
    if !li_config.enabled {
        return None;
    }

    let channel_size = li_config
        .x2
        .as_ref()
        .map(|x2| x2.channel_size)
        .unwrap_or(10_000);
    // Whether a content warrant can be provisioned at all depends on the media
    // backend: X1 and X2 work on every backend, but TS 103 221-2 content
    // framing lives in the native media engine. Config load already refuses a
    // configured `lawful_intercept.x3` on a backend that cannot deliver it;
    // this carries the same fact to `ActivateTask`, which can arrive long after
    // boot.
    let content_capability = crate::li::LiManager::content_capability_for(
        config
            .media
            .as_ref()
            .map(crate::config::MediaConfig::backend)
            .unwrap_or_default(),
    );
    let (li_manager, iri_rx, audit_rx) =
        crate::li::LiManager::new(li_config.clone(), channel_size, content_capability);

    let py_li_manager = li_manager.clone();
    pyo3::Python::attach(|python| {
        let py_li = crate::script::api::li::PyLiNamespace::new(py_li_manager);
        if let Err(error) = crate::script::api::set_li_singleton(python, py_li) {
            error!("failed to store LI singleton: {error}");
        } else {
            info!("lawful intercept namespace registered for injection");
        }
    });

    // Stash a clone for spawn_li_tasks to wire up X3 once it's built. All
    // LiManager clones share the same `Arc<OnceLock<X3Manager>>`, so setting
    // X3 on this clone makes it visible to the Python singleton too.
    let _ = LI_MANAGER.set(li_manager.clone());

    Some((li_manager, iri_rx, audit_rx))
}

pub(super) fn init_diameter(config: &Config) -> Option<Arc<crate::diameter::DiameterManager>> {
    let diameter_config = config.diameter.as_ref()?;

    // Route by application, so a Cx request reaches the HSS rather than
    // whichever peer the map happened to yield first.
    let manager = Arc::new(crate::diameter::DiameterManager::with_routes(
        &diameter_config.routes,
    ));

    // Server mode runtime: a JSON snapshot of tenants/listen for
    // `diameter.config`, plus the event sink behind `diameter.event_sink`.
    // Only built when the deployment opts into Diameter server mode (listen/tenants set).
    let server_enabled =
        diameter_config.listen.is_some() || !diameter_config.effective_tenants().is_empty();
    let event_sink = diameter_config
        .event_sink
        .as_ref()
        .map(|cfg| Arc::new(crate::diameter::event_sink::EventSink::spawn(cfg)));
    // Snapshot the fields scripts read via `diameter.config` — both the flat
    // single-domain shape (origin/clients/servers/connect_to) and the explicit
    // multi-tenant map, so a flat-config script's `diameter.config["origin_host"]`
    // resolves.
    let config_json = if server_enabled {
        Some(
            serde_json::json!({
                "origin_host": &diameter_config.origin_host,
                "origin_realm": &diameter_config.origin_realm,
                "clients": &diameter_config.clients,
                "servers": &diameter_config.servers,
                "connect_to": &diameter_config.connect_to,
                "tenants": &diameter_config.tenants,
                "listen": &diameter_config.listen,
            })
            .to_string(),
        )
    } else {
        None
    };

    pyo3::Python::attach(|python| {
        let py_diameter = crate::script::api::diameter::PyDiameter::new(Arc::clone(&manager));
        let py_diameter = match config_json {
            Some(json) => py_diameter.with_server_runtime(json, event_sink),
            None => py_diameter,
        };
        if let Err(error) = crate::script::api::set_diameter_singleton(python, py_diameter) {
            warn!("failed to set Diameter Python singleton: {error}");
        } else {
            info!("Diameter namespace registered for injection");
        }
    });

    Some(manager)
}

/// Background task that consumes the registrar's broadcast channel and
/// emits an Rf ACR-EVENT for every registration state change.  Each
/// event is a one-shot accounting record — no session state is held.
///
/// `cause_code` per RFC 3326 / TS 32.299 §5.2.5:
/// - `Registered` / `Refreshed` → 0 (success)
/// - `Deregistered` → -200 (clean unbind, mapped from successful 200 OK)
/// - `Expired` → -487 (Request Terminated semantically — the binding
///   was torn down because no refresh arrived)
pub(super) fn spawn_rf_register_emitter(
    service: Arc<crate::diameter::rf_service::RfChargingService>,
    mut events: tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>,
) {
    use crate::diameter::ro::{ImsChargingData, NodeRole};
    use crate::registrar::RegistrationEvent;

    tokio::spawn(async move {
        info!("rf: registrar ACR-EVENT emitter started");
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "rf: registrar event emitter lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let (aor, cause_code) = match &event {
                RegistrationEvent::Registered { aor } | RegistrationEvent::Refreshed { aor } => {
                    (aor.clone(), 0i32)
                }
                RegistrationEvent::Deregistered { aor } => (aor.clone(), -200),
                RegistrationEvent::Expired { aor } => (aor.clone(), -487),
            };
            let ims_data = ImsChargingData {
                calling_party: vec![aor.clone()],
                sip_method: Some("REGISTER".to_string()),
                role_of_node: Some(NodeRole::OriginatingRole),
                node_functionality: service.node_functionality(),
                cause_code: Some(cause_code),
                ..Default::default()
            };
            let _ = service.acr_event(ims_data, Some(aor)).await;
        }
        info!("rf: registrar ACR-EVENT emitter stopped");
    });
}

/// Build the Rf offline-charging service from the `rf:` config block.
///
/// Returns `None` (charging fully disabled) when:
/// - the `rf:` section is missing,
/// - `rf.enabled = false`, or
/// - no Diameter manager is available (no `diameter:` peers configured).
pub(super) fn init_rf_charging(
    config: &Config,
    diameter_manager: Option<&Arc<crate::diameter::DiameterManager>>,
) -> Option<Arc<crate::diameter::rf_service::RfChargingService>> {
    let rf_config = config.rf.as_ref()?;
    if !rf_config.enabled {
        return None;
    }
    let manager = match diameter_manager {
        Some(m) => Arc::clone(m),
        None => {
            warn!("rf.enabled = true but no diameter: peers configured — disabling Rf");
            return None;
        }
    };
    let service = crate::diameter::rf_service::RfChargingService::new(manager, rf_config.clone());
    info!(
        node_functionality = %rf_config.node_functionality,
        service_context_id = %rf_config.service_context_id,
        auto_emit_proxy = rf_config.auto_emit_proxy,
        auto_emit_b2bua = rf_config.auto_emit_b2bua,
        auto_emit_register = rf_config.auto_emit_register,
        interim_secs = rf_config.interim_interval_secs,
        "Rf offline charging enabled"
    );
    Some(service)
}

/// Build the Ro online-charging service from `ro:` config. Returns `None` when
/// `ro:` is absent/disabled or no Diameter peers are configured. The dispatcher
/// installs the call-teardown hook after construction.
pub(super) fn init_ro_charging(
    config: &Config,
    diameter_manager: Option<&Arc<crate::diameter::DiameterManager>>,
) -> Option<Arc<crate::diameter::ro_service::RoChargingService>> {
    let ro_config = config.ro.as_ref()?;
    if !ro_config.enabled {
        return None;
    }
    let manager = match diameter_manager {
        Some(m) => Arc::clone(m),
        None => {
            warn!("ro.enabled = true but no diameter: peers configured — disabling Ro");
            return None;
        }
    };
    let service = crate::diameter::ro_service::RoChargingService::new(manager, ro_config.clone());
    info!(
        node_functionality = %ro_config.node_functionality,
        service_context_id = %ro_config.service_context_id,
        reauth_secs = ro_config.reauth_interval_secs,
        charge = %ro_config.charge,
        "Ro online charging enabled (B2BUA-only, reserve-before-connect via call.ro_authorize())"
    );
    Some(service)
}

/// Wire the config entries + background refresh loop onto the registrant
/// `manager` that was created (and whose Python namespace was installed) early
/// in `serve()` — before `ScriptEngine::new()` — so the script's
/// `registration` namespace is the real Rust one, not the stub.
pub(super) fn init_registrant(
    manager: &Arc<crate::registrant::RegistrantManager>,
    config: &Config,
    outbound_senders: &Arc<transport::OutboundRouter>,
    local_addr: std::net::SocketAddr,
    listen_addrs: &std::collections::HashMap<transport::Transport, std::net::SocketAddr>,
    advertised_addrs: &std::collections::HashMap<transport::Transport, String>,
    hep_sender: &Option<Arc<HepSender>>,
    stream_connections: transport::StreamConnections,
) {
    use crate::registrant::{RegistrantCredentials, RegistrantEntry};

    let registrant_config = match config.registrant.as_ref() {
        Some(config) => config,
        None => return,
    };

    for entry_config in &registrant_config.entries {
        let registrar_host = entry_config
            .registrar
            .strip_prefix("sip:")
            .or_else(|| entry_config.registrar.strip_prefix("sips:"))
            .unwrap_or(&entry_config.registrar);

        let transport_type = match entry_config.transport.as_str() {
            "tcp" => transport::Transport::Tcp,
            "tls" => transport::Transport::Tls,
            _ => transport::Transport::Udp,
        };

        let default_port: u16 = if transport_type == transport::Transport::Tls {
            5061
        } else {
            5060
        };
        let address_str = if registrar_host.contains(':') {
            registrar_host.to_string()
        } else {
            format!("{registrar_host}:{default_port}")
        };
        let destination = match crate::gateway::resolve_address(&address_str) {
            Ok(addr) => addr,
            Err(error) => {
                error!(
                    host = %registrar_host,
                    error = %error,
                    "cannot resolve registrant host, skipping entry"
                );
                continue;
            }
        };

        let is_hostname = address_str.parse::<std::net::SocketAddr>().is_err();
        let mut entry = RegistrantEntry::new(
            entry_config.aor.clone(),
            entry_config.registrar.clone(),
            destination,
            transport_type,
            RegistrantCredentials::password(
                entry_config.user.clone(),
                entry_config.password.clone(),
                entry_config.realm.clone(),
            ),
            entry_config
                .interval
                .unwrap_or(registrant_config.default_interval),
            entry_config.contact.clone(),
        );
        if is_hostname {
            entry.address_str = Some(address_str.clone());
        }

        // IMS AKAv1-MD5 (3GPP TS 33.203): attach the USIM secrets so the 401
        // runs through Milenage instead of password digest.
        let entry = if entry_config
            .auth
            .as_deref()
            .map(|mode| mode.eq_ignore_ascii_case("aka"))
            .unwrap_or(false)
        {
            let aka_config = match &entry_config.aka {
                Some(aka) => aka,
                None => {
                    error!(aor = %entry_config.aor, "auth: aka requires an `aka:` block, skipping entry");
                    continue;
                }
            };
            let credentials = match crate::registrant::aka::AkaCredentials::from_hex(
                &aka_config.k,
                aka_config.op.as_deref(),
                aka_config.opc.as_deref(),
                &aka_config.amf,
            ) {
                Ok(credentials) => credentials,
                Err(error) => {
                    error!(aor = %entry_config.aor, %error, "invalid AKA credentials, skipping entry");
                    continue;
                }
            };
            let initial_sqn = match crate::ipsec::milenage::hex_to_bytes(&aka_config.sqn) {
                Some(bytes) if bytes.len() == 6 => {
                    let mut sqn = [0u8; 6];
                    sqn.copy_from_slice(&bytes);
                    sqn
                }
                _ => {
                    error!(aor = %entry_config.aor, "sqn must be 12 hex chars, skipping entry");
                    continue;
                }
            };
            entry.with_aka(credentials, initial_sqn)
        } else {
            entry
        };

        // IPsec sec-agree (UE side) — only meaningful alongside auth: aka.
        let entry = if let Some(ipsec_config) = &entry_config.ipsec {
            if entry.auth_mode != crate::registrant::AuthMode::Aka {
                error!(aor = %entry_config.aor, "registrant ipsec requires auth: aka, skipping entry");
                continue;
            }
            let aalg = match crate::ipsec::IntegrityAlgorithm::from_sec_agree_name(
                &ipsec_config.alg,
            ) {
                Some(alg) => alg,
                None => {
                    error!(aor = %entry_config.aor, alg = %ipsec_config.alg, "unknown ipsec alg, skipping entry");
                    continue;
                }
            };
            let ealg = match crate::ipsec::EncryptionAlgorithm::from_sec_agree_name(
                &ipsec_config.ealg,
            ) {
                Some(ealg) => ealg,
                None => {
                    error!(aor = %entry_config.aor, ealg = %ipsec_config.ealg, "unknown ipsec ealg, skipping entry");
                    continue;
                }
            };
            entry.with_ipsec(crate::registrant::UeIpsec::new(
                ipsec_config.ue_port_c,
                ipsec_config.ue_port_s,
                aalg,
                ealg,
            ))
        } else {
            entry
        };

        // IMS Contact feature tags (instance ID + MMTel/video/SMS).
        let entry = if let Some(ims_config) = &entry_config.ims {
            let has = |tag: &str| {
                ims_config
                    .features
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(tag))
            };
            entry.with_ims_contact(crate::registrant::ImsContactParams {
                instance_id: ims_config.imei.clone(),
                mmtel: has("mmtel"),
                video: has("video"),
                smsip: has("smsip"),
            })
        } else {
            entry
        };

        manager.add(entry);
    }

    info!(
        count = registrant_config.entries.len(),
        "outbound registrations configured"
    );

    init_registrant_source(manager, config, registrant_config);

    // Spawn background registration loop
    let loop_manager = Arc::clone(manager);
    let loop_outbound = Arc::clone(outbound_senders);
    let loop_listen_addrs = listen_addrs.clone();
    let loop_advertised_addrs = advertised_addrs.clone();
    let loop_advertised_address = config.advertised_address.clone();
    let loop_hep_sender = hep_sender.clone();
    let loop_stream_connections = Some(stream_connections);
    tokio::spawn(async move {
        crate::registrant::registration_loop(
            loop_manager,
            loop_outbound,
            local_addr,
            loop_listen_addrs,
            loop_advertised_addrs,
            loop_advertised_address,
            loop_hep_sender,
            loop_stream_connections,
        )
        .await;
    });

    // The `registration` Python namespace was already installed early in
    // `serve()` (before ScriptEngine::new) using this same manager.
}

pub(super) async fn spawn_li_tasks(li_state: Option<LiState>, config: &Config) {
    let (li_manager, iri_rx, audit_rx) = match li_state {
        Some(state) => state,
        None => return,
    };

    let li_config = match config.lawful_intercept.as_ref() {
        Some(cfg) => cfg,
        None => {
            error!("lawful_intercept config missing despite LI state being initialized");
            return;
        }
    };

    // --- X1 provisioning listener ---
    //
    // Bind it here, from the same place X2 and X3 are started. The previous
    // X1 module had no caller outside its own tests, so `lawful_intercept.x1`
    // was parsed and drove nothing: the interface was configured, reported as
    // present, and never listened. A configured X1 that cannot be bound is a
    // startup failure, not a warning — an ADMF that cannot provision a warrant
    // must find out immediately, not when the warrant is needed.
    if let Some(ref x1_config) = li_config.x1 {
        let audit_manager = li_manager.clone();
        let audit_hook: crate::li::x1::server::AuditHook =
            Arc::new(move |operation, subject, detail| {
                audit_manager.audit(
                    crate::li::AuditOperation::Provisioning(operation.to_string()),
                    subject,
                    detail,
                );
            });

        let x1_server = match crate::li::x1::server::X1Server::new(
            x1_config,
            li_manager.tasks().clone(),
            li_manager.destinations().clone(),
            audit_hook,
        ) {
            Ok(server) => Arc::new(server),
            Err(error) => {
                eprintln!("Failed to build the ETSI X1 server: {error}");
                std::process::exit(1);
            }
        };

        match crate::li::x1::server::serve(Arc::new(x1_config.clone()), x1_server).await {
            Ok(address) => {
                info!(address = %address, "ETSI X1 provisioning interface listening");
            }
            Err(error) => {
                eprintln!("Failed to start the ETSI X1 listener: {error}");
                std::process::exit(1);
            }
        }

        // --- the network-element-to-ADMF direction ---
        //
        // Optional: without it siphon answers X1 but never speaks first. With
        // it, the ADMF is told the node started, gets keepalives, hears about
        // task and destination faults, and — the reason this direction exists —
        // has its view of what is provisioned reconciled against ours after a
        // restart.
        //
        // A misconfigured block (unreadable certificate, no admf_identifier to
        // put in the envelope) is a startup error: an operator who asked for
        // this must not get a node that silently never reports.
        if let Some(ref admf_config) = x1_config.admf {
            let schema = match crate::li::x1::X1Schema::compile() {
                Ok(schema) => Arc::new(schema),
                Err(error) => {
                    eprintln!("Failed to compile the X1 schemas: {error}");
                    std::process::exit(1);
                }
            };
            match crate::li::x1::client::X1Client::new(x1_config, admf_config, schema) {
                Ok(client) => {
                    let client = Arc::new(client);
                    // The delivery path needs it too: an X3 content-loss event
                    // has to become a destination-level report toward the ADMF,
                    // not just a log line.
                    li_manager.set_x1_client(Arc::clone(&client));
                    crate::li::x1::client::spawn(
                        client,
                        admf_config,
                        li_manager.tasks().clone(),
                        li_manager.destinations().clone(),
                    );
                    info!(
                        endpoint = %admf_config.endpoint,
                        keepalive_secs = admf_config.keepalive_secs,
                        reconcile = admf_config.reconcile_on_start,
                        "ETSI X1 network-element-to-ADMF direction started"
                    );
                }
                Err(error) => {
                    eprintln!("Failed to build the ETSI X1 ADMF client: {error}");
                    std::process::exit(1);
                }
            }
        }
    }

    // Spawn X2 IRI delivery task
    if let Some(ref x2_config) = li_config.x2 {
        let x2_arc = Arc::new(x2_config.clone());
        tokio::spawn(crate::li::x2::delivery_task(iri_rx, x2_arc));
        info!("X2 IRI delivery task started");
    } else {
        tokio::spawn(async move {
            let mut receiver = iri_rx;
            while receiver.recv().await.is_some() {}
        });
    }

    // No X3 task here, deliberately.
    //
    // Content is framed as TS 103 221-2 and delivered by the media engine,
    // straight to the destinations the ADMF provisioned over X1. siphon's part
    // is the warrant and the `AttachX3` that starts it, both of which live on
    // the dispatcher's interception path. There is nothing for this process to
    // receive, encapsulate or forward.

    // Spawn audit log writer
    let audit_log_path = li_config.audit_log.clone();
    tokio::spawn(async move {
        let mut receiver = audit_rx;
        let mut file = if let Some(ref path) = audit_log_path {
            match crate::file_sink::open_append_async(path).await {
                Ok(file) => Some(file),
                Err(error) => {
                    error!("failed to open LI audit log {path}: {error}");
                    None
                }
            }
        } else {
            None
        };

        use tokio::io::AsyncWriteExt;
        while let Some(entry) = receiver.recv().await {
            if let Some(ref mut file) = file {
                let line = format!(
                    "{:?} {:?} liid={} {}\n",
                    entry.timestamp,
                    entry.operation,
                    entry.subject.as_deref().unwrap_or("-"),
                    entry.detail,
                );
                let _ = file.write_all(line.as_bytes()).await;
                // Flush per entry. Tokio buffers the write, and this handle is
                // held open for the life of the process, so an unflushed audit
                // record would sit in the buffer indefinitely rather than
                // being readable the moment the operation it records happened.
                let _ = file.flush().await;
            }
        }
    });
}

pub(super) fn build_transport_acl(
    config: &Config,
    firewall: Option<crate::firewall::KernelFirewall>,
) -> Arc<transport::acl::TransportAcl> {
    use transport::acl::TransportAcl;

    if let Some(ref sec) = config.security {
        let apiban_set = if let Some(ref apiban_config) = sec.apiban {
            // trusted_cidrs is applied inside the client, at insert, so a
            // trusted source reaches neither the userspace store nor the
            // kernel set. Doing it here would only cover the former.
            match crate::apiban::ApiBanClient::new(apiban_config, &sec.trusted_cidrs) {
                Ok(client) => {
                    let client = client.with_firewall(firewall.clone());
                    let banned = client.banned();
                    client.start();
                    info!("APIBAN blocklist poller started");
                    Some(banned)
                }
                Err(error) => {
                    error!("Failed to create APIBAN client: {error}");
                    None
                }
            }
        } else {
            None
        };

        let acl = if let Some(banned) = apiban_set {
            TransportAcl::with_apiban(vec![], vec![], banned)
        } else {
            TransportAcl::new(vec![], vec![])
        };
        Arc::new(acl)
    } else {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }
}

/// The default egress UDP socket address: the first *parseable* entry in
/// `listen.udp` config (Vec) order.
///
/// This must be deterministic and must match `listen_addrs[Udp]` — the address
/// advertised as the Via sent-by — which is likewise the first configured UDP
/// listener (`listen_addrs.entry(Udp).or_insert(addr)` in config order). Picking
/// the default from config order rather than `udp_listener_channels` HashMap
/// iteration (a per-process randomized `RandomState` seed) is what keeps a
/// multi-homed UDP deployment egressing from a *stable* socket that agrees with
/// the Via it advertises, instead of an arbitrary listener that could differ
/// from the Via and flip between restarts.
pub(super) fn default_udp_egress_addr(
    udp_entries: &[config::ListenEntry],
) -> Option<std::net::SocketAddr> {
    udp_entries
        .iter()
        .find_map(|entry| entry.address().parse::<std::net::SocketAddr>().ok())
}

/// Work out which listen addresses are shared between two protocol lists, and
/// reject the pairings that cannot share one socket.
///
/// Raw SIP and SIP-over-WebSocket are distinguishable on one socket because
/// their start lines are disjoint (RFC 3261 §7.1 ` SIP/2.0` versus RFC 6455
/// §4.1 ` HTTP/1.1`), so `tcp`+`ws` and `tls`+`wss` are multiplexed by
/// [`transport::mux`]. Every other overlap is a configuration error: plaintext
/// and TLS cannot share a socket at all (a ClientHello is not a SIP message),
/// and the remaining combinations mix a secure listener with a plaintext one.
///
/// Returns `(tcp+ws addresses, tls+wss addresses)`.
pub(super) fn resolve_mux_addresses(
    listen: &config::ListenConfig,
) -> Result<(Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>), String> {
    fn addresses(
        entries: &[config::ListenEntry],
        label: &str,
    ) -> Result<Vec<std::net::SocketAddr>, String> {
        entries
            .iter()
            .map(|entry| {
                entry
                    .address()
                    .parse::<std::net::SocketAddr>()
                    .map_err(|error| {
                        format!(
                            "Invalid {label} listen address '{}': {error}",
                            entry.address()
                        )
                    })
            })
            .collect()
    }

    let tcp = addresses(&listen.tcp, "TCP")?;
    let tls = addresses(&listen.tls, "TLS")?;
    let ws = addresses(&listen.ws, "WS")?;
    let wss = addresses(&listen.wss, "WSS")?;

    let shared = |left: &[std::net::SocketAddr],
                  right: &[std::net::SocketAddr]|
     -> Vec<std::net::SocketAddr> {
        left.iter()
            .filter(|addr| right.contains(addr))
            .copied()
            .collect()
    };

    for (left, left_label, right, right_label) in [
        (&tcp, "tcp", &tls, "tls"),
        (&tcp, "tcp", &wss, "wss"),
        (&tls, "tls", &ws, "ws"),
        (&ws, "ws", &wss, "wss"),
    ] {
        if let Some(addr) = shared(left, right).first() {
            return Err(format!(
                "listen.{left_label} and listen.{right_label} are both configured on {addr}, \
                 which cannot share one socket. Only tcp+ws and tls+wss can be multiplexed \
                 on the same port."
            ));
        }
    }

    Ok((shared(&tcp, &ws), shared(&tls, &wss)))
}

/// Parse a configured listen address, exiting with a clear message when it is
/// malformed (a typo in `listen:` must never start a half-configured server).
pub(super) fn parse_listen_addr(address: &str, label: &str) -> std::net::SocketAddr {
    address.parse().unwrap_or_else(|error| {
        eprintln!("Invalid {label} listen address '{address}': {error}");
        std::process::exit(1);
    })
}

/// Index one `listen:` list by socket address, so overlapping addresses across
/// two lists can be detected (and their entries recovered) before any listener
/// is spawned.
pub(super) fn listen_addr_map<'a>(
    entries: &'a [config::ListenEntry],
    label: &str,
) -> std::collections::HashMap<std::net::SocketAddr, &'a config::ListenEntry> {
    entries
        .iter()
        .map(|entry| (parse_listen_addr(entry.address(), label), entry))
        .collect()
}

// ---------------------------------------------------------------------------
// Runtime-thread Python attachment
// ---------------------------------------------------------------------------

thread_local! {
    /// The attach this thread is pinned with, so [`unpin_python_thread_state`]
    /// can unwind it symmetrically. `None` on a thread that was never pinned
    /// (or has already been unpinned), which makes the unpin idempotent.
    static PINNED_PYTHON_ATTACH: std::cell::Cell<
        Option<(pyo3::ffi::PyGILState_STATE, *mut pyo3::ffi::PyThreadState)>,
    > = const { std::cell::Cell::new(None) };
}

/// Pin this runtime thread to the Python interpreter for its whole life.
///
/// Free-threaded Python (3.14t) tears down a thread's mimalloc heap on every
/// `PyGILState_Release` whose attach count returns to 0 — calling `munmap` and
/// serializing every worker on the process-wide `mm_struct` rwsem (visible in
/// perf as `_PyThreadState_ClearMimallocHeaps → rwsem_down_write_slowpath`).
/// Holding one attach open for the thread's lifetime keeps that count above 0,
/// so each per-request pyo3 attach is a cheap nested no-op.
///
/// The attach is *held*, not leaked: the `(gstate, tstate)` pair is parked in a
/// thread-local so [`unpin_python_thread_state`] can release it when the thread
/// is reaped. That pairing is load-bearing — see that function.
pub(super) fn pin_python_thread_state() {
    // SAFETY: called once per runtime thread, before any pyo3 attach on it.
    // `PyEval_SaveThread` re-detaches so other threads (and pyo3 attaches on
    // this one) can take the per-thread state without conflict, while the
    // underlying `PyThreadState` stays cached against the OS thread.
    unsafe {
        let gstate = pyo3::ffi::PyGILState_Ensure();
        let tstate = pyo3::ffi::PyEval_SaveThread();
        PINNED_PYTHON_ATTACH.with(|slot| slot.set(Some((gstate, tstate))));
    }
}

/// Release the attach [`pin_python_thread_state`] took, so CPython frees this
/// thread's `PyThreadState` when the OS thread goes away.
///
/// Without this half, the pin is a leak. `PyGILState_Ensure` allocates the
/// state with `PyMem_RawCalloc` — CPython's *raw* domain, i.e. plain
/// `malloc`, invisible to jemalloc and therefore to `siphon_memory_*` — and an
/// unreleased `GILState` keeps CPython from ever destroying it. The runtime's
/// fixed async workers live for the whole process so it never showed there, but
/// `on_thread_start` also fires for tokio's **elastic blocking pool**, whose
/// threads are reaped after their idle keep-alive. Every reaped blocking thread
/// then orphaned its `PyThreadState` on the C heap, for the life of the process:
/// a steady, traffic-independent RSS climb on any deployment that does blocking
/// work on a timer (DNS, netlink, TLS handshakes, health probes).
///
/// Releasing on thread *stop* costs nothing on the hot path — the workers this
/// optimization exists for never stop — while bounding the blocking pool.
pub(super) fn unpin_python_thread_state() {
    let Some((gstate, tstate)) = PINNED_PYTHON_ATTACH.with(|slot| slot.take()) else {
        return;
    };
    // SAFETY: runs on the same thread `pin_python_thread_state` pinned, after
    // its work is done. The thread is currently detached (the pin ended with
    // `PyEval_SaveThread`), so restore that exact state before releasing the
    // matching `GILState` — `PyGILState_Release` requires an attached thread.
    unsafe {
        pyo3::ffi::PyEval_RestoreThread(tstate);
        pyo3::ffi::PyGILState_Release(gstate);
    }
}

/// Publish the kernel gateway allow set, then keep it current.
///
/// Called after the firewall handle exists and **before the listeners bind**, so
/// the node never takes traffic while the kernel is still dropping a carrier
/// siphon is willing to dial. The gateway source loop is spawned earlier than
/// this, which is why the bootstrap publish exists at all rather than leaving
/// the first one to the reconcile's poke.
///
/// A failure is warned, never fatal: the operator's ruleset keeps whatever it
/// was deployed with, which is what a node did before the set existed.
pub(super) async fn init_gateway_allow_set(
    config: &Config,
    gateway_manager: Option<&Arc<crate::gateway::DispatcherManager>>,
    kernel_firewall_up: bool,
) {
    if !kernel_firewall_up {
        return;
    }
    let (Some(manager), Some(firewall_config)) = (
        gateway_manager,
        config
            .security
            .as_ref()
            .and_then(|security| security.firewall.as_ref()),
    ) else {
        return;
    };
    if !firewall_config.gateway_set {
        return;
    }
    let trusted_cidrs = config
        .security
        .as_ref()
        .map(|security| security.trusted_cidrs.clone())
        .unwrap_or_default();
    let allow_set = Arc::new(crate::firewall::gateways::GatewayAllowSet::new(
        firewall_config,
        &trusted_cidrs,
        Arc::clone(manager),
    ));
    if let Err(error) = allow_set.publish().await {
        warn!(
            %error,
            "kernel firewall: gateway allow set not published — a carrier provisioned at run time may be dialable while the kernel drops its answers"
        );
    }
    crate::firewall::gateways::install(Arc::clone(&allow_set));
    tokio::spawn(allow_set.run());
}
