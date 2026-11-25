//! Connecting the registrar's persistence backend, at start-up or after it.
//!
//! A backend that answers at start-up is restored before any listener is up.
//! One that does not (a Redis in a maintenance window, a failover) is retried
//! in the background every [`RETRY_INTERVAL`], as the named caches probe
//! theirs, and attached the moment it answers: its stored bindings merged
//! beside the live ones, the restored stream bindings evicted, the writer
//! installed, and everything accepted meanwhile written through. The node runs
//! on memory alone until then; `siphon_registrar_backend_up` says so, and
//! `required_for_readiness` keeps it out of rotation.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use super::bootstrap::{
    init_ifc_redis_backend, init_presence_redis_backend, init_registrant_bindings, instance_id,
};
use super::restored_stream_eviction::evict_restored_stream_bindings;
use crate::config::{Config, RegistrarBackendType};
use crate::registrar::backend::{self, RegistrarBackend};
use crate::registrar::backend_status::BackendStatus;
use crate::registrar::Registrar;

/// How long to wait between attempts to reach a backend that is down.
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// One failed attempt in this many is logged at `warn`, the rest at `debug`:
/// the first one was an `error`, and a backend down for an hour is not 3600
/// lines.
const LOG_EVERY: u64 = 30;

/// Connect the registrar backend the configuration names, restore from it and
/// install its writer. Returns the status of the backend (for readiness), or
/// `None` with the memory backend.
///
/// A backend that cannot be reached now is retried in the background; this
/// returns without waiting for it.
pub(super) async fn init_registrar_backend(config: &Config) -> Option<Arc<BackendStatus>> {
    let registrar = crate::script::api::registrar_arc()?;

    match config.registrar.backend {
        RegistrarBackendType::Redis => {
            let Some(redis_cfg) = &config.registrar.redis else {
                error!("registrar backend is redis but no redis config provided");
                return None;
            };
            let status = Arc::new(BackendStatus::new(redis_cfg.required_for_readiness));
            let backend_config = backend::RedisBackendConfig {
                target: redis_cfg.target.clone(),
                urls: redis_cfg.urls.clone(),
                key_prefix: redis_cfg.key_prefix.clone(),
                shard_count: redis_cfg.shard_count,
                ttl_slack_secs: redis_cfg.ttl_slack_secs as u64,
            };
            let max_expires = u64::from(config.registrar.max_expires);
            let connect = move || {
                let backend_config = backend_config.clone();
                async move {
                    backend::RedisBackend::connect(backend_config)
                        .await
                        .map(|connected| connected.with_max_binding_lifetime(max_expires))
                }
            };
            let owned_config = config.clone();
            let attach_status = Arc::clone(&status);
            let attach = move |connected: backend::RedisBackend, late: bool| {
                let owned_config = owned_config.clone();
                let status = Arc::clone(&attach_status);
                async move { attach_redis(&owned_config, registrar, connected, late, &status).await }
            };
            connect_or_retry("Redis", connect, attach).await;
            Some(status)
        }
        RegistrarBackendType::Postgres => {
            let Some(postgres_cfg) = &config.registrar.postgres else {
                error!("registrar backend is postgres but no postgres config provided");
                return None;
            };
            let status = Arc::new(BackendStatus::new(postgres_cfg.required_for_readiness));
            let backend_config = backend::PostgresBackendConfig {
                url: postgres_cfg.url.clone(),
                urls: Vec::new(),
                table: postgres_cfg.table.clone(),
                shard_count: 0,
            };
            let max_expires = u64::from(config.registrar.max_expires);
            let connect = move || {
                let backend_config = backend_config.clone();
                async move {
                    backend::PostgresBackend::connect(backend_config)
                        .await
                        .map(|connected| connected.with_max_binding_lifetime(max_expires))
                }
            };
            let attach_status = Arc::clone(&status);
            let attach = move |connected: backend::PostgresBackend, late: bool| {
                let status = Arc::clone(&attach_status);
                async move {
                    attach_registrar_backend(
                        "Postgres",
                        registrar,
                        Arc::new(connected),
                        late,
                        config_ipsec_ports(None),
                        &status,
                    )
                    .await;
                    info!(
                        "presence subscriptions are written through with the redis registrar \
                         backend only; with postgres they stay in memory and a restart drops them"
                    );
                }
            };
            connect_or_retry("Postgres", connect, attach).await;
            Some(status)
        }
        RegistrarBackendType::Memory | RegistrarBackendType::Python => None,
    }
}

/// Hold `/admin/ready` at 503 on the backend's status, when it was asked to.
pub(super) fn register_registrar_backend_readiness(
    status: Option<Arc<BackendStatus>>,
    participants: &crate::lifecycle::Participants,
) {
    if let Some(status) = status {
        participants.register(status);
    }
}

/// Try `connect` once and attach what it returns; on failure keep trying in a
/// task of its own, attaching on the first success.
async fn connect_or_retry<B, E, Connect, ConnectFuture, Attach, AttachFuture>(
    label: &'static str,
    connect: Connect,
    attach: Attach,
) where
    B: Send + 'static,
    E: std::fmt::Display + Send + 'static,
    Connect: Fn() -> ConnectFuture + Send + 'static,
    ConnectFuture: std::future::Future<Output = Result<B, E>> + Send,
    Attach: FnOnce(B, bool) -> AttachFuture + Send + 'static,
    AttachFuture: std::future::Future<Output = ()> + Send + 'static,
{
    match connect().await {
        Ok(connected) => attach(connected, false).await,
        Err(error) => {
            error!(
                %error,
                "failed to connect to {label} registrar backend: running on memory alone and \
                 retrying every {}s",
                RETRY_INTERVAL.as_secs()
            );
            tokio::spawn(async move {
                let connected = connect_until(label, RETRY_INTERVAL, connect).await;
                info!("{label} registrar backend reachable, attaching it");
                attach(connected, true).await;
            });
        }
    }
}

/// Call `connect` every `interval` until it succeeds.
async fn connect_until<B, E, Connect, ConnectFuture>(
    label: &str,
    interval: Duration,
    connect: Connect,
) -> B
where
    E: std::fmt::Display,
    Connect: Fn() -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<B, E>>,
{
    let mut attempts = 0u64;
    loop {
        tokio::time::sleep(interval).await;
        match connect().await {
            Ok(connected) => return connected,
            Err(error) => {
                attempts += 1;
                if attempts.is_multiple_of(LOG_EVERY) {
                    warn!(%error, attempts, "{label} registrar backend still unreachable");
                } else {
                    tracing::debug!(%error, attempts, "{label} registrar backend unreachable");
                }
            }
        }
    }
}

/// The IPsec ports a late restore drops protected bindings on, when IPsec is
/// configured. A boot restore leaves it to `reconcile_ipsec_restart`.
fn config_ipsec_ports(config: Option<&Config>) -> Option<(Vec<u16>, u16)> {
    let ipsec = config?.ipsec.as_ref()?;
    Some((ipsec.pcscf_port_c.as_slice().to_vec(), ipsec.pcscf_port_s))
}

/// Everything a connected Redis backend gives besides the registrar's own
/// bindings: read-through, iFC profiles, presence subscriptions.
async fn attach_redis(
    config: &Config,
    registrar: &'static Arc<Registrar>,
    connected: backend::RedisBackend,
    late: bool,
    status: &BackendStatus,
) {
    let Some(redis_cfg) = &config.registrar.redis else {
        return;
    };
    let connected = Arc::new(connected);
    attach_registrar_backend(
        "Redis",
        registrar,
        Arc::clone(&connected),
        late,
        late.then(|| config_ipsec_ports(Some(config))).flatten(),
        status,
    )
    .await;
    if redis_cfg.read_through_ttl_ms > 0 {
        registrar.set_shared_reader(crate::registrar::SharedReader::new(
            connected,
            Duration::from_millis(redis_cfg.read_through_ttl_ms),
        ));
    }

    // --- iFC profile persistence (shares the same Redis instance) ---
    init_ifc_redis_backend(
        &redis_cfg.target,
        u64::from(redis_cfg.ttl_slack_secs),
        config,
    )
    .await;

    // --- presence subscriptions (the same Redis, its own prefix) ---
    init_presence_redis_backend(redis_cfg).await;

    // --- the registrant's bindings (the same Redis, its own prefix) ---
    if config.registrant.is_some() {
        init_registrant_bindings(redis_cfg, instance_id(config)).await;
    }
}

/// Restore the registrar from `backend`, install its writer, and mark the
/// backend up.
///
/// `late` is a backend that answered after start-up, into a registrar that has
/// been taking REGISTERs: what it restores is merged beside the live bindings,
/// the writer goes in before the evictions so they reach the backend, the
/// restored bindings of a protected UE whose security associations this
/// process does not hold (`ipsec_ports`) and then the restored stream bindings
/// are evicted, as start-up does in that order, and everything accepted before
/// the writer existed is written through.
pub(super) async fn attach_registrar_backend<B: RegistrarBackend + 'static>(
    label: &str,
    registrar: &Arc<Registrar>,
    backend: Arc<B>,
    late: bool,
    ipsec_ports: Option<(Vec<u16>, u16)>,
    status: &BackendStatus,
) {
    let restored = if late {
        backend::restore_from_backend_keeping_live(&*backend, registrar).await
    } else {
        backend::restore_from_backend(&*backend, registrar).await
    };
    match restored {
        Ok((aors, contacts)) => {
            if let Some(metrics) = crate::metrics::try_metrics() {
                let held = if late { registrar.aor_count() } else { aors };
                metrics.registrations_active.set(held as i64);
            }
            info!(
                aors,
                contacts, late, "restored contacts from {label} backend"
            );
        }
        Err(error) => {
            error!(%error, "failed to restore contacts from {label} backend");
        }
    }
    registrar.set_backend_writer(backend::spawn_backend_writer(backend));
    if late {
        if let (Some((ports_c, port_s)), Some(manager)) =
            (ipsec_ports, crate::ipsec::global_manager())
        {
            let dropped = manager.drop_restored_bindings_without_sa(registrar, &ports_c, port_s);
            if dropped > 0 {
                warn!(
                    dropped,
                    "IPsec: restored bindings without security associations dropped"
                );
            }
        }
        evict_restored_stream_bindings(registrar);
        let written = registrar.write_through_all();
        info!(
            written,
            "bindings accepted before the backend answered written through"
        );
    }
    status.mark_up();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::lifecycle::LifecycleParticipant;
    use crate::registrar::backend::{MemoryBackend, StoredContact};
    use crate::registrar::{FlowCapture, InstanceIdentity};
    use crate::sip::uri::SipUri;
    use crate::transport::Transport;

    fn save_over(registrar: &Registrar, aor: &str, transport: Transport) {
        registrar
            .save_full(
                aor,
                SipUri::new("192.0.2.10".to_string()).with_user("phone".to_string()),
                3600,
                1.0,
                format!("call-{aor}"),
                1,
                None,
                Some(transport),
                None,
                None,
                vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();
    }

    fn registrar(epoch: &str) -> Registrar {
        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "node-a".into(),
            epoch: epoch.into(),
        });
        registrar
    }

    async fn store(backend: &MemoryBackend, from: &Registrar, aor: &str) {
        let stored: Vec<StoredContact> = from
            .lookup_all(aor)
            .iter()
            .map(StoredContact::from_contact)
            .collect();
        RegistrarBackend::save(backend, aor, &stored).await.unwrap();
    }

    /// Wait for the writer task to apply a write.
    async fn eventually<Fut: std::future::Future<Output = bool>>(mut check: impl FnMut() -> Fut) {
        for _ in 0..200 {
            if check().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the backend never reached the expected state");
    }

    #[tokio::test]
    async fn a_connect_that_fails_is_retried_until_it_answers() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        let connected = connect_until("Test", Duration::from_millis(1), move || {
            let attempt = counted.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 3 {
                    Err("connection refused")
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;
        assert_eq!(connected, 3);
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    /// A backend that answers after the node has been taking REGISTERs: the
    /// stored bindings come back beside the live ones, the stored stream
    /// binding goes (its connection died with the old process) and the live
    /// stream binding stays, and what was accepted before the writer existed
    /// reaches the backend.
    #[tokio::test]
    async fn a_late_backend_restores_beside_the_live_bindings_and_catches_up() {
        let backend = Arc::new(MemoryBackend::new());
        let previous = registrar("previous-boot");
        save_over(&previous, "sip:stored-udp@example.com", Transport::Udp);
        save_over(&previous, "sip:stored-tcp@example.com", Transport::Tcp);
        store(&backend, &previous, "sip:stored-udp@example.com").await;
        store(&backend, &previous, "sip:stored-tcp@example.com").await;

        let live = Arc::new(registrar("this-boot"));
        save_over(&live, "sip:live-udp@example.com", Transport::Udp);
        save_over(&live, "sip:live-tls@example.com", Transport::Tls);
        let status = BackendStatus::new(true);
        assert!(status.ready().is_err());

        attach_registrar_backend("Test", &live, Arc::clone(&backend), true, None, &status).await;

        assert!(status.ready().is_ok());
        assert!(live.is_registered("sip:stored-udp@example.com"));
        assert!(!live.is_registered("sip:stored-tcp@example.com"));
        assert!(live.is_registered("sip:live-udp@example.com"));
        assert!(
            live.is_registered("sip:live-tls@example.com"),
            "a live connection"
        );
        eventually(|| async {
            RegistrarBackend::exists(&*backend, "sip:live-udp@example.com")
                .await
                .unwrap()
                && RegistrarBackend::exists(&*backend, "sip:live-tls@example.com")
                    .await
                    .unwrap()
                && !RegistrarBackend::exists(&*backend, "sip:stored-tcp@example.com")
                    .await
                    .unwrap()
        })
        .await;
        assert!(
            RegistrarBackend::exists(&*backend, "sip:stored-udp@example.com")
                .await
                .unwrap()
        );
    }

    /// At start-up the eviction is the server's, after the IPsec reconcile:
    /// attaching alone leaves the restored stream binding for it.
    #[tokio::test]
    async fn a_backend_attached_at_start_up_leaves_the_eviction_to_the_server() {
        let backend = Arc::new(MemoryBackend::new());
        let previous = registrar("previous-boot");
        save_over(&previous, "sip:stored-tcp@example.com", Transport::Tcp);
        store(&backend, &previous, "sip:stored-tcp@example.com").await;
        let fresh = Arc::new(registrar("this-boot"));
        let status = BackendStatus::new(false);

        attach_registrar_backend("Test", &fresh, backend, false, None, &status).await;

        assert!(fresh.is_registered("sip:stored-tcp@example.com"));
        assert!(status.is_up());
    }
}
