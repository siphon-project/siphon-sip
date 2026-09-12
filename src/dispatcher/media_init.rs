//! Building the media backend and its health probe.
//!
//! One-time setup rather than datapath: called from `run` at startup to pick
//! between rtpengine, siphon-rtp and rtpproxy, and to spawn the probe that
//! marks an instance down.

use super::*;

/// Run a Python coroutine to completion.
///
/// When a handler is `async def`, calling it returns a coroutine object.
/// This function drives it using `asyncio.run()` which creates a fresh
/// event loop, runs the coroutine, and tears it down.
/// Initialize the media-control backend, media session store, and profile
/// registry, and register the Python `siphon.rtpengine` singleton.
///
/// Selects rtpengine NG or the native siphon-rtp engine per `media.backend`.
/// `event_sender` carries async engine events (DTMF, media-timeout) onward to
/// the dispatcher's consumer loop; the native backend forwards events from its
/// control connection over it (the rtpengine backend uses the separate TCP
/// event listener instead). Returns `(None, None, None)` when `media` is not
/// configured or the selected backend cannot be built.
pub fn init_rtpengine(
    config: &Config,
    event_sender: tokio::sync::mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
) -> RtpEngineComponents {
    let media_config = match &config.media {
        Some(c) => c,
        None => return (None, None, None),
    };

    let backend = match media_config.backend {
        crate::config::MediaBackendKind::Rtpengine => build_rtpengine_backend(media_config),
        crate::config::MediaBackendKind::SiphonRtp => {
            build_siphon_rtp_backend(media_config, event_sender)
        }
        crate::config::MediaBackendKind::Rtpproxy => build_rtpproxy_backend(media_config),
    };
    let backend = match backend {
        Some(backend) => Arc::new(backend),
        None => return (None, None, None),
    };

    let sessions = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
    // Profile registry from built-in defaults + custom YAML profiles (shared
    // across backends — profiles map to NG flags / proto ProfileFlags alike).
    let registry = Arc::new(crate::rtpengine::ProfileRegistry::from_config(
        &media_config.profiles,
    ));

    // `address_family` has no equivalent in the classic rtpproxy control
    // protocol: its `6` modifier states the family of the address the command
    // carries (derived from the offered c= line), it does not select a family for
    // the relay.  Say so at boot rather than let the knob look wired.
    if matches!(
        media_config.backend,
        crate::config::MediaBackendKind::Rtpproxy
    ) {
        let mut with_family: Vec<&str> = media_config
            .profiles
            .iter()
            .filter(|(_, profile)| {
                profile.offer.address_family.is_some() || profile.answer.address_family.is_some()
            })
            .map(|(name, _)| name.as_str())
            .collect();
        if !with_family.is_empty() {
            with_family.sort_unstable();
            warn!(
                profiles = %with_family.join(", "),
                "media profile sets address_family, which the rtpproxy backend \
                 cannot honour (rtpengine / siphon-rtp only) — IPv4/IPv6 \
                 interworking will not happen on these profiles"
            );
        }
    }

    // Create the Python-side singleton (shares the same Arcs).
    let py_rtpengine = crate::script::api::rtpengine::PyRtpEngine::new(
        Arc::clone(&backend),
        Arc::clone(&sessions),
        Arc::clone(&registry),
    );
    Python::attach(|python| {
        if let Err(error) = crate::script::api::set_rtpengine_singleton(python, py_rtpengine) {
            error!("failed to store RTPEngine singleton: {error}");
        } else {
            info!(
                instances = backend.instance_count(),
                "media backend registered"
            );
        }
    });

    (Some(backend), Some(sessions), Some(registry))
}

/// Build the rtpengine NG/bencode backend from `media.rtpengine`.
pub(super) fn build_rtpengine_backend(
    media_config: &crate::config::MediaConfig,
) -> Option<crate::rtpengine::MediaBackend> {
    let rtpengine_config = match &media_config.rtpengine {
        Some(config) => config,
        None => {
            error!("media.backend is 'rtpengine' but no media.rtpengine block is configured");
            return None;
        }
    };

    let instances_config = rtpengine_config.instances();
    let mut instance_tuples = Vec::new();
    for instance in &instances_config {
        match instance.address.parse::<std::net::SocketAddr>() {
            Ok(address) => instance_tuples.push((address, instance.timeout_ms, instance.weight)),
            Err(parse_error) => error!(
                address = %instance.address,
                error = %parse_error,
                "invalid RTPEngine address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        return None;
    }

    let count = instance_tuples.len();
    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::client::RtpEngineSet::new(instance_tuples))
    }) {
        Ok(set) => {
            info!(
                instances = count,
                "rtpengine NG backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::RtpEngine(Arc::new(set)))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize RTPEngine client");
            None
        }
    }
}

/// Build the native siphon-rtp JSON-over-TCP backend from `media.siphon_rtp`.
pub(super) fn build_siphon_rtp_backend(
    media_config: &crate::config::MediaConfig,
    event_sender: tokio::sync::mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
) -> Option<crate::rtpengine::MediaBackend> {
    let siphon_rtp_config = match &media_config.siphon_rtp {
        Some(config) => config,
        None => {
            error!("media.backend is 'siphon-rtp' but no media.siphon_rtp block is configured");
            return None;
        }
    };

    let mut instance_tuples = Vec::new();
    for (address, timeout_ms, weight) in siphon_rtp_config.instances() {
        match address.parse::<std::net::SocketAddr>() {
            Ok(parsed) => instance_tuples.push((parsed, timeout_ms, weight)),
            Err(parse_error) => error!(
                address = %address,
                error = %parse_error,
                "invalid siphon-rtp control address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        error!("media.backend is 'siphon-rtp' but no valid control address is configured");
        return None;
    }

    let count = instance_tuples.len();
    match crate::rtpengine::SiphonRtpClientSet::new(
        instance_tuples,
        siphon_rtp_config.control_secret.clone(),
        siphon_rtp_config.play_timeout_ms,
        event_sender,
    ) {
        Ok(set) => {
            info!(
                instances = count,
                "siphon-rtp native media backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::SiphonRtp(set))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize siphon-rtp client set");
            None
        }
    }
}

/// Build the classic rtpproxy text-over-UDP backend from `media.rtpproxy`.
pub(super) fn build_rtpproxy_backend(
    media_config: &crate::config::MediaConfig,
) -> Option<crate::rtpengine::MediaBackend> {
    let rtpproxy_config = match &media_config.rtpproxy {
        Some(config) => config,
        None => {
            error!("media.backend is 'rtpproxy' but no media.rtpproxy block is configured");
            return None;
        }
    };

    let mut instance_tuples = Vec::new();
    for (address, timeout_ms, weight) in rtpproxy_config.instances() {
        match address.parse::<std::net::SocketAddr>() {
            Ok(parsed) => instance_tuples.push((parsed, timeout_ms, weight)),
            Err(parse_error) => error!(
                address = %address,
                error = %parse_error,
                "invalid rtpproxy control address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        error!("media.backend is 'rtpproxy' but no valid control address is configured");
        return None;
    }

    let count = instance_tuples.len();
    let retries = rtpproxy_config.retries;
    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::RtpProxyClientSet::new(
            instance_tuples,
            retries,
        ))
    }) {
        Ok(set) => {
            info!(
                instances = count,
                "rtpproxy media backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::RtpProxy(set))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize rtpproxy client set");
            None
        }
    }
}

/// Spawn a background task that pings every RTPEngine instance on a fixed
/// interval and exports per-instance health to Prometheus.
///
/// The first probe runs immediately so the gauges reflect reality from the
/// moment the task starts; subsequent probes run every `interval_secs`
/// seconds.  Pass `interval_secs == 0` to disable health probing entirely.
///
/// Updates these metrics:
/// - `siphon_rtpengine_instances_total` — number of configured instances
/// - `siphon_rtpengine_instances_up` — number that answered the last ping
/// - `siphon_rtpengine_instance_up{address}` — 0/1 for each instance
pub fn spawn_rtpengine_health_check(
    rtpengine_set: Arc<crate::rtpengine::MediaBackend>,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        info!("RTPEngine health probing disabled (interval_secs=0)");
        return;
    }

    let total_instances = rtpengine_set.instance_count();
    let addresses = rtpengine_set.instance_addresses();

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics
            .rtpengine_instances_total
            .set(total_instances as i64);
        // Pre-create the per-instance label series so they appear at zero
        // before the first probe completes.
        for address in &addresses {
            metrics
                .rtpengine_instance_up
                .with_label_values(&[&address.to_string()])
                .set(0);
        }
    }

    info!(
        instances = total_instances,
        interval_secs, "starting RTPEngine health probe"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let results = rtpengine_set.health_check().await;
            let healthy_count = results.iter().filter(|(_, healthy)| *healthy).count();

            for (address, healthy) in &results {
                if !healthy {
                    warn!(
                        address = %address,
                        "RTPEngine instance failed health probe"
                    );
                }
            }

            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.rtpengine_instances_up.set(healthy_count as i64);
                for (address, healthy) in &results {
                    metrics
                        .rtpengine_instance_up
                        .with_label_values(&[&address.to_string()])
                        .set(if *healthy { 1 } else { 0 });
                }
            }
        }
    });
}

/// Run a Python coroutine to completion.
/// Check if a Python object is a coroutine (awaitable).
pub(super) fn is_coroutine(python: Python<'_>, obj: &Bound<'_, pyo3::PyAny>) -> PyResult<bool> {
    let asyncio = python.import("asyncio")?;
    let result = asyncio.call_method1("iscoroutine", (obj,))?;
    result.is_truthy()
}
