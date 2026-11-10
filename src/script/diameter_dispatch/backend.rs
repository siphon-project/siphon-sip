//! Backend connection and DNS group bootstrap.
use super::*;
use crate::diameter::backoff::ReconnectSchedule;

/// Connect one backend server as an outbound client, reconnecting on drop.
/// Supports both TCP and SCTP transports. Requests the backend sends on the
/// connection (an HSS's Cancel-Location, an OCS's Re-Auth) are served like
/// any other: RFC 6733 lets either end of a connection send requests.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_backend_connection(
    tenant_name: &str,
    tenant: &crate::config::DiameterTenant,
    server: &crate::config::DiameterServerEntry,
    manager: Arc<DiameterManager>,
    engine: Arc<ScriptEngine>,
    semaphore: Arc<Semaphore>,
    applications: TenantApplications,
    product_name: &str,
    product_version: &str,
) -> tokio::task::JoinHandle<()> {
    let grouped = server.all_addresses;
    let transport = server.transport.clone();
    let mut config = PeerConfig {
        host: server.host.clone(),
        port: server.port,
        origin_host: tenant.identity.origin_host.clone(),
        origin_realm: tenant.identity.origin_realm.clone(),
        destination_host: None,
        destination_realm: tenant.identity.origin_realm.clone(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: vec![],
        watchdog_interval: server.watchdog_interval.unwrap_or(30),
        reconnect_delay: server.reconnect_delay.unwrap_or(5),
        source_address: server.source_address,
        lifecycle: server.lifecycle(),
        product_name: product_name.to_string(),
        firmware_revision: peer::version_to_firmware_revision(product_version),
    };
    let name = server.name.clone();
    let tenant_name = tenant_name.to_string();
    let identity = (
        tenant.identity.origin_host.clone(),
        tenant.identity.origin_realm.clone(),
    );
    let peer_info = PyInboundPeer {
        name: name.clone(),
        tenant: tenant_name.clone(),
        addr: format!("{}:{}", server.host, server.port),
        transport: transport.clone(),
        // The peer's CER/CEA identity, once connected (`serve_requests`).
        host: String::new(),
    };
    let mut schedule =
        ReconnectSchedule::new(config.reconnect_delay, config.lifecycle.reconnect_delay_max);
    tokio::spawn(async move {
        if grouped {
            crate::metrics::set_diameter_peer_up(&name, false);
        }
        loop {
            let delay;
            // Asked per attempt: the CER advertises what the script serves now.
            config.application_ids = applications(&tenant_name);
            match peer::connect_with_transport(config.clone(), &transport).await {
                Ok((connected, incoming_rx)) => {
                    if schedule.connected() {
                        connected.enter_reopen().await;
                    }
                    let client = Arc::new(DiameterClient::new(Arc::clone(&connected)));
                    manager.register_backend(&tenant_name, &name, client);
                    if grouped {
                        crate::metrics::set_diameter_peer_up(&name, true);
                    }
                    info!(peer = %name, tenant = %tenant_name, "Diameter server backend connected");
                    let ended = Arc::clone(&connected);
                    serve_requests(
                        connected,
                        incoming_rx,
                        peer_info.clone(),
                        Arc::clone(&engine),
                        Arc::clone(&semaphore),
                        identity.clone(),
                    )
                    .await;
                    if grouped {
                        crate::metrics::set_diameter_peer_up(&name, false);
                    }
                    match schedule.ended(&ended) {
                        None => {
                            info!(peer = %name, "Diameter server backend disconnected by this node, not reconnecting");
                            return;
                        }
                        Some(wait) => {
                            warn!(peer = %name, wait_secs = wait.as_secs(), "Diameter server backend disconnected, reconnecting");
                            delay = wait;
                        }
                    }
                }
                Err(error) => {
                    delay = schedule.failed();
                    warn!(peer = %name, %error, wait_secs = delay.as_secs(), "Diameter server backend connect failed, retrying");
                }
            }
            tokio::time::sleep(delay).await;
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn(
    tenant_name: &str,
    tenant: &crate::config::DiameterTenant,
    server: &crate::config::DiameterServerEntry,
    manager: Arc<DiameterManager>,
    engine: Arc<ScriptEngine>,
    semaphore: Arc<Semaphore>,
    applications: TenantApplications,
    product_name: &str,
    product_version: &str,
    interval: u64,
) {
    if !server.all_addresses {
        spawn_backend_connection(
            tenant_name,
            tenant,
            server,
            manager,
            engine,
            semaphore,
            applications,
            product_name,
            product_version,
        );
        return;
    }
    let tenant_name = tenant_name.to_owned();
    let tenant = tenant.clone();
    let server = server.clone();
    let product_name = product_name.to_owned();
    let product_version = product_version.to_owned();
    crate::diameter::group::spawn_group(
        manager.clone(),
        Some(tenant_name.clone()),
        server.name.clone(),
        server.host.clone(),
        server.port,
        interval,
        move |name, address| {
            let mut member = server.clone();
            member.name = name;
            member.host = crate::diameter::group::connection_host(address);
            member.port = address.port();
            spawn_backend_connection(
                &tenant_name,
                &tenant,
                &member,
                manager.clone(),
                engine.clone(),
                semaphore.clone(),
                applications.clone(),
                &product_name,
                &product_version,
            )
        },
    );
}
