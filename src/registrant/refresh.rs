//! The background loop that keeps every outbound registration alive, and the
//! de-registrations sent when an entry goes away or the process stops.
//!
//! Split from [`super`] so the manager's state and the schedule that drives it
//! read separately: the manager decides what a REGISTER looks like and what an
//! answer does, this decides when one leaves and from which socket.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tracing::{debug, error, warn};

use super::pacing::RegisterRateLimiter;
use super::{BuiltRegister, RegistrantEgress, RegistrantManager, RegistrantState};
use crate::hep::HepSender;
use crate::ipsec::IpsecManager;
use crate::transport::outbound_tls::registrar_server_name;
use crate::transport::pool::ConnectionPool;
use crate::transport::ue_sockets::UeSockets;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};
use crate::uac::resolve_via_addr;

/// Everything [`registration_loop`] needs from the server.
pub struct RegistrationLoopContext {
    pub outbound: Arc<OutboundRouter>,
    /// The process's primary listen address.
    pub local_addr: SocketAddr,
    /// The first listener of each transport.
    pub listen_addrs: HashMap<Transport, SocketAddr>,
    pub advertised_addrs: HashMap<Transport, String>,
    pub advertised_address: Option<String>,
    pub hep_sender: Option<Arc<HepSender>>,
    pub connection_pool: Arc<ConnectionPool>,
    /// Where entries with a `local_addr` get their sockets. `None` leaves such
    /// an entry unable to bind (it is logged and never sent).
    pub ue_sockets: Option<Arc<UeSockets>>,
    /// Tears down the SAs of an entry that moved off its address.
    pub ipsec_manager: Option<Arc<IpsecManager>>,
}

/// The tick when no start-rate cap is configured.
const TICK: Duration = Duration::from_secs(5);

/// The tick under `max_registers_per_sec`: short, so the starts a second
/// allows spread across it instead of leaving in one burst every five seconds.
const PACED_TICK: Duration = Duration::from_millis(200);

/// Background registration refresh loop.
///
/// Runs for the life of the process. De-registration at shutdown is driven by
/// `serve()` through [`deregister_all`] instead of from here: a loop signalled
/// over a channel would be racing its own sleep against `std::process::exit`,
/// which is why the sender used to be leaked rather than held.
pub async fn registration_loop(manager: Arc<RegistrantManager>, context: RegistrationLoopContext) {
    let tick_interval = if manager.max_registers_per_sec().is_some() {
        PACED_TICK
    } else {
        TICK
    };
    let mut limiter = manager
        .max_registers_per_sec()
        .map(RegisterRateLimiter::new);

    // A de-registration is built at the moment an entry is removed, outside
    // this loop, so the addressing a REGISTER needs is recorded on the manager.
    manager.set_egress(RegistrantEgress {
        local_addr: context.local_addr,
        listen_addrs: context.listen_addrs.clone(),
        advertised_addrs: context.advertised_addrs.clone(),
        advertised_address: context.advertised_address.clone(),
        hep_sender: context.hep_sender.clone(),
    });
    let Some(egress) = manager.egress.get() else {
        error!("registrant egress could not be installed — outbound registration is not running");
        return;
    };
    if let Some(ipsec) = context.ipsec_manager.clone() {
        manager.install_ipsec(ipsec);
    }

    loop {
        tokio::time::sleep(tick_interval).await;
        run_tick(&manager, &context, egress, limiter.as_mut());
    }
}

/// One pass of [`registration_loop`].
fn run_tick(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
    mut limiter: Option<&mut RegisterRateLimiter>,
) {
    // Clear bindings for entries removed since the last tick. Sent before
    // anything else so a trunk that was deleted stops receiving calls as soon
    // as possible.
    for built in manager.take_pending_deregistrations() {
        debug!(destination = %built.destination, "sending de-REGISTER for a removed registrant");
        send_registrant_message(&context.outbound, egress, built);
    }

    // SAs of entries that moved off an address (before the new address's
    // handshake installs fresh ones), superseded or abandoned SA sets, and
    // those of removed entries whose de-REGISTER went unanswered.
    manager.expire_teardowns(std::time::Instant::now());
    delete_queued_sas(manager, context, egress);

    // Sockets for every entry that registers from an address of its own. An
    // entry whose socket cannot bind sits this tick out.
    let unbindable = reconcile_ue_sockets(manager, context, egress);

    // Stated before the liveness check below reads those connections, and
    // before the first REGISTER of a trunk added since the last tick opens one.
    exempt_trunk_connections_from_idle_reap(manager, &context.connection_pool);

    // Connection loss on TLS/TCP: re-register on this tick instead of at the
    // refresh timer, which also re-opens the connection the registrar reaches
    // this trunk over.
    force_refresh_lost_connections(manager, &context.connection_pool);

    // Time out entries stuck in Registering/Challenging (RFC 3261 Timer F —
    // 32s). Catches dead sockets where no response ever arrives, and a per-UE
    // address that left the host (its sends fail in the kernel).
    for aor in manager.entries_timed_out() {
        warn!(aor = %aor, "REGISTER transaction timed out — no response received");
        manager.handle_failure(&aor, 0, None);
    }
    // The temporary SA sets the timeouts abandoned.
    delete_queued_sas(manager, context, egress);

    let now = tokio::time::Instant::now();
    for aor in manager.entries_due() {
        if unbindable.contains(&aor) {
            continue;
        }
        if let Some(limiter) = limiter.as_deref_mut() {
            // Due entries come longest-overdue first, so the ones left for the
            // next tick are the newest.
            if !limiter.try_acquire(now) {
                break;
            }
        }
        let Some(built) = manager.build_register(&aor, egress.defaults(), manager.default_interval)
        else {
            continue;
        };
        debug!(aor = %aor, branch = %built.branch, "sending REGISTER");
        if let Err(error) = context.outbound.send(outbound_message(egress, built)) {
            warn!(aor = %aor, %error, "failed to send REGISTER");
            manager.handle_failure(&aor, 0, None);
        }
    }
}

/// Converge the per-UE sockets on what the entries need; returns the AoRs
/// whose sockets could not be bound this tick.
fn reconcile_ue_sockets(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
) -> HashSet<String> {
    let plan = manager.ue_socket_plan(egress.defaults().plain_port(), process_ue_ip(egress));
    let Some(sockets) = context.ue_sockets.as_ref() else {
        if !plan.is_empty() {
            debug!(
                entries = plan.len(),
                "entries with a local_addr but no per-UE socket support in this process"
            );
        }
        return plan.into_iter().map(|(aor, _)| aor).collect();
    };
    let desired: HashSet<SocketAddr> = plan
        .iter()
        .flat_map(|(_, addrs)| addrs.iter().copied())
        .collect();
    let outcome = sockets.reconcile(&desired);
    if outcome.failed.is_empty() {
        return HashSet::new();
    }
    plan.into_iter()
        .filter(|(_, addrs)| addrs.iter().any(|addr| outcome.failed.contains(addr)))
        .map(|(aor, _)| aor)
        .collect()
}

/// Delete the SA pairs the manager queued.
fn delete_queued_sas(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
) {
    let deletions = manager.take_pending_sa_deletions();
    if deletions.is_empty() {
        return;
    }
    let Some(ipsec_manager) = context.ipsec_manager.as_ref() else {
        debug!(
            pairs = deletions.len(),
            "SA deletions queued with no IPsec manager in this process"
        );
        return;
    };
    super::protected::spawn_sa_deletions(deletions, ipsec_manager, process_ue_ip(egress));
}

/// The UE address a process-address entry's SAs carry: the dispatcher's
/// resolved local address, which is what it installed them with.
fn process_ue_ip(egress: &RegistrantEgress) -> IpAddr {
    resolve_via_addr(
        egress.local_addr,
        &Transport::Udp,
        &HashMap::new(),
        egress.advertised_address.as_deref(),
    )
    .ip()
}

/// Keep every stream-transport trunk's pooled connection out of the pool's idle
/// reaper. Returns the exempted destinations.
///
/// A trunk's connection is long-lived by definition and
/// [`force_refresh_lost_connections`] judges the trunk from it, so the pool
/// closing it after 30 s of silence had an *idle* trunk read as dead ~5 s later
/// and re-registering roughly every 35 s whatever its interval said. Detection
/// is untouched — [`ConnectionPool::set_idle_exempt_destinations`] has both
/// halves.
///
/// Every entry counts, not only the Registered ones: a trunk mid-401 needs the
/// connection its next response comes back on. The set is re-stated in full each
/// tick, so a removed trunk releases its destination.
pub(super) fn exempt_trunk_connections_from_idle_reap(
    manager: &RegistrantManager,
    connection_pool: &ConnectionPool,
) -> Vec<(SocketAddr, Transport)> {
    let destinations: Vec<(SocketAddr, Transport)> = manager
        .entries
        .iter()
        .filter(|entry| matches!(entry.transport, Transport::Tls | Transport::Tcp))
        .map(|entry| (entry.destination, entry.transport))
        .collect();
    connection_pool.set_idle_exempt_destinations(destinations.iter().copied());
    destinations
}

/// Force an immediate re-register for every Registered TLS/TCP entry whose
/// own outbound connection is gone. Returns the AoRs it refreshed.
///
/// Judged from the pool connection the REGISTERs actually go out on (a default
/// pool send to exactly the entry's destination and transport), never from the
/// shared stream registry: that one also holds inbound connections keyed by
/// peer address, so a connection the registrar's host opened towards siphon
/// would keep a dead trunk looking alive, and it holds no outbound TCP at all,
/// which made every TCP trunk look dead on every tick.
///
/// SCTP is not checked: the pool has no outbound SCTP path, so there is no
/// connection of the registrant's own to judge.
pub(super) fn force_refresh_lost_connections(
    manager: &RegistrantManager,
    connection_pool: &ConnectionPool,
) -> Vec<String> {
    let stale: Vec<String> = manager
        .entries
        .iter()
        .filter(|entry| {
            entry.state == RegistrantState::Registered
                && matches!(entry.transport, Transport::Tls | Transport::Tcp)
                && !connection_pool.has_live(entry.destination, entry.transport)
        })
        .map(|entry| entry.aor.clone())
        .collect();
    for aor in &stale {
        warn!(aor = %aor, "connection lost — forcing immediate re-register");
        manager.refresh(aor);
    }
    stale
}

/// The wire form of a built REGISTER, HEP-captured.
fn outbound_message(egress: &RegistrantEgress, built: BuiltRegister) -> OutboundMessage {
    let data = Bytes::from(built.message.to_bytes());

    if let Some(ref hep) = egress.hep_sender {
        // An entry on its own address is captured from that address; every
        // other one from the process's resolved Via address, as before.
        let via_addr = if built.own_address {
            built.source_local_addr.unwrap_or(built.sent_by)
        } else {
            resolve_via_addr(
                egress.local_addr,
                &built.transport,
                &egress.advertised_addrs,
                egress.advertised_address.as_deref(),
            )
        };
        hep.capture_outbound(via_addr, built.destination, built.transport, &data);
    }

    OutboundMessage {
        followups: None,
        connection_id: ConnectionId::default(),
        transport: built.transport,
        destination: built.destination,
        data,
        source_local_addr: built.source_local_addr,
        server_name: registrar_server_name(&built.message, built.transport),
        verify_server: None,
    }
}

/// Put one built registrant message on the wire, with HEP capture.
///
/// Shared by the two de-registration paths — an entry removed at run time, and
/// shutdown. Both are fire-and-forget: the entry is already gone, so there is
/// nothing left to record a failure against.
fn send_registrant_message(
    outbound: &OutboundRouter,
    egress: &RegistrantEgress,
    built: BuiltRegister,
) {
    let _ = outbound.send(outbound_message(egress, built));
}

/// Clear every outbound binding this node holds, for shutdown.
///
/// Driven by `serve()` when the signal arrives rather than by
/// [`registration_loop`], so the caller knows the de-REGISTERs have reached the
/// transport before the process exits. Signalling the loop instead would race
/// its 5-second sleep against `std::process::exit`.
///
/// Each entry's de-REGISTER leaves from the address it registered from, its own
/// `local_addr` included.
///
/// Returns how many de-registrations were sent.
pub fn deregister_all(manager: &RegistrantManager, outbound: &OutboundRouter) -> usize {
    let Some(egress) = manager.egress.get() else {
        // The loop never started, so nothing ever registered.
        return 0;
    };

    // Anything removed but not yet sent goes out too: this is the last chance
    // to clear those bindings.
    let pending = manager.take_pending_deregistrations();
    let active = manager.build_deregistrations(egress.defaults());

    let mut sent = 0;
    for built in pending.into_iter().chain(active) {
        send_registrant_message(outbound, egress, built);
        sent += 1;
    }
    sent
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
