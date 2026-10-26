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
        // States a previous process left keep their SPIs out of every offer.
        manager.note_kernel_spis(ipsec.kernel_spi_snapshot().await);
        manager.install_ipsec(ipsec);
    }
    // Every REGISTER goes under a client transaction of the dispatcher's
    // (see `lifecycle`), which attaches its layer as it starts.
    manager.transactions_attached().await;

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
        send_registrant_message(manager, &context.outbound, egress, built);
    }

    // SAs of entries that moved off an address (before the new address's
    // handshake installs fresh ones), superseded or abandoned SA sets, and
    // those of removed entries whose de-REGISTER went unanswered.
    manager.expire_teardowns(std::time::Instant::now());
    delete_queued_sas(manager, context, egress);

    // Shutting down: nothing is started, and the sockets and connections stay
    // as they are, so the de-REGISTERs, their retransmissions and their
    // answers (a challenge among them) still have them. They close with the
    // process.
    if manager.is_shutting_down() {
        return;
    }

    // Sockets for every entry that registers from an address of its own. An
    // entry whose socket cannot bind sits this tick out.
    let mut unbindable = reconcile_ue_sockets(manager, context, egress);
    unbindable.extend(reconcile_ue_streams(manager, context, egress));

    // Stated before the liveness check below reads those connections, and
    // before the first REGISTER of a trunk added since the last tick opens one.
    exempt_trunk_connections_from_idle_reap(manager, &context.connection_pool);

    // Connection loss on TLS/TCP: re-register on this tick instead of at the
    // refresh timer, which also re-opens the connection the registrar reaches
    // this trunk over.
    force_refresh_lost_connections(manager, &context.connection_pool);

    // An unanswered REGISTER is retransmitted and timed out by its client
    // transaction (RFC 3261 Timer E / Timer F), not here: see `lifecycle`.

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
        let Some(built) =
            manager.build_register(&aor, egress.defaults(), manager.interval_for(&aor))
        else {
            continue;
        };
        debug!(aor = %aor, branch = %built.branch, "sending REGISTER");
        if let Err(error) = send_register(manager, &context.outbound, egress, &built) {
            warn!(aor = %aor, %error, "failed to send REGISTER");
            manager.handle_failure(&aor, 0, None);
        }
    }
}

/// How many times one tick re-plans the sockets after moving protected
/// client ports that would not bind.
const SOCKET_PLAN_ROUNDS: usize = 4;

/// Converge the per-UE sockets on what the entries need; returns the AoRs
/// that cannot register this tick.
///
/// A protected port that will not bind does not stall its entry: the entry
/// moves a free rotation port elsewhere, or takes its established set out of
/// use and re-registers unprotected
/// ([`RegistrantManager::degrade_unbindable_ports`]), and the plan is re-run
/// for the moved ports within the tick.
fn reconcile_ue_sockets(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
) -> HashSet<String> {
    let plain_port = egress.defaults().plain_port();
    let mut blocked = HashSet::new();
    for _ in 0..SOCKET_PLAN_ROUNDS {
        let plan = manager.ue_socket_plan(plain_port, process_ue_ip(egress));
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
        blocked.clear();
        let mut moved = false;
        for (aor, addrs) in plan {
            let failed: Vec<u16> = addrs
                .iter()
                .filter(|addr| outcome.failed.contains(addr))
                .map(|addr| addr.port())
                .collect();
            if failed.is_empty() {
                continue;
            }
            let degradation = manager.degrade_unbindable_ports(&aor, &failed, plain_port);
            moved |= degradation.moved;
            if degradation.blocked {
                blocked.insert(aor);
            }
        }
        if !moved {
            break;
        }
    }
    blocked
}

/// Converge the per-UE TCP listeners and the pool's pinned UE sources on what
/// the TCP entries with an address of their own need
/// ([`RegistrantManager::ue_stream_plan`]); returns the AoRs that cannot
/// register this tick.
///
/// A listener that will not bind blocks its entry the way an unbound protected
/// server port does over UDP ([`RegistrantManager::degrade_unbindable_ports`]):
/// the P-CSCF could not reach it.
fn reconcile_ue_streams(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
) -> HashSet<String> {
    let plain_port = egress.defaults().plain_port();
    let (plan, owners) = manager.ue_stream_plan(plain_port);
    let Some(sockets) = context.ue_sockets.as_ref() else {
        if !owners.is_empty() {
            debug!(
                entries = owners.len(),
                "TCP entries with a local_addr but no per-UE listener support in this process"
            );
        }
        return owners.into_iter().map(|(aor, _)| aor).collect();
    };
    let outcome = sockets.reconcile_tcp(&plan);
    owners
        .into_iter()
        .filter(|(_, listener)| outcome.failed.contains(listener))
        .filter_map(|(aor, listener)| {
            manager
                .degrade_unbindable_ports(&aor, &[listener.port()], plain_port)
                .blocked
                .then_some(aor)
        })
        .collect()
}

/// Delete the SA pairs the manager queued.
fn delete_queued_sas(
    manager: &RegistrantManager,
    context: &RegistrationLoopContext,
    egress: &RegistrantEgress,
) {
    let Some(ipsec_manager) = context.ipsec_manager.as_ref() else {
        let dropped = manager.take_pending_sa_deletions();
        if !dropped.is_empty() {
            debug!(
                pairs = dropped.len(),
                "SA deletions queued with no IPsec manager in this process"
            );
        }
        return;
    };
    manager.spawn_sa_deletions(ipsec_manager, process_ue_ip(egress));
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
    let plain_port = manager
        .egress
        .get()
        .map_or(5060, |egress| egress.defaults().plain_port());
    let stale: Vec<String> = manager
        .entries
        .iter()
        .filter(|entry| {
            entry.state == RegistrantState::Registered
                && matches!(entry.transport, Transport::Tls | Transport::Tcp)
                && match RegistrantManager::ue_tcp_connection(entry, plain_port) {
                    // A UE on an address of its own: the connection from it.
                    Some((source, destination)) => {
                        !connection_pool.has_live_from(source, destination)
                    }
                    None => !connection_pool.has_live(entry.destination, entry.transport),
                }
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
fn outbound_message(egress: &RegistrantEgress, built: &BuiltRegister) -> OutboundMessage {
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

/// Put a built REGISTER on the wire under its client transaction (see
/// [`RegistrantManager::open_transaction`]), with HEP capture.
fn send_register(
    manager: &RegistrantManager,
    outbound: &OutboundRouter,
    egress: &RegistrantEgress,
    built: &BuiltRegister,
) -> Result<(), String> {
    let message = outbound_message(egress, built);
    manager.open_transaction(&built.message, &message)?;
    outbound.send(message).map_err(|error| error.to_string())
}

/// Put one built de-registration on the wire.
///
/// Shared by the two de-registration paths — an entry removed at run time, and
/// shutdown. Both are fire-and-forget: the entry is already gone, so there is
/// nothing left to record a failure against beyond the log.
fn send_registrant_message(
    manager: &RegistrantManager,
    outbound: &OutboundRouter,
    egress: &RegistrantEgress,
    built: BuiltRegister,
) {
    if let Err(error) = send_register(manager, outbound, egress, &built) {
        warn!(destination = %built.destination, %error, "failed to send de-REGISTER");
    }
}

/// Clear every outbound binding this node holds, for shutdown.
///
/// Driven by `serve()` when the signal arrives rather than by
/// [`registration_loop`], so the caller knows the de-REGISTERs have reached the
/// transport before the process exits. Signalling the loop instead would race
/// its 5-second sleep against `std::process::exit`.
///
/// Shutdown begins first ([`RegistrantManager::begin_shutdown`]), before a
/// de-REGISTER leaves, so nothing registers again afterwards: not the loop's
/// refresh or retry, not a source reconcile or a script adding an entry or
/// moving one to a new address, not a challenge answered meanwhile.
///
/// Every registered entry sends `Expires: 0` on its registration's Call-ID
/// (TS 24.229 5.1.1.6), from the address it registered from (its own
/// `local_addr` included) and, for an IMS UE, over its SA set; one whose
/// REGISTER is in flight sends it when that is answered (see the `lifecycle`
/// module). The entries are kept rather than removed: their answers, a
/// challenge to answer among them, have to find them, and the loop keeps
/// their sockets open while they do. De-REGISTERs of entries removed before
/// the shutdown and not yet sent go out too.
///
/// Returns how many de-registrations were sent.
pub fn deregister_all(manager: &RegistrantManager, outbound: &OutboundRouter) -> usize {
    let Some(egress) = manager.egress.get() else {
        // The loop never started, so nothing ever registered.
        manager.begin_shutdown();
        return 0;
    };

    let mut sent = 0;
    let removed = manager.take_pending_deregistrations();
    for built in manager
        .begin_deregistration(egress.defaults())
        .into_iter()
        .chain(removed)
    {
        send_registrant_message(manager, outbound, egress, built);
        sent += 1;
    }
    sent
}

/// How long shutdown waits, from the de-REGISTERs [`deregister_all`] sent, for
/// them to end ([`await_deregistrations`]): answered, a challenge to one
/// answered too, and the SA sets they rode released (TS 24.229 5.1.1.6.1: the
/// UE deletes them once nothing is registered over them). Long enough for
/// Timer E to resend a lost one several times and for a challenge round trip
/// over a slow network; with [`SHUTDOWN_DELETE_BOUND`] still inside the
/// 30-second stop grace of a typical container runtime.
pub const SHUTDOWN_ANSWER_WAIT: Duration = Duration::from_secs(20);

/// Wait, until `deadline`, for every shutdown de-registration to end (see
/// [`deregister_all`]). `false` when some had not by then.
pub async fn await_deregistrations(
    manager: &RegistrantManager,
    deadline: tokio::time::Instant,
) -> bool {
    while manager.deregistrations_pending() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// The most shutdown spends deleting the SA sets left after that wait.
const SHUTDOWN_DELETE_BOUND: Duration = Duration::from_secs(5);

/// Delete every IMS UE SA set the registrant still holds, before the process
/// exits, rather than leave them in the kernel to their hard lifetime (TS
/// 33.203 7.4.1a: "The UE shall delete all SAs it holds once all the IMPUs are
/// de-registered").
///
/// Waits until `answers_by` for the de-REGISTERs [`deregister_all`] sent to be
/// answered (the dispatcher deletes a set when its answer arrives), then
/// deletes whatever is left, unanswered or still live, itself, within
/// [`SHUTDOWN_DELETE_BOUND`]. Bounded either way: it never holds shutdown
/// beyond `answers_by` plus that bound. Returns how many SA pairs it deleted
/// itself.
pub async fn retire_ue_security_associations(
    manager: &RegistrantManager,
    answers_by: tokio::time::Instant,
) -> usize {
    let (Some(ipsec), Some(egress)) = (manager.ipsec.get().cloned(), manager.egress.get()) else {
        return 0;
    };
    while (manager.deregistrations_pending() || !manager.sa_deletions_settled())
        && tokio::time::Instant::now() < answers_by
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    manager.surrender_all_sa_sets();
    let deletions = manager.take_pending_sa_deletions();
    let unanswered = deletions.len();
    let deadline = tokio::time::Instant::now() + SHUTDOWN_DELETE_BOUND;
    let deleted = tokio::time::timeout_at(
        deadline,
        super::protected::delete_sa_sets(&ipsec, deletions, process_ue_ip(egress)),
    )
    .await;
    let settled = manager.await_sa_deletions_in_flight(deadline).await;
    match deleted {
        Ok(deleted) if settled => {
            debug!(unanswered, deleted, "IMS UE SA sets deleted at shutdown");
            deleted
        }
        Ok(deleted) => {
            warn!(
                deleted,
                "IMS UE SA deletions still running at the shutdown bound; the rest go at their hard lifetime"
            );
            deleted
        }
        Err(_) => {
            warn!(
                unanswered,
                "IMS UE SA sets not all deleted within the shutdown bound; the rest go at their hard lifetime"
            );
            0
        }
    }
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
