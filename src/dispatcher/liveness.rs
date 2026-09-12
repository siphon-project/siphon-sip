//! Registrar liveness: noticing a UE that has gone away.
//!
//! Pairs the kernel IPsec SA activity with SIP last-seen, probes what looks
//! idle, and de-registers what does not answer — including the network-side
//! de-REGISTER so the registrar of record agrees.

use super::*;

// ===========================================================================
// Registrar liveness — UDP+IPsec idle detection + network-initiated dereg.
// (TCP/TLS flow-failure dereg is handled at the transport layer via the
// connection-close channel → Registrar::unregister_flow.)
// ===========================================================================

/// Everything a detached liveness-dereg task needs, cloned out of
/// `DispatcherState` so the task is `'static`.
#[derive(Clone)]
pub(super) struct LivenessDeregCtx {
    pub(super) registrar: Arc<Registrar>,
    pub(super) ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    pub(super) uac_sender: Arc<UacSender>,
    pub(super) dns_resolver: Arc<SipResolver>,
    pub(super) dereg_mode: crate::config::LivenessDeregMode,
    /// Shared SIP-layer last-seen map (source IP → UNIX secs) — see
    /// [`DispatcherState::liveness_last_seen`].  The idle sweep reads it, the
    /// probe stamps it on an answer, and the dereg funnel prunes it on reap.
    pub(super) last_seen: Arc<DashMap<std::net::IpAddr, u64>>,
    /// Shared consecutive-miss counter (AoR → misses) for probe hysteresis —
    /// see [`DispatcherState::liveness_misses`].
    pub(super) misses: Arc<DashMap<String, u64>>,
    /// Consecutive failed sweeps before a suspect binding is reaped
    /// (`registrar_liveness.miss_threshold`).
    pub(super) miss_threshold: u32,
}

impl LivenessDeregCtx {
    pub(super) fn from_state(state: &DispatcherState, registrar: Arc<Registrar>) -> Self {
        Self {
            registrar,
            ipsec_manager: state.ipsec_manager.clone(),
            uac_sender: Arc::clone(&state.uac_sender),
            dns_resolver: Arc::clone(&state.dns_resolver),
            dereg_mode: state.registrar_liveness.dereg_mode,
            last_seen: Arc::clone(&state.liveness_last_seen),
            misses: Arc::clone(&state.liveness_misses),
            miss_threshold: state.registrar_liveness.miss_threshold,
        }
    }

    /// Build the funnel context from process globals, for the flow-failure
    /// close-drain task (`server.rs`) which has no `DispatcherState`.  Returns
    /// `None` if the registrar / UAC / resolver globals aren't installed yet.
    ///
    /// The flow-failure path only synthesizes the upstream de-REGISTER and
    /// never touches the idle-sweep bookkeeping, so `last_seen` / `misses` are
    /// fresh empty maps and `miss_threshold` is the config default.
    pub(super) fn from_globals(dereg_mode: crate::config::LivenessDeregMode) -> Option<Self> {
        Some(Self {
            registrar: crate::script::api::registrar_arc()?.clone(),
            ipsec_manager: crate::ipsec::global_manager(),
            uac_sender: crate::script::api::proxy_utils::uac_sender()?.clone(),
            dns_resolver: crate::script::api::proxy_utils::send_resolver()?.clone(),
            dereg_mode,
            last_seen: Arc::new(DashMap::new()),
            misses: Arc::new(DashMap::new()),
            miss_threshold: crate::config::RegistrarLivenessConfig::default().miss_threshold,
        })
    }
}

/// Current UNIX time in whole seconds, or `None` if the clock is before the
/// epoch (never, in practice).  Shared by the liveness last-seen stamp sites.
pub(super) fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Most recent liveness evidence for a binding: the kernel XFRM inbound
/// `use_time` folded with siphon's own SIP-layer last-seen.  The kernel
/// counter can fail to advance on an inbound-answered SA (making a live UE
/// look perpetually idle), so the SIP signal — refreshed on every message
/// arriving on a protected port — is the corrective input.
pub(super) fn liveness_last_active(kernel_last_active: u64, sip_last_seen: u64) -> u64 {
    kernel_last_active.max(sip_last_seen)
}

/// Whether a binding counts as recently active (inside the idle window) and so
/// must not be probed this sweep.
pub(super) fn liveness_recently_active(now: u64, last_active: u64, idle_window: u64) -> bool {
    now.saturating_sub(last_active) <= idle_window
}

/// Where and how one idle-liveness OPTIONS is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LivenessProbeRoute {
    /// Where the OPTIONS is addressed.
    pub(super) destination: SocketAddr,
    /// The P-CSCF listener it leaves from — what the kernel XFRM egress policy
    /// keys on, so it must be the SA's own port.
    pub(super) source_local_addr: SocketAddr,
    pub(super) transport: Transport,
    /// A captured stream connection to ride, or the default for a fresh send.
    pub(super) connection_id: ConnectionId,
}

/// Where an MT request to this binding goes, as the idle-liveness OPTIONS
/// route.  The probe answers "can an MT request reach this binding?", so it
/// has to take the route MT takes wherever MT's route is determined, or it can
/// pass while MT fails (and fail while MT works).
///
/// - The binding still has a flow (UDP, or TCP while the connection is up):
///   what `relay(flow=...)` does, the UE's source address from the listener
///   the REGISTER landed on, on the captured connection, with the SA's
///   transport pin applied as the relay applies it.
/// - It has no flow: a stream binding [`registrar::Registrar::close_flow`]
///   detached because its socket closed.  MT to it is relayed without a flow
///   to its Contact, the UE's protected server port, so the probe goes the
///   same way: over the binding's own SA from `port_pc` (SA #3), on the
///   transport the Contact's `;transport=` names (mapped as the relay maps
///   it), under the SA pin.  A bare Contact is the one case MT leaves open,
///   because MT then follows the transport its own request arrived on; the
///   probe cannot know that, and uses the transport the binding registered
///   over.
///
/// `sa` is the binding's own SA pair.  `None` when a detached binding has no
/// SA to route over, or a transport an SA cannot carry.
pub(super) fn liveness_probe_route(
    contact: &crate::registrar::Contact,
    sa: Option<&crate::ipsec::SecurityAssociationPair>,
) -> Option<LivenessProbeRoute> {
    if let Some(flow) = contact.flow() {
        let transport = match (sa, flow.transport) {
            (Some(sa), Transport::Udp | Transport::Tcp) => {
                crate::script::api::ipsec::outbound_for_sa(
                    sa,
                    flow.source_addr.port(),
                    flow.transport,
                )
                .map_or(flow.transport, |(_, pinned)| pinned)
            }
            _ => flow.transport,
        };
        return Some(LivenessProbeRoute {
            destination: flow.source_addr,
            source_local_addr: flow.local_addr,
            transport,
            connection_id: ConnectionId(flow.connection_id),
        });
    }
    let sa = sa?;
    let transport = contact
        .uri
        .get_param("transport")
        .and_then(transport_from_token)
        .unwrap_or_else(|| contact.source_transport.unwrap_or(Transport::Udp));
    if !matches!(transport, Transport::Udp | Transport::Tcp) {
        return None;
    }
    let (source_local_addr, transport) =
        crate::script::api::ipsec::outbound_for_sa(sa, sa.ue_port_s, transport)?;
    Some(LivenessProbeRoute {
        destination: SocketAddr::new(sa.ue_addr, sa.ue_port_s),
        source_local_addr,
        transport,
        connection_id: ConnectionId::default(),
    })
}

/// Hysteresis decision after a suspect binding fails its in-sweep OPTIONS probe
/// loop.  Given the prior consecutive-miss count and the configured threshold,
/// returns `(new_count, reap)`: within grace it bumps the counter and keeps the
/// binding (`reap == false`); once the threshold is reached it resets the
/// counter and signals a reap (`reap == true`).  A `threshold` of 0 is treated
/// as 1 (reap on the first miss) so the feature can never be silently disabled
/// by a zero.
pub(super) fn liveness_miss_outcome(before: u64, threshold: u32) -> (u64, bool) {
    let misses = before.saturating_add(1);
    if misses < threshold.max(1) as u64 {
        (misses, false)
    } else {
        (0, true)
    }
}

/// Record that a UE is alive (answered a probe, or an inbound arrived): stamp
/// its SIP last-seen and clear any accumulated miss strike so the next sweep
/// skips it for a full idle window and a later transient miss starts from zero.
pub(super) fn liveness_note_alive(
    last_seen: &DashMap<std::net::IpAddr, u64>,
    misses: &DashMap<String, u64>,
    ue_ip: std::net::IpAddr,
    aor: &str,
    now: u64,
) {
    last_seen.insert(ue_ip, now);
    misses.remove(aor);
}

/// Reconcile the liveness bookkeeping with the current registration set: keep
/// last-seen only for IPs that still have a live SA, and miss counters only for
/// AoRs still present as IPsec bindings.  This is what drains both maps to
/// baseline as UEs deregister (project per-module leak rule).
pub(super) fn liveness_gc(
    last_seen: &DashMap<std::net::IpAddr, u64>,
    misses: &DashMap<String, u64>,
    live_ips: &std::collections::HashSet<std::net::IpAddr>,
    live_aors: &std::collections::HashSet<String>,
) {
    last_seen.retain(|ip, _| live_ips.contains(ip));
    misses.retain(|aor, _| live_aors.contains(aor));
}

/// Run the network-dereg cascade for bindings removed by the **flow-failure**
/// close path (`server.rs` drain task).  Under `network_dereg`, a P-CSCF cache
/// binding (one carrying a `flow_token`) additionally synthesizes an
/// `Expires: 0` REGISTER toward the S-CSCF via its stored Service-Route, so
/// the registrar of record clears it too — matching the SA-idle path.  No-op
/// under `local_only`, or when none of the removed bindings is a P-CSCF cache
/// binding.  The local removal + `on_change` cascade already happened in
/// `unregister_flow_collect`; this adds only the upstream de-REGISTER.
// Only caller is `liveness_on_flow_close` below. It was `pub(crate)` in the
// monolith with no cross-module user; the split surfaced that, so it narrows to
// the module rather than keeping a crate-wide path nothing reaches.
async fn liveness_flow_failure_network_dereg(
    removed: Vec<(crate::registrar::Aor, crate::registrar::Contact)>,
    dereg_mode: crate::config::LivenessDeregMode,
) {
    if dereg_mode != crate::config::LivenessDeregMode::NetworkDereg
        || !removed
            .iter()
            .any(|(_, contact)| contact.flow_token.is_some())
    {
        return;
    }
    let context = match LivenessDeregCtx::from_globals(dereg_mode) {
        Some(context) => context,
        None => return,
    };
    for (aor, contact) in removed {
        if contact.flow_token.is_some() {
            send_liveness_network_dereg(&context, &aor, &contact.uri.to_string()).await;
        }
    }
}

/// The set of contact URIs to **retain** (detach, not deregister) when a stream
/// flow closes: those whose UE source IP still has a live IPsec SA.  A closed
/// IPsec flow is a recoverable RFC 5626 §4.2.2 flow failure owned by the
/// SA-idle sweep, not a death signal — the UE stays reachable via paging and
/// its XFRM SA stays warm across ECM-IDLE.  A non-IPsec stream close has no SA
/// to consult and remains an authoritative death signal (keep set excludes it).
pub(super) fn flow_close_keep_set(
    bindings: &[(crate::registrar::Aor, crate::registrar::Contact)],
    sa_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> std::collections::HashSet<String> {
    bindings
        .iter()
        .filter(|(_, contact)| {
            contact
                .source_addr
                .map(|addr| sa_ips.contains(&addr.ip()))
                .unwrap_or(false)
        })
        .map(|(_, contact)| contact.uri.to_string())
        .collect()
}

/// Handle a stream connection close under registrar liveness (RFC 5626
/// §4.2.2).  Runs from the `server.rs` close-drain task (which has no
/// `DispatcherState`), so it reads process globals.
///
/// IPsec bindings on the dead flow are **retained** (detached) and left to the
/// SA-idle sweep ([`sweep_registrar_liveness`]), which ages them on the
/// authoritative XFRM SA use-time plus an OPTIONS probe.  This stops a VoLTE UE
/// from being network-deregistered on every benign ECM-IDLE transition: its
/// SIP-over-TCP flow FINs at the radio inactivity timer, but the IMS
/// registration must survive so an MT INVITE can page it.  Non-IPsec stream
/// closes (plain TCP, WSS WebRTC) keep today's immediate flow-failure
/// deregistration and cascade.
pub(crate) async fn liveness_on_flow_close(
    connection_id: u64,
    dereg_mode: crate::config::LivenessDeregMode,
) {
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };

    // Same discriminator the SA-idle sweep uses: a UE IP with a live SA.
    let sa_ips: std::collections::HashSet<std::net::IpAddr> = match crate::ipsec::global_manager() {
        Some(manager) => manager
            .liveness_snapshot()
            .into_iter()
            .map(|row| row.ue_addr)
            .collect(),
        None => std::collections::HashSet::new(),
    };

    let keep = flow_close_keep_set(&registrar.bindings_for_connection(connection_id), &sa_ips);
    let retained = keep.len();
    let removed = registrar.close_flow(connection_id, &keep);

    if retained > 0 {
        tracing::info!(
            connection_id,
            retained,
            "registrar liveness: stream flow closed — IPsec binding(s) retained, \
             deferring to SA-idle sweep (RFC 5626 flow recovery)"
        );
    }
    if !removed.is_empty() {
        tracing::info!(
            connection_id,
            removed = removed.len(),
            "registrar liveness: flow-failure deregistration (non-IPsec stream connection closed)"
        );
        liveness_flow_failure_network_dereg(removed, dereg_mode).await;
    }
}

/// Part B.4 — an abandoned UE's SA pair was just reaped from the kernel;
/// remove the matching registrar binding(s) so the registration doesn't
/// linger to its own `Expires`.  Runs synchronously in the sweep because the
/// reaped set is small and the dereg is local + (optionally) one upstream
/// REGISTER.
pub(super) async fn liveness_dereg_reaped_sas(
    state: &DispatcherState,
    reaped: &[(std::net::IpAddr, u16)],
) {
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };
    let context = LivenessDeregCtx::from_state(state, registrar);
    let reaped_ips: std::collections::HashSet<std::net::IpAddr> =
        reaped.iter().map(|(ip, _)| *ip).collect();
    let port_for: std::collections::HashMap<std::net::IpAddr, u16> =
        reaped.iter().map(|(ip, port)| (*ip, *port)).collect();

    for (aor, contact) in context.registrar.all_contacts() {
        let ue_ip = match contact.source_addr {
            Some(addr) => addr.ip(),
            None => continue,
        };
        if !reaped_ips.contains(&ue_ip) {
            continue;
        }
        let ue_port_c = port_for.get(&ue_ip).copied();
        liveness_dereg_contact(
            &context,
            &aor,
            &contact,
            ue_port_c,
            "ipsec SA torn down (abandoned-SA sweep)",
        )
        .await;
    }
}

/// Part B — UDP+IPsec idle-liveness sweep.  Polls the kernel SA use-times,
/// flags bindings whose SA has been silent beyond
/// `idle_multiplier × keepalive_interval`, and spawns a one-shot OPTIONS
/// probe that deregisters on no answer.  A live UE's response is itself
/// inbound protected traffic, so it refreshes the SA use-time and clears the
/// suspect state on the next sweep.
pub(super) async fn sweep_registrar_liveness(state: &DispatcherState) {
    let manager = match &state.ipsec_manager {
        Some(manager) => manager,
        None => return, // no P-CSCF IPsec role → no UDP+IPsec bindings to age
    };
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };

    let use_times = manager.dump_sa_use_times().await;
    let snapshot = manager.liveness_snapshot();
    // One registration per UE IP in an IPsec P-CSCF — index the SA rows by IP.
    let mut sa_by_ip: std::collections::HashMap<std::net::IpAddr, crate::ipsec::SaLivenessRow> =
        std::collections::HashMap::with_capacity(snapshot.len());
    for row in snapshot {
        sa_by_ip.insert(row.ue_addr, row);
    }
    let context = LivenessDeregCtx::from_state(state, registrar);
    let live_ips: std::collections::HashSet<std::net::IpAddr> = sa_by_ip.keys().copied().collect();

    // No live SAs, or the kernel use-time dump is unavailable on this platform
    // → nothing to age this sweep.  Still reconcile the liveness bookkeeping so
    // last-seen / miss entries for UEs whose SA has gone drain to baseline
    // instead of accumulating (project per-module leak rule).  No bindings are
    // eligible, so `live_aors` is empty and every miss counter is cleared.
    if live_ips.is_empty() || use_times.is_empty() {
        liveness_gc(
            &context.last_seen,
            &context.misses,
            &live_ips,
            &std::collections::HashSet::new(),
        );
        return;
    }

    let now = match now_unix() {
        Some(now) => now,
        None => return,
    };
    let liveness = &state.registrar_liveness;
    let idle_window =
        liveness.keepalive_interval_secs as u64 * liveness.idle_multiplier.max(1) as u64;
    let probe_timeout = std::time::Duration::from_millis(liveness.probe_timeout_ms);
    // AoRs of live IPsec bindings seen this sweep — the post-sweep GC keeps miss
    // counters only for these and drops counters for bindings that have vanished.
    let mut live_aors: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(sa_by_ip.len());
    let mut total = 0usize;
    let mut ipsec_protected = 0usize;
    let mut suspects = 0usize;

    for (aor, contact) in context.registrar.all_contacts() {
        total += 1;
        let ue_addr = match contact.source_addr {
            Some(addr) => addr,
            None => continue,
        };
        // Any IPsec-protected binding is eligible — UDP *or* TCP/TLS/WS.  The
        // XFRM SA use-time is the authoritative liveness signal regardless of
        // SIP transport: a Gm registration over TCP whose UE silently dies
        // (radio loss, no FIN/RST) is invisible to flow-failure dereg until
        // the CRLF-keepalive timeout (minutes), but its SA goes stale at the
        // same rate as a UDP UE's.  Matching on the SA (by UE IP) also
        // naturally excludes non-IPsec bindings, which have no use-time signal
        // and rely on flow-failure (Part A) alone.
        let row = match sa_by_ip.get(&ue_addr.ip()) {
            Some(row) => row,
            None => continue, // not an IPsec-protected UE
        };
        ipsec_protected += 1;
        live_aors.insert(aor.clone());

        // Most recent inbound activity across the two inbound SAs (the SAs the
        // UE's keepalive / MO requests land on).
        let kernel_last_active = use_times
            .get(&row.spi_ps)
            .copied()
            .unwrap_or(0)
            .max(use_times.get(&row.spi_pc).copied().unwrap_or(0));
        if kernel_last_active == 0 {
            // Neither inbound SA is currently in the kernel dump — likely a
            // dump/snapshot race or an SA mid-teardown.  Genuine teardown is
            // handled by the abandoned-SA sweep (Part B.4); skip here to avoid
            // false deregistration.
            continue;
        }
        // Fold in siphon's own SIP-layer last-seen: on some kernels the XFRM
        // inbound use-time does not advance on an inbound-answered SA, so a live
        // UE that answers its keepalive / OPTIONS every 30 s still looks idle to
        // the kernel counter alone.  The SIP signal (refreshed on every message
        // arriving on a protected port) corrects that, collapsing the probe
        // cadence for a responsive UE from every sweep to at most once per idle
        // window.
        let sip_last_seen = context
            .last_seen
            .get(&ue_addr.ip())
            .map(|entry| *entry)
            .unwrap_or(0);
        let last_active = liveness_last_active(kernel_last_active, sip_last_seen);
        if liveness_recently_active(now, last_active, idle_window) {
            // Recently active → clear any stale miss strike so a UE that
            // answered normally never carries a partial strike into a later
            // idle window.
            context.misses.remove(&aor);
            continue;
        }

        // Suspect.  Probe the route an MT request to this binding takes
        // (`liveness_probe_route`): its flow while it has one, else its own SA
        // from port_pc to the UE's protected server port.  The SA is the
        // binding's own pair, looked up by its client port; the per-IP row above
        // only decides eligibility and activity.  Detach so a slow UE can't
        // stall the sweep.
        suspects += 1;
        let binding_transport = contact.source_transport.unwrap_or(Transport::Udp);
        let sa = manager.get_sa(&ue_addr.ip(), ue_addr.port());
        let Some(route) = liveness_probe_route(&contact, sa.as_ref()) else {
            // No SA to route a detached binding over (a re-authentication
            // overlap, a stale port): skip it this sweep rather than count a
            // miss.  A binding whose SA is really gone is reaped by the
            // abandoned-SA sweep.
            debug!(
                aor = %aor,
                ue = %ue_addr,
                "registrar liveness: no MT route for idle binding, skipping this sweep"
            );
            continue;
        };
        debug!(
            aor = %aor,
            ue = %ue_addr,
            binding_transport = %binding_transport,
            probe_destination = %route.destination,
            probe_transport = %route.transport,
            idle_secs = now.saturating_sub(last_active),
            idle_window,
            "registrar liveness: binding idle past window — probing with OPTIONS"
        );
        let context = context.clone();
        let aor = aor.clone();
        let contact = contact.clone();
        // Tear down the binding's own SA pair on a reap, not whichever pair
        // the per-IP row happened to index during a re-auth overlap.
        let ue_port_c = sa.as_ref().map_or(row.ue_port_c, |sa| sa.ue_port_c);
        tokio::spawn(async move {
            liveness_probe_then_dereg(context, aor, contact, ue_port_c, route, probe_timeout).await;
        });
    }

    // Reconcile the liveness bookkeeping with the current registration set so
    // last-seen / miss entries drain to baseline as UEs deregister (project
    // per-module leak rule): keep last-seen only for IPs that still have a live
    // SA, and miss counters only for AoRs still present as IPsec bindings.  A
    // UE that de-REGISTERs normally has its SA torn down, so its IP leaves
    // `live_ips` and its entries are dropped on the next sweep.
    liveness_gc(&context.last_seen, &context.misses, &live_ips, &live_aors);

    // Census so an operator can see why a dead UE is (or isn't) being reaped.
    debug!(
        contacts = total,
        ipsec_protected,
        idle_suspect = suspects,
        idle_window_secs = idle_window,
        tracked_last_seen = context.last_seen.len(),
        tracked_misses = context.misses.len(),
        "registrar liveness: idle sweep census"
    );
}

/// Send one OPTIONS along `route` (with a single retry); if the UE
/// answers, stamp its SIP-layer last-seen and clear any miss strike so the next
/// sweep skips it for a full idle window.  On no answer, apply consecutive-miss
/// hysteresis: keep the binding for `miss_threshold` failed sweeps (a UE racing
/// an ECM-IDLE → paging → reconnect window misses one sweep and answers the
/// next) and only run the dereg funnel once the grace is exhausted.
pub(super) async fn liveness_probe_then_dereg(
    context: LivenessDeregCtx,
    aor: String,
    contact: crate::registrar::Contact,
    ue_port_c: u16,
    route: LivenessProbeRoute,
    probe_timeout: std::time::Duration,
) {
    let destination = route.destination;
    let request_uri = contact.uri.clone();

    for attempt in 0..2 {
        let receiver = context.uac_sender.send_options_over_flow(
            destination,
            route.source_local_addr,
            route.transport,
            route.connection_id,
            request_uri.clone(),
        );
        if let Ok(Ok(crate::uac::UacResult::Response(_))) =
            tokio::time::timeout(probe_timeout, receiver).await
        {
            // The UE is alive — stamp its SIP last-seen (in case the general
            // inbound stamp raced or the answer arrived over UDP) and reset the
            // hysteresis counter so a later transient miss starts from zero.
            if let Some(now) = now_unix() {
                liveness_note_alive(
                    &context.last_seen,
                    &context.misses,
                    destination.ip(),
                    &aor,
                    now,
                );
            }
            debug!(aor = %aor, attempt, "registrar liveness: UE answered OPTIONS probe — keeping binding");
            return;
        }
    }

    // No answer this sweep.  Bump the consecutive-miss counter; only reap once
    // it reaches `miss_threshold`, so a single missed probe (paging in flight)
    // never false-deregisters a live UE.
    let before = context.misses.get(&aor).map(|entry| *entry).unwrap_or(0);
    let (misses, reap) = liveness_miss_outcome(before, context.miss_threshold);
    if !reap {
        context.misses.insert(aor.clone(), misses);
        info!(
            aor = %aor,
            misses,
            threshold = context.miss_threshold,
            "registrar liveness: probe unanswered — within grace, re-probing next sweep"
        );
        return;
    }
    context.misses.remove(&aor);
    liveness_dereg_contact(
        &context,
        &aor,
        &contact,
        Some(ue_port_c),
        "ipsec idle (no OPTIONS answer, grace exhausted)",
    )
    .await;
}

/// The shared dereg funnel for both the idle-probe path and the SA-teardown
/// path.  Removes the local binding (which emits `Deregistered` →
/// `@registrar.on_change` → the terminated reg-event NOTIFY), tears down the
/// UE's IPsec SA, and — for a P-CSCF cache binding under `network_dereg` —
/// synthesizes a de-REGISTER (`Expires: 0`) toward the S-CSCF so the
/// registrar of record clears the binding too.
pub(super) async fn liveness_dereg_contact(
    context: &LivenessDeregCtx,
    aor: &str,
    contact: &crate::registrar::Contact,
    ue_port_c: Option<u16>,
    reason: &str,
) {
    let contact_uri = contact.uri.to_string();
    let network_dereg = context.dereg_mode == crate::config::LivenessDeregMode::NetworkDereg
        && contact.flow_token.is_some();
    info!(
        aor = %aor,
        contact = %contact_uri,
        reason,
        network_dereg,
        "registrar liveness: deregistering binding"
    );

    // 1. P-CSCF network de-REGISTER (before dropping local state, while the
    //    Service-Route is still available).  Only for a proxy-cached binding
    //    (one carrying a flow_token) under network-dereg mode.
    if network_dereg {
        send_liveness_network_dereg(context, aor, &contact_uri).await;
    }

    // 2. Drop the local binding — emits Deregistered → on_change cascade.
    context.registrar.remove_contact(aor, &contact_uri);

    // 3. Tear down the UE's IPsec SA so the kernel state goes with the binding.
    if let (Some(manager), Some(ue_addr), Some(ue_port_c)) =
        (&context.ipsec_manager, contact.source_addr, ue_port_c)
    {
        if let Err(error) = manager.delete_sa_pair(&ue_addr.ip(), ue_port_c).await {
            debug!(aor = %aor, %error, "registrar liveness: IPsec SA teardown failed (may already be gone)");
        }
    }

    // 4. Prune the liveness bookkeeping for the gone binding so it drains with
    //    the registration (the sweep GC would also catch it once the SA leaves
    //    the kernel snapshot, but pruning here keeps both maps tight).
    context.misses.remove(aor);
    if let Some(ue_addr) = contact.source_addr {
        context.last_seen.remove(&ue_addr.ip());
    }
}

/// Synthesize and fire-and-forget a de-REGISTER (`Expires: 0`) toward the
/// S-CSCF via the binding's stored Service-Route, on the UE's behalf.
pub(super) async fn send_liveness_network_dereg(
    context: &LivenessDeregCtx,
    aor: &str,
    contact_uri: &str,
) {
    let routes = context.registrar.service_routes(aor);
    let top_route = match routes.first() {
        Some(route) => route.clone(),
        None => {
            debug!(aor = %aor, "registrar liveness: no Service-Route — skipping network de-REGISTER");
            return;
        }
    };

    // Resolve the top Service-Route to a next hop.
    let route_uri = match parse_route_uri(&top_route) {
        Some(uri) => uri,
        None => {
            warn!(aor = %aor, route = %top_route, "registrar liveness: unparseable Service-Route");
            return;
        }
    };
    let scheme = if route_uri.scheme.is_sips() {
        "sips"
    } else {
        "sip"
    };
    let targets = context
        .dns_resolver
        .resolve(&route_uri.host, route_uri.port, scheme, Some("udp"))
        .await;
    let destination = match targets.first() {
        Some(target) => target.address,
        None => {
            warn!(aor = %aor, host = %route_uri.host, "registrar liveness: Service-Route did not resolve");
            return;
        }
    };

    let register = match build_dereg_register(aor, contact_uri, &routes, destination) {
        Ok(message) => message,
        Err(error) => {
            warn!(aor = %aor, %error, "registrar liveness: failed to build de-REGISTER");
            return;
        }
    };
    info!(aor = %aor, %destination, "registrar liveness: sending network de-REGISTER (Expires: 0) to S-CSCF");
    context
        .uac_sender
        .send_request(register, destination, Transport::Udp);
}

/// Parse a Route/Service-Route header value (`<sip:host:port;lr>`) into a
/// `SipUri`.
pub(super) fn parse_route_uri(route: &str) -> Option<SipUri> {
    let trimmed = route.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
        .unwrap_or(trimmed);
    parse_uri_standalone(inner).ok()
}

/// Build a de-REGISTER (REGISTER with `Expires: 0`) on the UE's behalf,
/// routed to the S-CSCF via the stored Service-Route(s).
///
/// - R-URI is the registrar domain (the AoR's host).
/// - To/From are the AoR; Contact is the UE's binding with `;expires=0`.
/// - `Route` carries the Service-Route set so the request reaches the same
///   S-CSCF that granted the registration.
pub(super) fn build_dereg_register(
    aor: &str,
    contact_uri: &str,
    routes: &[String],
    destination: SocketAddr,
) -> Result<SipMessage, String> {
    let aor_uri = parse_uri_standalone(aor).ok();
    let domain = aor_uri
        .as_ref()
        .map(|uri| uri.host.clone())
        .unwrap_or_else(|| destination.ip().to_string());
    // The S-CSCF skips the IMS-AKA re-challenge on a re-/de-REGISTER only when
    // it arrives integrity-protected (TS 24.229 §5.4.1.2.2): a real UE de-REG
    // rides the IPsec SA and the P-CSCF stamps `integrity-protected="ip-assoc-yes"`
    // (§5.2.6.3).  This synthesized de-REGISTER asserts that same protection on
    // the (now-torn-down) SA's behalf — the P-CSCF *was* the entity holding the
    // SA — so it must carry the marker; without it the S-CSCF challenges
    // (401/403) and the de-registration never completes (no SAR
    // User-Deregistration, no AS 3rd-party de-REGISTER, no terminated NOTIFY).
    // The S-CSCF keys the skip on the marker substring + `is_registered(pub_id)`
    // (pub_id from To/From, not the Authorization username), so the digest
    // fields are placeholders.
    let username = aor_uri
        .as_ref()
        .and_then(|uri| uri.user.clone())
        .map(|user| format!("{user}@{domain}"))
        .unwrap_or_else(|| domain.clone());
    let authorization = format!(
        "Digest username=\"{username}\", realm=\"{domain}\", nonce=\"\", \
         uri=\"sip:{domain}\", response=\"\", integrity-protected=\"ip-assoc-yes\""
    );
    let request_uri = SipUri::new(domain);

    let branch = format!("z9hG4bK-liveness-{}", uuid::Uuid::new_v4());
    let via = format!(
        "SIP/2.0/UDP {}:{};branch={}",
        destination.ip(),
        destination.port(),
        branch
    );
    let from_tag = uuid::Uuid::new_v4();
    let call_id = format!("liveness-dereg-{}", uuid::Uuid::new_v4());

    let mut builder = SipMessageBuilder::new()
        .request(Method::Register, request_uri)
        .via(via)
        .from(format!("<{aor}>;tag=liveness-{from_tag}"))
        .to(format!("<{aor}>"))
        .call_id(call_id)
        .cseq("1 REGISTER".to_string())
        .max_forwards(70)
        .header("Authorization", authorization)
        .header("Contact", format!("<{contact_uri}>;expires=0"))
        .header("Expires", "0".to_string());

    for route in routes {
        builder = builder.header("Route", route.clone());
    }

    builder.content_length(0).build()
}

/// Cap an attacker-controlled string before it reaches the log.
///
/// A parse error quotes the bytes that failed to parse, so without a cap the
/// source of an unparseable message decides how much it writes into the
/// operator's log — a scanner sending a full browser request header block emits
/// a kilobyte per probe. The head is what identifies the traffic; the rest is
/// noise.
pub(super) fn truncate_for_log(detail: &str) -> Cow<'_, str> {
    const MAX_LOGGED_BYTES: usize = 200;
    if detail.len() <= MAX_LOGGED_BYTES {
        return Cow::Borrowed(detail);
    }
    // Never split a UTF-8 character (the cap is a byte count, the string is not).
    let mut end = MAX_LOGGED_BYTES;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!(
        "{}… ({} more bytes elided)",
        &detail[..end],
        detail.len() - end
    ))
}
