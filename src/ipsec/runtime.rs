//! Process-wide access to the running `IpsecManager` and its config.
//!
//! These are the P-CSCF runtime lookups the datapath needs: whether a packet
//! arrived on a protected port, which local address to egress from, which SA
//! matches a UE, and the hard-lifetime re-pin on a REGISTER refresh.
//!
//! They used to live in `script::api::ipsec`, which put them in the PyO3
//! binding layer and made `transport::stream` import from it — a transport
//! module reaching into the Python bindings for a kernel-level question. They
//! are Rust-side runtime state that the scripting API happens to populate, so
//! they belong here; `script::api::ipsec` re-exports them and remains the only
//! thing that installs them.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use tracing::warn;

use crate::config::IpsecConfig;
use crate::ipsec::{IpsecManager, SaProtocol, SecurityAssociationPair};

/// Publish the manager and config for the process.
///
/// Called once, from `PyIpsec::new`, when a P-CSCF deployment wires IPsec.
/// Both are `OnceLock`s: a second call is ignored rather than racing.
pub fn install(manager: Arc<IpsecManager>, config: Arc<IpsecConfig>) {
    let _ = IPSEC_MANAGER_REF.set(manager);
    let _ = IPSEC_CONFIG_REF.set(config);
}

/// Whether a manager has been wired, for tests that must not assume either way.
#[cfg(test)]
pub(crate) fn manager_installed() -> bool {
    IPSEC_MANAGER_REF.get().is_some()
}

/// Whether a config has been wired.
#[cfg(test)]
pub(crate) fn config_installed() -> bool {
    IPSEC_CONFIG_REF.get().is_some()
}

// ---------------------------------------------------------------------------
// Process-wide accessors for the IpsecManager + IpsecConfig.
//
// Used by `PyRequest::is_ipsec_protected` and `PyRequest::matched_sa` to
// look up whether the request arrived on a protected port and whether it
// matches an active SA — both without holding the GIL or descending into
// the Python type system.
// ---------------------------------------------------------------------------

static IPSEC_MANAGER_REF: OnceLock<Arc<IpsecManager>> = OnceLock::new();
static IPSEC_CONFIG_REF: OnceLock<Arc<IpsecConfig>> = OnceLock::new();

/// Whether the given local port matches one of the configured P-CSCF
/// protected ports (`pcscf_port_c` / `pcscf_port_s`).  Returns `false`
/// when no IPsec config is wired (i.e. siphon is not running as P-CSCF).
pub fn is_protected_local_port(local_port: u16) -> bool {
    match IPSEC_CONFIG_REF.get() {
        Some(config) => local_port == config.pcscf_port_c || local_port == config.pcscf_port_s,
        None => false,
    }
}

/// The Gm port a `Record-Route` entry must name, given the local socket a leg
/// actually uses.  Returns `local_port` unchanged when it isn't `pcscf_port_c`,
/// and always when no IPsec config is wired (siphon not running as P-CSCF).
///
/// The Gm port pair is asymmetric (3GPP TS 33.203 §6.3, the four SAs laid out
/// on [`outbound_local_addr_for`]): the P-CSCF **sends** requests from
/// `port_pc` (SA #3) but **receives** them on `port_ps` (SA #1).  That splits
/// two things a proxy normally stamps with the same value:
///
/// - a `Via` names where the *response* comes back, so it names the sending
///   socket — `port_pc` on an MT relay, which is what SA #4 covers;
/// - a `Record-Route` names where future *requests* go, so on a Gm leg it is
///   always `port_ps`, whichever direction this particular relay ran.
///
/// Stamping the egress port into the Record-Route instead hands the UE a route
/// target it has no SA to transmit into — the kernel selector drops every
/// in-dialog request it tries to send, and the dialog is one-way for its whole
/// life.  Do not "simplify" this back to the sending socket.
pub fn record_route_port_for(local_port: u16) -> u16 {
    match IPSEC_CONFIG_REF.get() {
        Some(config) => record_route_port(local_port, config.pcscf_port_c, config.pcscf_port_s),
        None => local_port,
    }
}

/// Pure half of [`record_route_port_for`], split out so the mapping is
/// unit-testable without installing the process-wide `IpsecConfig`.
fn record_route_port(local_port: u16, port_c: u16, port_s: u16) -> u16 {
    if local_port == port_c {
        port_s
    } else {
        local_port
    }
}

/// Configured `ipsec.path_host` — the host part siphon writes into the
/// Path URI advertised by `request.add_pcscf_path(token)` (RFC 3327 §5
/// / TS 24.229 §5.2.7.2).  Returns `None` when not configured (siphon
/// not running as P-CSCF, or the deployment hasn't set the per-replica
/// path host); callers should error rather than guess.
pub fn pcscf_path_host() -> Option<String> {
    IPSEC_CONFIG_REF
        .get()
        .and_then(|config| config.path_host.clone())
}

/// Pick the local egress address that should be used to send a packet
/// to `destination` over an installed IPsec SA pair, or `None` when
/// the destination isn't IPsec-protected.
///
/// 3GPP TS 33.203 §6.3 installs four SAs per registered UE:
///
/// ```text
///   #1  UE:port_uc   → P-CSCF:port_ps   (UE → P-CSCF requests)
///   #2  P-CSCF:port_ps → UE:port_uc     (P-CSCF → UE responses)
///   #3  P-CSCF:port_pc → UE:port_us     (P-CSCF → UE requests, e.g. MT INVITE)
///   #4  UE:port_us   → P-CSCF:port_pc   (UE → P-CSCF responses to MT)
/// ```
///
/// SA #2 fires automatically because the dispatcher's reply path pins
/// `source_local_addr = Some(inbound.local_addr)` — that local addr
/// IS `(pcscf_addr, port_ps)` and the kernel egress XFRM policy
/// matches.  But there is no equivalent capture for an originated MT
/// request (the script has no inbound to copy from), so without this
/// helper the dispatcher defaults to the listen-port-5060 listener
/// and the kernel selector for SA #3 (src=`port_pc`, dst=`port_us`)
/// never matches, silently dropping the packet.
///
/// Resolution rules, keyed on `destination.port()`:
///
/// - `== sa.ue_port_s` → SA #3 outbound, return `(pcscf_addr, pcscf_port_c)`.
/// - `== sa.ue_port_c` → SA #2 outbound, return `(pcscf_addr, pcscf_port_s)`.
///
/// Returns `None` when:
///
/// - No IPsec manager is wired (siphon isn't running as P-CSCF).
/// - The destination IP isn't a registered UE (ordinary outbound).
/// - The destination port doesn't match either of the UE's registered
///   ports (defensive — shouldn't happen if the SA was installed).
///
/// Walks the active-SA DashMap (O(N) in concurrent UEs).  Cheap at a
/// few hundred UEs, noticeable at 50k+; revisit when that becomes a
/// real workload.
pub fn outbound_local_addr_for(destination: std::net::SocketAddr) -> Option<std::net::SocketAddr> {
    let manager = IPSEC_MANAGER_REF.get()?;
    let sa = manager.find_sa_by_ue(&destination.ip(), destination.port())?;
    outbound_endpoint_for_sa(&sa, destination.port())
}

/// Outbound source + pinned transport for an IPsec-protected destination.
///
/// Equivalent cost to [`outbound_local_addr_for`] — one DashMap walk —
/// but also returns the upper-layer protocol pinned into the SA's XFRM
/// selector (3GPP TS 33.203 §7.2: UDP for ESP-over-UDP, TCP for
/// ESP-over-TCP).  Use this on relay paths where the dispatcher would
/// otherwise pick the transport from the URI's ``;transport=`` param or
/// the inbound transport — in-dialog requests (BYE, UPDATE, in-dialog
/// re-INVITE) route via the cached Contact captured at REGISTER time,
/// which may not carry a ``;transport=`` stamp, so without this pin a
/// TCP-only SA would silently drop the UDP egress because the kernel
/// selector doesn't match.  Initial out-of-dialog INVITE works without
/// this pin because the script stamps ``;transport=`` on the Path
/// header and the cached binding's R-URI carries it; in-dialog re-uses
/// the dialog route set/Contact and that stamp is absent on many UE
/// implementations.
///
/// `current_transport` is the transport the dispatcher would otherwise
/// use (URI hint / inbound transport / default).  When the SA covers
/// both transports (`SaProtocol::Any` — the spec-compliant default per
/// TS 33.203 §7.2), the caller's choice is preserved verbatim; only
/// when the SA is single-transport-pinned does this function override.
///
/// Returns `None` under the same conditions as `outbound_local_addr_for`
/// (no manager wired, destination not a registered UE, port mismatch).
pub fn outbound_for(
    destination: std::net::SocketAddr,
    current_transport: crate::transport::Transport,
) -> Option<(std::net::SocketAddr, crate::transport::Transport)> {
    let manager = IPSEC_MANAGER_REF.get()?;
    let sa = manager.find_sa_by_ue(&destination.ip(), destination.port())?;
    outbound_for_sa(&sa, destination.port(), current_transport)
}

/// Pure resolution logic split out so tests can drive it with a
/// synthetic `SecurityAssociationPair` without touching the global
/// `IPSEC_MANAGER_REF`.  Encapsulates the TS 33.203 §6.3 SA-pair
/// directional layout: the destination port tells us which SA's
/// outbound leg the packet will traverse, which dictates which
/// P-CSCF source port pairs with it.
fn outbound_endpoint_for_sa(
    sa: &SecurityAssociationPair,
    dst_port: u16,
) -> Option<std::net::SocketAddr> {
    if dst_port == sa.ue_port_s {
        // SA #3 outbound — P-CSCF originating, e.g. MT INVITE.
        Some(std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c))
    } else if dst_port == sa.ue_port_c {
        // SA #2 outbound — P-CSCF response to UE-originated request.
        Some(std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_s))
    } else {
        None
    }
}

/// Combined (source, transport) resolution from an SA pair.  Pure
/// function so tests can drive both axes (port-direction + protocol)
/// without standing up a real IpsecManager.
///
/// `current_transport` is the transport the dispatcher would otherwise
/// use; it's returned verbatim when the SA covers both transports
/// (`SaProtocol::Any` — spec default per TS 33.203 §7.2).  For
/// single-transport pins the SA's protocol wins, since a UDP-over-TCP
/// or TCP-over-UDP mismatch silently drops the frame at the kernel
/// XFRM selector.
pub(crate) fn outbound_for_sa(
    sa: &SecurityAssociationPair,
    dst_port: u16,
    current_transport: crate::transport::Transport,
) -> Option<(std::net::SocketAddr, crate::transport::Transport)> {
    let source = outbound_endpoint_for_sa(sa, dst_port)?;
    let transport = match sa.protocol {
        SaProtocol::Udp => crate::transport::Transport::Udp,
        SaProtocol::Tcp => crate::transport::Transport::Tcp,
        // SA covers both transports — preserve whatever the caller
        // already picked.  The kernel will encrypt either way under
        // the same SPI pair.
        SaProtocol::Any => current_transport,
    };
    Some((source, transport))
}

/// Find the active SA pair (if any) matching the given UE address and
/// source port.  The UE may be sending from either its client port
/// (`ue_port_c`) or its server port (`ue_port_s`); we try both keys
/// (cheap DashMap walk over the small number of currently-active SAs).
pub fn find_sa_for_ue(ue_addr: &IpAddr, ue_port: u16) -> Option<SecurityAssociationPair> {
    let manager = IPSEC_MANAGER_REF.get()?;
    // Direct hit on the (ue_addr, ue_port_c) key — the common case where
    // the UE is sending requests from its client port to our server port.
    if let Some(sa) = manager.get_sa(ue_addr, ue_port) {
        return Some(sa);
    }
    // Otherwise the UE may be sending replies from its server port — walk
    // for a match on `ue_port_s`.
    manager.find_sa_by_ue(ue_addr, ue_port)
}

/// Re-pin the kernel hard-lifetime of the IPsec SA pair bound to a UE flow
/// to `hard_lifetime_secs` (measured from now), fire-and-forget.
///
/// This is the framework-side hook the registrar calls on every accepted
/// REGISTER refresh for an IPsec-protected UE (3GPP TS 33.203 §7.4: the SA
/// lifetime tracks the SIP registration lifetime).  IR.92 refreshes carry no
/// AKA challenge, so without this an actively-refreshing UE's SA would age out
/// of the kernel under it and be reaped + de-REGISTERed — see
/// `IpsecManager::update_sa_pair_lifetime` for the elapsed-since-install
/// arithmetic that makes the kernel deadline actually move forward.
///
/// `ue_addr` / `ue_port` are the UE's source address and port as seen on the
/// protected REGISTER (`ue_port` is the UE's protected client port — the SA's
/// `contact_key`).  No-ops cleanly when:
///
/// - no IPsec manager is wired (siphon isn't a P-CSCF),
/// - no SA matches the flow (e.g. the binding predates the SA, or it was
///   already reaped),
/// - or no Tokio runtime is in scope to spawn the async UPDSA work.
///
/// Mirrors `PyPendingSA.activate`'s fire-and-forget shape: a missed re-pin only
/// widens (never tightens) the window relative to the spec, and the next
/// refresh retries.
pub fn repin_sa_for_ue(ue_addr: &IpAddr, ue_port: u16, hard_lifetime_secs: u64) {
    let Some(manager) = IPSEC_MANAGER_REF.get() else {
        return;
    };
    // Resolve to the canonical (ue_addr, ue_port_c) the SA is keyed on — the
    // refresh may arrive from the UE's client *or* server port, but the
    // re-pin must target the contact_key.
    let Some(sa) = find_sa_for_ue(ue_addr, ue_port) else {
        return;
    };
    let runtime = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle,
        Err(_) => {
            warn!(
                ue = %ue_addr,
                ue_port_c = sa.ue_port_c,
                "ipsec.repin_sa_for_ue: no Tokio runtime in scope; skipping SA re-pin"
            );
            return;
        }
    };
    let manager = Arc::clone(manager);
    let ue_addr = sa.ue_addr;
    let ue_port_c = sa.ue_port_c;
    runtime.spawn(async move {
        if let Err(error) = manager
            .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(hard_lifetime_secs))
            .await
        {
            warn!(
                %error,
                ue = %ue_addr,
                ue_port_c,
                hard_lifetime_secs,
                "ipsec.repin_sa_for_ue: kernel hard-lifetime re-pin failed"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::{
        EncryptionAlgorithm, IntegrityAlgorithm, SaProtocol, SecurityAssociationPair,
    };

    /// A P-CSCF-side SA pair with the TS 33.203 §6.3 asymmetric port layout.
    fn ipsec_test_sa() -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr: "192.0.2.1".parse().expect("ue addr"),
            pcscf_addr: "192.0.2.10".parse().expect("pcscf addr"),
            ue_port_c: 50000,
            ue_port_s: 50001,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 1000,
            spi_us: 1001,
            spi_pc: 10000,
            spi_ps: 10001,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
            hard_lifetime_secs: None,
            protocol: SaProtocol::Udp,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: crate::ipsec::SaRole::PCscf,
        }
    }

    #[test]
    fn outbound_endpoint_picks_pcscf_port_c_for_mt_request() {
        // Destination port == ue_port_s: this is an MT INVITE landing
        // on the UE's server port — the kernel selector for SA #3
        // requires source port == pcscf_port_c.  Without this, the
        // packet leaves on listen port 5060, no SA matches, drop.
        let sa = ipsec_test_sa();
        let result = outbound_endpoint_for_sa(&sa, sa.ue_port_s);
        assert_eq!(
            result,
            Some(std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c)),
            "MT request to ue_port_s must egress from pcscf_port_c (SA #3)"
        );
    }
    #[test]
    fn outbound_endpoint_picks_pcscf_port_s_for_response_to_mo() {
        // Destination port == ue_port_c: P-CSCF responding to a UE-
        // originated request — the kernel selector for SA #2 requires
        // source port == pcscf_port_s (already what
        // `source_local_addr = Some(inbound.local_addr)` produces on
        // the reply path; this case fires for fresh proxy-originated
        // traffic to the same port, e.g. an in-dialog request siphon
        // emits without an inbound to copy from).
        let sa = ipsec_test_sa();
        let result = outbound_endpoint_for_sa(&sa, sa.ue_port_c);
        assert_eq!(
            result,
            Some(std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_s)),
            "request to ue_port_c must egress from pcscf_port_s (SA #2)"
        );
    }
    #[test]
    fn outbound_endpoint_returns_none_for_unknown_port() {
        // Destination port matches neither of the UE's registered
        // ports — defensive case; should never fire if the SA was
        // installed correctly, but we don't want to silently pick
        // the wrong source.
        let sa = ipsec_test_sa();
        assert!(outbound_endpoint_for_sa(&sa, 9999).is_none());
    }
    #[test]
    fn outbound_endpoint_distinguishes_close_ports() {
        // ue_port_c=50000, ue_port_s=50001 — make sure we're matching
        // exactly, not by range or off-by-one.
        let sa = ipsec_test_sa();
        let from_us = outbound_endpoint_for_sa(&sa, sa.ue_port_s).unwrap();
        let from_uc = outbound_endpoint_for_sa(&sa, sa.ue_port_c).unwrap();
        assert_ne!(
            from_us.port(),
            from_uc.port(),
            "SA #3 and SA #2 must not collapse onto the same source port"
        );
        assert_eq!(from_us.port(), sa.pcscf_port_c);
        assert_eq!(from_uc.port(), sa.pcscf_port_s);
    }
    #[test]
    fn outbound_for_sa_returns_udp_transport_for_udp_protocol() {
        // ESP-over-UDP SA — pinned single-transport.  The resolution
        // must surface Transport::Udp regardless of what the caller
        // would otherwise have picked (here: TCP), so the dispatcher
        // routes the egress through the UDP send path and hits the
        // kernel selector that matches IPPROTO_UDP.
        let mut sa = ipsec_test_sa();
        sa.protocol = SaProtocol::Udp;

        let (source, transport) = outbound_for_sa(
            &sa,
            sa.ue_port_s,
            crate::transport::Transport::Tcp, // caller hint — overridden
        )
        .unwrap();
        assert_eq!(
            source,
            std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c)
        );
        assert_eq!(transport, crate::transport::Transport::Udp);
    }
    #[test]
    fn outbound_for_sa_returns_tcp_transport_for_tcp_protocol() {
        // ESP-over-TCP SA — TS 33.203 §7.2, iOS-style TCP-first UEs.
        // The dispatcher MUST route this destination via the TCP send
        // path even when the URI / inbound suggested UDP; the kernel
        // selector (proto=IPPROTO_TCP) silently drops UDP egress to
        // the same address+port.  This is the load-bearing change for
        // in-dialog BYE/UPDATE to TCP-pinned UEs.
        let mut sa = ipsec_test_sa();
        sa.protocol = SaProtocol::Tcp;

        let (source, transport) =
            outbound_for_sa(&sa, sa.ue_port_s, crate::transport::Transport::Udp).unwrap();
        assert_eq!(
            source,
            std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c)
        );
        assert_eq!(transport, crate::transport::Transport::Tcp);
    }
    #[test]
    fn outbound_for_sa_returns_tcp_for_response_direction_too() {
        // Sanity: SA #2 direction (P-CSCF responding via pcscf_port_s
        // to UE's port_c) inherits the same protocol pin as SA #3.
        // The protocol is a property of the SA pair, not the
        // direction — covers re-keyed in-dialog responses too.
        let mut sa = ipsec_test_sa();
        sa.protocol = SaProtocol::Tcp;

        let (source, transport) =
            outbound_for_sa(&sa, sa.ue_port_c, crate::transport::Transport::Udp).unwrap();
        assert_eq!(
            source,
            std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_s)
        );
        assert_eq!(transport, crate::transport::Transport::Tcp);
    }
    #[test]
    fn outbound_for_sa_preserves_caller_transport_for_any_protocol() {
        // SaProtocol::Any — the spec-compliant default per TS 33.203
        // §7.2.  The SA covers both UDP and TCP under one SPI pair,
        // so the dispatcher's choice (URI ;transport= hint, inbound
        // transport, or default) MUST be preserved verbatim — no
        // override.  This is what lets iOS REGISTER over TCP and then
        // send MO MESSAGE over UDP without the kernel dropping the
        // UDP frame at the XFRM selector.
        let mut sa = ipsec_test_sa();
        sa.protocol = SaProtocol::Any;

        // Caller wants UDP — Any SA preserves it.
        let (source, transport) =
            outbound_for_sa(&sa, sa.ue_port_s, crate::transport::Transport::Udp).unwrap();
        assert_eq!(
            source,
            std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c)
        );
        assert_eq!(transport, crate::transport::Transport::Udp);

        // Caller wants TCP — same Any SA preserves that too.
        let (_, transport_tcp) =
            outbound_for_sa(&sa, sa.ue_port_s, crate::transport::Transport::Tcp).unwrap();
        assert_eq!(transport_tcp, crate::transport::Transport::Tcp);
    }
    #[test]
    fn outbound_for_sa_returns_none_when_endpoint_unresolved() {
        // Port mismatch propagates as None — `outbound_for_sa` must
        // not invent a transport when the source endpoint can't be
        // derived, otherwise the caller would pin the wrong transport
        // for a destination that isn't actually on the SA pair.
        let sa = ipsec_test_sa();
        assert!(outbound_for_sa(&sa, 9999, crate::transport::Transport::Udp).is_none());
    }
    #[test]
    fn outbound_local_addr_for_returns_none_without_manager() {
        // No IpsecManager wired (typical non-P-CSCF deployment) —
        // helper short-circuits, dispatcher falls back to the default
        // listener.  Zero-impact on non-P-CSCF hot paths.
        //
        // Note: this test is order-dependent on IPSEC_MANAGER_REF
        // being unset.  If a future test installs the static, this
        // assertion flips.  Keep this as the only test that pokes
        // the global accessor.
        let dst: std::net::SocketAddr = "10.0.0.99:50001".parse().unwrap();
        // Best-effort: only assert when no manager is present.
        if !manager_installed() {
            assert!(outbound_local_addr_for(dst).is_none());
        }
    }
    #[test]
    fn record_route_port_maps_the_client_port_to_the_server_port() {
        // TS 33.203 §6.3: the P-CSCF sends requests from port_pc but receives
        // them on port_ps.  A Record-Route names where future requests go, so
        // an MT relay leaving port_pc must still advertise port_ps — otherwise
        // the UE's in-dialog request would have to leave an SA that does not
        // exist, and the dialog is unusable in that direction.
        assert_eq!(record_route_port(5064, 5064, 5066), 5066);
    }
    #[test]
    fn record_route_port_leaves_every_other_socket_alone() {
        // port_ps is already the request-facing socket, and the core-facing
        // listener is not a Gm socket at all.
        assert_eq!(record_route_port(5066, 5064, 5066), 5066);
        assert_eq!(record_route_port(5060, 5064, 5066), 5060);
    }
    #[test]
    fn record_route_port_for_is_identity_without_config() {
        // No IpsecConfig wired (every non-P-CSCF deployment) — the port passes
        // through untouched.
        //
        // IPSEC_CONFIG_REF is a process-global OnceLock that cannot be unset,
        // and tests in this binary run in parallel, so checking it once and
        // then asserting is a race: another test can wire the config in
        // between, and the assertion then measures a configured P-CSCF. Read
        // it again afterwards and only assert if it was unset throughout.
        if !config_installed() {
            let passthrough_5060 = record_route_port_for(5060);
            let passthrough_5064 = record_route_port_for(5064);
            if !config_installed() {
                assert_eq!(passthrough_5060, 5060);
                assert_eq!(passthrough_5064, 5064);
            }
        }
    }
}
