//! Python-callable IMS-AKA + IPsec sec-agree primitives (3GPP TS 33.203).
//!
//! Exposed to scripts as ``siphon.ipsec`` plus a handful of method/property
//! additions on :class:`Request` and :class:`Reply`.  Layered on top of the
//! existing [`crate::ipsec::IpsecManager`] which performs the actual kernel
//! ``ip xfrm`` calls.
//!
//! Lifecycle (Phase 1):
//!
//! 1. ``request.parse_security_client()`` — parse the UE's
//!    ``Security-Client`` header into a list of :class:`SecurityOffer`.
//!    Each offer carries the UE address from ``request.source_ip``, so it
//!    is enough on its own to fully describe the UE side of the SA pair.
//! 2. ``reply.take_av()`` — on the relayed 401 from the S-CSCF, extract
//!    ``ck=``/``ik=`` from any auth header and **strip them in place** so
//!    they don't leak to the access side.  Returns an opaque
//!    :class:`AuthVectorHandle`.
//! 3. ``ipsec.allocate(av, offer, transform, protocol=…)`` — consume the
//!    AV, allocate SPIs, install the four XFRM SAs and policies, return
//!    a :class:`PendingSA`.  ``protocol`` selects the inner transport
//!    pinned into the XFRM selector — ``"udp"`` (default, ESP-over-UDP)
//!    or ``"tcp"`` (ESP-over-TCP, TS 33.203 §7.2).  Must match the
//!    transport the UE used for the initial REGISTER, otherwise the
//!    kernel selectors won't match the UE's protected frames and every
//!    subsequent REGISTER arrives unprotected.
//! 4. ``pending.security_server_params()`` — produce the
//!    ``Security-Server`` parameters; the script formats and injects the
//!    header on the relayed 401.
//! 5. ``ipsec.stash(call_id, pending)`` — keep the PendingSA alive across
//!    the second REGISTER round-trip (TTL default 30 s; abandoned entries
//!    auto-cleanup).
//! 6. On 200 OK to the auth REGISTER: ``ipsec.unstash(call_id).activate()``
//!    (state transition; SAs were already installed in step 3).
//! 7. On de-REGISTER: ``pending.cleanup()`` (or auto-cleanup via the
//!    dispatcher de-register hook).
//!
//! What's intentionally *not* in this module today (Phase 2/3 deferrals):
//!
//! * HMAC-SHA-256 / AES-CBC transforms.
//! * 3GPP TS 33.203 Annex H key derivation (we use raw CK/IK with
//!   zero-padding, matching the existing ``IpsecManager`` behaviour).
//! * Replacement of ``ip xfrm`` shell-out with rtnetlink.
//! * Real ``request.is_ipsec_protected`` / ``request.matched_sa`` — these
//!   getters are stubbed (always ``False``/``None``) until the transport
//!   layer plumbs the SA discriminator through.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use tracing::{debug, info, warn};

use crate::config::IpsecConfig;
use crate::ipsec::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecError, IpsecManager, SaProtocol,
    SecurityAssociationPair, SecurityClient,
};

/// Default TTL for a stashed PendingSA awaiting the auth REGISTER round-trip.
const DEFAULT_STASH_TTL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Direct Rust-side accessors for the IpsecManager + IpsecConfig.
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

/// Configured `ipsec.path_host` — the host part siphon writes into the
/// Path URI advertised by `request.add_pcscf_path(token)` (RFC 3327 §5
/// / TS 24.229 §5.2.7.2).  Returns `None` when not configured (siphon
/// not running as P-CSCF, or the deployment hasn't set the per-replica
/// path host); callers should error rather than guess.
pub fn pcscf_path_host() -> Option<String> {
    IPSEC_CONFIG_REF.get().and_then(|config| config.path_host.clone())
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
fn outbound_for_sa(
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

// ---------------------------------------------------------------------------
// SecurityOffer — parsed UE proposal from the Security-Client header.
// ---------------------------------------------------------------------------

/// One UE-side IPsec proposal from a ``Security-Client`` header
/// (3GPP TS 33.203 §6.1, RFC 3329).  A header may carry multiple
/// comma-separated offers; each is exposed as one :class:`SecurityOffer`.
#[pyclass(name = "SecurityOffer", from_py_object)]
#[derive(Clone, Debug)]
pub struct PySecurityOffer {
    /// Security mechanism, typically ``"ipsec-3gpp"``.
    #[pyo3(get)]
    pub mechanism: String,
    /// Integrity algorithm, e.g. ``"hmac-sha-1-96"``.
    #[pyo3(get)]
    pub alg: String,
    /// Encryption algorithm.  Always a string — ``"null"`` when the UE
    /// did not propose encryption (most common case for IMS-AKA).
    #[pyo3(get)]
    pub ealg: String,
    /// Client SPI proposed by the UE.
    #[pyo3(get)]
    pub spi_c: u32,
    /// Server SPI proposed by the UE.
    #[pyo3(get)]
    pub spi_s: u32,
    /// Client port proposed by the UE.
    #[pyo3(get)]
    pub port_c: u16,
    /// Server port proposed by the UE.
    #[pyo3(get)]
    pub port_s: u16,
    /// UE source address (string), captured from
    /// ``request.source_ip`` at parse time.
    #[pyo3(get)]
    pub ue_addr: String,
}

impl PySecurityOffer {
    pub(crate) fn from_security_client(client: SecurityClient, ue_addr: &str) -> Self {
        Self {
            mechanism: client.mechanism,
            alg: client.algorithm,
            ealg: client.ealg.unwrap_or_else(|| "null".to_string()),
            spi_c: client.spi_c,
            spi_s: client.spi_s,
            port_c: client.port_c,
            port_s: client.port_s,
            ue_addr: ue_addr.to_string(),
        }
    }
}

#[pymethods]
impl PySecurityOffer {
    fn __repr__(&self) -> String {
        format!(
            "SecurityOffer(mechanism={:?}, alg={:?}, ealg={:?}, spi_c={}, spi_s={}, port_c={}, port_s={}, ue_addr={:?})",
            self.mechanism,
            self.alg,
            self.ealg,
            self.spi_c,
            self.spi_s,
            self.port_c,
            self.port_s,
            self.ue_addr,
        )
    }
}

// ---------------------------------------------------------------------------
// Transform — operator-policy choice, exposed as a Python enum.
// ---------------------------------------------------------------------------

/// Operator policy choice for which IPsec transform to install.
///
/// Phase 1 shipped the two NULL-encryption transforms we already had
/// kernel ``xfrm`` algorithm names for.  Phase 2 adds:
///
/// * HMAC-SHA-256-128 integrity (RFC 4868) — required for newer IMS
///   profiles, with 256-bit keys derived via 3GPP TS 33.203 Annex H.
/// * AES-CBC-128 encryption variants for confidentiality.
///
/// All transforms install identical xfrm policies; only the algorithm
/// IDs and key material change.
#[pyclass(name = "Transform", eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyTransform {
    /// HMAC-SHA-1-96 integrity, NULL encryption.
    HmacSha1_96Null,
    /// HMAC-MD5-96 integrity, NULL encryption.
    HmacMd5_96Null,
    /// HMAC-SHA-256-128 integrity, NULL encryption.
    HmacSha256_128Null,
    /// HMAC-SHA-1-96 integrity, AES-CBC-128 encryption.
    HmacSha1_96AesCbc128,
    /// HMAC-MD5-96 integrity, AES-CBC-128 encryption.
    HmacMd5_96AesCbc128,
    /// HMAC-SHA-256-128 integrity, AES-CBC-128 encryption.
    HmacSha256_128AesCbc128,
}

impl PyTransform {
    fn aalg(&self) -> IntegrityAlgorithm {
        match self {
            PyTransform::HmacSha1_96Null | PyTransform::HmacSha1_96AesCbc128 => {
                IntegrityAlgorithm::HmacSha1
            }
            PyTransform::HmacMd5_96Null | PyTransform::HmacMd5_96AesCbc128 => {
                IntegrityAlgorithm::HmacMd5
            }
            PyTransform::HmacSha256_128Null | PyTransform::HmacSha256_128AesCbc128 => {
                IntegrityAlgorithm::HmacSha256
            }
        }
    }

    fn ealg(&self) -> EncryptionAlgorithm {
        match self {
            PyTransform::HmacSha1_96Null
            | PyTransform::HmacMd5_96Null
            | PyTransform::HmacSha256_128Null => EncryptionAlgorithm::Null,
            PyTransform::HmacSha1_96AesCbc128
            | PyTransform::HmacMd5_96AesCbc128
            | PyTransform::HmacSha256_128AesCbc128 => EncryptionAlgorithm::AesCbc128,
        }
    }

    fn alg_str(&self) -> &'static str {
        match self {
            PyTransform::HmacSha1_96Null | PyTransform::HmacSha1_96AesCbc128 => "hmac-sha-1-96",
            PyTransform::HmacMd5_96Null | PyTransform::HmacMd5_96AesCbc128 => "hmac-md5-96",
            PyTransform::HmacSha256_128Null | PyTransform::HmacSha256_128AesCbc128 => {
                "hmac-sha-256-128"
            }
        }
    }

    fn ealg_str(&self) -> &'static str {
        match self {
            PyTransform::HmacSha1_96Null
            | PyTransform::HmacMd5_96Null
            | PyTransform::HmacSha256_128Null => "null",
            PyTransform::HmacSha1_96AesCbc128
            | PyTransform::HmacMd5_96AesCbc128
            | PyTransform::HmacSha256_128AesCbc128 => "aes-cbc",
        }
    }
}

#[pymethods]
impl PyTransform {
    /// Whether this transform is compatible with the UE's offer.
    ///
    /// True when the offer's ``alg`` and ``ealg`` strings match
    /// (case-insensitive).  Empty/missing ``ealg`` on the offer is
    /// treated as ``"null"`` (most IMS UEs do not advertise an ealg
    /// when they want NULL encryption).
    pub fn compatible_with(&self, offer: &PySecurityOffer) -> bool {
        let offer_alg = offer.alg.to_lowercase();
        let offer_ealg = offer.ealg.to_lowercase();
        let want_ealg = self.ealg_str();
        offer_alg == self.alg_str()
            && (offer_ealg == want_ealg
                || (offer_ealg.is_empty() && want_ealg == "null"))
    }

    fn __repr__(&self) -> String {
        match self {
            PyTransform::HmacSha1_96Null => "Transform.HmacSha1_96Null".to_string(),
            PyTransform::HmacMd5_96Null => "Transform.HmacMd5_96Null".to_string(),
            PyTransform::HmacSha256_128Null => "Transform.HmacSha256_128Null".to_string(),
            PyTransform::HmacSha1_96AesCbc128 => "Transform.HmacSha1_96AesCbc128".to_string(),
            PyTransform::HmacMd5_96AesCbc128 => "Transform.HmacMd5_96AesCbc128".to_string(),
            PyTransform::HmacSha256_128AesCbc128 => {
                "Transform.HmacSha256_128AesCbc128".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AuthVectorHandle — opaque key-material container.
// ---------------------------------------------------------------------------

/// Opaque handle carrying the CK/IK pair extracted from a relayed 401.
///
/// No Python-side accessor returns the raw bytes.  The handle is consumed
/// by :func:`siphon.ipsec.allocate`; calling ``allocate`` twice with the
/// same handle raises :class:`ValueError`.
#[pyclass(name = "AuthVectorHandle")]
pub struct PyAuthVectorHandle {
    inner: Mutex<Option<AuthVectorBytes>>,
}

pub struct AuthVectorBytes {
    pub ck: [u8; 16],
    pub ik: [u8; 16],
}

impl Drop for AuthVectorBytes {
    fn drop(&mut self) {
        // Best-effort zeroize — no `zeroize` crate dependency for one struct.
        for byte in self.ck.iter_mut() {
            *byte = 0;
        }
        for byte in self.ik.iter_mut() {
            *byte = 0;
        }
    }
}

impl PyAuthVectorHandle {
    pub fn new(ck: [u8; 16], ik: [u8; 16]) -> Self {
        Self {
            inner: Mutex::new(Some(AuthVectorBytes { ck, ik })),
        }
    }

    /// Take the bytes out of the handle, leaving it empty.  Returns
    /// ``None`` if already consumed.  Rust-only — never exposed to Python.
    pub fn take(&self) -> Option<AuthVectorBytes> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.take()
    }
}

#[pymethods]
impl PyAuthVectorHandle {
    fn __repr__(&self) -> String {
        let consumed = self
            .inner
            .lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true);
        if consumed {
            "AuthVectorHandle(<consumed>)".to_string()
        } else {
            "AuthVectorHandle(<128-bit CK + 128-bit IK>)".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// SAHandle — read-only view of an active SA, returned by request.matched_sa.
// ---------------------------------------------------------------------------

/// Read-only handle to the IPsec SA pair that decrypted an incoming
/// protected request.  Distinct from :class:`PendingSA` (which is
/// script-owned and supports lifecycle transitions); this handle is
/// purely informational — for logging, metrics, audit trail, etc.
#[pyclass(name = "SAHandle", from_py_object)]
#[derive(Clone, Debug)]
pub struct PySAHandle {
    #[pyo3(get)]
    ue_addr: String,
    #[pyo3(get)]
    pcscf_addr: String,
    #[pyo3(get)]
    ue_port_c: u16,
    #[pyo3(get)]
    ue_port_s: u16,
    #[pyo3(get)]
    pcscf_port_c: u16,
    #[pyo3(get)]
    pcscf_port_s: u16,
    #[pyo3(get)]
    spi_uc: u32,
    #[pyo3(get)]
    spi_us: u32,
    #[pyo3(get)]
    spi_pc: u32,
    #[pyo3(get)]
    spi_ps: u32,
    #[pyo3(get)]
    alg: String,
    #[pyo3(get)]
    ealg: String,
    /// Lower-case transport carrying ESP — ``"udp"`` or ``"tcp"``.
    #[pyo3(get)]
    protocol: String,
}

impl PySAHandle {
    pub fn from_sa(sa: &SecurityAssociationPair) -> Self {
        Self {
            ue_addr: sa.ue_addr.to_string(),
            pcscf_addr: sa.pcscf_addr.to_string(),
            ue_port_c: sa.ue_port_c,
            ue_port_s: sa.ue_port_s,
            pcscf_port_c: sa.pcscf_port_c,
            pcscf_port_s: sa.pcscf_port_s,
            spi_uc: sa.spi_uc,
            spi_us: sa.spi_us,
            spi_pc: sa.spi_pc,
            spi_ps: sa.spi_ps,
            alg: format!("{}", sa.aalg),
            ealg: format!("{}", sa.ealg),
            protocol: sa.protocol.as_str().to_string(),
        }
    }
}

#[pymethods]
impl PySAHandle {
    fn __repr__(&self) -> String {
        format!(
            "SAHandle(ue={}:{}, pcscf={}:{}, spi_pc={}, spi_ps={}, alg={:?}, ealg={:?}, protocol={:?})",
            self.ue_addr,
            self.ue_port_c,
            self.pcscf_addr,
            self.pcscf_port_c,
            self.spi_pc,
            self.spi_ps,
            self.alg,
            self.ealg,
            self.protocol,
        )
    }
}

// ---------------------------------------------------------------------------
// SecurityServerParams — what the script needs to format the response header.
// ---------------------------------------------------------------------------

/// Snapshot of the chosen ``Security-Server`` parameters after
/// :func:`siphon.ipsec.allocate` has run.  All fields are read-only.
#[pyclass(name = "SecurityServerParams", from_py_object)]
#[derive(Clone, Debug)]
pub struct PySecurityServerParams {
    /// Always ``"ipsec-3gpp"`` in Phase 1.
    #[pyo3(get)]
    pub mechanism: String,
    /// Integrity algorithm name as it should appear in the
    /// ``Security-Server`` header (e.g. ``"hmac-sha-1-96"``).
    #[pyo3(get)]
    pub alg: String,
    /// Encryption algorithm name (e.g. ``"null"``).
    #[pyo3(get)]
    pub ealg: String,
    /// P-CSCF client SPI.
    #[pyo3(get)]
    pub spi_c: u32,
    /// P-CSCF server SPI.
    #[pyo3(get)]
    pub spi_s: u32,
    /// P-CSCF protected client port (shared across all UEs — see
    /// ``ipsec.pcscf_port_c`` in ``siphon.yaml``).
    #[pyo3(get)]
    pub port_c: u16,
    /// P-CSCF protected server port.
    #[pyo3(get)]
    pub port_s: u16,
    /// Wire-form transport for the RFC 3329 ``Security-Server``
    /// ``protocol=`` parameter — either ``"udp"`` or ``"tcp"``.  The
    /// caller appends ``protocol=tcp`` to the header only when this
    /// field is ``"tcp"``; ``"udp"`` is the RFC 3329 §2.2 default and
    /// should be omitted from the wire format every existing UE
    /// expects.
    ///
    /// Note: when :func:`siphon.ipsec.allocate` was called with the
    /// multi-protocol default (no ``protocol`` kwarg), this field
    /// reads ``"udp"`` — wire-compatible with the spec default — even
    /// though the underlying SA pair covers both UDP and TCP.  For
    /// diagnostics of the actual SA selector mode, inspect
    /// :attr:`SAHandle.protocol`, which surfaces ``"any"`` in that
    /// case.
    #[pyo3(get)]
    pub protocol: String,
}

#[pymethods]
impl PySecurityServerParams {
    fn __repr__(&self) -> String {
        format!(
            "SecurityServerParams(mechanism={:?}, alg={:?}, ealg={:?}, spi_c={}, spi_s={}, port_c={}, port_s={}, protocol={:?})",
            self.mechanism,
            self.alg,
            self.ealg,
            self.spi_c,
            self.spi_s,
            self.port_c,
            self.port_s,
            self.protocol,
        )
    }
}

// ---------------------------------------------------------------------------
// PendingSA — handle for a freshly-installed but not-yet-acknowledged SA pair.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingState {
    Pending,
    Active,
    Cleaned,
}

struct PendingSAInner {
    manager: Arc<IpsecManager>,
    sa: SecurityAssociationPair,
    params: PySecurityServerParams,
    state: PendingState,
}

/// Handle to an installed-but-not-yet-confirmed pair of IPsec SAs.
///
/// Keeps the four kernel ``xfrm`` states + four policies installed by
/// :func:`siphon.ipsec.allocate` reachable for header-formatting (via
/// :meth:`security_server_params`) and lifecycle transitions
/// (:meth:`activate`, :meth:`cleanup`, :meth:`refresh`).
#[pyclass(name = "PendingSA")]
pub struct PyPendingSA {
    inner: Arc<Mutex<PendingSAInner>>,
}

impl PyPendingSA {
    fn new(
        manager: Arc<IpsecManager>,
        sa: SecurityAssociationPair,
        params: PySecurityServerParams,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PendingSAInner {
                manager,
                sa,
                params,
                state: PendingState::Pending,
            })),
        }
    }
}

#[pymethods]
impl PyPendingSA {
    /// The chosen ``Security-Server`` parameters — feed these into the
    /// header you set on the relayed 401.
    fn security_server_params(&self) -> PyResult<PySecurityServerParams> {
        let guard = self.inner.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "PendingSA lock poisoned: {error}"
            ))
        })?;
        Ok(guard.params.clone())
    }

    /// Mark the SA pair active.  Call on receipt of the 200 OK to the auth
    /// REGISTER (the SAs are already installed in the kernel — this is a
    /// metadata-only transition).  Idempotent on repeated calls; raises
    /// :class:`ValueError` if the PendingSA was already cleaned up.
    ///
    /// ``hard_lifetime_secs`` (optional) — when set, also re-pins the
    /// kernel hard-lifetime on all four SAs of the pair via
    /// ``XFRM_MSG_UPDSA``, without rekeying or disturbing selectors / SPIs.
    /// Use this on the path that processes the 200 OK to the auth
    /// REGISTER to tighten the SA expiry from the placeholder value
    /// installed at allocation time (typically the UE's `Expires:` ask,
    /// commonly 600000 s for VoLTE handsets) down to the actual grant
    /// from the registrar of record (3GPP TS 33.203 §7.4 — IPsec SA
    /// lifetime tracks SIP registration lifetime).  ``None`` (the
    /// default) preserves the existing behaviour: state transition only,
    /// no kernel touch.
    ///
    /// The kernel preserves ``xfrm_state.curlft.add_time`` across
    /// ``UPDSA``, so the resulting deadline is
    /// ``add_time + hard_lifetime_secs`` — i.e. the SAs expire
    /// ``hard_lifetime_secs`` after their **original** install, not from
    /// "now".  For a normal REGISTER → 401 → REGISTER → 200 OK round-trip
    /// the install / repin gap is sub-second, so this is
    /// indistinguishable from "expires after the granted Expires".
    ///
    /// The kernel re-pin is dispatched as a fire-and-forget tokio task,
    /// matching the broader IPsec API shape (`ipsec.stash` auto-cleanup,
    /// `PyPendingSA.cleanup` on stash TTL).  Failures are logged but
    /// don't fail ``activate`` — the metadata transition has already
    /// committed, and a missed repin only widens (never tightens) the
    /// expiry window relative to the spec.
    #[pyo3(signature = (*, hard_lifetime_secs=None))]
    fn activate(&self, hard_lifetime_secs: Option<u64>) -> PyResult<()> {
        let (manager, ue_addr, ue_port_c) = {
            let mut guard = self.inner.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "PendingSA lock poisoned: {error}"
                ))
            })?;
            if guard.state == PendingState::Cleaned {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "PendingSA already cleaned up",
                ));
            }
            guard.state = PendingState::Active;
            // Mirror into the cached SA so subsequent inspection sees the
            // tightened limit even before the netlink call lands.
            if hard_lifetime_secs.is_some() {
                guard.sa.hard_lifetime_secs = hard_lifetime_secs;
            }
            info!(
                spi_pc = guard.sa.spi_pc,
                spi_ps = guard.sa.spi_ps,
                ue = %guard.sa.ue_addr,
                hard_lifetime_secs = ?hard_lifetime_secs,
                "ipsec.PendingSA: activated"
            );
            (
                Arc::clone(&guard.manager),
                guard.sa.ue_addr,
                guard.sa.ue_port_c,
            )
        };

        if let Some(secs) = hard_lifetime_secs {
            // Fire-and-forget the four UPDSA messages.  See doc-comment
            // for why this is sound — a missed repin can only widen the
            // expiry window, never tighten it past the registrar's grant.
            let manager_for_repin = Arc::clone(&manager);
            tokio::spawn(async move {
                if let Err(error) = manager_for_repin
                    .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(secs))
                    .await
                {
                    warn!(
                        %error,
                        ue = %ue_addr,
                        ue_port_c,
                        hard_lifetime_secs = secs,
                        "ipsec.PendingSA.activate: kernel hard-lifetime repin failed"
                    );
                }
            });
        }

        // Tear down any prior SA pair for this UE address that's still
        // sitting in the manager under a stale (port_uc, port_us).  The
        // UE picks a fresh random port_uc on every REGISTER, so a
        // re-REGISTER from the same UE address always installs its new
        // pair under a different contact_key than the previous one — and
        // without explicit cleanup the previous pair's four XFRM
        // policies leak into the kernel forever.  After enough refresh
        // cycles a new random port_uc collides with a leaked selector
        // and the policy add returns EEXIST, breaking the registration.
        // Fired here (post-200-OK, post-state-transition) because that's
        // the point where the new binding has been granted by the
        // registrar of record and the old one is definitionally stale.
        // Fire-and-forget for the same reason as the lifetime repin —
        // the activate transition has already committed and a missed
        // cleanup degrades to "kernel policy table grows by 4 until the
        // next successful activate", which the next round will catch.
        tokio::spawn(async move {
            manager.cleanup_other_pairs_for_ue(&ue_addr, ue_port_c).await;
        });

        Ok(())
    }

    /// Whether this PendingSA is in the active state.
    #[getter]
    fn is_active(&self) -> PyResult<bool> {
        let guard = self.inner.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "PendingSA lock poisoned: {error}"
            ))
        })?;
        Ok(guard.state == PendingState::Active)
    }

    /// Whether this PendingSA has been torn down.
    #[getter]
    fn is_cleaned(&self) -> PyResult<bool> {
        let guard = self.inner.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "PendingSA lock poisoned: {error}"
            ))
        })?;
        Ok(guard.state == PendingState::Cleaned)
    }

    /// Tear down all four XFRM states + policies for this pair.
    /// Idempotent — calling on an already-cleaned PendingSA is a no-op.
    fn cleanup<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(python, async move {
            let (manager, ue_addr, ue_port_c, already_cleaned) = {
                let mut guard = inner.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "PendingSA lock poisoned: {error}"
                    ))
                })?;
                let already = guard.state == PendingState::Cleaned;
                let manager = Arc::clone(&guard.manager);
                let ue_addr = guard.sa.ue_addr;
                let ue_port_c = guard.sa.ue_port_c;
                if !already {
                    guard.state = PendingState::Cleaned;
                }
                (manager, ue_addr, ue_port_c, already)
            };
            if already_cleaned {
                return Ok(());
            }
            if let Err(error) = manager.delete_sa_pair(&ue_addr, ue_port_c).await {
                warn!(%error, ue = %ue_addr, "ipsec.PendingSA.cleanup: delete failed");
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "delete_sa_pair failed: {error}"
                )));
            }
            debug!(ue = %ue_addr, ue_port_c, "ipsec.PendingSA: cleaned up");
            Ok(())
        })
    }

    /// Re-key the SA pair for a re-REGISTER under the same Call-ID.
    ///
    /// Phase 1 implementation: tears down the existing pair and reinstalls
    /// it with the same UE/P-CSCF ports and SPIs but fresh CK/IK.  SPI/port
    /// reuse keeps the UE's selectors stable; only the keys change.
    fn refresh<'py>(
        &self,
        python: Python<'py>,
        av_new: Bound<'py, PyAuthVectorHandle>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let new_keys = av_new.borrow().take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("AuthVectorHandle already consumed")
        })?;
        let inner = Arc::clone(&self.inner);
        future_into_py(python, async move {
            let manager;
            let mut sa_new;
            {
                let guard = inner.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "PendingSA lock poisoned: {error}"
                    ))
                })?;
                if guard.state == PendingState::Cleaned {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "PendingSA already cleaned up",
                    ));
                }
                manager = Arc::clone(&guard.manager);
                sa_new = guard.sa.clone();
            }
            // Tear down the old SAs first; ignore errors (xfrm may have
            // already lost them — we still want the new ones to land).
            if let Err(error) = manager.delete_sa_pair(&sa_new.ue_addr, sa_new.ue_port_c).await {
                debug!(
                    %error,
                    "ipsec.PendingSA.refresh: prior delete_sa_pair returned error (ignored)"
                );
            }
            sa_new.integrity_key = hex_encode(&new_keys.ik);
            sa_new.encryption_key = if sa_new.ealg == EncryptionAlgorithm::Null {
                String::new()
            } else {
                hex_encode(&new_keys.ck)
            };
            manager
                .create_sa_pair(sa_new.clone())
                .await
                .map_err(map_ipsec_error)?;
            {
                let mut guard = inner.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "PendingSA lock poisoned: {error}"
                    ))
                })?;
                guard.sa = sa_new;
            }
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return "PendingSA(<lock-poisoned>)".to_string(),
        };
        format!(
            "PendingSA(state={:?}, ue={}, ue_port_c={}, spi_pc={}, spi_ps={})",
            guard.state, guard.sa.ue_addr, guard.sa.ue_port_c, guard.sa.spi_pc, guard.sa.spi_ps,
        )
    }
}

fn map_ipsec_error(error: IpsecError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("IPsec allocate failed: {error}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Parse the ``protocol`` kwarg from :meth:`PyIpsec.allocate`.
///
/// `None` → :data:`SaProtocol::Any`, the spec-compliant default per
/// 3GPP TS 33.203 §7.2 — same SPI pair covers both UDP and TCP inner
/// flows.  Explicit ``"udp"`` / ``"tcp"`` / ``"any"`` (case-insensitive)
/// pin the selectors to that one inner protocol.  Anything else is an
/// error message the caller surfaces as a Python ``ValueError``.
fn parse_allocate_protocol(value: Option<&str>) -> Result<SaProtocol, String> {
    match value {
        None => Ok(SaProtocol::Any),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "udp" => Ok(SaProtocol::Udp),
            "tcp" => Ok(SaProtocol::Tcp),
            "any" => Ok(SaProtocol::Any),
            other => Err(format!(
                "protocol must be 'udp', 'tcp', 'any', or None, got {other:?}"
            )),
        },
    }
}

/// Map an internal :data:`SaProtocol` to the wire-form value the
/// script appends to the RFC 3329 ``Security-Server`` ``protocol=``
/// parameter.  `Any` collapses to ``"udp"`` because RFC 3329 §2.2
/// declares an absent ``protocol=`` parameter to imply UDP — keeping
/// the wire output identical to the pre-multi-protocol shape every
/// existing UE expects, while the underlying SA covers both transports.
fn format_params_protocol(sa_protocol: SaProtocol) -> String {
    match sa_protocol {
        SaProtocol::Udp | SaProtocol::Any => "udp".to_string(),
        SaProtocol::Tcp => "tcp".to_string(),
    }
}

// ---------------------------------------------------------------------------
// PyIpsec — the singleton injected as ``siphon.ipsec``.
// ---------------------------------------------------------------------------

struct StashEntry {
    pending: Py<PyPendingSA>,
    expires_at: Instant,
}

/// Python-visible namespace.
#[pyclass(name = "Ipsec")]
pub struct PyIpsec {
    manager: Arc<IpsecManager>,
    config: Arc<IpsecConfig>,
    /// Local P-CSCF address per family, captured at startup from the listener
    /// configuration.  The SA's P-CSCF side MUST match the UE's address family
    /// — the kernel rejects a mixed-family XFRM selector (3GPP TS 33.203 §7.2),
    /// so a dual-stack P-CSCF keeps a v4 and a v6 local address and picks the
    /// one matching the UE that is registering.
    pcscf_addr_v4: Option<IpAddr>,
    pcscf_addr_v6: Option<IpAddr>,
    /// Stash for PendingSAs awaiting the auth REGISTER round-trip.
    stash: Arc<DashMap<String, StashEntry>>,
    /// TTL for stashed entries.
    stash_ttl: Duration,
}

impl PyIpsec {
    pub fn new(
        manager: Arc<IpsecManager>,
        config: Arc<IpsecConfig>,
        pcscf_addr_v4: Option<IpAddr>,
        pcscf_addr_v6: Option<IpAddr>,
    ) -> Self {
        // Wire up the direct Rust-side accessors so `PyRequest`'s
        // `is_ipsec_protected` and `matched_sa` getters can resolve
        // without going through the Python type system.  Idempotent —
        // safe to call multiple times (only the first wins).
        let _ = IPSEC_MANAGER_REF.set(Arc::clone(&manager));
        let _ = IPSEC_CONFIG_REF.set(Arc::clone(&config));
        Self {
            manager,
            config,
            pcscf_addr_v4,
            pcscf_addr_v6,
            stash: Arc::new(DashMap::new()),
            stash_ttl: DEFAULT_STASH_TTL,
        }
    }

    /// The P-CSCF local address matching the UE's address family, or `None`
    /// when no listener of that family is configured.  The SA's P-CSCF side
    /// must be the same family as the UE — a mixed-family selector never
    /// matches in the kernel (3GPP TS 33.203 §7.2).
    fn pcscf_addr_for(&self, ue_ipv6: bool) -> Option<IpAddr> {
        if ue_ipv6 {
            self.pcscf_addr_v6
        } else {
            self.pcscf_addr_v4
        }
    }
}

#[pymethods]
impl PyIpsec {
    /// The configured P-CSCF protected client port (shared across all UEs).
    #[getter]
    fn pcscf_port_c(&self) -> u16 {
        self.config.pcscf_port_c
    }

    /// The configured P-CSCF protected server port (shared across all UEs).
    #[getter]
    fn pcscf_port_s(&self) -> u16 {
        self.config.pcscf_port_s
    }

    /// Number of PendingSAs currently stashed awaiting the auth REGISTER.
    #[getter]
    fn stash_size(&self) -> usize {
        self.stash.len()
    }

    /// Number of active SA pairs in the kernel (across all UEs).
    #[getter]
    fn active_count(&self) -> usize {
        self.manager.active_count()
    }

    /// Allocate SPIs and install the four IPsec SAs + four policies in the
    /// kernel.  Consumes ``av``.  Returns a :class:`PendingSA`.
    ///
    /// ``expires_secs`` (optional) sets a kernel-enforced hard lifetime on
    /// each of the four SAs.  Pass the SIP registration's ``expires`` to
    /// tie SA lifetime to the registration per 3GPP TS 33.203 §7.4 — once
    /// the kernel marks the SA expired, no further packets decrypt and
    /// the script must allocate fresh SAs on re-REGISTER.  Default is
    /// ``None`` (no kernel-enforced expiry).
    ///
    /// ``protocol`` selects the upper-layer transport(s) the XFRM
    /// selectors will match against.  The default (``None``) is
    /// **multi-protocol** — the kernel selector stamps ``proto=0``
    /// ("any"), so the same SPI pair covers *both* ESP-over-UDP and
    /// ESP-over-TCP under a single :class:`AuthVectorHandle`
    /// consumption.  This is the spec-compliant behaviour required by
    /// 3GPP TS 33.203 §7.2 ("the SAs shall be used to protect *all*
    /// SIP signalling … including over UDP and TCP") and the only
    /// shape that works for handsets that mix transports — iOS
    /// REGISTERs over TCP but sends MO MESSAGE over UDP, and a
    /// single-transport pin would silently drop the MESSAGE on
    /// ``XfrmInStateMismatch``.
    ///
    /// Explicit ``"udp"`` or ``"tcp"`` pins the selectors to that one
    /// inner protocol (kept for tests, single-transport deployments,
    /// and parity with the pre-multi-protocol API).  Pinning to one
    /// transport while the UE uses the other silently drops every
    /// protected frame because the kernel selector won't bind.
    ///
    /// Raises :class:`ValueError` when ``av`` was already consumed, when
    /// the chosen ``transform`` is not compatible with ``offer``, when
    /// ``offer.ue_addr`` is not a valid IP literal, or when ``protocol``
    /// is set to anything other than ``"udp"``, ``"tcp"``, or ``"any"``.
    /// Raises :class:`RuntimeError` on kernel/SPI failures.
    #[pyo3(signature = (av, offer, transform, expires_secs=None, protocol=None))]
    fn allocate<'py>(
        &self,
        python: Python<'py>,
        av: Bound<'py, PyAuthVectorHandle>,
        offer: PySecurityOffer,
        transform: PyTransform,
        expires_secs: Option<u64>,
        protocol: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !transform.compatible_with(&offer) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "transform {:?} not compatible with offer alg={:?} ealg={:?}",
                transform, offer.alg, offer.ealg
            )));
        }
        let sa_protocol = parse_allocate_protocol(protocol).map_err(|message| {
            pyo3::exceptions::PyValueError::new_err(message)
        })?;
        let keys = av.borrow().take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("AuthVectorHandle already consumed")
        })?;
        let ue_addr: IpAddr = offer.ue_addr.parse().map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "offer.ue_addr {:?} is not a valid IP: {error}",
                offer.ue_addr
            ))
        })?;
        let manager = Arc::clone(&self.manager);
        // Pick the P-CSCF local address matching the UE's family.  The four SAs
        // and policies are keyed on (source, destination) of the same family;
        // a v4 P-CSCF address against a v6 UE (or vice-versa) programs a
        // mixed-family selector the kernel silently never matches — so fail
        // loudly rather than install a dead SA (3GPP TS 33.203 §7.2).
        let pcscf_addr = self.pcscf_addr_for(ue_addr.is_ipv6()).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "no {family} P-CSCF listener configured for {family} UE {ue_addr}; \
                 cannot build a same-family IPsec SA selector (3GPP TS 33.203 §7.2)",
                family = if ue_addr.is_ipv6() { "IPv6" } else { "IPv4" },
            ))
        })?;
        let pcscf_port_c = self.config.pcscf_port_c;
        let pcscf_port_s = self.config.pcscf_port_s;

        future_into_py(python, async move {
            let (spi_pc, spi_ps) = manager.allocate_spi_pair();
            let aalg = transform.aalg();
            let ealg = transform.ealg();

            // 3GPP TS 33.203 Annex H key derivation — produces a key
            // matching the algorithm's required length.  Falls back to
            // raw IK on derivation failure (which only happens with a
            // non-128-bit IK, never in practice for IMS-AKA).
            let integrity_bytes = crate::ipsec::IpsecManager::derive_integrity_key(aalg, &keys.ik)
                .unwrap_or_else(|| keys.ik.to_vec());
            let integrity_key = crate::ipsec::bytes_to_hex(&integrity_bytes);
            let encryption_key = if ealg == EncryptionAlgorithm::Null {
                String::new()
            } else {
                // AES-CBC-128 key — first 16 bytes of CK directly.
                crate::ipsec::bytes_to_hex(&keys.ck)
            };
            let sa = SecurityAssociationPair {
                ue_addr,
                pcscf_addr,
                ue_port_c: offer.port_c,
                ue_port_s: offer.port_s,
                pcscf_port_c,
                pcscf_port_s,
                spi_uc: offer.spi_c,
                spi_us: offer.spi_s,
                spi_pc,
                spi_ps,
                ealg,
                aalg,
                encryption_key,
                integrity_key,
                hard_lifetime_secs: expires_secs,
                protocol: sa_protocol,
                // Placeholders — create_sa_pair recomputes the authoritative
                // sweep deadline (expires_at) and install anchor (created_at)
                // from hard_lifetime_secs + grace at the kernel install moment.
                expires_at: std::time::Instant::now(),
                created_at: std::time::Instant::now(),
                // This namespace is the P-CSCF (network) side.
                role: crate::ipsec::SaRole::PCscf,
            };
            manager
                .create_sa_pair(sa.clone())
                .await
                .map_err(map_ipsec_error)?;
            let params_protocol = format_params_protocol(sa_protocol);
            let params = PySecurityServerParams {
                mechanism: "ipsec-3gpp".to_string(),
                alg: transform.alg_str().to_string(),
                ealg: transform.ealg_str().to_string(),
                spi_c: spi_pc,
                spi_s: spi_ps,
                port_c: pcscf_port_c,
                port_s: pcscf_port_s,
                protocol: params_protocol,
            };
            let pending = PyPendingSA::new(manager, sa, params);
            Python::attach(|python| Py::new(python, pending))
        })
    }

    /// Stash a :class:`PendingSA` under ``call_id`` so it survives until the
    /// auth REGISTER round-trip.  Replaces any prior entry under the same
    /// key (which is auto-cleaned).  Auto-cleanup of the stashed entry
    /// fires after the configured TTL (default 30 s).
    fn stash(&self, call_id: String, pending: Py<PyPendingSA>) {
        let expires_at = Instant::now() + self.stash_ttl;
        let entry = StashEntry { pending, expires_at };
        if let Some(prior) = self.stash.insert(call_id.clone(), entry) {
            spawn_pending_cleanup(prior.pending);
        }

        let stash = Arc::clone(&self.stash);
        let ttl = self.stash_ttl;
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            if let Some((_, expired)) = stash.remove(&call_id) {
                debug!(call_id, "ipsec.stash: TTL expired, cleaning up PendingSA");
                spawn_pending_cleanup(expired.pending);
            }
        });
    }

    /// Pop a stashed :class:`PendingSA`.  Returns ``None`` if the call_id
    /// is unknown or its TTL already expired.
    fn unstash(&self, call_id: &str) -> Option<Py<PyPendingSA>> {
        self.stash.remove(call_id).and_then(|(_, entry)| {
            if entry.expires_at < Instant::now() {
                spawn_pending_cleanup(entry.pending);
                None
            } else {
                Some(entry.pending)
            }
        })
    }

    fn __repr__(&self) -> String {
        let fmt = |addr: Option<IpAddr>| addr.map(|a| a.to_string()).unwrap_or_else(|| "-".to_string());
        format!(
            "Ipsec(pcscf_addr_v4={}, pcscf_addr_v6={}, pcscf_port_c={}, pcscf_port_s={}, active={}, stashed={})",
            fmt(self.pcscf_addr_v4),
            fmt(self.pcscf_addr_v6),
            self.config.pcscf_port_c,
            self.config.pcscf_port_s,
            self.manager.active_count(),
            self.stash.len(),
        )
    }
}

fn spawn_pending_cleanup(pending: Py<PyPendingSA>) {
    // Fire-and-forget kernel teardown of an abandoned/displaced PendingSA.
    let inner = Python::attach(|python| {
        let bound = pending.bind(python);
        let cell = bound.borrow();
        Arc::clone(&cell.inner)
    });
    tokio::spawn(async move {
        let (manager, ue_addr, ue_port_c, already_cleaned) = {
            let mut guard = match inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let already = guard.state == PendingState::Cleaned;
            let manager = Arc::clone(&guard.manager);
            let ue_addr = guard.sa.ue_addr;
            let ue_port_c = guard.sa.ue_port_c;
            if !already {
                guard.state = PendingState::Cleaned;
            }
            (manager, ue_addr, ue_port_c, already)
        };
        if already_cleaned {
            return;
        }
        if let Err(error) = manager.delete_sa_pair(&ue_addr, ue_port_c).await {
            warn!(%error, ue = %ue_addr, "ipsec auto-cleanup: delete_sa_pair failed");
        }
    });
}

// ---------------------------------------------------------------------------
// Free helpers — used by PyRequest::parse_security_client and PyReply::take_av.
// ---------------------------------------------------------------------------

/// Parse a ``Security-Client`` header value containing one *or more*
/// comma-separated offers (RFC 3329 §2.2 grammar).  Returns the offers
/// successfully parsed; malformed sub-offers are silently skipped.
pub fn parse_security_client_multi(value: &str, ue_addr: &str) -> Vec<PySecurityOffer> {
    split_top_level_commas(value)
        .into_iter()
        .filter_map(|chunk| {
            let trimmed = chunk.trim();
            if trimmed.is_empty() {
                return None;
            }
            crate::ipsec::parse_security_client(trimmed)
                .map(|client| PySecurityOffer::from_security_client(client, ue_addr))
        })
        .collect()
}

/// A parsed (CK, IK) key pair extracted from an auth header — two 128-bit keys.
type CkIkPair = ([u8; 16], [u8; 16]);

/// Strip ``ck=…`` and ``ik=…`` parameters from a single auth header value
/// (e.g. a ``Digest …`` ``WWW-Authenticate`` value).  Returns the rewritten
/// header and the extracted (CK, IK) pair only when **both** parsed
/// cleanly.  When either is missing or malformed, returns the original
/// value unchanged and ``None``.
///
/// The parser is conservative: it splits on top-level commas (respecting
/// double-quoted strings), removes whole tokens whose name is ``ck`` or
/// ``ik`` (case-insensitive), and rejoins the surviving tokens with
/// ``", "`` separators.  Quoting style of untouched parameters is
/// preserved byte-for-byte.
pub fn strip_ck_ik(value: &str) -> (String, Option<CkIkPair>) {
    let (scheme, rest) = match value.split_once(char::is_whitespace) {
        Some((scheme, rest)) => (scheme, rest),
        None => return (value.to_string(), None),
    };

    let tokens = split_top_level_commas(rest);
    let mut kept = Vec::with_capacity(tokens.len());
    let mut ck = None;
    let mut ik = None;

    for token in tokens {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (name, raw_value) = match trimmed.split_once('=') {
            Some(parts) => parts,
            None => {
                kept.push(trimmed.to_string());
                continue;
            }
        };
        let name_lower = name.trim().to_lowercase();
        if name_lower == "ck" {
            ck = parse_hex_param(raw_value);
            continue;
        }
        if name_lower == "ik" {
            ik = parse_hex_param(raw_value);
            continue;
        }
        kept.push(trimmed.to_string());
    }

    match (ck, ik) {
        (Some(ck_bytes), Some(ik_bytes)) => {
            let rewritten = format!("{} {}", scheme, kept.join(", "));
            (rewritten, Some((ck_bytes, ik_bytes)))
        }
        _ => (value.to_string(), None),
    }
}

/// Split a header parameter list on top-level commas, treating
/// double-quoted strings as opaque (commas inside quotes are kept).
/// The result is a list of slices including their original interior
/// whitespace; callers trim as needed.
fn split_top_level_commas(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_quote => {
                escaped = true;
            }
            b'"' => {
                in_quote = !in_quote;
            }
            b',' if !in_quote => {
                out.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out
}

/// Parse ``"hex…"`` or ``hex…`` into a 16-byte array.  Returns ``None``
/// for any length other than 16 bytes (32 hex chars) — IMS-AKA AVs are
/// always 128-bit.
fn parse_hex_param(raw: &str) -> Option<[u8; 16]> {
    let trimmed = raw.trim();
    let unquoted = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if unquoted.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, chunk) in unquoted.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_top_level_commas_respects_quotes() {
        let value = r#"realm="ims, example", nonce="abc", qop="auth""#;
        let parts = split_top_level_commas(value);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].trim(), r#"realm="ims, example""#);
        assert_eq!(parts[1].trim(), r#"nonce="abc""#);
        assert_eq!(parts[2].trim(), r#"qop="auth""#);
    }

    #[test]
    fn split_top_level_commas_handles_escaped_quote() {
        let value = r#"a="x\"y", b=2"#;
        let parts = split_top_level_commas(value);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].trim(), r#"a="x\"y""#);
        assert_eq!(parts[1].trim(), "b=2");
    }

    #[test]
    fn parse_hex_param_quoted_and_bare() {
        let bytes = parse_hex_param("\"0123456789abcdef0123456789abcdef\"").unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[15], 0xef);
        let bytes2 = parse_hex_param("0123456789ABCDEF0123456789ABCDEF").unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn parse_hex_param_rejects_wrong_length() {
        assert!(parse_hex_param("abc").is_none());
        assert!(parse_hex_param("\"00\"").is_none());
    }

    #[test]
    fn pcscf_addr_for_selects_by_ue_family() {
        let manager = Arc::new(IpsecManager::with_partition(
            crate::ipsec::XfrmBackend::Netlink,
            10000,
            8192,
        ));
        let config = Arc::new(IpsecConfig {
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            backend: crate::config::IpsecBackend::Netlink,
            spi_range_start: None,
            spi_range_count: 8192,
            path_host: None,
        });
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();

        // Dual-stack: each UE family selects its own P-CSCF local address.
        let dual = PyIpsec::new(Arc::clone(&manager), Arc::clone(&config), Some(v4), Some(v6));
        assert_eq!(dual.pcscf_addr_for(false), Some(v4));
        assert_eq!(dual.pcscf_addr_for(true), Some(v6));

        // v4-only P-CSCF: a v6 UE has no same-family local address, so allocate
        // must fail loudly rather than program a mixed-family selector.
        let v4_only = PyIpsec::new(Arc::clone(&manager), Arc::clone(&config), Some(v4), None);
        assert_eq!(v4_only.pcscf_addr_for(false), Some(v4));
        assert_eq!(v4_only.pcscf_addr_for(true), None);
    }

    #[test]
    fn strip_ck_ik_basic_extraction() {
        let header = r#"Digest realm="ims.example.com", nonce="abc", algorithm=AKAv1-MD5, ck="0123456789abcdef0123456789abcdef", ik="fedcba9876543210fedcba9876543210", qop="auth""#;
        let (rewritten, parsed) = strip_ck_ik(header);
        let (ck, ik) = parsed.expect("expected ck+ik to parse");
        assert_eq!(ck[0], 0x01);
        assert_eq!(ik[0], 0xfe);
        assert!(!rewritten.contains("ck="));
        assert!(!rewritten.contains("ik="));
        assert!(rewritten.contains(r#"realm="ims.example.com""#));
        assert!(rewritten.contains(r#"nonce="abc""#));
        assert!(rewritten.contains(r#"qop="auth""#));
        assert!(rewritten.starts_with("Digest "));
    }

    #[test]
    fn strip_ck_ik_idempotent_after_strip() {
        let header = r#"Digest realm="ims.example.com", nonce="abc", ck="0123456789abcdef0123456789abcdef", ik="fedcba9876543210fedcba9876543210""#;
        let (first, parsed1) = strip_ck_ik(header);
        assert!(parsed1.is_some());
        let (second, parsed2) = strip_ck_ik(&first);
        assert_eq!(first, second);
        assert!(parsed2.is_none());
    }

    #[test]
    fn strip_ck_ik_missing_ik_returns_none_and_preserves_input() {
        let header = r#"Digest realm="x", nonce="y", ck="0123456789abcdef0123456789abcdef""#;
        let (out, parsed) = strip_ck_ik(header);
        assert!(parsed.is_none());
        assert_eq!(out, header);
    }

    #[test]
    fn strip_ck_ik_missing_ck_returns_none_and_preserves_input() {
        let header = r#"Digest realm="x", nonce="y", ik="0123456789abcdef0123456789abcdef""#;
        let (out, parsed) = strip_ck_ik(header);
        assert!(parsed.is_none());
        assert_eq!(out, header);
    }

    #[test]
    fn strip_ck_ik_preserves_quoted_commas_in_realm() {
        let header = r#"Digest realm="ims, example", nonce="abc", ck="0123456789abcdef0123456789abcdef", ik="fedcba9876543210fedcba9876543210""#;
        let (rewritten, parsed) = strip_ck_ik(header);
        assert!(parsed.is_some());
        assert!(rewritten.contains(r#"realm="ims, example""#));
    }

    #[test]
    fn strip_ck_ik_handles_no_quotes() {
        let header = "Digest realm=x, nonce=y, ck=0123456789abcdef0123456789abcdef, ik=fedcba9876543210fedcba9876543210";
        let (rewritten, parsed) = strip_ck_ik(header);
        let (ck, ik) = parsed.expect("expected ck+ik to parse");
        assert_eq!(ck[0], 0x01);
        assert_eq!(ik[0], 0xfe);
        assert_eq!(rewritten, "Digest realm=x, nonce=y");
    }

    #[test]
    fn strip_ck_ik_uppercase_param_names_recognized() {
        let header = r#"Digest realm="x", nonce="y", CK="0123456789abcdef0123456789abcdef", IK="fedcba9876543210fedcba9876543210""#;
        let (_rewritten, parsed) = strip_ck_ik(header);
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_security_client_multi_single_offer() {
        let header = "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062";
        let offers = parse_security_client_multi(header, "10.0.0.1");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].mechanism, "ipsec-3gpp");
        assert_eq!(offers[0].alg, "hmac-sha-1-96");
        assert_eq!(offers[0].spi_c, 11111);
        assert_eq!(offers[0].ue_addr, "10.0.0.1");
    }

    #[test]
    fn parse_security_client_multi_two_offers() {
        let header = concat!(
            "ipsec-3gpp; alg=hmac-md5-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062, ",
            "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=33333; spi-s=44444; port-c=5063; port-s=5064",
        );
        let offers = parse_security_client_multi(header, "10.0.0.1");
        assert_eq!(offers.len(), 2);
        assert_eq!(offers[0].alg, "hmac-md5-96");
        assert_eq!(offers[0].spi_c, 11111);
        assert_eq!(offers[1].alg, "hmac-sha-1-96");
        assert_eq!(offers[1].spi_c, 33333);
    }

    #[test]
    fn parse_security_client_multi_skips_malformed_subsection() {
        let header = "junk-without-required-params, ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1; spi-s=2; port-c=3; port-s=4";
        let offers = parse_security_client_multi(header, "10.0.0.1");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].spi_c, 1);
    }

    #[test]
    fn transform_compatible_with_matches_alg() {
        let offer = PySecurityOffer {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "null".into(),
            spi_c: 1,
            spi_s: 2,
            port_c: 3,
            port_s: 4,
            ue_addr: "10.0.0.1".into(),
        };
        assert!(PyTransform::HmacSha1_96Null.compatible_with(&offer));
        assert!(!PyTransform::HmacMd5_96Null.compatible_with(&offer));
    }

    #[test]
    fn transform_compatible_with_treats_empty_ealg_as_null() {
        let offer = PySecurityOffer {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "".into(),
            spi_c: 1,
            spi_s: 2,
            port_c: 3,
            port_s: 4,
            ue_addr: "10.0.0.1".into(),
        };
        assert!(PyTransform::HmacSha1_96Null.compatible_with(&offer));
    }

    #[test]
    fn auth_vector_handle_take_consumes() {
        let handle = PyAuthVectorHandle::new([1u8; 16], [2u8; 16]);
        let first = handle.take();
        assert!(first.is_some());
        let second = handle.take();
        assert!(second.is_none());
    }

    #[test]
    fn auth_vector_bytes_zeroize_on_drop() {
        // Smoke test — we can't observe the zeroization from outside, but
        // the Drop impl runs.  This just ensures the type compiles and
        // drops cleanly with the contained bytes.
        let bytes = AuthVectorBytes {
            ck: [0xab; 16],
            ik: [0xcd; 16],
        };
        drop(bytes);
    }

    #[test]
    fn hex_encode_round_trip() {
        let bytes = [0x00u8, 0x01, 0xff, 0xab];
        assert_eq!(hex_encode(&bytes), "0001ffab");
    }

    #[test]
    fn security_server_params_carries_protocol() {
        let params = PySecurityServerParams {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "null".into(),
            spi_c: 10000,
            spi_s: 10001,
            port_c: 5064,
            port_s: 5066,
            protocol: "tcp".into(),
        };
        assert_eq!(params.protocol, "tcp");
        let rendered = params.__repr__();
        assert!(rendered.contains("protocol=\"tcp\""));
    }

    /// SAHandle surfaces the *internal* SA selector mode for
    /// diagnostics — UDP/TCP for single-transport pins, `any` for the
    /// multi-protocol default (TS 33.203 §7.2).  The Security-Server
    /// wire format (set via PendingSA) is a separate concern; this
    /// test pins the diagnostic surface so logs and metrics stay
    /// useful when chasing iOS-style mixed-transport bugs.
    #[test]
    fn sa_handle_protocol_surfaces_any_for_dual_transport_sa() {
        let mut sa = ipsec_test_sa();
        sa.protocol = SaProtocol::Any;
        let handle = PySAHandle::from_sa(&sa);
        assert_eq!(handle.protocol, "any");
    }

    /// `protocol=None` (the new default) MUST map to SaProtocol::Any
    /// so :meth:`PyIpsec.allocate` installs an XFRM selector covering
    /// both ESP-over-UDP and ESP-over-TCP under one SPI pair
    /// (3GPP TS 33.203 §7.2).  Without this, iOS handsets that
    /// REGISTER over TCP and dispatch MO MESSAGE over UDP would have
    /// their MESSAGEs silently dropped by the kernel selector.
    #[test]
    fn parse_allocate_protocol_defaults_to_any_for_none() {
        assert_eq!(parse_allocate_protocol(None).unwrap(), SaProtocol::Any);
    }

    #[test]
    fn parse_allocate_protocol_accepts_explicit_pins() {
        assert_eq!(parse_allocate_protocol(Some("udp")).unwrap(), SaProtocol::Udp);
        assert_eq!(parse_allocate_protocol(Some("tcp")).unwrap(), SaProtocol::Tcp);
        assert_eq!(parse_allocate_protocol(Some("any")).unwrap(), SaProtocol::Any);
        // Case-insensitive — UE-supplied transport strings vary.
        assert_eq!(parse_allocate_protocol(Some("UDP")).unwrap(), SaProtocol::Udp);
        assert_eq!(parse_allocate_protocol(Some("TCP")).unwrap(), SaProtocol::Tcp);
        assert_eq!(parse_allocate_protocol(Some("Any")).unwrap(), SaProtocol::Any);
    }

    #[test]
    fn parse_allocate_protocol_rejects_garbage() {
        let error = parse_allocate_protocol(Some("sctp")).unwrap_err();
        assert!(error.contains("'udp', 'tcp', 'any'"));
        assert!(error.contains("sctp"));
    }

    /// `Any` MUST collapse to wire-form ``"udp"`` so the existing
    /// ``protocol=`` formatting in scripts
    /// (``f"; protocol={params.protocol}" if params.protocol != "udp" else ""``)
    /// keeps emitting parameter-less Security-Server headers — RFC 3329
    /// §2.2 says an absent ``protocol=`` parameter implies UDP, and
    /// every existing UE handles that wire shape.
    #[test]
    fn format_params_protocol_collapses_any_to_udp_for_wire() {
        assert_eq!(format_params_protocol(SaProtocol::Any), "udp");
        assert_eq!(format_params_protocol(SaProtocol::Udp), "udp");
        assert_eq!(format_params_protocol(SaProtocol::Tcp), "tcp");
    }

    /// `activate(hard_lifetime_secs=…)` flips the metadata to Active and
    /// writes the new lifetime into the cached SA in-line, before
    /// dispatching the kernel UPDSA work.  Subsequent inspection sees
    /// the tightened limit even if the netlink call hasn't landed yet.
    #[tokio::test]
    async fn activate_with_hard_lifetime_secs_updates_cached_sa() {
        let manager = Arc::new(IpsecManager::new());
        let sa = SecurityAssociationPair {
            ue_addr: "10.0.0.1".parse().unwrap(),
            pcscf_addr: "10.0.0.10".parse().unwrap(),
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
            hard_lifetime_secs: Some(600_000),
            protocol: SaProtocol::Udp,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: crate::ipsec::SaRole::PCscf,
        };
        let params = PySecurityServerParams {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "null".into(),
            spi_c: 10000,
            spi_s: 10001,
            port_c: 5064,
            port_s: 5066,
            protocol: "udp".into(),
        };
        let pending = PyPendingSA::new(manager, sa, params);

        // No SA installed in the kernel — the spawned UPDSA work
        // resolves to a no-op via `update_sa_pair_lifetime`'s unknown-UE
        // branch, so the test is hermetic.
        pending
            .activate(Some(3632))
            .expect("activate must accept hard_lifetime_secs kwarg");

        let guard = pending.inner.lock().unwrap();
        assert_eq!(guard.state, PendingState::Active);
        assert_eq!(
            guard.sa.hard_lifetime_secs,
            Some(3632),
            "cached SA should reflect the tightened hard-lifetime in-line"
        );
    }

    /// `activate()` (no kwarg) keeps the original behaviour: pure
    /// metadata transition, no kernel work, cached lifetime preserved.
    #[tokio::test]
    async fn activate_without_kwarg_preserves_cached_lifetime() {
        let manager = Arc::new(IpsecManager::new());
        let sa = SecurityAssociationPair {
            ue_addr: "10.0.0.2".parse().unwrap(),
            pcscf_addr: "10.0.0.10".parse().unwrap(),
            ue_port_c: 50002,
            ue_port_s: 50003,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 2000,
            spi_us: 2001,
            spi_pc: 20000,
            spi_ps: 20001,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "cafebabecafebabecafebabecafebabe".into(),
            hard_lifetime_secs: Some(600_000),
            protocol: SaProtocol::Udp,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: crate::ipsec::SaRole::PCscf,
        };
        let params = PySecurityServerParams {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "null".into(),
            spi_c: 20000,
            spi_s: 20001,
            port_c: 5064,
            port_s: 5066,
            protocol: "udp".into(),
        };
        let pending = PyPendingSA::new(manager, sa, params);

        pending.activate(None).unwrap();

        let guard = pending.inner.lock().unwrap();
        assert_eq!(guard.state, PendingState::Active);
        assert_eq!(
            guard.sa.hard_lifetime_secs,
            Some(600_000),
            "cached SA lifetime must be untouched when kwarg omitted"
        );
    }

    /// `activate(hard_lifetime_secs=…)` on an already-cleaned PendingSA
    /// raises before scheduling kernel work — the spec contract
    /// (idempotence on cleanup) is preserved across the kwarg path.
    #[tokio::test]
    async fn activate_after_cleanup_rejects_lifetime_kwarg() {
        let manager = Arc::new(IpsecManager::new());
        let sa = SecurityAssociationPair {
            ue_addr: "10.0.0.3".parse().unwrap(),
            pcscf_addr: "10.0.0.10".parse().unwrap(),
            ue_port_c: 50004,
            ue_port_s: 50005,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 3000,
            spi_us: 3001,
            spi_pc: 30000,
            spi_ps: 30001,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "11111111111111111111111111111111".into(),
            hard_lifetime_secs: None,
            protocol: SaProtocol::Udp,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: crate::ipsec::SaRole::PCscf,
        };
        let params = PySecurityServerParams {
            mechanism: "ipsec-3gpp".into(),
            alg: "hmac-sha-1-96".into(),
            ealg: "null".into(),
            spi_c: 30000,
            spi_s: 30001,
            port_c: 5064,
            port_s: 5066,
            protocol: "udp".into(),
        };
        let pending = PyPendingSA::new(manager, sa, params);
        // Mark cleaned without going through the async cleanup path.
        pending.inner.lock().unwrap().state = PendingState::Cleaned;

        assert!(pending.activate(Some(3632)).is_err());
    }

    #[test]
    fn sa_handle_reflects_security_association_protocol() {
        let sa = SecurityAssociationPair {
            ue_addr: "10.0.0.1".parse().unwrap(),
            pcscf_addr: "10.0.0.10".parse().unwrap(),
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
            integrity_key: "deadbeef".into(),
            hard_lifetime_secs: None,
            protocol: SaProtocol::Tcp,
            expires_at: std::time::Instant::now(),
            created_at: std::time::Instant::now(),
            role: crate::ipsec::SaRole::PCscf,
        };
        let handle = PySAHandle::from_sa(&sa);
        assert_eq!(handle.protocol, "tcp");
        assert!(handle.__repr__().contains("protocol=\"tcp\""));
    }

    fn ipsec_test_sa() -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr: "10.0.0.1".parse().unwrap(),
            pcscf_addr: "10.0.0.10".parse().unwrap(),
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
        assert_eq!(source, std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c));
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

        let (source, transport) = outbound_for_sa(
            &sa,
            sa.ue_port_s,
            crate::transport::Transport::Udp,
        )
        .unwrap();
        assert_eq!(source, std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c));
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

        let (source, transport) = outbound_for_sa(
            &sa,
            sa.ue_port_c,
            crate::transport::Transport::Udp,
        )
        .unwrap();
        assert_eq!(source, std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_s));
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
        let (source, transport) = outbound_for_sa(
            &sa,
            sa.ue_port_s,
            crate::transport::Transport::Udp,
        )
        .unwrap();
        assert_eq!(source, std::net::SocketAddr::new(sa.pcscf_addr, sa.pcscf_port_c));
        assert_eq!(transport, crate::transport::Transport::Udp);

        // Caller wants TCP — same Any SA preserves that too.
        let (_, transport_tcp) = outbound_for_sa(
            &sa,
            sa.ue_port_s,
            crate::transport::Transport::Tcp,
        )
        .unwrap();
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
        if IPSEC_MANAGER_REF.get().is_none() {
            assert!(outbound_local_addr_for(dst).is_none());
        }
    }
}
