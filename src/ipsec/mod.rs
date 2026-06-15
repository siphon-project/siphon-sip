//! IPsec SA management for P-CSCF (3GPP TS 33.203).
//!
//! Manages IPsec Security Associations (SAs) and Security Policies (SPs)
//! for IMS UE registration. Uses Linux xfrm via the `ip` command.

pub mod milenage;

#[cfg(target_os = "linux")]
pub mod netlink;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Grace added on top of an SA's hard lifetime before the sweeper reaps
/// its in-memory `associations` entry (RFC 3261 Timer F = 64·T1 = 64 s).
///
/// The kernel reaps the four XFRM states + four policies on the SA hard
/// lifetime directly; this grace only governs when `sweep_expired` drops
/// the manager's bookkeeping entry (and best-effort re-deletes the kernel
/// objects, which are usually already gone).  Matching the 64 s Timer F
/// window used elsewhere in the codebase keeps the in-memory view alive
/// just long enough for any in-flight re-REGISTER to refresh the SA
/// rather than race the sweep.
const SA_SWEEP_GRACE_SECS: u64 = 64;

/// Compute the wall-clock instant after which `sweep_expired` may reap an
/// SA pair's in-memory entry.  For an SA with a hard lifetime this is
/// `now + lifetime + grace`; an SA created with no hard lifetime
/// (`None` — intentionally permanent, dev/test) is never swept by this
/// path, so it gets a far-future instant.
fn compute_sa_expires_at(hard_lifetime_secs: Option<u64>) -> Instant {
    match hard_lifetime_secs {
        Some(secs) => {
            let total = secs.saturating_add(SA_SWEEP_GRACE_SECS);
            Instant::now()
                .checked_add(Duration::from_secs(total))
                .unwrap_or_else(far_future_instant)
        }
        // No kernel-enforced expiry → never swept by the expiry path.
        None => far_future_instant(),
    }
}

/// A far-future `Instant` used as the "never sweep" sentinel.  ~100 years
/// out — well past any realistic process lifetime, and saturating-add
/// guards against overflow on platforms with a near-`now` epoch.
fn far_future_instant() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(100 * 365 * 24 * 60 * 60))
        .unwrap_or_else(Instant::now)
}

/// Global `IpsecManager` handle, set once at server bootstrap so
/// background sweeps (the dispatcher's 30 s cleanup tick) can reach the
/// same manager the script API uses.  Mirrors
/// `subscribe_state::set_global_store` / `global_store`.
static GLOBAL_MANAGER: OnceLock<Arc<IpsecManager>> = OnceLock::new();

/// Register the process-wide `IpsecManager`.  Idempotent — the first
/// caller wins; later calls are ignored (returns the already-set handle
/// via the `Err`-side of `OnceLock::set` being swallowed).  Called once
/// where the manager is constructed during server startup.
pub fn set_global_manager(manager: Arc<IpsecManager>) {
    let _ = GLOBAL_MANAGER.set(manager);
}

/// Fetch the process-wide `IpsecManager`, if one has been registered.
/// Returns `None` when IPsec is not configured (no P-CSCF role).
pub fn global_manager() -> Option<Arc<IpsecManager>> {
    GLOBAL_MANAGER.get().cloned()
}

// ---------------------------------------------------------------------------
// Local helpers — HMAC-SHA-256, hex encoding, IPv4/IPv6 prefix length.
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 (RFC 2104) — single-shot helper.  Used by
/// `derive_integrity_key` for 3GPP TS 33.203 Annex H key derivation.  No
/// extra crate dependency: SHA-256 is already available via `sha2`.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    const OPAD: u8 = 0x5c;
    const IPAD: u8 = 0x36;

    // Reduce a long key by hashing it (RFC 2104 §2 - "the key" rule).
    let mut k_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        k_block[..digest.len()].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_input = [0u8; BLOCK_SIZE];
    let mut outer_input = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_input[index] = k_block[index] ^ IPAD;
        outer_input[index] = k_block[index] ^ OPAD;
    }

    let mut inner = Sha256::new();
    inner.update(inner_input);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_input);
    outer.update(inner_digest);
    outer.finalize().to_vec()
}

/// Lower-case hex encoding for IPsec key serialization.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{:02x}", byte));
    }
    output
}

/// Host-route prefix length for an IP — `/32` for IPv4, `/128` for IPv6.
fn host_prefix(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Format the integrity key in the hex form expected by `ip xfrm`,
/// applying the legacy zero-padding for HMAC-SHA-1 (16-byte IK → 20-byte
/// kernel key) when the supplied key is exactly 16 bytes (32 hex chars).
fn format_integrity_key(aalg: &IntegrityAlgorithm, integrity_key: &str) -> String {
    if *aalg == IntegrityAlgorithm::HmacSha1 && integrity_key.len() == 32 {
        format!("0x{}00000000", integrity_key)
    } else {
        format!("0x{}", integrity_key)
    }
}

/// Decode a hex string into raw bytes — used by the netlink backend
/// since the kernel ABI takes the key as raw bytes (the `ip` shell-out
/// path passes the hex string through verbatim).
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, IpsecError> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if hex.len() % 2 != 0 {
        return Err(IpsecError::InvalidKey(format!(
            "hex key has odd length: {}",
            hex.len()
        )));
    }
    let mut output = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for chunk in bytes.chunks(2) {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, IpsecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(IpsecError::InvalidKey(format!(
            "non-hex character {:?}",
            byte as char
        ))),
    }
}

/// Direction of an XFRM policy — backend-agnostic.  Maps to the
/// kernel's `XFRM_POLICY_IN`/`XFRM_POLICY_OUT` (and the `dir in`/`dir
/// out` strings of the `ip xfrm` shell-out path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyDir {
    In,
    Out,
}

/// Upper-layer protocol pinned into the XFRM selector for an SA pair —
/// determines which inner-protocol frames the SA applies to.  IMS IPsec
/// supports both ESP-over-UDP (the common deployment) and ESP-over-TCP
/// (3GPP TS 33.203 §7.2 — used by UEs that prefer TCP-first SIP).
///
/// `Any` is the spec-compliant default: 3GPP TS 33.203 §7.2 requires that
/// "the Security Associations established between the UE and the P-CSCF
/// shall be used to protect *all* SIP signalling exchanged between the UE
/// and the P-CSCF, including SIP traffic over UDP and TCP."  iOS handsets
/// rely on this — they REGISTER over TCP but emit MO MESSAGE over UDP,
/// and a TCP-pinned SA would silently drop the MESSAGE on
/// `XfrmInStateMismatch`.  When `Any` is selected, the XFRM selector
/// stamps `proto = 0` (kernel-side "match any inner protocol"), so the
/// same SPI pair covers both transports without doubling kernel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaProtocol {
    /// IPPROTO_UDP (17).
    Udp,
    /// IPPROTO_TCP (6).
    Tcp,
    /// "Any" — selector_proto=0 in XFRM, matches both TCP and UDP inner
    /// flows.  Default when the script doesn't pin a transport.
    Any,
}

impl SaProtocol {
    /// Numeric IP protocol value as carried in the selector byte.  `0`
    /// for `Any` — the kernel treats `xfrm_selector.proto == 0` as
    /// "match any inner protocol" (Linux `__xfrm{4,6}_selector_match`
    /// short-circuits the proto check when `sel->proto == 0`).
    pub fn as_u8(self) -> u8 {
        match self {
            SaProtocol::Udp => 17,
            SaProtocol::Tcp => 6,
            SaProtocol::Any => 0,
        }
    }

    /// Lower-case name as used in the ``ip xfrm`` UPSPEC grammar.
    /// iproute2 accepts the literal string ``any`` and maps it to
    /// selector proto 0.  Note: this is NOT the right value to put on
    /// the RFC 3329 ``protocol=`` parameter wire-side for `Any` —
    /// callers serialising Security-Server headers should treat `Any`
    /// the same as omitting the ``protocol=`` param (which per
    /// RFC 3329 §2.2 implies UDP).
    pub fn as_str(self) -> &'static str {
        match self {
            SaProtocol::Udp => "udp",
            SaProtocol::Tcp => "tcp",
            SaProtocol::Any => "any",
        }
    }
}

impl Default for SaProtocol {
    fn default() -> Self {
        SaProtocol::Any
    }
}

impl std::fmt::Display for SaProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Encryption algorithm
// ---------------------------------------------------------------------------

/// Encryption algorithm for IPsec SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// NULL encryption (integrity-only).
    Null,
    /// AES-CBC with 128-bit key.
    AesCbc128,
    /// DES-EDE3-CBC (3DES).
    DesEde3Cbc,
}

impl EncryptionAlgorithm {
    /// Return the `ip xfrm` algorithm name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            Self::Null => "ecb(cipher_null)",
            Self::AesCbc128 => "aes",
            Self::DesEde3Cbc => "des3_ede",
        }
    }

    /// Key length in bytes.
    pub fn key_length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::AesCbc128 => 16,
            Self::DesEde3Cbc => 24,
        }
    }
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(formatter, "NULL"),
            Self::AesCbc128 => write!(formatter, "AES-CBC-128"),
            Self::DesEde3Cbc => write!(formatter, "DES-EDE3-CBC"),
        }
    }
}

// ---------------------------------------------------------------------------
// Integrity algorithm
// ---------------------------------------------------------------------------

/// Integrity algorithm for IPsec SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    /// HMAC-MD5-96 (RFC 2403).
    HmacMd5,
    /// HMAC-SHA-1-96 (RFC 2404) — most common in IMS deployments today.
    HmacSha1,
    /// HMAC-SHA-256-128 (RFC 4868) — required for newer IMS profiles.
    HmacSha256,
}

impl IntegrityAlgorithm {
    /// Return the `ip xfrm` algorithm name.
    ///
    /// HMAC-SHA-256 is exposed as `hmac(sha256)` with a truncation of 128
    /// bits in the kernel; the algorithm name is the same regardless of
    /// truncation length.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            Self::HmacMd5 => "hmac(md5)",
            Self::HmacSha1 => "hmac(sha1)",
            Self::HmacSha256 => "hmac(sha256)",
        }
    }

    /// Key length in bytes.
    ///
    /// Note: SHA-1 uses a 160-bit (20-byte) key per RFC 4868; the IMS
    /// IK is 128-bit, so the legacy zero-padding approach in
    /// `create_sa_pair` extends it to 20 bytes.  SHA-256 uses a full
    /// 256-bit (32-byte) key derived per 3GPP TS 33.203 Annex H.
    pub fn key_length(&self) -> usize {
        match self {
            Self::HmacMd5 => 16,
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
        }
    }
}

impl std::fmt::Display for IntegrityAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacMd5 => write!(formatter, "HMAC-MD5-96"),
            Self::HmacSha1 => write!(formatter, "HMAC-SHA-1-96"),
            Self::HmacSha256 => write!(formatter, "HMAC-SHA-256-128"),
        }
    }
}

// ---------------------------------------------------------------------------
// Security Association pair
// ---------------------------------------------------------------------------

/// IPsec SAs for a UE registration (4 SAs per 3GPP TS 33.203 §7.1).
///
/// The four SAs cover two port pairs (client and server) in both directions:
/// 1. UE:port_uc → PCSCF:port_ps, SPI=spi_ps (UE sends requests to P-CSCF server)
/// 2. PCSCF:port_ps → UE:port_uc, SPI=spi_uc (P-CSCF replies from server port)
/// 3. PCSCF:port_pc → UE:port_us, SPI=spi_us (P-CSCF sends requests from client port)
/// 4. UE:port_us → PCSCF:port_pc, SPI=spi_pc (UE replies to P-CSCF client port)
#[derive(Debug, Clone)]
pub struct SecurityAssociationPair {
    /// UE IP address.
    pub ue_addr: IpAddr,
    /// P-CSCF IP address.
    pub pcscf_addr: IpAddr,
    /// UE client port (from Security-Client).
    pub ue_port_c: u16,
    /// UE server port (from Security-Client).
    pub ue_port_s: u16,
    /// P-CSCF protected client port.
    pub pcscf_port_c: u16,
    /// P-CSCF protected server port.
    pub pcscf_port_s: u16,
    /// UE client SPI (from Security-Client spi-c).
    pub spi_uc: u32,
    /// UE server SPI (from Security-Client spi-s).
    pub spi_us: u32,
    /// P-CSCF client SPI (allocated by P-CSCF, in Security-Server spi-c).
    pub spi_pc: u32,
    /// P-CSCF server SPI (allocated by P-CSCF, in Security-Server spi-s).
    pub spi_ps: u32,
    /// Encryption algorithm.
    pub ealg: EncryptionAlgorithm,
    /// Integrity algorithm.
    pub aalg: IntegrityAlgorithm,
    /// Encryption key (hex-encoded for ip xfrm).
    pub encryption_key: String,
    /// Integrity key (hex-encoded for ip xfrm).
    pub integrity_key: String,
    /// Optional hard lifetime in seconds — kernel will expire the SA
    /// after this many seconds.  `None` means no kernel-enforced expiry
    /// (caller manages lifetime via `delete_sa_pair`).  Used to tie the
    /// IPsec SA lifetime to the SIP registration expiry per 3GPP
    /// TS 33.203 §7.4.
    pub hard_lifetime_secs: Option<u64>,
    /// Upper-layer protocol pinned into the XFRM selector.  `Any`
    /// (selector_proto=0, the default) covers both ESP-over-UDP and
    /// ESP-over-TCP under the same SPI pair — required for spec
    /// compliance with 3GPP TS 33.203 §7.2 ("the SAs shall be used to
    /// protect *all* SIP signalling … including over UDP and TCP") and
    /// for iOS UEs that mix transports (REGISTER over TCP, MO MESSAGE
    /// over UDP).  Pin to `Udp` or `Tcp` only for single-transport
    /// deployments or tests; a mismatched pin silently drops every
    /// frame the UE sends on the other transport.
    pub protocol: SaProtocol,
    /// Wall-clock instant after which the background sweeper
    /// (`IpsecManager::sweep_expired`) may reap this pair's in-memory
    /// entry and best-effort re-delete its kernel objects.
    ///
    /// Computed in `create_sa_pair` from `hard_lifetime_secs` plus
    /// `SA_SWEEP_GRACE_SECS` (RFC 3261 Timer F).  An SA created with no
    /// hard lifetime gets a far-future instant and is never swept by the
    /// expiry path (intentionally permanent — dev/test).  An ACTIVE
    /// registration re-REGISTERs before this deadline, which replaces the
    /// pair with a fresh `expires_at`, so only truly-abandoned UEs are
    /// reaped.
    pub expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Security-Client header (3GPP TS 33.203)
// ---------------------------------------------------------------------------

/// Parsed Security-Client header (3GPP TS 33.203).
///
/// Example header value:
/// ```text
/// ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062
/// ```
#[derive(Debug, Clone)]
pub struct SecurityClient {
    /// Security mechanism, e.g. `"ipsec-3gpp"`.
    pub mechanism: String,
    /// Integrity algorithm, e.g. `"hmac-md5-96"` or `"hmac-sha-1-96"`.
    pub algorithm: String,
    /// Client SPI proposed by the UE.
    pub spi_c: u32,
    /// Server SPI proposed by the UE.
    pub spi_s: u32,
    /// Client port proposed by the UE.
    pub port_c: u16,
    /// Server port proposed by the UE.
    pub port_s: u16,
    /// Optional encryption algorithm, e.g. `"aes-cbc"`.
    pub ealg: Option<String>,
}

/// Parse a Security-Client header value.
///
/// Expects a semicolon-separated list of parameters following the mechanism name.
/// Returns `None` if the header is malformed or missing required parameters.
///
/// # Example
///
/// ```
/// use siphon::ipsec::parse_security_client;
///
/// let header = "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062";
/// let parsed = parse_security_client(header).unwrap();
/// assert_eq!(parsed.mechanism, "ipsec-3gpp");
/// assert_eq!(parsed.spi_c, 11111);
/// ```
pub fn parse_security_client(header: &str) -> Option<SecurityClient> {
    let parts: Vec<&str> = header.split(';').map(|part| part.trim()).collect();
    if parts.is_empty() {
        return None;
    }

    let mechanism = parts[0].to_string();
    let mut algorithm = None;
    let mut spi_c = None;
    let mut spi_s = None;
    let mut port_c = None;
    let mut port_s = None;
    let mut ealg = None;

    for part in &parts[1..] {
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "alg" => algorithm = Some(value.to_string()),
                "spi-c" => spi_c = value.parse().ok(),
                "spi-s" => spi_s = value.parse().ok(),
                "port-c" => port_c = value.parse().ok(),
                "port-s" => port_s = value.parse().ok(),
                "ealg" => ealg = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some(SecurityClient {
        mechanism,
        algorithm: algorithm?,
        spi_c: spi_c?,
        spi_s: spi_s?,
        port_c: port_c?,
        port_s: port_s?,
        ealg,
    })
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from IPsec SA management.
#[derive(Debug)]
pub enum IpsecError {
    /// `ip xfrm` command failed.
    Command(String),
    /// Invalid key material.
    InvalidKey(String),
}

impl std::fmt::Display for IpsecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(message) => write!(formatter, "IPsec command error: {}", message),
            Self::InvalidKey(message) => write!(formatter, "IPsec invalid key: {}", message),
        }
    }
}

impl std::error::Error for IpsecError {}

// ---------------------------------------------------------------------------
// IPsec Manager
// ---------------------------------------------------------------------------

/// XFRM backend — either direct netlink (fast, requires CAP_NET_ADMIN
/// on the netlink socket) or `/sbin/ip xfrm` shell-out (slower but
/// works in any environment where ``ip`` itself works).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmBackend {
    Netlink,
    IpCommand,
}

impl Default for XfrmBackend {
    fn default() -> Self {
        // Netlink is the production default; switch with `ipsec.backend: ip`.
        Self::Netlink
    }
}

/// Manages active IPsec SAs for UE registrations.
///
/// Each UE registration that negotiates IPsec (via
/// Security-Client/Security-Server headers) gets a pair of SAs: one
/// inbound (UE → P-CSCF) and one outbound (P-CSCF → UE).  The manager
/// tracks these pairs and creates/deletes the corresponding Linux XFRM
/// state and policies — by default via direct netlink (Phase 3), with
/// `ip xfrm` shell-out as the fallback backend.
pub struct IpsecManager {
    /// contact_key (e.g. "ue_ip:ue_port") -> SA pair.
    associations: DashMap<String, SecurityAssociationPair>,
    /// SPI counter for generating unique SPIs.
    next_spi: AtomicU32,
    /// Upper bound on `next_spi` — when an allocation would exceed
    /// `spi_range_end`, the counter wraps back to `spi_range_start`.
    /// Both default to a wide range starting at 10000 when no
    /// partitioning is configured (matches Phase 1 behaviour).
    spi_range_start: u32,
    spi_range_end: u32,
    /// XFRM backend.  Picked at startup from `IpsecConfig.backend`.
    backend: XfrmBackend,
}

impl Default for IpsecManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpsecManager {
    /// Create a new IPsec manager with no active SAs and the default
    /// backend (netlink) and SPI range (`10000..10000+8192`).
    pub fn new() -> Self {
        Self::with_partition(XfrmBackend::default(), 10000, 8192)
    }

    /// Create with explicit backend + SPI partition.  Used by the
    /// server bootstrap to honour `ipsec.backend` /
    /// `ipsec.spi_range_start` / `ipsec.spi_range_count`.
    ///
    /// `spi_range_count` is clamped to at least 2 (we always need to
    /// allocate pairs).  Wraparound is handled inside `allocate_spi_pair`.
    pub fn with_partition(backend: XfrmBackend, spi_range_start: u32, spi_range_count: u32) -> Self {
        let count = spi_range_count.max(2);
        let end = spi_range_start.saturating_add(count);
        Self {
            associations: DashMap::new(),
            next_spi: AtomicU32::new(spi_range_start),
            spi_range_start,
            spi_range_end: end,
            backend,
        }
    }

    /// Currently-active backend.
    pub fn backend(&self) -> XfrmBackend {
        self.backend
    }

    /// Generate a unique SPI pair (inbound, outbound) within the
    /// configured partition.  Wraps when the counter exceeds
    /// `spi_range_end` — guaranteed unique within the lifetime of the
    /// process so long as `spi_range_count` is larger than any
    /// reasonable concurrent SA count.
    pub fn allocate_spi_pair(&self) -> (u32, u32) {
        let mut spi1 = self.next_spi.fetch_add(2, Ordering::Relaxed);
        // Wraparound: if we ran past the end, reset and grab another
        // pair.  Worst case: two threads collide on the reset, but the
        // counter still moves forward and uniqueness is maintained
        // across this process.
        if spi1.saturating_add(1) >= self.spi_range_end {
            self.next_spi.store(self.spi_range_start, Ordering::Relaxed);
            spi1 = self.next_spi.fetch_add(2, Ordering::Relaxed);
        }
        (spi1, spi1 + 1)
    }

    /// Contact key for looking up SAs.
    fn contact_key(ue_addr: &IpAddr, ue_port_c: u16) -> String {
        format!("{}:{}", ue_addr, ue_port_c)
    }

    /// Create IPsec SAs and SPs for a UE registration.
    ///
    /// Per 3GPP TS 33.203 §7.1, creates 4 SAs and 4 policies:
    /// 1. UE:port_uc → PCSCF:port_ps, SPI=spi_ps (inbound requests)
    /// 2. PCSCF:port_ps → UE:port_uc, SPI=spi_uc (outbound replies)
    /// 3. PCSCF:port_pc → UE:port_us, SPI=spi_us (outbound requests)
    /// 4. UE:port_us → PCSCF:port_pc, SPI=spi_pc (inbound replies)
    pub async fn create_sa_pair(
        &self,
        mut sa: SecurityAssociationPair,
    ) -> Result<(), IpsecError> {
        let key = Self::contact_key(&sa.ue_addr, sa.ue_port_c);
        let proto = sa.protocol;

        // Stamp the authoritative sweep deadline from the SA's own hard
        // lifetime (+ grace).  Computed here, ignoring whatever the caller
        // pre-set, so the in-memory entry always agrees with the kernel
        // hard-lifetime that the four states/policies were installed with.
        sa.expires_at = compute_sa_expires_at(sa.hard_lifetime_secs);

        // SA1: UE:port_uc → PCSCF:port_ps, SPI=spi_ps (inbound to P-CSCF server)
        self.add_sa(
            &sa.ue_addr, sa.ue_port_c,
            &sa.pcscf_addr, sa.pcscf_port_s,
            sa.spi_ps,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, sa.hard_lifetime_secs,
        ).await?;

        // SA2: PCSCF:port_ps → UE:port_uc, SPI=spi_uc (outbound from P-CSCF server)
        self.add_sa(
            &sa.pcscf_addr, sa.pcscf_port_s,
            &sa.ue_addr, sa.ue_port_c,
            sa.spi_uc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, sa.hard_lifetime_secs,
        ).await?;

        // SA3: PCSCF:port_pc → UE:port_us, SPI=spi_us (outbound from P-CSCF client)
        self.add_sa(
            &sa.pcscf_addr, sa.pcscf_port_c,
            &sa.ue_addr, sa.ue_port_s,
            sa.spi_us,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, sa.hard_lifetime_secs,
        ).await?;

        // SA4: UE:port_us → PCSCF:port_pc, SPI=spi_pc (inbound to P-CSCF client)
        self.add_sa(
            &sa.ue_addr, sa.ue_port_s,
            &sa.pcscf_addr, sa.pcscf_port_c,
            sa.spi_pc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, sa.hard_lifetime_secs,
        ).await?;

        // Policies get the SAME hard lifetime as the states (above).
        // Without this, XFRM policies have no kernel-enforced expiry and
        // an abandoned UE that never de-registers/refreshes leaks all four
        // forever; the states reap on hard-lifetime but the policies don't.
        // Threading the lifetime through makes the policies self-reap on
        // the same deadline (3GPP TS 33.203 §7.4) — and restart-orphaned
        // policies from a prior process self-reap too, so no startup flush
        // is needed.  `None` preserves the old permanent-policy behaviour.
        let policy_lifetime = sa.hard_lifetime_secs;

        // Policy 1 (in): UE:port_uc → PCSCF:port_ps
        self.add_policy(
            &sa.ue_addr, sa.ue_port_c,
            &sa.pcscf_addr, sa.pcscf_port_s,
            PolicyDir::In, sa.spi_ps, proto, policy_lifetime,
        ).await?;

        // Policy 2 (out): PCSCF:port_ps → UE:port_uc
        self.add_policy(
            &sa.pcscf_addr, sa.pcscf_port_s,
            &sa.ue_addr, sa.ue_port_c,
            PolicyDir::Out, sa.spi_uc, proto, policy_lifetime,
        ).await?;

        // Policy 3 (out): PCSCF:port_pc → UE:port_us
        self.add_policy(
            &sa.pcscf_addr, sa.pcscf_port_c,
            &sa.ue_addr, sa.ue_port_s,
            PolicyDir::Out, sa.spi_us, proto, policy_lifetime,
        ).await?;

        // Policy 4 (in): UE:port_us → PCSCF:port_pc
        self.add_policy(
            &sa.ue_addr, sa.ue_port_s,
            &sa.pcscf_addr, sa.pcscf_port_c,
            PolicyDir::In, sa.spi_pc, proto, policy_lifetime,
        ).await?;

        info!(
            ue = %sa.ue_addr,
            ue_port_c = sa.ue_port_c,
            spi_uc = sa.spi_uc,
            spi_us = sa.spi_us,
            spi_pc = sa.spi_pc,
            spi_ps = sa.spi_ps,
            protocol = %proto,
            "IPsec: SA pair created"
        );

        self.associations.insert(key, sa);
        Ok(())
    }

    /// Delete IPsec SAs and SPs for a UE.
    pub async fn delete_sa_pair(
        &self,
        ue_addr: &IpAddr,
        ue_port_c: u16,
    ) -> Result<(), IpsecError> {
        let key = Self::contact_key(ue_addr, ue_port_c);
        if let Some((_, sa)) = self.associations.remove(&key) {
            let proto = sa.protocol;
            // Delete all 4 SAs.  Pairs mirror create_sa_pair's order so
            // src/dst align with each SA's flow direction.
            self.del_sa(&sa.ue_addr, &sa.pcscf_addr, sa.spi_ps).await?;
            self.del_sa(&sa.pcscf_addr, &sa.ue_addr, sa.spi_uc).await?;
            self.del_sa(&sa.pcscf_addr, &sa.ue_addr, sa.spi_us).await?;
            self.del_sa(&sa.ue_addr, &sa.pcscf_addr, sa.spi_pc).await?;

            // Delete policies (best-effort — ignore errors on cleanup).
            // The selector proto must match what was used at install time
            // — kernel keys policies on the full selector including the
            // upper-layer protocol number.
            self.del_policy(
                &sa.ue_addr, sa.ue_port_c,
                &sa.pcscf_addr, sa.pcscf_port_s,
                PolicyDir::In, proto,
            ).await.ok();
            self.del_policy(
                &sa.pcscf_addr, sa.pcscf_port_c,
                &sa.ue_addr, sa.ue_port_s,
                PolicyDir::Out, proto,
            ).await.ok();
            self.del_policy(
                &sa.ue_addr, sa.ue_port_s,
                &sa.pcscf_addr, sa.pcscf_port_c,
                PolicyDir::In, proto,
            ).await.ok();
            self.del_policy(
                &sa.pcscf_addr, sa.pcscf_port_s,
                &sa.ue_addr, sa.ue_port_c,
                PolicyDir::Out, proto,
            ).await.ok();

            info!(ue = %ue_addr, ue_port_c, "IPsec: SA pair deleted");
        }
        Ok(())
    }

    /// Tear down every SA pair belonging to `ue_addr` other than the one
    /// keyed by `keep_port_c`.
    ///
    /// A UE's `port_uc` is a fresh random port on every REGISTER (3GPP
    /// TS 24.229 §5.1.1.2 — the IMS UE generates new protected ports for
    /// each registration).  The manager's `contact_key` includes
    /// `ue_port_c`, so the previous binding's entry sits in
    /// `associations` under the old port until something tears it down.
    /// The kernel reaps the four SAs on hard-lifetime expiry, but XFRM
    /// policies have no lifetime — they accumulate until a future
    /// REGISTER picks a `port_uc` that collides with a leaked selector,
    /// at which point policy install hits `EEXIST` and the new
    /// registration fails to protect.
    ///
    /// Called from `PyPendingSA::activate` once the 200 OK to the auth
    /// REGISTER has landed: at that point the new binding is granted by
    /// the registrar of record, the UE has proven possession of the
    /// fresh keys, and any earlier binding for the same UE address is
    /// definitionally stale.  Per-victim failures are logged but never
    /// propagated — the in-memory entry is removed (via
    /// `delete_sa_pair`'s `remove`-before-kernel-call ordering) even
    /// when individual kernel deletes fail, so the manager's view stays
    /// authoritative.
    ///
    /// Walks `associations` once (O(N) in active SA count); the inner
    /// `delete_sa_pair` call deletes four SAs + four policies per
    /// victim.
    pub async fn cleanup_other_pairs_for_ue(
        &self,
        ue_addr: &IpAddr,
        keep_port_c: u16,
    ) {
        let victim_ports: Vec<u16> = self
            .associations
            .iter()
            .filter_map(|entry| {
                let sa = entry.value();
                if sa.ue_addr == *ue_addr && sa.ue_port_c != keep_port_c {
                    Some(sa.ue_port_c)
                } else {
                    None
                }
            })
            .collect();

        if victim_ports.is_empty() {
            return;
        }

        debug!(
            ue = %ue_addr,
            keep_port_c,
            victim_count = victim_ports.len(),
            "IPsec: tearing down stale SA pairs for re-REGISTER"
        );

        for victim_port_c in victim_ports {
            if let Err(error) = self.delete_sa_pair(ue_addr, victim_port_c).await {
                // delete_sa_pair removes the in-memory entry before the
                // kernel call, so the map is already clean here — just
                // log the kernel-side failure.  Leaving stale policies
                // in the kernel for this victim is at worst a no-op:
                // the new pair's selectors don't collide (different
                // port_c by construction), and the victim's SAs will
                // expire on hard-lifetime even if policies linger.
                tracing::warn!(
                    ue = %ue_addr,
                    victim_port_c,
                    %error,
                    "IPsec: stale SA pair cleanup — kernel delete failed (in-memory entry already removed)"
                );
            } else {
                info!(
                    ue = %ue_addr,
                    victim_port_c,
                    keep_port_c,
                    "IPsec: stale SA pair torn down on re-REGISTER"
                );
            }
        }
    }

    /// Re-pin the kernel hard-lifetime on all four SAs of an existing
    /// pair, without rekeying or disturbing selectors / SPIs.
    ///
    /// Used by ``ipsec.PendingSA.activate(hard_lifetime_secs=…)`` to
    /// tighten the SA expiry from whatever was installed at allocation
    /// time (usually the UE's `Expires:` ask, commonly 600000 s for
    /// VoLTE handsets) to the value the registrar of record actually
    /// granted (3GPP TS 33.203 §7.4 ties IPsec SA lifetime to SIP
    /// registration lifetime).
    ///
    /// The kernel keys `XFRM_MSG_UPDSA` by `(daddr, spi, proto=ESP)` and
    /// preserves `xfrm_state.curlft.add_time`, so the resulting deadline
    /// is `add_time + hard_lifetime_secs` — i.e. the SA expires
    /// `hard_lifetime_secs` after its **original** install, not from
    /// "now".  For a typical IMS REGISTER → 401 → REGISTER → 200 OK
    /// round-trip the install / repin gap is sub-second, so this is
    /// indistinguishable from "expires after the granted Expires".
    ///
    /// Returns `Ok(())` even when the UE has no active SA pair (no-op).
    /// Errors from any of the four UPDSA messages are surfaced verbatim.
    pub async fn update_sa_pair_lifetime(
        &self,
        ue_addr: &IpAddr,
        ue_port_c: u16,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        let key = Self::contact_key(ue_addr, ue_port_c);
        let mut sa = match self.associations.get(&key) {
            Some(entry) => entry.value().clone(),
            None => {
                debug!(ue = %ue_addr, ue_port_c, "IPsec: update_sa_pair_lifetime — no active SA, ignoring");
                return Ok(());
            }
        };
        let proto = sa.protocol;

        // SA1: UE:port_uc → PCSCF:port_ps, SPI=spi_ps
        self.update_sa_only(
            &sa.ue_addr, sa.ue_port_c,
            &sa.pcscf_addr, sa.pcscf_port_s,
            sa.spi_ps,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, hard_lifetime_secs,
        ).await?;
        // SA2: PCSCF:port_ps → UE:port_uc, SPI=spi_uc
        self.update_sa_only(
            &sa.pcscf_addr, sa.pcscf_port_s,
            &sa.ue_addr, sa.ue_port_c,
            sa.spi_uc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, hard_lifetime_secs,
        ).await?;
        // SA3: PCSCF:port_pc → UE:port_us, SPI=spi_us
        self.update_sa_only(
            &sa.pcscf_addr, sa.pcscf_port_c,
            &sa.ue_addr, sa.ue_port_s,
            sa.spi_us,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, hard_lifetime_secs,
        ).await?;
        // SA4: UE:port_us → PCSCF:port_pc, SPI=spi_pc
        self.update_sa_only(
            &sa.ue_addr, sa.ue_port_s,
            &sa.pcscf_addr, sa.pcscf_port_c,
            sa.spi_pc,
            &sa.ealg, &sa.aalg, &sa.encryption_key, &sa.integrity_key,
            proto, hard_lifetime_secs,
        ).await?;

        info!(
            ue = %sa.ue_addr,
            ue_port_c = sa.ue_port_c,
            hard_lifetime_secs = ?hard_lifetime_secs,
            "IPsec: SA pair hard-lifetime re-pinned"
        );

        // Mirror the new value into the cached SecurityAssociationPair so
        // any subsequent inspection (or downstream re-pin) sees the
        // tightened limit.  Re-insert under the same key.  Also refresh
        // the sweep deadline so the in-memory entry reaps in step with the
        // re-pinned hard lifetime — without this an SA installed with the
        // UE's 600000 s ask but re-pinned down to the granted Expires
        // would keep its old far-out `expires_at` and never sweep on time.
        // The kernel preserves `add_time` across UPDSA so its true expiry
        // is `original_install + new_lifetime`; the install→repin gap is
        // sub-second, so computing from `now` here is conservatively close
        // (slightly later) and the kernel still reaps states/policies on
        // the exact deadline regardless.
        sa.hard_lifetime_secs = hard_lifetime_secs;
        sa.expires_at = compute_sa_expires_at(hard_lifetime_secs);
        self.associations.insert(key, sa);
        Ok(())
    }

    /// Number of active SA pairs.
    pub fn active_count(&self) -> usize {
        self.associations.len()
    }

    /// Collect the contact keys of every SA pair whose sweep deadline
    /// (`expires_at`) has already passed.
    ///
    /// Split out from [`sweep_expired`] so the selection logic is unit-
    /// testable without `CAP_NET_ADMIN` / a live kernel netlink socket.
    /// Snapshots into a `Vec` so the caller can `remove` while iterating
    /// without holding a DashMap shard guard across the delete (avoids the
    /// iterator/remove deadlock).
    fn expired_keys(&self, now: Instant) -> Vec<String> {
        self.associations
            .iter()
            .filter_map(|entry| {
                if entry.value().expires_at <= now {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Sweep abandoned SA pairs whose own hard lifetime (+ grace) has
    /// elapsed, tearing down their kernel states/policies and dropping the
    /// in-memory entry.  Returns the number of pairs reaped.
    ///
    /// This is the background-cleanup counterpart to the re-REGISTER /
    /// de-REGISTER paths (`cleanup_other_pairs_for_ue` / `delete_sa_pair`),
    /// which only fire when the UE comes back.  A UE that registers once
    /// and then vanishes (crash, radio loss, never refreshes) would
    /// otherwise leak its four states + four policies + one map entry
    /// forever.  Ageing on each pair's `expires_at` — its own SA lifetime
    /// plus `SA_SWEEP_GRACE_SECS` — means an ACTIVE registration, which
    /// re-REGISTERs and reinstalls a fresh SA (new `expires_at`) before the
    /// deadline, is never disturbed; only truly-abandoned pairs pass their
    /// `expires_at`.
    ///
    /// Collect-then-delete: snapshots the expired keys first (`expired_keys`)
    /// then deletes each, so we never `remove` while holding a DashMap
    /// iterator guard.  Per-victim kernel-delete failures are logged but
    /// never propagated — `delete_sa_pair` removes the in-memory entry
    /// before any kernel call, so the manager's view stays authoritative
    /// even when the kernel objects were already reaped on hard-lifetime
    /// (the common case, since the kernel deadline precedes the grace).
    pub async fn sweep_expired(&self) -> usize {
        let victims = self.expired_keys(Instant::now());
        if victims.is_empty() {
            return 0;
        }

        let mut reaped = 0usize;
        for key in victims {
            // Re-read the entry to recover the UE address/port for
            // delete_sa_pair; if it vanished between snapshot and now
            // (concurrent re-REGISTER teardown), skip it.
            let (ue_addr, ue_port_c) = match self.associations.get(&key) {
                Some(entry) => {
                    let sa = entry.value();
                    (sa.ue_addr, sa.ue_port_c)
                }
                None => continue,
            };
            if let Err(error) = self.delete_sa_pair(&ue_addr, ue_port_c).await {
                tracing::warn!(
                    ue = %ue_addr,
                    ue_port_c,
                    %error,
                    "IPsec: abandoned SA sweep — kernel delete failed (in-memory entry already removed)"
                );
            }
            reaped += 1;
        }

        if reaped > 0 {
            info!(reaped, "IPsec: swept abandoned SA pairs past their hard lifetime");
        }
        reaped
    }

    /// Check if a UE has an active SA pair.
    pub fn has_sa(&self, ue_addr: &IpAddr, ue_port_c: u16) -> bool {
        self.associations
            .contains_key(&Self::contact_key(ue_addr, ue_port_c))
    }

    /// Get the SA pair for a UE (for inspection/logging).
    pub fn get_sa(
        &self,
        ue_addr: &IpAddr,
        ue_port_c: u16,
    ) -> Option<SecurityAssociationPair> {
        self.associations
            .get(&Self::contact_key(ue_addr, ue_port_c))
            .map(|entry| entry.value().clone())
    }

    /// Find an SA pair where the given UE address sends from either of
    /// the two registered ports (client or server).  Used to map an
    /// inbound request's `(source_addr, source_port)` to the SA that
    /// just decrypted it.  Walks the DashMap — O(N) in number of
    /// currently active SAs.
    pub fn find_sa_by_ue(
        &self,
        ue_addr: &IpAddr,
        ue_port: u16,
    ) -> Option<SecurityAssociationPair> {
        for entry in self.associations.iter() {
            let sa = entry.value();
            if sa.ue_addr == *ue_addr && (sa.ue_port_c == ue_port || sa.ue_port_s == ue_port) {
                return Some(sa.clone());
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Backend dispatch — routes to either netlink or `ip xfrm` shell-out.
    // -----------------------------------------------------------------------

    /// Add an SA via the active backend.
    #[allow(clippy::too_many_arguments)]
    async fn add_sa(
        &self,
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        spi: u32,
        ealg: &EncryptionAlgorithm,
        aalg: &IntegrityAlgorithm,
        encryption_key: &str,
        integrity_key: &str,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            XfrmBackend::Netlink => {
                let auth_key_bytes = decode_hex(integrity_key)?;
                let enc_key_bytes = if *ealg == EncryptionAlgorithm::Null {
                    Vec::new()
                } else {
                    decode_hex(encryption_key)?
                };
                netlink::add_sa(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    spi,
                    *ealg,
                    *aalg,
                    &enc_key_bytes,
                    &auth_key_bytes,
                    protocol.as_u8(),
                    hard_lifetime_secs,
                )
                .await
            }
            #[cfg(not(target_os = "linux"))]
            XfrmBackend::Netlink => Err(IpsecError::Command(
                "XFRM netlink backend is Linux-only".to_string(),
            )),
            XfrmBackend::IpCommand => {
                Self::xfrm_sa_add(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    spi,
                    ealg,
                    aalg,
                    encryption_key,
                    integrity_key,
                    protocol,
                    hard_lifetime_secs,
                )
                .await
            }
        }
    }

    /// Update an existing SA's mutable fields (lifetime today; replay
    /// window in the future).  Backend-routed sibling of [`add_sa`].
    /// IPCommand backend reuses the `xfrm_sa_add` path with `update`
    /// instead of `add` — iproute2 maps both to the same payload, only
    /// the netlink message type differs.
    #[allow(clippy::too_many_arguments)]
    async fn update_sa_only(
        &self,
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        spi: u32,
        ealg: &EncryptionAlgorithm,
        aalg: &IntegrityAlgorithm,
        encryption_key: &str,
        integrity_key: &str,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            XfrmBackend::Netlink => {
                let auth_key_bytes = decode_hex(integrity_key)?;
                let enc_key_bytes = if *ealg == EncryptionAlgorithm::Null {
                    Vec::new()
                } else {
                    decode_hex(encryption_key)?
                };
                netlink::update_sa(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    spi,
                    *ealg,
                    *aalg,
                    &enc_key_bytes,
                    &auth_key_bytes,
                    protocol.as_u8(),
                    hard_lifetime_secs,
                )
                .await
            }
            #[cfg(not(target_os = "linux"))]
            XfrmBackend::Netlink => Err(IpsecError::Command(
                "XFRM netlink backend is Linux-only".to_string(),
            )),
            XfrmBackend::IpCommand => {
                Self::xfrm_sa_update(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    spi,
                    ealg,
                    aalg,
                    encryption_key,
                    integrity_key,
                    protocol,
                    hard_lifetime_secs,
                )
                .await
            }
        }
    }

    async fn del_sa(
        &self,
        source: &IpAddr,
        destination: &IpAddr,
        spi: u32,
    ) -> Result<(), IpsecError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            XfrmBackend::Netlink => {
                let _ = source;
                netlink::del_sa(destination, spi).await
            }
            #[cfg(not(target_os = "linux"))]
            XfrmBackend::Netlink => Err(IpsecError::Command(
                "XFRM netlink backend is Linux-only".to_string(),
            )),
            XfrmBackend::IpCommand => Self::xfrm_sa_del(source, destination, spi).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_policy(
        &self,
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: PolicyDir,
        spi: u32,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            XfrmBackend::Netlink => {
                let netlink_dir = match direction {
                    PolicyDir::In => netlink::PolicyDirection::In,
                    PolicyDir::Out => netlink::PolicyDirection::Out,
                };
                netlink::add_policy(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    netlink_dir,
                    spi,
                    protocol.as_u8(),
                    hard_lifetime_secs,
                )
                .await
            }
            #[cfg(not(target_os = "linux"))]
            XfrmBackend::Netlink => Err(IpsecError::Command(
                "XFRM netlink backend is Linux-only".to_string(),
            )),
            XfrmBackend::IpCommand => {
                let dir_str = match direction {
                    PolicyDir::In => "in",
                    PolicyDir::Out => "out",
                };
                Self::xfrm_policy_add(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    dir_str,
                    spi,
                    protocol,
                    hard_lifetime_secs,
                )
                .await
            }
        }
    }

    async fn del_policy(
        &self,
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: PolicyDir,
        protocol: SaProtocol,
    ) -> Result<(), IpsecError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            XfrmBackend::Netlink => {
                let netlink_dir = match direction {
                    PolicyDir::In => netlink::PolicyDirection::In,
                    PolicyDir::Out => netlink::PolicyDirection::Out,
                };
                netlink::del_policy(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    netlink_dir,
                    protocol.as_u8(),
                )
                .await
            }
            #[cfg(not(target_os = "linux"))]
            XfrmBackend::Netlink => Err(IpsecError::Command(
                "XFRM netlink backend is Linux-only".to_string(),
            )),
            XfrmBackend::IpCommand => {
                let dir_str = match direction {
                    PolicyDir::In => "in",
                    PolicyDir::Out => "out",
                };
                Self::xfrm_policy_del(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    dir_str,
                    protocol,
                )
                .await
            }
        }
    }

    // -----------------------------------------------------------------------
    // Legacy `ip xfrm` shell-out helpers — kept for the IpCommand backend.
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn xfrm_sa_add(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        spi: u32,
        ealg: &EncryptionAlgorithm,
        aalg: &IntegrityAlgorithm,
        encryption_key: &str,
        integrity_key: &str,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);
        let sel_src = format!("{}/{}", source, host_prefix(source));
        let sel_dst = format!("{}/{}", destination, host_prefix(destination));
        let sel_sport = source_port.to_string();
        let sel_dport = destination_port.to_string();
        let proto_str = protocol.as_str();
        let lifetime_secs_str;

        // iproute2 UPSPEC grammar (man ip-xfrm) requires `proto X` to
        // precede `sport`/`dport` — sport/dport are sub-arguments of the
        // protocol token.  Putting them out of order makes iproute2 fail
        // with `argument "udp" is wrong: PROTO value is invalid`.
        let mut args = vec![
            "xfrm", "state", "add",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
            "mode", "transport",
            "sel",
            "src", &sel_src,
            "dst", &sel_dst,
            "proto", proto_str,
            "sport", &sel_sport,
            "dport", &sel_dport,
        ];

        let enc_key_hex = format!("0x{}", encryption_key);
        let int_key_hex = format_integrity_key(aalg, integrity_key);

        // ESP always requires an enc algorithm — use ecb(cipher_null) with empty key for null
        args.push("enc");
        args.push(ealg.xfrm_name());
        if *ealg != EncryptionAlgorithm::Null {
            args.push(&enc_key_hex);
        } else {
            args.push("");
        }
        args.push("auth");
        args.push(aalg.xfrm_name());
        args.push(&int_key_hex);

        // Optional hard lifetime — `limit time-hard <secs>` instructs the
        // kernel to expire the SA after this many wall-clock seconds.
        if let Some(secs) = hard_lifetime_secs {
            lifetime_secs_str = secs.to_string();
            args.push("limit");
            args.push("time-hard");
            args.push(&lifetime_secs_str);
        }

        Self::run_ip_command(&args).await
    }

    /// `ip xfrm state update` — same payload shape as `add`, different
    /// kernel verb.  iproute2 sends `XFRM_MSG_UPDSA` instead of NEWSA;
    /// the kernel preserves `add_time`, so a tightened
    /// `limit time-hard` produces deadline = original install + new
    /// value, not now + new value.
    #[allow(clippy::too_many_arguments)]
    async fn xfrm_sa_update(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        spi: u32,
        ealg: &EncryptionAlgorithm,
        aalg: &IntegrityAlgorithm,
        encryption_key: &str,
        integrity_key: &str,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);
        let sel_src = format!("{}/{}", source, host_prefix(source));
        let sel_dst = format!("{}/{}", destination, host_prefix(destination));
        let sel_sport = source_port.to_string();
        let sel_dport = destination_port.to_string();
        let proto_str = protocol.as_str();
        let lifetime_secs_str;

        let mut args = vec![
            "xfrm", "state", "update",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
            "mode", "transport",
            "sel",
            "src", &sel_src,
            "dst", &sel_dst,
            "proto", proto_str,
            "sport", &sel_sport,
            "dport", &sel_dport,
        ];

        let enc_key_hex = format!("0x{}", encryption_key);
        let int_key_hex = format_integrity_key(aalg, integrity_key);

        args.push("enc");
        args.push(ealg.xfrm_name());
        if *ealg != EncryptionAlgorithm::Null {
            args.push(&enc_key_hex);
        } else {
            args.push("");
        }
        args.push("auth");
        args.push(aalg.xfrm_name());
        args.push(&int_key_hex);

        if let Some(secs) = hard_lifetime_secs {
            lifetime_secs_str = secs.to_string();
            args.push("limit");
            args.push("time-hard");
            args.push(&lifetime_secs_str);
        }

        Self::run_ip_command(&args).await
    }

    async fn xfrm_sa_del(
        source: &IpAddr,
        destination: &IpAddr,
        spi: u32,
    ) -> Result<(), IpsecError> {
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);

        let args = vec![
            "xfrm", "state", "delete",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
        ];
        Self::run_ip_command(&args).await
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn xfrm_policy_add(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: &str,
        spi: u32,
        protocol: SaProtocol,
        hard_lifetime_secs: Option<u64>,
    ) -> Result<(), IpsecError> {
        let source_cidr = format!("{}/{}", source, host_prefix(source));
        let destination_cidr = format!("{}/{}", destination, host_prefix(destination));
        let source_port_str = source_port.to_string();
        let destination_port_str = destination_port.to_string();
        let source_str = source.to_string();
        let destination_str = destination.to_string();
        let spi_str = format!("0x{:x}", spi);
        let proto_str = protocol.as_str();
        let lifetime_secs_str;

        // `proto X` must precede `sport`/`dport` per the iproute2 UPSPEC
        // grammar — see xfrm_sa_add for the same ordering constraint.
        let mut args = vec![
            "xfrm", "policy", "add",
            "src", &source_cidr,
            "dst", &destination_cidr,
            "proto", proto_str,
            "sport", &source_port_str,
            "dport", &destination_port_str,
            "dir", direction,
            "tmpl",
            "src", &source_str,
            "dst", &destination_str,
            "proto", "esp",
            "spi", &spi_str,
            "mode", "transport",
        ];

        // Optional hard lifetime — mirrors xfrm_sa_add so a policy reaps
        // on the same deadline as its states.  `limit time-hard <secs>`
        // sets xfrm_userpolicy_info.lft.hard_add_expires_seconds.
        if let Some(secs) = hard_lifetime_secs {
            lifetime_secs_str = secs.to_string();
            args.push("limit");
            args.push("time-hard");
            args.push(&lifetime_secs_str);
        }

        Self::run_ip_command(&args).await
    }

    async fn xfrm_policy_del(
        source: &IpAddr,
        source_port: u16,
        destination: &IpAddr,
        destination_port: u16,
        direction: &str,
        protocol: SaProtocol,
    ) -> Result<(), IpsecError> {
        let source_cidr = format!("{}/{}", source, host_prefix(source));
        let destination_cidr = format!("{}/{}", destination, host_prefix(destination));
        let source_port_str = source_port.to_string();
        let destination_port_str = destination_port.to_string();
        let proto_str = protocol.as_str();

        // Same UPSPEC ordering as xfrm_policy_add — `proto X` first.
        let args = vec![
            "xfrm", "policy", "delete",
            "src", &source_cidr,
            "dst", &destination_cidr,
            "proto", proto_str,
            "sport", &source_port_str,
            "dport", &destination_port_str,
            "dir", direction,
        ];
        Self::run_ip_command(&args).await
    }

    /// 3GPP TS 33.203 Annex H IPsec key derivation.
    ///
    /// For algorithms requiring keys longer than the 128-bit IK (HMAC-
    /// SHA-256-128 with a 256-bit key), Annex H specifies derivation via
    /// HMAC-SHA-256(IK, label).  For algorithms that fit inside the
    /// 128-bit IK (HMAC-MD5, HMAC-SHA-1 with zero-pad), the IK is used
    /// directly.
    ///
    /// `ik` must be 16 bytes (128-bit IK from Milenage).  Returns the
    /// derived integrity key as raw bytes.  Returns `None` if the
    /// requested length cannot be derived.
    pub fn derive_integrity_key(
        aalg: IntegrityAlgorithm,
        ik: &[u8],
    ) -> Option<Vec<u8>> {
        if ik.len() != 16 {
            return None;
        }
        match aalg {
            IntegrityAlgorithm::HmacMd5 => Some(ik.to_vec()),
            IntegrityAlgorithm::HmacSha1 => {
                // 160-bit key — zero-pad the 128-bit IK to 20 bytes.
                let mut key = Vec::with_capacity(20);
                key.extend_from_slice(ik);
                key.extend_from_slice(&[0u8; 4]);
                Some(key)
            }
            IntegrityAlgorithm::HmacSha256 => {
                // 256-bit key — derived via HMAC-SHA-256(IK, "ipsec-int")
                // per 3GPP TS 33.203 Annex H.  This pattern follows the
                // Annex H "P-key derivation" template using the algorithm
                // name as the FC label.
                Some(hmac_sha256(ik, b"ipsec-int-sha256-128"))
            }
        }
    }

    async fn run_ip_command(args: &[&str]) -> Result<(), IpsecError> {
        debug!(cmd = %args.join(" "), "IPsec: running ip command");
        let output = tokio::process::Command::new("ip")
            .args(args)
            .output()
            .await
            .map_err(|error| {
                IpsecError::Command(format!("failed to run ip: {}", error))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(IpsecError::Command(format!(
                "ip {} failed (exit {}): {}",
                args.get(1).copied().unwrap_or(""),
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn encryption_algorithm_xfrm_names() {
        assert_eq!(EncryptionAlgorithm::Null.xfrm_name(), "ecb(cipher_null)");
        assert_eq!(EncryptionAlgorithm::AesCbc128.xfrm_name(), "aes");
        assert_eq!(EncryptionAlgorithm::DesEde3Cbc.xfrm_name(), "des3_ede");
    }

    #[test]
    fn encryption_algorithm_key_lengths() {
        assert_eq!(EncryptionAlgorithm::Null.key_length(), 0);
        assert_eq!(EncryptionAlgorithm::AesCbc128.key_length(), 16);
        assert_eq!(EncryptionAlgorithm::DesEde3Cbc.key_length(), 24);
    }

    #[test]
    fn integrity_algorithm_xfrm_names() {
        assert_eq!(IntegrityAlgorithm::HmacMd5.xfrm_name(), "hmac(md5)");
        assert_eq!(IntegrityAlgorithm::HmacSha1.xfrm_name(), "hmac(sha1)");
    }

    #[test]
    fn integrity_algorithm_key_lengths() {
        assert_eq!(IntegrityAlgorithm::HmacMd5.key_length(), 16);
        assert_eq!(IntegrityAlgorithm::HmacSha1.key_length(), 20);
    }

    #[test]
    fn allocate_spi_pair_unique() {
        let manager = IpsecManager::new();
        let (spi1_a, spi1_b) = manager.allocate_spi_pair();
        let (spi2_a, spi2_b) = manager.allocate_spi_pair();

        // Each pair is consecutive.
        assert_eq!(spi1_b, spi1_a + 1);
        assert_eq!(spi2_b, spi2_a + 1);

        // Pairs do not overlap.
        assert_ne!(spi1_a, spi2_a);
        assert_ne!(spi1_b, spi2_b);
        assert_eq!(spi2_a, spi1_a + 2);
    }

    #[test]
    fn allocate_spi_pair_starts_above_well_known_range() {
        let manager = IpsecManager::new();
        let (spi_a, _) = manager.allocate_spi_pair();
        assert!(spi_a >= 10000);
    }

    #[test]
    fn contact_key_format() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let key = IpsecManager::contact_key(&addr, 5060);
        assert_eq!(key, "10.0.0.1:5060");
    }

    #[test]
    fn contact_key_format_ipv6() {
        let addr: IpAddr = "::1".parse().unwrap();
        let key = IpsecManager::contact_key(&addr, 5060);
        assert_eq!(key, "::1:5060");
    }

    #[test]
    fn manager_new_empty() {
        let manager = IpsecManager::new();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn has_sa_false_initially() {
        let manager = IpsecManager::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(!manager.has_sa(&addr, 5060));
    }

    #[test]
    fn get_sa_none_initially() {
        let manager = IpsecManager::new();
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(manager.get_sa(&addr, 5060).is_none());
    }

    #[test]
    fn parse_security_client_basic() {
        let header = concat!(
            "ipsec-3gpp; alg=hmac-sha-1-96; ",
            "spi-c=11111; spi-s=22222; ",
            "port-c=5060; port-s=5062"
        );
        let parsed = parse_security_client(header).unwrap();
        assert_eq!(parsed.mechanism, "ipsec-3gpp");
        assert_eq!(parsed.algorithm, "hmac-sha-1-96");
        assert_eq!(parsed.spi_c, 11111);
        assert_eq!(parsed.spi_s, 22222);
        assert_eq!(parsed.port_c, 5060);
        assert_eq!(parsed.port_s, 5062);
        assert!(parsed.ealg.is_none());
    }

    #[test]
    fn parse_security_client_with_ealg() {
        let header = concat!(
            "ipsec-3gpp; alg=hmac-md5-96; ealg=aes-cbc; ",
            "spi-c=33333; spi-s=44444; ",
            "port-c=6060; port-s=6062"
        );
        let parsed = parse_security_client(header).unwrap();
        assert_eq!(parsed.mechanism, "ipsec-3gpp");
        assert_eq!(parsed.algorithm, "hmac-md5-96");
        assert_eq!(parsed.spi_c, 33333);
        assert_eq!(parsed.spi_s, 44444);
        assert_eq!(parsed.port_c, 6060);
        assert_eq!(parsed.port_s, 6062);
        assert_eq!(parsed.ealg.as_deref(), Some("aes-cbc"));
    }

    #[test]
    fn parse_security_client_missing_required_field() {
        // Missing spi-s — should return None.
        let header = "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; port-c=5060; port-s=5062";
        assert!(parse_security_client(header).is_none());
    }

    #[test]
    fn parse_security_client_empty() {
        assert!(parse_security_client("").is_none());
    }

    #[test]
    fn parse_security_client_no_alg() {
        let header = "ipsec-3gpp; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062";
        assert!(parse_security_client(header).is_none());
    }

    #[test]
    fn encryption_algorithm_display() {
        assert_eq!(format!("{}", EncryptionAlgorithm::Null), "NULL");
        assert_eq!(format!("{}", EncryptionAlgorithm::AesCbc128), "AES-CBC-128");
        assert_eq!(
            format!("{}", EncryptionAlgorithm::DesEde3Cbc),
            "DES-EDE3-CBC"
        );
    }

    #[test]
    fn integrity_algorithm_display() {
        assert_eq!(format!("{}", IntegrityAlgorithm::HmacMd5), "HMAC-MD5-96");
        assert_eq!(
            format!("{}", IntegrityAlgorithm::HmacSha1),
            "HMAC-SHA-1-96"
        );
    }

    #[test]
    fn ipsec_error_display() {
        let command_error = IpsecError::Command("something broke".to_string());
        assert_eq!(
            format!("{}", command_error),
            "IPsec command error: something broke"
        );

        let key_error = IpsecError::InvalidKey("bad hex".to_string());
        assert_eq!(
            format!("{}", key_error),
            "IPsec invalid key: bad hex"
        );
    }

    #[test]
    fn security_association_pair_clone() {
        let sa = SecurityAssociationPair {
            ue_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            pcscf_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ue_port_c: 5060,
            ue_port_s: 5062,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 10000,
            spi_us: 10001,
            spi_pc: 10002,
            spi_ps: 10003,
            ealg: EncryptionAlgorithm::AesCbc128,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: "deadbeef".to_string(),
            integrity_key: "cafebabe".to_string(),
            hard_lifetime_secs: None,
            protocol: SaProtocol::Udp,
            expires_at: Instant::now(),
        };
        let cloned = sa.clone();
        assert_eq!(cloned.spi_uc, 10000);
        assert_eq!(cloned.spi_us, 10001);
        assert_eq!(cloned.spi_pc, 10002);
        assert_eq!(cloned.spi_ps, 10003);
        assert_eq!(cloned.ealg, EncryptionAlgorithm::AesCbc128);
        assert_eq!(cloned.aalg, IntegrityAlgorithm::HmacSha1);
        assert_eq!(cloned.protocol, SaProtocol::Udp);
    }

    #[test]
    fn sa_protocol_numeric_values_match_iana() {
        assert_eq!(SaProtocol::Udp.as_u8(), 17);
        assert_eq!(SaProtocol::Tcp.as_u8(), 6);
        // `Any` is XFRM's "match any inner proto" — selector_proto=0 in
        // the kernel ABI.  Linux short-circuits the proto check when
        // sel->proto==0 (see __xfrm{4,6}_selector_match), so the SA
        // pair covers both TCP and UDP under one SPI.  This is the
        // spec-compliant default per 3GPP TS 33.203 §7.2.
        assert_eq!(SaProtocol::Any.as_u8(), 0);
    }

    #[test]
    fn sa_protocol_string_form_round_trips_for_rfc3329() {
        assert_eq!(SaProtocol::Udp.as_str(), "udp");
        assert_eq!(SaProtocol::Tcp.as_str(), "tcp");
        assert_eq!(format!("{}", SaProtocol::Tcp), "tcp");
        // `any` is the iproute2 UPSPEC literal for selector_proto=0 —
        // accepted by `ip xfrm policy add ... proto any sport X dport Y`.
        // Not a valid RFC 3329 `protocol=` value; callers formatting the
        // Security-Server header must omit the parameter for `Any`
        // (RFC 3329 §2.2: absent implies UDP, which is wire-compatible).
        assert_eq!(SaProtocol::Any.as_str(), "any");
        assert_eq!(format!("{}", SaProtocol::Any), "any");
    }

    /// `update_sa_pair_lifetime` is a no-op (returns Ok) when the UE
    /// has no active SA pair — the script may activate after the SA was
    /// already auto-cleaned (de-REGISTER race, stash TTL fire), and that
    /// must not surface as an error.
    #[tokio::test]
    async fn update_sa_pair_lifetime_no_op_for_unknown_ue() {
        let manager = IpsecManager::new();
        let unknown_ue: IpAddr = "10.99.99.99".parse().unwrap();
        // No SA installed → must not touch the kernel and must succeed.
        manager
            .update_sa_pair_lifetime(&unknown_ue, 50000, Some(3632))
            .await
            .expect("update_sa_pair_lifetime should be Ok for unknown UE");
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn sa_protocol_default_is_any() {
        // Spec-driven default change (3GPP TS 33.203 §7.2): an SA pair
        // must protect SIP signalling on *both* UDP and TCP between the
        // UE and the P-CSCF.  Single-transport pins are opt-in for tests
        // / niche deployments; `Default::default()` returns the
        // any-protocol selector that covers both transports under one
        // SPI pair.
        assert_eq!(SaProtocol::default(), SaProtocol::Any);
    }

    /// Construct a `SecurityAssociationPair` for in-memory bookkeeping
    /// tests.  Uses RFC 5737 documentation addresses so the SPI/port
    /// quintuples cannot collide with any real-world XFRM state on the
    /// host running the test suite.
    fn test_sa_pair(ue_addr: IpAddr, ue_port_c: u16, spi_base: u32) -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr,
            pcscf_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ue_port_c,
            ue_port_s: ue_port_c + 1,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: spi_base,
            spi_us: spi_base + 1,
            spi_pc: spi_base + 2,
            spi_ps: spi_base + 3,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "00112233445566778899aabbccddeeff".to_string(),
            hard_lifetime_secs: Some(3600),
            protocol: SaProtocol::Any,
            expires_at: compute_sa_expires_at(Some(3600)),
        }
    }

    /// Direct insert into `associations` for tests that exercise the
    /// manager's bookkeeping without going through `create_sa_pair`
    /// (which requires `CAP_NET_ADMIN` to talk to the kernel).
    fn insert_test_pair(manager: &IpsecManager, sa: SecurityAssociationPair) {
        let key = IpsecManager::contact_key(&sa.ue_addr, sa.ue_port_c);
        manager.associations.insert(key, sa);
    }

    /// Regression test for the XFRM-policy leak that surfaced as
    /// `EEXIST` on policy add after several REGISTER refresh cycles from
    /// the same UE.
    ///
    /// Root cause: `contact_key` includes `ue_port_c`, which the UE
    /// regenerates on every REGISTER.  A re-REGISTER inserts the new
    /// pair under a fresh key and never invokes `delete_sa_pair` for the
    /// previous one — so the previous pair's four policies linger in
    /// the kernel forever (they have no kernel-side lifetime, unlike
    /// SAs).  Eventually a new random `port_uc` collides with a leaked
    /// selector and policy install hits `EEXIST`.
    ///
    /// `cleanup_other_pairs_for_ue` is invoked from `PendingSA.activate`
    /// (once the 200 OK has landed and the new binding is granted by
    /// the registrar of record) and tears down every prior pair for the
    /// same UE address other than the one being kept.
    #[tokio::test]
    async fn cleanup_other_pairs_removes_stale_entries_for_same_ue() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        let ue: IpAddr = "192.0.2.50".parse().unwrap();

        // Simulate four prior REGISTER cycles for the same UE — each with
        // a fresh random `port_uc` (mirroring the field trace where the UE
        // chose 6101 / 6201 / 6301 / 6401 across May 20 18:05–19:49).
        insert_test_pair(&manager, test_sa_pair(ue, 6101, 10000));
        insert_test_pair(&manager, test_sa_pair(ue, 6201, 10004));
        insert_test_pair(&manager, test_sa_pair(ue, 6301, 10008));
        insert_test_pair(&manager, test_sa_pair(ue, 6401, 10012));
        // Today's REGISTER lands on the same port_uc the UE happened to
        // pick back at 18:05 — without cleanup, policy add would EEXIST
        // against the leaked May-20-18:05 selector.
        insert_test_pair(&manager, test_sa_pair(ue, 6500, 10016));
        assert_eq!(manager.active_count(), 5);

        manager.cleanup_other_pairs_for_ue(&ue, 6500).await;

        // Only the kept pair survives; the four prior ones have been
        // removed from the in-memory map.  Per-victim kernel deletes may
        // fail in the unit test environment (no CAP_NET_ADMIN, no real
        // SAs to delete), but `delete_sa_pair` removes from the map
        // before issuing the kernel call, so observable manager state is
        // deterministic.
        assert_eq!(manager.active_count(), 1);
        assert!(manager.has_sa(&ue, 6500));
        for port in [6101u16, 6201, 6301, 6401] {
            assert!(
                !manager.has_sa(&ue, port),
                "stale pair for port_c={port} should have been torn down"
            );
        }
    }

    /// Pairs for other UE addresses must be untouched — the cleanup is
    /// scoped to `ue_addr`, not "all UEs".
    #[tokio::test]
    async fn cleanup_other_pairs_leaves_other_ues_untouched() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        let ue_a: IpAddr = "192.0.2.50".parse().unwrap();
        let ue_b: IpAddr = "192.0.2.51".parse().unwrap();

        insert_test_pair(&manager, test_sa_pair(ue_a, 6101, 10000));
        insert_test_pair(&manager, test_sa_pair(ue_a, 6201, 10004));
        insert_test_pair(&manager, test_sa_pair(ue_b, 7001, 10008));
        insert_test_pair(&manager, test_sa_pair(ue_b, 7101, 10012));
        assert_eq!(manager.active_count(), 4);

        // Activate cleanup for ue_a, keeping port_c=6201 — must remove
        // ue_a:6101 only.
        manager.cleanup_other_pairs_for_ue(&ue_a, 6201).await;

        assert_eq!(manager.active_count(), 3);
        assert!(manager.has_sa(&ue_a, 6201));
        assert!(!manager.has_sa(&ue_a, 6101));
        // ue_b's pairs are untouched.
        assert!(manager.has_sa(&ue_b, 7001));
        assert!(manager.has_sa(&ue_b, 7101));
    }

    /// First REGISTER for a UE (no prior pair in the map) must complete
    /// the cleanup as a no-op — no kernel calls, no map mutations.
    #[tokio::test]
    async fn cleanup_other_pairs_no_op_on_first_register() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        let ue: IpAddr = "192.0.2.50".parse().unwrap();

        insert_test_pair(&manager, test_sa_pair(ue, 6500, 10000));
        assert_eq!(manager.active_count(), 1);

        manager.cleanup_other_pairs_for_ue(&ue, 6500).await;

        assert_eq!(manager.active_count(), 1);
        assert!(manager.has_sa(&ue, 6500));
    }

    /// Cleanup must remain a no-op when called for a UE that has no
    /// pairs in the map at all — defends against the race where the
    /// stash TTL fires `cleanup` before `activate` runs.
    #[tokio::test]
    async fn cleanup_other_pairs_no_op_when_ue_has_no_pairs() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        let unknown_ue: IpAddr = "192.0.2.99".parse().unwrap();

        manager.cleanup_other_pairs_for_ue(&unknown_ue, 6500).await;

        assert_eq!(manager.active_count(), 0);
    }

    /// A pair with a hard lifetime gets a finite sweep deadline; one with
    /// no hard lifetime is parked far in the future and is never reaped by
    /// the expiry path.
    #[test]
    fn compute_sa_expires_at_finite_for_lifetime_and_far_for_none() {
        let now = Instant::now();
        let with_lifetime = compute_sa_expires_at(Some(3600));
        // now + 3600 + grace, comfortably in the future but not far-future.
        assert!(with_lifetime > now);
        assert!(with_lifetime < now + Duration::from_secs(3600 + SA_SWEEP_GRACE_SECS + 60));

        let none = compute_sa_expires_at(None);
        // ~100 years out — well past the lifetime-based deadline.
        assert!(none > now + Duration::from_secs(10 * 365 * 24 * 60 * 60));
    }

    /// `sweep_expired` reaps only pairs whose `expires_at` has passed; a
    /// fresh pair (deadline in the future) survives.  Mirrors the
    /// abandoned-UE scenario: a UE registers once and vanishes, so its SA
    /// passes its own hard-lifetime+grace deadline and is swept, while an
    /// actively-refreshing UE keeps a future deadline and is left alone.
    #[tokio::test]
    async fn sweep_expired_reaps_only_past_deadline_pairs() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        let abandoned: IpAddr = "192.0.2.60".parse().unwrap();
        let active: IpAddr = "192.0.2.61".parse().unwrap();

        // Abandoned UE: deadline already in the past.
        let mut stale = test_sa_pair(abandoned, 6601, 10000);
        stale.expires_at = Instant::now() - Duration::from_secs(1);
        insert_test_pair(&manager, stale);

        // Active UE: a fresh SA whose deadline is comfortably in the
        // future (as if it just re-REGISTERed).
        let fresh = test_sa_pair(active, 6701, 10004);
        // test_sa_pair already sets expires_at = now + 3600 + grace.
        insert_test_pair(&manager, fresh);

        assert_eq!(manager.active_count(), 2);

        let reaped = manager.sweep_expired().await;
        assert_eq!(reaped, 1, "exactly the one past-deadline pair is reaped");

        // The abandoned pair's map entry is gone; the active one survives.
        assert!(
            !manager.has_sa(&abandoned, 6601),
            "abandoned SA past its deadline must be swept"
        );
        assert!(
            manager.has_sa(&active, 6701),
            "actively-refreshing SA with a future deadline must be left alone"
        );
        assert_eq!(manager.active_count(), 1);
    }

    /// `sweep_expired` on an empty / all-fresh manager reaps nothing.
    #[tokio::test]
    async fn sweep_expired_no_op_when_nothing_is_due() {
        let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 60000, 1024);
        assert_eq!(manager.sweep_expired().await, 0);

        // A single fresh pair (far-future deadline because it has no hard
        // lifetime) is not swept.
        let mut permanent = test_sa_pair("192.0.2.62".parse().unwrap(), 6801, 10000);
        permanent.hard_lifetime_secs = None;
        permanent.expires_at = compute_sa_expires_at(None);
        insert_test_pair(&manager, permanent);

        assert_eq!(manager.sweep_expired().await, 0);
        assert_eq!(manager.active_count(), 1);
    }
}
