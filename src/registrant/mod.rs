//! Outbound Registration (UAC Registrant) — maintains REGISTER bindings
//! to upstream carriers/SBCs.
//!
//! Each [`RegistrantEntry`] represents a single AoR that SIPhon keeps
//! registered at an upstream registrar.  The [`RegistrantManager`] owns
//! all entries and runs a background refresh loop that:
//!
//! - Sends REGISTER at startup for every configured entry.
//! - Re-registers at 50 % of the granted `expires` interval.
//! - Handles 401/407 challenges using [`crate::auth`] digest computation.
//! - Applies exponential backoff on failure.
//! - Sends de-registration (Expires: 0) on shutdown.

pub mod aka;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::auth::{
    self, DigestChallenge, DigestCredentials, NonceCounter,
};
use std::net::IpAddr;

use crate::ipsec::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair, SecurityClient,
};
use crate::ipsec::ue::{build_security_client, UeSecurityOffer};
use crate::hep::HepSender;
use crate::uac::resolve_via_addr;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, StreamConnections, Transport};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// A registrant state change event emitted by the manager.
#[derive(Debug, Clone)]
pub enum RegistrantEvent {
    /// Registration succeeded (first time or after failure).
    Registered { aor: String },
    /// Re-registration succeeded (was already registered).
    Refreshed { aor: String },
    /// Registration failed (non-auth error or auth exhaustion).
    Failed { aor: String, status_code: u16 },
    /// De-registration sent (shutdown or manual remove).
    Deregistered { aor: String },
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Registration state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrantState {
    /// Not yet attempted.
    Unregistered,
    /// REGISTER sent, waiting for response.
    Registering,
    /// 401/407 received, re-sending with credentials.
    Challenging,
    /// 200 OK received — binding is active.
    Registered,
    /// Last attempt failed (non-401/407 error or auth failure).
    Failed,
}

impl fmt::Display for RegistrantState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unregistered => write!(formatter, "unregistered"),
            Self::Registering => write!(formatter, "registering"),
            Self::Challenging => write!(formatter, "challenging"),
            Self::Registered => write!(formatter, "registered"),
            Self::Failed => write!(formatter, "failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Authentication credentials for a registration entry.
#[derive(Debug, Clone)]
pub struct RegistrantCredentials {
    pub username: String,
    pub password: String,
    /// Optional realm hint — if `None`, derived from the 401 challenge.
    pub realm: Option<String>,
}

/// How an entry authenticates to its upstream registrar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// RFC 2617 / RFC 7616 password digest (carriers, SBCs). The default.
    #[default]
    Digest,
    /// IMS AKAv1-MD5 (RFC 3310 / 3GPP TS 33.203) — register *into* an IMS core
    /// as a UE. The digest "password" is the Milenage RES; CK/IK seed the
    /// IPsec SAs (wired in Phase 2).
    Aka,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest => write!(formatter, "digest"),
            Self::Aka => write!(formatter, "aka"),
        }
    }
}

/// IMS Contact-header feature tags (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92,
/// NG.114). These let the S-CSCF match iFCs and register the UE's MMTel /
/// voice / video / SMS services, and carry the instance ID for GRUU/outbound
/// (RFC 5626). Emitted after the `<sip:…>` of the Contact when present.
#[derive(Debug, Clone, Default)]
pub struct ImsContactParams {
    /// IMEI for `+sip.instance="<urn:gsma:imei:…>"` (RFC 5626 instance ID).
    /// `None` → no instance tag.
    pub instance_id: Option<String>,
    /// Emit the MMTel ICSI tag (`+g.3gpp.icsi-ref` mmtel).
    pub mmtel: bool,
    /// Emit `;video`.
    pub video: bool,
    /// Emit `+g.3gpp.smsip` (SMS-over-IP).
    pub smsip: bool,
}

/// UE-side IPsec sec-agree parameters for an AKA registration (3GPP TS 33.203).
///
/// `ue_port_c`/`ue_port_s` are the UE's protected client/server ports — they
/// must be declared as `listen.udp` entries so siphon can source the protected
/// REGISTER from `ue_port_c` and receive MT requests on `ue_port_s`. The
/// transform (`aalg`/`ealg`) is what the UE offers in Security-Client.
///
/// `spi_uc`/`spi_us` and `ck`/`ik` are per-handshake runtime state: SPIs are
/// freshly allocated each initial REGISTER (and echoed in Security-Client), and
/// CK/IK are filled from the AKA challenge before the SAs are installed.
#[derive(Debug, Clone)]
pub struct UeIpsec {
    /// UE protected client port (also a `listen.udp` listener).
    pub ue_port_c: u16,
    /// UE protected server port (also a `listen.udp` listener).
    pub ue_port_s: u16,
    /// Chosen integrity algorithm for the SA (the preferred one until the
    /// P-CSCF picks one in Security-Server, see [`record_server_answer`]).
    pub aalg: IntegrityAlgorithm,
    /// Integrity algorithms offered in Security-Client (one `ipsec-3gpp`
    /// mechanism each), preference order — handsets offer SHA-1 + MD5.
    pub offered_aalgs: Vec<IntegrityAlgorithm>,
    /// Offered encryption algorithm (`Null` for integrity-only).
    pub ealg: EncryptionAlgorithm,
    /// UE client SPI for the current handshake (0 before the first offer).
    pub spi_uc: u32,
    /// UE server SPI for the current handshake (0 before the first offer).
    pub spi_us: u32,
    /// Cipher key from the most recent successful AKA challenge (SA encryption).
    pub ck: Option<[u8; 16]>,
    /// Integrity key from the most recent successful AKA challenge (SA integrity).
    pub ik: Option<[u8; 16]>,

    // --- P-CSCF answer (from the 401's Security-Server) ---
    /// P-CSCF protected client port.
    pub pcscf_port_c: u16,
    /// P-CSCF protected server port — destination for the protected REGISTER.
    pub pcscf_port_s: u16,
    /// P-CSCF client SPI.
    pub spi_pc: u32,
    /// P-CSCF server SPI.
    pub spi_ps: u32,
    /// Raw Security-Server value, echoed verbatim in Security-Verify.
    pub security_server: Option<String>,
}

/// The integrity algorithms a UE offers in Security-Client: the preferred one
/// first, then the interoperable defaults (HMAC-SHA-1-96, HMAC-MD5-96), deduped.
/// Real handsets offer both SHA-1 and MD5, letting the P-CSCF pick.
fn offered_integrity_algs(preferred: IntegrityAlgorithm) -> Vec<IntegrityAlgorithm> {
    let mut algs = vec![preferred];
    for alg in [IntegrityAlgorithm::HmacSha1, IntegrityAlgorithm::HmacMd5] {
        if !algs.contains(&alg) {
            algs.push(alg);
        }
    }
    algs
}

impl UeIpsec {
    /// Build from configured ports + transform; runtime fields start empty.
    pub fn new(
        ue_port_c: u16,
        ue_port_s: u16,
        aalg: IntegrityAlgorithm,
        ealg: EncryptionAlgorithm,
    ) -> Self {
        Self {
            ue_port_c,
            ue_port_s,
            aalg,
            offered_aalgs: offered_integrity_algs(aalg),
            ealg,
            spi_uc: 0,
            spi_us: 0,
            ck: None,
            ik: None,
            pcscf_port_c: 0,
            pcscf_port_s: 0,
            spi_pc: 0,
            spi_ps: 0,
            security_server: None,
        }
    }

    /// The Security-Client offer for the current SPIs/ports — one mechanism per
    /// offered integrity algorithm.
    pub fn offer(&self) -> UeSecurityOffer {
        UeSecurityOffer::new(
            self.offered_aalgs.clone(),
            self.ealg,
            self.spi_uc,
            self.spi_us,
            self.ue_port_c,
            self.ue_port_s,
        )
    }

    /// Record the P-CSCF's Security-Server answer for the current handshake.
    ///
    /// Adopts the P-CSCF's chosen transform for the SA (it selects from the
    /// UE's offer; falls back to the offered algorithm if the token is
    /// unrecognised) and stashes the raw value for the Security-Verify echo.
    pub fn record_server_answer(&mut self, server: &SecurityClient, raw: &str) {
        self.pcscf_port_c = server.port_c;
        self.pcscf_port_s = server.port_s;
        self.spi_pc = server.spi_c;
        self.spi_ps = server.spi_s;
        if let Some(alg) = IntegrityAlgorithm::from_sec_agree_name(&server.algorithm) {
            self.aalg = alg;
        }
        if let Some(ealg_token) = server.ealg.as_deref() {
            if let Some(ealg) = EncryptionAlgorithm::from_sec_agree_name(ealg_token) {
                self.ealg = ealg;
            }
        }
        self.security_server = Some(raw.to_string());
    }

    /// Construct the four-SA descriptor for `create_ue_sa_pair`, deriving the
    /// ESP keys from CK (encryption) and IK (integrity). Returns `None` until
    /// both an AKA challenge (CK/IK) and a Security-Server answer have landed.
    pub fn sa_pair(
        &self,
        ue_addr: IpAddr,
        pcscf_addr: IpAddr,
        hard_lifetime_secs: Option<u64>,
        protocol: SaProtocol,
    ) -> Option<SecurityAssociationPair> {
        let ck = self.ck?;
        let ik = self.ik?;
        self.security_server.as_ref()?;
        let integrity_key = IpsecManager::derive_integrity_key(self.aalg, &ik)?;
        let encryption_key = if self.ealg == EncryptionAlgorithm::Null {
            String::new()
        } else {
            crate::ipsec::bytes_to_hex(&ck)
        };
        Some(SecurityAssociationPair {
            ue_addr,
            pcscf_addr,
            ue_port_c: self.ue_port_c,
            ue_port_s: self.ue_port_s,
            pcscf_port_c: self.pcscf_port_c,
            pcscf_port_s: self.pcscf_port_s,
            spi_uc: self.spi_uc,
            spi_us: self.spi_us,
            spi_pc: self.spi_pc,
            spi_ps: self.spi_ps,
            ealg: self.ealg,
            aalg: self.aalg,
            encryption_key,
            integrity_key: crate::ipsec::bytes_to_hex(&integrity_key),
            hard_lifetime_secs,
            protocol,
            // Recomputed authoritatively inside create_ue_sa_pair (→ create_sa_pair).
            expires_at: Instant::now(),
            created_at: Instant::now(),
            role: SaRole::Ue,
        })
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single outbound registration binding.
#[derive(Debug)]
pub struct RegistrantEntry {
    /// Address-of-Record (e.g. `sip:alice@carrier.com`).
    pub aor: String,
    /// Registrar URI (e.g. `sip:registrar.carrier.com:5060`).
    pub registrar_uri: String,
    /// Resolved destination for sending REGISTER.
    pub destination: SocketAddr,
    /// Original hostname:port for DNS re-resolution on failure.
    pub address_str: Option<String>,
    /// Transport to use (default: UDP).
    pub transport: Transport,
    /// Authentication credentials.
    pub credentials: RegistrantCredentials,
    /// Desired registration interval (seconds).
    pub interval_secs: u32,
    /// Contact URI to bind (auto-generated if not specified).
    pub contact_uri: Option<String>,

    // --- Runtime state ---
    pub state: RegistrantState,
    /// When the current registration expires.
    pub expires_at: Option<Instant>,
    /// When to next attempt registration.
    pub next_attempt: Instant,
    /// Current backoff duration for retries after failure.
    pub backoff: Duration,
    /// Per-entry CSeq counter.
    pub cseq: AtomicU32,
    /// Nonce counter for digest auth.
    pub nonce_counter: NonceCounter,
    /// Call-ID for this registration dialog (stable across refreshes).
    pub call_id: String,
    /// Number of consecutive failures.
    pub failure_count: u32,
    /// When the last REGISTER was sent (for transaction timeout detection).
    pub last_sent_at: Option<Instant>,

    // --- IMS AKA (Phase 1) ---
    /// Authentication mode. `Digest` (default) keeps the carrier-trunk path
    /// unchanged; `Aka` routes the 401 through Milenage (see [`aka`]).
    pub auth_mode: AuthMode,
    /// IMS AKA credentials (K/OPc/AMF). `Some` only when `auth_mode == Aka`.
    pub aka: Option<aka::AkaCredentials>,
    /// UE's stored sequence number `SQN_MS`. Advances on each accepted
    /// challenge; a challenge whose SQN is not strictly greater triggers an
    /// AUTS re-synchronisation (3GPP TS 33.102 §6.3.3).
    pub sqn_ms: [u8; 6],

    // --- Captured from the 200 OK (IMS) ---
    /// Service-Route set (RFC 3608) — the path to the S-CSCF for originating
    /// requests. Consumed by the B2BUA when routing MO calls (Phase 3).
    pub service_route: Vec<String>,
    /// P-Associated-URI list (the implicit registration set).
    pub associated_uris: Vec<String>,
    /// Path header set (RFC 3327) returned by the registrar.
    pub path: Vec<String>,

    /// UE IPsec sec-agree parameters (3GPP TS 33.203). `Some` when this AKA
    /// registration must establish IPsec SAs with the P-CSCF; the initial
    /// REGISTER then carries Security-Client and the protected re-REGISTER
    /// carries Security-Verify. `None` = AKA without IPsec (test cores).
    pub ue_ipsec: Option<UeIpsec>,

    /// IMS Contact feature tags (instance ID + MMTel/video/SMS). `Some` →
    /// appended to the Contact so the S-CSCF registers the implied services.
    pub ims_contact: Option<ImsContactParams>,
}

impl RegistrantEntry {
    pub fn new(
        aor: String,
        registrar_uri: String,
        destination: SocketAddr,
        transport: Transport,
        credentials: RegistrantCredentials,
        interval_secs: u32,
        contact_uri: Option<String>,
    ) -> Self {
        Self {
            aor,
            registrar_uri,
            destination,
            address_str: None,
            transport,
            credentials,
            interval_secs,
            contact_uri,
            state: RegistrantState::Unregistered,
            expires_at: None,
            next_attempt: Instant::now(),
            backoff: Duration::from_secs(5),
            cseq: AtomicU32::new(1),
            nonce_counter: NonceCounter::new(),
            call_id: format!("reg-{}", uuid::Uuid::new_v4()),
            failure_count: 0,
            last_sent_at: None,
            auth_mode: AuthMode::Digest,
            aka: None,
            sqn_ms: [0u8; 6],
            service_route: Vec::new(),
            associated_uris: Vec::new(),
            path: Vec::new(),
            ue_ipsec: None,
            ims_contact: None,
        }
    }

    /// Switch this entry to IMS AKAv1-MD5 authentication (3GPP TS 33.203).
    ///
    /// `initial_sqn` seeds `SQN_MS`; pass all-zeros for a fresh soft-UE (the
    /// first in-range challenge then sets the real baseline). The digest
    /// `username` carried in `RegistrantCredentials` should be the IMPI.
    pub fn with_aka(mut self, credentials: aka::AkaCredentials, initial_sqn: [u8; 6]) -> Self {
        self.auth_mode = AuthMode::Aka;
        self.aka = Some(credentials);
        self.sqn_ms = initial_sqn;
        self
    }

    /// Enable IPsec sec-agree for this (AKA) registration (3GPP TS 33.203).
    /// Only meaningful together with [`with_aka`](Self::with_aka).
    pub fn with_ipsec(mut self, ipsec: UeIpsec) -> Self {
        self.ue_ipsec = Some(ipsec);
        self
    }

    /// Attach IMS Contact feature tags (instance ID + MMTel/video/SMS) so the
    /// S-CSCF registers the implied services (TS 24.229 / GSMA IR.92).
    pub fn with_ims_contact(mut self, ims: ImsContactParams) -> Self {
        self.ims_contact = Some(ims);
        self
    }

    /// Returns seconds until expiry, or 0 if expired/not registered.
    pub fn expires_in(&self) -> u64 {
        self.expires_at
            .map(|at| {
                at.checked_duration_since(Instant::now())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    /// Next CSeq value.
    pub fn next_cseq(&self) -> u32 {
        self.cseq.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Manages all outbound registrations.
pub struct RegistrantManager {
    entries: DashMap<String, RegistrantEntry>,
    /// Default interval when not specified per-entry.
    pub default_interval: u32,
    /// Base retry interval on failure.
    pub retry_interval: Duration,
    /// Maximum retry interval (backoff cap).
    pub max_retry_interval: Duration,
    /// User-Agent header value for outbound REGISTERs.
    user_agent_header: Option<String>,
    /// Broadcast channel for registrant state change events.
    event_sender: broadcast::Sender<RegistrantEvent>,
    /// Monotonic counter for UE-side IPsec SPIs (sec-agree). Each initial
    /// REGISTER that offers IPsec consumes a pair. Seeded high so it never
    /// overlaps a co-resident P-CSCF's SPI range.
    ue_spi_counter: AtomicU32,
}

impl RegistrantManager {
    pub fn new(
        default_interval: u32,
        retry_interval: Duration,
        max_retry_interval: Duration,
        user_agent_header: Option<String>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(64);
        Self {
            entries: DashMap::new(),
            default_interval,
            retry_interval,
            max_retry_interval,
            user_agent_header,
            event_sender,
            ue_spi_counter: AtomicU32::new(Self::UE_SPI_BASE),
        }
    }

    /// Base for UE IPsec SPI allocation. Above the default P-CSCF SPI partition
    /// (10000..18192) so a single host could run both roles without colliding,
    /// and well clear of the RFC 4303 §2.1 reserved 1..255 range. Kept in a
    /// normal, handset-like magnitude (not 0x20000000) — the value advertised
    /// in Security-Client IS the value installed in the kernel inbound SA.
    const UE_SPI_BASE: u32 = 50_000;

    /// Allocate a fresh `(spi_uc, spi_us)` pair for a UE sec-agree offer.
    pub fn allocate_ue_spi_pair(&self) -> (u32, u32) {
        let first = self.ue_spi_counter.fetch_add(2, Ordering::Relaxed);
        (first, first.wrapping_add(1))
    }

    /// Subscribe to registrant state change events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<RegistrantEvent> {
        self.event_sender.subscribe()
    }

    /// Emit a registrant event (best-effort, ignores if no receivers).
    fn emit_event(&self, event: RegistrantEvent) {
        let _ = self.event_sender.send(event);
    }

    /// Add a new registration entry.
    pub fn add(&self, entry: RegistrantEntry) {
        info!(aor = %entry.aor, registrar = %entry.registrar_uri, "registrant added");
        self.entries.insert(entry.aor.clone(), entry);
    }

    /// Remove a registration entry by AoR.
    pub fn remove(&self, aor: &str) -> Option<RegistrantEntry> {
        let removed = self.entries.remove(aor).map(|(_, entry)| entry);
        if removed.is_some() {
            self.emit_event(RegistrantEvent::Deregistered { aor: aor.to_string() });
        }
        removed
    }

    /// Get number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the state of an entry.
    pub fn state(&self, aor: &str) -> Option<RegistrantState> {
        self.entries.get(aor).map(|entry| entry.state)
    }

    /// List all AoRs and their states.
    pub fn list(&self) -> Vec<(String, RegistrantState, u64)> {
        self.entries
            .iter()
            .map(|entry| {
                (
                    entry.aor.clone(),
                    entry.state,
                    entry.expires_in(),
                )
            })
            .collect()
    }

    /// Get extended info for a single entry (used by dispatcher for event callbacks).
    ///
    /// Returns `(expires_in, failure_count, registrar_uri)`.
    pub fn entry_info(&self, aor: &str) -> Option<(u64, u32, String)> {
        self.entries.get(aor).map(|entry| {
            (entry.expires_in(), entry.failure_count, entry.registrar_uri.clone())
        })
    }

    /// Force an immediate refresh for a specific AoR.
    pub fn refresh(&self, aor: &str) -> bool {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.next_attempt = Instant::now();
            entry.state = RegistrantState::Unregistered;
            true
        } else {
            false
        }
    }

    /// Build a REGISTER request for an entry.
    ///
    /// `listen_addrs` maps each transport to its listen address. The entry's
    /// transport is used to pick the correct local address (and port) for the
    /// Contact and Via headers. Falls back to `local_addr` when no
    /// transport-specific address is configured.
    pub fn build_register(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry
            .contact_uri
            .clone()
            .unwrap_or_else(|| default_contact_uri(&entry.credentials.username, effective_addr, entry.transport));

        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!(
                "<{}>;tag=reg-{}",
                entry.aor, cseq
            ))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header("Contact", build_contact_header(&contact, entry.ims_contact.as_ref()))
            .header("Expires", expires.to_string())
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        // IMS AKA: the initial (unprotected) REGISTER carries an Authorization
        // header with an empty response so the S-CSCF learns the IMPI and
        // fetches an authentication vector — the 401 challenge then comes back
        // through build_register_aka (RFC 3310 / TS 24.229 §5.1.1.2).
        if entry.auth_mode == AuthMode::Aka {
            let realm = entry
                .credentials
                .realm
                .clone()
                .unwrap_or_else(|| home_domain_from_aor(&entry.aor));
            let registrar_host = entry
                .registrar_uri
                .strip_prefix("sip:")
                .unwrap_or(&entry.registrar_uri);
            let digest_uri = format!("sip:{registrar_host}");
            builder = builder.header(
                "Authorization",
                initial_aka_authorization(&entry.credentials.username, &realm, &digest_uri),
            );
        }

        // IMS IPsec sec-agree: the initial (unprotected) REGISTER offers the
        // UE's transform, freshly allocated SPIs, and protected ports in
        // Security-Client, and demands the extension via Require/Proxy-Require
        // (RFC 3329 / TS 33.203 §7.2). The 401 answers with Security-Server.
        // Deregistration (expires == 0) rides the existing SA and does not
        // re-offer.
        if expires > 0 && entry.ue_ipsec.is_some() {
            let (spi_uc, spi_us) = self.allocate_ue_spi_pair();
            if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                ipsec.spi_uc = spi_uc;
                ipsec.spi_us = spi_us;
                let security_client = build_security_client(&ipsec.offer());
                builder = builder
                    .header("Security-Client", security_client)
                    .header("Require", "sec-agree".to_string())
                    .header("Proxy-Require", "sec-agree".to_string())
                    .header("Supported", "path, sec-agree".to_string())
                    .header("Allow", IMS_ALLOW_METHODS.to_string());
            }
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        if expires > 0 {
            entry.state = RegistrantState::Registering;
            entry.last_sent_at = Some(Instant::now());
        }

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build REGISTER");
                None
            }
        }
    }

    /// Build an authenticated REGISTER retry after receiving a 401/407 challenge.
    pub fn build_register_with_auth(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        challenge: &DigestChallenge,
        is_proxy_auth: bool,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri_str = entry
            .registrar_uri
            .strip_prefix("sip:")
            .unwrap_or(&entry.registrar_uri)
            .to_string();
        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry
            .contact_uri
            .clone()
            .unwrap_or_else(|| default_contact_uri(&entry.credentials.username, effective_addr, entry.transport));

        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let nc = entry.nonce_counter.next_for(&challenge.nonce);
        let cnonce = format!("{:08x}", rand_u32());

        let digest_uri = format!("sip:{request_uri_str}");
        let credentials = DigestCredentials {
            username: entry.credentials.username.clone(),
            password: entry.credentials.password.clone(),
        };

        let auth_header_value = auth::format_authorization_header(
            challenge,
            &credentials,
            "REGISTER",
            &digest_uri,
            Some(nc),
            Some(&cnonce),
        );

        let auth_header_name = if is_proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        entry.state = RegistrantState::Challenging;
        entry.last_sent_at = Some(Instant::now());

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!(
                "<{}>;tag=reg-{}",
                entry.aor, cseq
            ))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header("Contact", build_contact_header(&contact, entry.ims_contact.as_ref()))
            .header("Expires", expires.to_string())
            .header(auth_header_name, auth_header_value)
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build authenticated REGISTER");
                None
            }
        }
    }

    /// Build an authenticated REGISTER in response to an IMS AKAv1-MD5 challenge.
    ///
    /// Runs Milenage over the challenge's RAND/AUTN (carried base64 in the
    /// nonce). On success, the Authorization response is computed from RES and
    /// `SQN_MS` advances; on a sequence-number mismatch the REGISTER instead
    /// carries an `auts=` re-synchronisation token (3GPP TS 33.102 §6.3.3); on
    /// a MAC failure (untrusted network) it returns `None` so the caller fails
    /// the registration.
    ///
    /// This is the Phase-1 (no-IPsec) shape — it does not yet emit
    /// `Security-Verify` or install SAs (Phase 2), and CK/IK are discarded.
    pub fn build_register_aka(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        challenge: &DigestChallenge,
        expires: u32,
        security_verify: Option<&str>,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;

        let credentials = entry.aka.clone()?;
        let (rand, autn) = match aka::decode_aka_nonce(&challenge.nonce) {
            Some(parts) => parts,
            None => {
                warn!(aor = %entry.aor, "AKA challenge nonce is not valid base64(RAND||AUTN)");
                return None;
            }
        };

        let (res, auts): (Vec<u8>, Option<String>) =
            match aka::aka_challenge(&credentials, &rand, &autn, &entry.sqn_ms) {
                aka::AkaOutcome::Success { res, ck, ik, sqn } => {
                    entry.sqn_ms = sqn;
                    // Stash CK/IK so the dispatcher can derive the IPsec SA
                    // keys before sending the protected REGISTER (Phase 2).
                    if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                        ipsec.ck = Some(ck);
                        ipsec.ik = Some(ik);
                    }
                    (res, None)
                }
                aka::AkaOutcome::SyncFailure { auts } => {
                    warn!(aor = %entry.aor, "AKA SQN out of range — sending AUTS re-synchronisation");
                    // RFC 3310 §3.4: the resync REGISTER carries the auts token;
                    // the response is computed over an empty RES and the server
                    // re-bases SQN and re-challenges.
                    (Vec::new(), Some(aka::encode_auts(&auts)))
                }
                aka::AkaOutcome::MacFailure => {
                    warn!(aor = %entry.aor, "AKA AUTN MAC failed — untrusted network challenge, aborting");
                    return None;
                }
            };

        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri_str = entry
            .registrar_uri
            .strip_prefix("sip:")
            .unwrap_or(&entry.registrar_uri)
            .to_string();
        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry
            .contact_uri
            .clone()
            .unwrap_or_else(|| default_contact_uri(&entry.credentials.username, effective_addr, entry.transport));
        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let nc = entry.nonce_counter.next_for(&challenge.nonce);
        let cnonce = format!("{:08x}", rand_u32());
        let digest_uri = format!("sip:{request_uri_str}");

        let auth_header_value = auth::format_aka_authorization_header(
            challenge,
            &entry.credentials.username,
            &res,
            &digest_uri,
            Some(nc),
            Some(&cnonce),
            auts.as_deref(),
        );

        entry.state = RegistrantState::Challenging;
        entry.last_sent_at = Some(Instant::now());

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!("<{}>;tag=reg-{}", entry.aor, cseq))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header("Contact", build_contact_header(&contact, entry.ims_contact.as_ref()))
            .header("Expires", expires.to_string())
            .header("Authorization", auth_header_value)
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        // IPsec sec-agree: on the protected re-REGISTER, echo the P-CSCF's
        // Security-Server verbatim in Security-Verify and repeat Security-Client
        // (RFC 3329 §2.4 / TS 33.203 §7.4). This REGISTER egresses over the SA
        // the dispatcher installs from the stashed CK/IK.
        if let Some(verify) = security_verify {
            builder = builder.header("Security-Verify", verify.to_string());
            if let Some(ipsec) = entry.ue_ipsec.as_ref() {
                builder = builder
                    .header("Security-Client", build_security_client(&ipsec.offer()))
                    .header("Require", "sec-agree".to_string())
                    .header("Proxy-Require", "sec-agree".to_string())
                    .header("Supported", "path, sec-agree".to_string())
                    .header("Allow", IMS_ALLOW_METHODS.to_string());
            }
        }

        let message = builder.build();
        let transport = entry.transport;

        // The protected REGISTER goes to the P-CSCF's protected server port
        // (from Security-Server), not the default SIP port the initial REGISTER
        // used. Without a recorded answer, fall back to the default destination.
        let destination = match entry.ue_ipsec.as_ref() {
            Some(ipsec) if security_verify.is_some() && ipsec.pcscf_port_s != 0 => {
                SocketAddr::new(entry.destination.ip(), ipsec.pcscf_port_s)
            }
            _ => entry.destination,
        };

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build AKA REGISTER");
                None
            }
        }
    }

    /// The authentication mode of an entry (used by the dispatcher to pick the
    /// digest vs. AKA challenge path).
    pub fn auth_mode(&self, aor: &str) -> Option<AuthMode> {
        self.entries.get(aor).map(|entry| entry.auth_mode)
    }

    /// Store the routing headers captured from a 200 OK (IMS). Replaces any
    /// previously captured set. Called from the dispatcher's 200 handler.
    pub fn store_registration_routes(
        &self,
        aor: &str,
        service_route: Vec<String>,
        associated_uris: Vec<String>,
        path: Vec<String>,
    ) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.service_route = service_route;
            entry.associated_uris = associated_uris;
            entry.path = path;
        }
    }

    /// Captured Service-Route set for an AoR (RFC 3608) — empty if none.
    pub fn service_route(&self, aor: &str) -> Vec<String> {
        self.entries
            .get(aor)
            .map(|entry| entry.service_route.clone())
            .unwrap_or_default()
    }

    /// Captured P-Associated-URI list for an AoR — empty if none.
    pub fn associated_uris(&self, aor: &str) -> Vec<String> {
        self.entries
            .get(aor)
            .map(|entry| entry.associated_uris.clone())
            .unwrap_or_default()
    }

    /// Whether this entry negotiates IPsec sec-agree (UE side).
    pub fn is_ipsec_entry(&self, aor: &str) -> bool {
        self.entries
            .get(aor)
            .map(|entry| entry.ue_ipsec.is_some())
            .unwrap_or(false)
    }

    /// The UE's protected client port — the source the protected REGISTER and
    /// subsequent protected traffic egress from. `None` for non-IPsec entries.
    pub fn ue_protected_client_port(&self, aor: &str) -> Option<u16> {
        self.entries
            .get(aor)
            .and_then(|entry| entry.ue_ipsec.as_ref().map(|ipsec| ipsec.ue_port_c))
    }

    /// Record the P-CSCF's Security-Server answer (from the 401) on the entry,
    /// so the protected REGISTER can echo it and the SA keys can be derived.
    pub fn store_security_server(&self, aor: &str, server: &SecurityClient, raw: &str) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                ipsec.record_server_answer(server, raw);
            }
        }
    }

    /// The raw Security-Server value to echo in Security-Verify, if recorded.
    pub fn security_server_value(&self, aor: &str) -> Option<String> {
        self.entries
            .get(aor)
            .and_then(|entry| entry.ue_ipsec.as_ref().and_then(|i| i.security_server.clone()))
    }

    /// Components for the UE→P-CSCF SA flow, used to build a `Flow` the B2BUA
    /// can dial over for MO calls: `(pcscf_addr, pcscf_port_s, ue_port_c)`.
    /// Returns `None` until the handshake recorded a Security-Server (i.e.
    /// `pcscf_port_s` is set). The MO B-leg sends to `pcscf_addr:pcscf_port_s`
    /// sourced from `ue_port_c`, so it rides the established SA.
    pub fn ue_flow_components(&self, aor: &str) -> Option<(IpAddr, u16, u16)> {
        self.entries.get(aor).and_then(|entry| {
            entry.ue_ipsec.as_ref().and_then(|ipsec| {
                if ipsec.pcscf_port_s == 0 {
                    None
                } else {
                    Some((entry.destination.ip(), ipsec.pcscf_port_s, ipsec.ue_port_c))
                }
            })
        })
    }

    /// Build the four-SA descriptor to install for this entry's UE side.
    /// Returns `None` until both an AKA challenge (CK/IK) and a Security-Server
    /// answer have been recorded.
    pub fn ue_sa_pair(
        &self,
        aor: &str,
        ue_addr: IpAddr,
        pcscf_addr: IpAddr,
        hard_lifetime_secs: Option<u64>,
        protocol: SaProtocol,
    ) -> Option<SecurityAssociationPair> {
        self.entries.get(aor).and_then(|entry| {
            entry
                .ue_ipsec
                .as_ref()
                .and_then(|ipsec| ipsec.sa_pair(ue_addr, pcscf_addr, hard_lifetime_secs, protocol))
        })
    }

    /// Handle a successful 200 OK response.
    pub fn handle_success(&self, aor: &str, granted_expires: u32) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            let was_registered = entry.state == RegistrantState::Registered;
            let refresh_at = Duration::from_secs((granted_expires as u64) / 2);
            entry.state = RegistrantState::Registered;
            entry.expires_at = Some(Instant::now() + Duration::from_secs(granted_expires as u64));
            entry.next_attempt = Instant::now() + refresh_at;
            entry.failure_count = 0;
            entry.backoff = Duration::from_secs(5);
            entry.last_sent_at = None;
            info!(
                aor = %entry.aor,
                expires = granted_expires,
                refresh_in = ?refresh_at,
                "registered successfully"
            );
            let aor_owned = entry.aor.clone();
            drop(entry);
            if was_registered {
                self.emit_event(RegistrantEvent::Refreshed { aor: aor_owned });
            } else {
                self.emit_event(RegistrantEvent::Registered { aor: aor_owned });
            }
        }
    }

    /// Handle a failure response (non-401/407, or auth failed twice).
    pub fn handle_failure(&self, aor: &str, status_code: u16) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.state = RegistrantState::Failed;
            entry.failure_count += 1;
            entry.expires_at = None;

            // Exponential backoff capped at max_retry_interval
            let backoff = std::cmp::min(
                entry.backoff * 2,
                self.max_retry_interval,
            );
            entry.backoff = backoff;
            entry.next_attempt = Instant::now() + backoff;

            warn!(
                aor = %entry.aor,
                status_code,
                failures = entry.failure_count,
                retry_in = ?backoff,
                "registration failed"
            );

            // Re-resolve DNS to try a different IP on next attempt
            if let Some(ref address_str) = entry.address_str {
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = address_str.to_socket_addrs() {
                    let old = entry.destination;
                    let new_addr = addrs.find(|a| *a != old)
                        .or_else(|| address_str.to_socket_addrs().ok()?.next());
                    if let Some(new_addr) = new_addr {
                        if new_addr != old {
                            info!(
                                aor = %entry.aor,
                                old = %old,
                                new = %new_addr,
                                "re-resolved registrar to different IP"
                            );
                            entry.destination = new_addr;
                        }
                    }
                }
            }

            let aor_owned = entry.aor.clone();
            drop(entry);
            self.emit_event(RegistrantEvent::Failed { aor: aor_owned, status_code });
        }
    }

    /// Get entries that are due for registration attempt.
    pub fn entries_due(&self) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|entry| entry.next_attempt <= now)
            .filter(|entry| matches!(
                entry.state,
                RegistrantState::Unregistered
                    | RegistrantState::Registered
                    | RegistrantState::Failed
            ))
            .map(|entry| entry.aor.clone())
            .collect()
    }

    /// RFC 3261 Timer F — non-INVITE transaction timeout (32 seconds).
    const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(32);

    /// Find entries stuck in `Registering` or `Challenging` past the
    /// transaction timeout (RFC 3261 Timer F, 32s).  The registration
    /// loop should treat these as transport-level failures.
    pub fn entries_timed_out(&self) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    RegistrantState::Registering | RegistrantState::Challenging
                ) && entry
                    .last_sent_at
                    .map(|sent| now.duration_since(sent) > Self::TRANSACTION_TIMEOUT)
                    .unwrap_or(false)
            })
            .map(|entry| entry.aor.clone())
            .collect()
    }

    /// Build de-registration (Expires: 0) for all active entries.
    pub fn build_deregistrations(
        &self,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
    ) -> Vec<(SipMessage, SocketAddr, Transport)> {
        // Collect AoRs first to avoid deadlock: iter() holds a read lock on
        // each DashMap shard, and build_register() needs a write lock (get_mut).
        let registered_aors: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.state == RegistrantState::Registered)
            .map(|entry| entry.aor.clone())
            .collect();

        let mut result = Vec::new();
        for aor in &registered_aors {
            if let Some((message, _branch, destination, transport)) =
                self.build_register(aor, local_addr, listen_addrs, 0)
            {
                result.push((message, destination, transport));
            }
        }
        result
    }

    /// Match an incoming response to a registrant entry by branch prefix.
    ///
    /// Returns the AoR if matched, plus the status code for processing.
    pub fn match_response(&self, branch: &str) -> Option<String> {
        if !branch.starts_with("z9hG4bK-reg-") {
            return None;
        }
        // Find entry by matching call_id in the response — but since we
        // can't easily do that here, we search all entries whose state is
        // Registering or Challenging.
        for entry in self.entries.iter() {
            if matches!(
                entry.state,
                RegistrantState::Registering | RegistrantState::Challenging
            ) {
                return Some(entry.aor.clone());
            }
        }
        None
    }

    /// More precise matching: find entry by Call-ID.
    pub fn find_by_call_id(&self, call_id: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|entry| entry.call_id == call_id)
            .map(|entry| entry.aor.clone())
    }
}

impl fmt::Debug for RegistrantManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrantManager")
            .field("entries", &self.entries.len())
            .field("default_interval", &self.default_interval)
            .finish()
    }
}

/// Background registration refresh loop.
///
/// Runs until the provided shutdown signal fires. On shutdown, sends
/// de-registration (Expires: 0) for all active bindings.
pub async fn registration_loop(
    manager: Arc<RegistrantManager>,
    outbound: Arc<OutboundRouter>,
    local_addr: SocketAddr,
    listen_addrs: HashMap<Transport, SocketAddr>,
    advertised_addrs: HashMap<Transport, String>,
    advertised_address: Option<String>,
    hep_sender: Option<Arc<HepSender>>,
    stream_connections: Option<StreamConnections>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let tick_interval = Duration::from_secs(5);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick_interval) => {
                // Detect connection loss on connection-oriented transports
                // (TLS/TCP/SCTP).  The pool removes dead connections from the
                // stream registry; if the registrar destination is gone, force
                // an immediate re-register instead of waiting for the
                // refresh timer.  The lookup is transport-filtered so an
                // unrelated WS/WSS UE sharing the trunk's IP can't mask a dead
                // trunk connection (preserves the pre-unification TLS-only
                // membership semantics exactly).
                if let Some(ref stream_connections) = stream_connections {
                    let stale: Vec<String> = manager.entries.iter()
                        .filter(|entry| {
                            entry.state == RegistrantState::Registered
                                && matches!(entry.transport, Transport::Tls | Transport::Tcp | Transport::Sctp)
                                && !stream_connections.has_ip_transport(entry.destination.ip(), entry.transport)
                        })
                        .map(|entry| entry.aor.clone())
                        .collect();
                    for aor in stale {
                        warn!(aor = %aor, "connection lost — forcing immediate re-register");
                        manager.refresh(&aor);
                    }
                }

                // Time out entries stuck in Registering/Challenging (RFC 3261
                // Timer F — 32s).  Catches dead sockets where no response
                // ever arrives.
                let timed_out = manager.entries_timed_out();
                for aor in &timed_out {
                    warn!(aor = %aor, "REGISTER transaction timed out — no response received");
                    manager.handle_failure(aor, 0);
                }

                let due = manager.entries_due();
                for aor in due {
                    if let Some((message, branch, destination, transport)) =
                        manager.build_register(&aor, local_addr, &listen_addrs, manager.default_interval)
                    {
                        let data = Bytes::from(message.to_bytes());

                        // HEP capture — outbound REGISTER
                        if let Some(ref hep) = hep_sender {
                            let via_addr = resolve_via_addr(local_addr, &transport, &advertised_addrs, advertised_address.as_deref());
                            hep.capture_outbound(via_addr, destination, transport, &data);
                        }

                        // UDP only: egress from the same local address advertised
                        // in the Via (build_register uses the same listen_addrs
                        // lookup), so the source port matches the Via and the
                        // response / conntrack return path is consistent. With
                        // multiple UDP listeners + IPsec, a `None` source picks a
                        // non-deterministic udp_default — the initial REGISTER
                        // could egress from a protected port (e.g. 6100) while the
                        // Via said 5060, breaking the 401 return path. For TCP/TLS
                        // the outbound connection is separate from the listener,
                        // so leave the source unpinned.
                        let source_local_addr = if transport == Transport::Udp {
                            Some(listen_addrs.get(&transport).copied().unwrap_or(local_addr))
                        } else {
                            None
                        };
                        let outbound_message = OutboundMessage {
                            connection_id: ConnectionId::default(),
                            transport,
                            destination,
                            data,
                            source_local_addr,
                            server_name: None,
                        };
                        debug!(aor = %aor, branch = %branch, "sending REGISTER");
                        if let Err(error) = outbound.send(outbound_message) {
                            warn!(aor = %aor, %error, "failed to send REGISTER");
                            manager.handle_failure(&aor, 0);
                        }
                    }
                }
            }
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    info!("registrant shutting down — de-registering all bindings");
                    let dereg_messages = manager.build_deregistrations(local_addr, &listen_addrs);
                    for (message, destination, transport) in dereg_messages {
                        let data = Bytes::from(message.to_bytes());

                        // HEP capture — outbound de-registration
                        if let Some(ref hep) = hep_sender {
                            let via_addr = resolve_via_addr(local_addr, &transport, &advertised_addrs, advertised_address.as_deref());
                            hep.capture_outbound(via_addr, destination, transport, &data);
                        }

                        let source_local_addr = if transport == Transport::Udp {
                            Some(listen_addrs.get(&transport).copied().unwrap_or(local_addr))
                        } else {
                            None
                        };
                        let outbound_message = OutboundMessage {
                            connection_id: ConnectionId::default(),
                            transport,
                            destination,
                            data,
                            source_local_addr,
                            server_name: None,
                        };
                        let _ = outbound.send(outbound_message);
                    }
                    break;
                }
            }
        }
    }
}

/// Methods the soft-UE advertises in `Allow` on IMS REGISTERs (RFC 3261 §20.5)
/// — what a real VoLTE handset offers, so the S-CSCF/AS see the supported set.
const IMS_ALLOW_METHODS: &str =
    "INVITE, ACK, OPTIONS, CANCEL, BYE, UPDATE, INFO, REFER, NOTIFY, MESSAGE, PRACK";

/// Build the Contact header value: `<contact_uri>` plus any IMS feature tags
/// (3GPP TS 24.229 §5.1.1.2 / GSMA IR.92). The instance ID, `q=1.0`, MMTel
/// ICSI, `video` and SMS-over-IP tags are emitted in handset order so the
/// S-CSCF registers the implied services. Without `ims`, just `<contact_uri>`.
fn build_contact_header(contact_uri: &str, ims: Option<&ImsContactParams>) -> String {
    let mut header = format!("<{}>", contact_uri);
    if let Some(ims) = ims {
        if let Some(ref imei) = ims.instance_id {
            header.push_str(&format!(";+sip.instance=\"<urn:gsma:imei:{imei}>\""));
        }
        header.push_str(";q=1.0");
        if ims.mmtel {
            header.push_str(";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"");
        }
        if ims.video {
            header.push_str(";video");
        }
        if ims.smsip {
            header.push_str(";+g.3gpp.smsip");
        }
    }
    header
}

/// Build a default Contact URI from the entry's username, effective address, and transport.
///
/// Appends `;transport=<proto>` for non-UDP transports (UDP is the default per RFC 3261).
fn default_contact_uri(username: &str, address: SocketAddr, transport: Transport) -> String {
    let transport_param = match transport {
        Transport::Udp => "",
        Transport::Tcp => ";transport=tcp",
        Transport::Tls => ";transport=tls",
        Transport::WebSocket => ";transport=ws",
        Transport::WebSocketSecure => ";transport=wss",
        Transport::Sctp => ";transport=sctp",
    };
    // For IMS the username is the IMPI (`user@home-domain`); the Contact
    // userpart is just the `user` portion — otherwise we'd emit a malformed
    // `sip:user@domain@ip:port` (two `@`). For a plain trunk username with no
    // `@`, this is a no-op.
    let user = username.split('@').next().unwrap_or(username);
    format!("sip:{}@{}{}", user, address, transport_param)
}

/// Parse a registrar URI ("sip:host:port" or "sip:host") into the REGISTER
/// Request-URI. Uses the full SIP-URI parser so host and port are split
/// correctly — `SipUri::new("host:port")` would put the whole thing in the
/// host field, and the IPv6 heuristic in `format_sip_host` would then bracket
/// it (`sip:[172.16.0.101:5060]`), which breaks the registrar's DNS/relay.
fn registrar_request_uri(registrar_uri: &str) -> SipUri {
    crate::sip::parser::parse_uri_standalone(registrar_uri).unwrap_or_else(|_| {
        SipUri::new(
            registrar_uri
                .strip_prefix("sip:")
                .or_else(|| registrar_uri.strip_prefix("sips:"))
                .unwrap_or(registrar_uri)
                .to_string(),
        )
    })
}

/// Build the empty-response Authorization header the UE puts on its initial
/// (unprotected) IMS REGISTER (RFC 3310 / TS 24.229). Carries the IMPI as
/// `username` so the network can fetch an authentication vector; `nonce` and
/// `response` are empty because no challenge has been received yet.
fn initial_aka_authorization(impi: &str, realm: &str, digest_uri: &str) -> String {
    format!(
        "Digest username=\"{impi}\", realm=\"{realm}\", uri=\"{digest_uri}\", nonce=\"\", response=\"\", algorithm=AKAv1-MD5"
    )
}

/// Extract the home-network domain (host) from an AoR/IMPU like
/// `sip:user@home.domain` or `sip:home.domain`, stripping any port/parameters.
/// Used as the digest realm on the initial IMS REGISTER when none is configured.
fn home_domain_from_aor(aor: &str) -> String {
    let without_scheme = aor
        .strip_prefix("sip:")
        .or_else(|| aor.strip_prefix("sips:"))
        .unwrap_or(aor);
    let host = without_scheme.rsplit('@').next().unwrap_or(without_scheme);
    host.split([':', ';']).next().unwrap_or(host).to_string()
}

/// Simple PRNG for cnonce generation — not cryptographic, just unique enough.
fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64);
    hasher.finish() as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_manager() -> RegistrantManager {
        RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            Some("SIPhon/test".to_string()),
        )
    }

    fn make_entry(aor: &str) -> RegistrantEntry {
        RegistrantEntry::new(
            aor.to_string(),
            "sip:registrar.carrier.com:5060".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            RegistrantCredentials {
                username: "alice".to_string(),
                password: "secret123".to_string(),
                realm: None,
            },
            3600,
            None,
        )
    }

    #[test]
    fn add_and_list() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.add(make_entry("sip:bob@carrier.com"));

        assert_eq!(manager.len(), 2);
        let list = manager.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn remove_entry() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        assert_eq!(manager.len(), 1);

        let removed = manager.remove("sip:alice@carrier.com");
        assert!(removed.is_some());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let manager = make_manager();
        assert!(manager.remove("sip:nobody@example.com").is_none());
    }

    #[test]
    fn initial_state_is_unregistered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Unregistered)
        );
    }

    #[test]
    fn entries_due_includes_new_entries() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let due = manager.entries_due();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], "sip:alice@carrier.com");
    }

    #[test]
    fn build_register_sets_registering() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        assert!(result.is_some());

        let (message, branch, destination, transport) = result.unwrap();
        assert!(branch.starts_with("z9hG4bK-reg-"));
        assert_eq!(destination, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Udp);

        // Check the message has correct headers
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("REGISTER"));
        assert!(raw.contains("sip:alice@carrier.com"));
        assert!(raw.contains("Expires: 3600"));
        assert!(raw.contains("Contact:"));

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Registering)
        );
    }

    #[test]
    fn build_register_tls_uses_correct_port_and_transport() {
        let manager = make_manager();
        let mut entry = make_entry("sip:trunk@carrier.com");
        entry.transport = Transport::Tls;
        entry.destination = "10.0.0.1:5061".parse().unwrap();
        manager.add(entry);

        let mut listen = HashMap::new();
        listen.insert(Transport::Tls, "172.16.0.153:5061".parse().unwrap());

        let result = manager.build_register(
            "sip:trunk@carrier.com",
            "172.16.0.153:5060".parse().unwrap(),
            &listen,
            3600,
        );
        assert!(result.is_some());

        let (message, _, _, transport) = result.unwrap();
        assert_eq!(transport, Transport::Tls);

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        // Contact should use TLS listen port and transport param
        assert!(
            raw.contains("172.16.0.153:5061;transport=tls"),
            "Contact should use TLS port 5061 and transport=tls: {raw}"
        );
        // Via should also use TLS port
        assert!(
            raw.contains("SIP/2.0/TLS 172.16.0.153:5061"),
            "Via should use TLS port 5061: {raw}"
        );
    }

    #[test]
    fn handle_success_transitions_to_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Simulate registration attempt
        let _ = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        manager.handle_success("sip:alice@carrier.com", 3600);

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Registered)
        );

        // Should not be due immediately — refresh at 50% of expires
        let due = manager.entries_due();
        assert!(due.is_empty());
    }

    #[test]
    fn handle_failure_transitions_to_failed_with_backoff() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_failure("sip:alice@carrier.com", 403);

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Failed)
        );

        // Should not be due immediately due to backoff
        let due = manager.entries_due();
        assert!(due.is_empty());
    }

    #[test]
    fn backoff_increases_on_repeated_failures() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // First failure
        manager.handle_failure("sip:alice@carrier.com", 503);
        let backoff_1 = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;

        // Override next_attempt to make it due again
        manager
            .entries
            .get_mut("sip:alice@carrier.com")
            .unwrap()
            .next_attempt = Instant::now();

        // Second failure
        manager.handle_failure("sip:alice@carrier.com", 503);
        let backoff_2 = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;

        assert!(backoff_2 > backoff_1);
    }

    #[test]
    fn backoff_capped_at_max() {
        let manager = RegistrantManager::new(
            3600,
            Duration::from_secs(10),
            Duration::from_secs(30),
            None,
        );
        manager.add(make_entry("sip:alice@carrier.com"));

        // Fail many times
        for _ in 0..20 {
            manager.handle_failure("sip:alice@carrier.com", 503);
        }

        let backoff = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;
        assert!(backoff <= Duration::from_secs(30));
    }

    #[test]
    fn success_resets_backoff_and_failure_count() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Fail a few times
        manager.handle_failure("sip:alice@carrier.com", 503);
        manager.handle_failure("sip:alice@carrier.com", 503);

        // Then succeed
        manager.handle_success("sip:alice@carrier.com", 3600);

        let entry = manager.entries.get("sip:alice@carrier.com").unwrap();
        assert_eq!(entry.failure_count, 0);
        assert_eq!(entry.backoff, Duration::from_secs(5));
    }

    #[test]
    fn refresh_resets_state_and_schedule() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        // Not due yet
        assert!(manager.entries_due().is_empty());

        // Force refresh
        assert!(manager.refresh("sip:alice@carrier.com"));

        // Now it should be due
        let due = manager.entries_due();
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn refresh_nonexistent_returns_false() {
        let manager = make_manager();
        assert!(!manager.refresh("sip:nobody@example.com"));
    }

    #[test]
    fn find_by_call_id() {
        let manager = make_manager();
        let entry = make_entry("sip:alice@carrier.com");
        let call_id = entry.call_id.clone();
        manager.add(entry);

        assert_eq!(
            manager.find_by_call_id(&call_id),
            Some("sip:alice@carrier.com".to_string())
        );
        assert!(manager.find_by_call_id("nonexistent-call-id").is_none());
    }

    #[test]
    fn expires_in_when_not_registered() {
        let entry = make_entry("sip:alice@carrier.com");
        assert_eq!(entry.expires_in(), 0);
    }

    #[test]
    fn cseq_increments() {
        let entry = make_entry("sip:alice@carrier.com");
        let first = entry.next_cseq();
        let second = entry.next_cseq();
        assert_eq!(second, first + 1);
    }

    #[test]
    fn state_display() {
        assert_eq!(RegistrantState::Unregistered.to_string(), "unregistered");
        assert_eq!(RegistrantState::Registering.to_string(), "registering");
        assert_eq!(RegistrantState::Challenging.to_string(), "challenging");
        assert_eq!(RegistrantState::Registered.to_string(), "registered");
        assert_eq!(RegistrantState::Failed.to_string(), "failed");
    }

    #[test]
    fn build_register_with_auth_sets_challenging() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let challenge = DigestChallenge {
            realm: "carrier.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: auth::DigestAlgorithm::Md5,
            stale: false,
        };

        let result = manager.build_register_with_auth(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            &challenge,
            false,
            3600,
        );
        assert!(result.is_some());

        let (message, branch, _, _) = result.unwrap();
        assert!(branch.starts_with("z9hG4bK-reg-"));

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Authorization:"));
        assert!(raw.contains("username=\"alice\""));
        assert!(raw.contains("realm=\"carrier.com\""));

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Challenging)
        );
    }

    #[test]
    fn build_deregistrations_only_for_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.add(make_entry("sip:bob@carrier.com"));

        // Register only alice
        manager.handle_success("sip:alice@carrier.com", 3600);

        let dereg = manager.build_deregistrations("127.0.0.1:5060".parse().unwrap(), &HashMap::new());
        assert_eq!(dereg.len(), 1);

        let bytes = dereg[0].0.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Expires: 0"));
    }

    #[test]
    fn concurrent_access() {
        let manager = Arc::new(make_manager());
        let mut handles = Vec::new();

        for index in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(std::thread::spawn(move || {
                let aor = format!("sip:user{}@carrier.com", index);
                manager.add(make_entry(&aor));
                manager.state(&aor);
                manager.list();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(manager.len(), 10);
    }

    #[test]
    fn is_empty_on_new_manager() {
        let manager = make_manager();
        assert!(manager.is_empty());
        manager.add(make_entry("sip:alice@carrier.com"));
        assert!(!manager.is_empty());
    }

    #[test]
    fn manager_debug() {
        let manager = make_manager();
        let debug = format!("{:?}", manager);
        assert!(debug.contains("RegistrantManager"));
        assert!(debug.contains("entries"));
    }

    #[test]
    fn event_emitted_on_first_registration() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_success("sip:alice@carrier.com", 3600);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Registered { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_refresh() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        let mut receiver = manager.subscribe_events();
        // Second success while already Registered → Refreshed
        manager.handle_success("sip:alice@carrier.com", 3600);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Refreshed { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_failure() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_failure("sip:alice@carrier.com", 503);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Failed { ref aor, status_code: 503 } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_remove() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.remove("sip:alice@carrier.com");

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Deregistered { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn no_event_on_remove_nonexistent() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();

        manager.remove("sip:nobody@carrier.com");

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn entry_info_returns_data() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        let (expires_in, failure_count, registrar) = manager.entry_info("sip:alice@carrier.com").unwrap();
        assert!(expires_in > 0);
        assert_eq!(failure_count, 0);
        assert_eq!(registrar, "sip:registrar.carrier.com:5060");
    }

    #[test]
    fn entry_info_none_for_missing() {
        let manager = make_manager();
        assert!(manager.entry_info("sip:nobody@carrier.com").is_none());
    }

    #[test]
    fn build_register_sets_last_sent_at() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Before building: no last_sent_at
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_none());

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // After building: last_sent_at should be set
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_some());
    }

    #[test]
    fn success_clears_last_sent_at() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_some());

        manager.handle_success("sip:alice@carrier.com", 3600);
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_none());
    }

    #[test]
    fn entries_timed_out_not_triggered_before_timeout() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Send a REGISTER (sets state to Registering + last_sent_at)
        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // Should not be timed out yet (just sent)
        assert!(manager.entries_timed_out().is_empty());
    }

    #[test]
    fn entries_timed_out_triggered_after_timeout() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // Simulate passage of time by backdating last_sent_at
        manager.entries.get_mut("sip:alice@carrier.com").unwrap().last_sent_at =
            Some(Instant::now() - Duration::from_secs(33));

        let timed_out = manager.entries_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], "sip:alice@carrier.com");
    }

    #[test]
    fn build_register_includes_user_agent() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            raw.contains("User-Agent: SIPhon/test"),
            "REGISTER should include User-Agent header: {raw}"
        );
    }

    #[test]
    fn build_register_omits_user_agent_when_none() {
        let manager = RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            None,
        );
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            !raw.contains("User-Agent:"),
            "REGISTER should not include User-Agent header when None: {raw}"
        );
    }

    #[test]
    fn build_register_with_auth_includes_user_agent() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let challenge = DigestChallenge {
            realm: "carrier.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: auth::DigestAlgorithm::Md5,
            stale: false,
        };

        let result = manager.build_register_with_auth(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            &challenge,
            false,
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            raw.contains("User-Agent: SIPhon/test"),
            "Authenticated REGISTER should include User-Agent header: {raw}"
        );
    }

    #[test]
    fn entries_timed_out_not_triggered_for_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Registered entries should never time out (even with stale last_sent_at)
        manager.handle_success("sip:alice@carrier.com", 3600);
        manager.entries.get_mut("sip:alice@carrier.com").unwrap().last_sent_at =
            Some(Instant::now() - Duration::from_secs(60));

        assert!(manager.entries_timed_out().is_empty());
    }

    // -- IMS AKA registration (Phase 1) --

    // 3GPP test IMSI range (MCC 001 / MNC 01) — never a real subscriber.
    const AKA_AOR: &str = "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
    const AKA_REALM: &str = "ims.mnc01.mcc001.3gppnetwork.org";

    fn make_aka_entry(aor: &str) -> RegistrantEntry {
        // TS 35.208 Test Set 1 secrets.
        let credentials = aka::AkaCredentials::from_hex(
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            None,
            Some("cd63cb71954a9f4e48a5994e37a02baf"),
            "b9b9",
        )
        .unwrap();
        RegistrantEntry::new(
            aor.to_string(),
            format!("sip:pcscf.{AKA_REALM}:5060"),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            RegistrantCredentials {
                username: "001010000000001@ims.mnc01.mcc001.3gppnetwork.org".to_string(),
                password: String::new(), // unused for AKA
                realm: Some(AKA_REALM.to_string()),
            },
            600000,
            None,
        )
        .with_aka(credentials, [0u8; 6])
    }

    /// Build a well-formed AKAv1-MD5 challenge for a given network SQN, using
    /// the same Test Set 1 secrets as `make_aka_entry` so Milenage verifies.
    fn build_aka_challenge(sqn_hex: &str) -> DigestChallenge {
        use crate::ipsec::milenage::{generate_vector_with_rand, hex_to_bytes};
        use base64::Engine as _;

        let to_array = |hex: &str, out: &mut [u8]| {
            out.copy_from_slice(&hex_to_bytes(hex).unwrap());
        };
        let mut key = [0u8; 16];
        to_array("465b5ce8b199b49faa5f0a2ee238a6bc", &mut key);
        let mut op = [0u8; 16];
        to_array("cdc202d5123e20f62b6d676ac72cb318", &mut op);
        let mut sqn = [0u8; 6];
        to_array(sqn_hex, &mut sqn);
        let mut rand = [0u8; 16];
        to_array("23553cbe9637a89d218ae64dae47bf35", &mut rand);
        let amf = [0xb9u8, 0xb9u8];

        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);
        let mut joined = Vec::new();
        joined.extend_from_slice(&vector.rand);
        joined.extend_from_slice(&vector.autn);
        let nonce = base64::engine::general_purpose::STANDARD.encode(&joined);

        DigestChallenge {
            realm: AKA_REALM.to_string(),
            nonce,
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: auth::DigestAlgorithm::AkaV1Md5,
            stale: false,
        }
    }

    #[test]
    fn build_register_initial_aka_carries_empty_auth() {
        let manager = make_manager();
        manager.add(make_aka_entry(AKA_AOR));

        let (message, _, _, _) = manager
            .build_register(AKA_AOR, "127.0.0.1:5060".parse().unwrap(), &HashMap::new(), 600000)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Authorization: Digest"), "{raw}");
        assert!(raw.contains("algorithm=AKAv1-MD5"));
        assert!(raw.contains("nonce=\"\""));
        assert!(raw.contains("response=\"\""));
        assert!(raw.contains(
            "username=\"001010000000001@ims.mnc01.mcc001.3gppnetwork.org\""
        ));
        assert!(raw.contains(&format!("realm=\"{AKA_REALM}\"")));
    }

    #[test]
    fn build_register_aka_success_advances_sqn() {
        let manager = make_manager();
        manager.add(make_aka_entry(AKA_AOR));

        let challenge = build_aka_challenge("ff9bb4d0b607");
        let result = manager.build_register_aka(
            AKA_AOR,
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            &challenge,
            600000,
            None,
        );
        assert!(result.is_some());

        let (message, branch, _, _) = result.unwrap();
        assert!(branch.starts_with("z9hG4bK-reg-"));
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Authorization: Digest"));
        assert!(raw.contains("algorithm=AKAv1-MD5"));
        assert!(!raw.contains("auts="), "fresh challenge must not resync: {raw}");

        let entry = manager.entries.get(AKA_AOR).unwrap();
        assert_eq!(entry.sqn_ms, [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]);
        assert_eq!(entry.state, RegistrantState::Challenging);
    }

    #[test]
    fn build_register_aka_resync_includes_auts() {
        let manager = make_manager();
        let mut entry = make_aka_entry(AKA_AOR);
        entry.sqn_ms = [0, 0, 0, 0, 0, 0x10]; // ahead of the challenge SQN (0x05)
        manager.add(entry);

        let challenge = build_aka_challenge("000000000005");
        let (message, _, _, _) = manager
            .build_register_aka(
                AKA_AOR,
                "127.0.0.1:5060".parse().unwrap(),
                &HashMap::new(),
                &challenge,
                600000,
                None,
            )
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("auts="), "SQN mismatch must emit AUTS: {raw}");
    }

    #[test]
    fn build_register_aka_mac_failure_returns_none() {
        use base64::Engine as _;
        let manager = make_manager();
        manager.add(make_aka_entry(AKA_AOR));

        let good = build_aka_challenge("ff9bb4d0b607");
        // Corrupt the AUTN MAC (bytes 24..32 of RAND‖AUTN) so authentication fails.
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(good.nonce.as_bytes())
            .unwrap();
        bytes[24] ^= 0xff;
        let corrupted = DigestChallenge {
            nonce: base64::engine::general_purpose::STANDARD.encode(&bytes),
            ..good
        };

        assert!(manager
            .build_register_aka(
                AKA_AOR,
                "127.0.0.1:5060".parse().unwrap(),
                &HashMap::new(),
                &corrupted,
                600000,
                None,
            )
            .is_none());
    }

    #[test]
    fn auth_mode_reports_digest_and_aka() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.add(make_aka_entry(AKA_AOR));
        assert_eq!(manager.auth_mode("sip:alice@carrier.com"), Some(AuthMode::Digest));
        assert_eq!(manager.auth_mode(AKA_AOR), Some(AuthMode::Aka));
        assert_eq!(manager.auth_mode("sip:nobody@x.com"), None);
    }

    #[test]
    fn store_and_get_registration_routes() {
        let manager = make_manager();
        manager.add(make_aka_entry(AKA_AOR));

        manager.store_registration_routes(
            AKA_AOR,
            vec![format!("<sip:scscf.{AKA_REALM}:6060;lr>")],
            vec![
                AKA_AOR.to_string(),
                "tel:+15551234567".to_string(),
            ],
            vec![format!("<sip:pcscf.{AKA_REALM}:5060;lr>")],
        );

        assert_eq!(manager.service_route(AKA_AOR).len(), 1);
        assert_eq!(manager.associated_uris(AKA_AOR).len(), 2);
        assert!(manager.service_route("sip:nobody@x.com").is_empty());
    }

    #[test]
    fn home_domain_extraction() {
        assert_eq!(home_domain_from_aor(AKA_AOR), AKA_REALM);
        assert_eq!(home_domain_from_aor("sip:ims.example.com:5060"), "ims.example.com");
        assert_eq!(
            home_domain_from_aor("sip:user@host.com;transport=tcp"),
            "host.com"
        );
    }

    #[test]
    fn build_contact_header_emits_ims_feature_tags() {
        // No IMS params → plain Contact.
        assert_eq!(
            build_contact_header("sip:bob@10.0.0.2:5060", None),
            "<sip:bob@10.0.0.2:5060>"
        );

        // Full handset-shaped tag set, in order.
        let ims = ImsContactParams {
            instance_id: Some("35436012-861541-0".to_string()),
            mmtel: true,
            video: true,
            smsip: true,
        };
        let header = build_contact_header("sip:208909990000002@100.65.0.4:5060", Some(&ims));
        assert!(header.starts_with("<sip:208909990000002@100.65.0.4:5060>"));
        assert!(header.contains(";+sip.instance=\"<urn:gsma:imei:35436012-861541-0>\""));
        assert!(header.contains(";q=1.0"));
        assert!(header
            .contains(";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""));
        assert!(header.contains(";video"));
        assert!(header.contains(";+g.3gpp.smsip"));

        // No mmtel → no ICSI; q=1.0 still emitted when IMS params present.
        let minimal = ImsContactParams::default();
        assert_eq!(
            build_contact_header("sip:x@y:5060", Some(&minimal)),
            "<sip:x@y:5060>;q=1.0"
        );
    }

    /// Regression: an IPv4:port registrar must produce a clean Request-URI
    /// (no IPv6 brackets), and an IMPI username (user@domain) must produce a
    /// single-`@` Contact. Both broke the live REGISTER (P-CSCF 502 + DNS fail).
    #[test]
    fn build_register_ip_registrar_and_impi_contact_are_well_formed() {
        let manager = make_manager();
        // 3GPP test range; IMPI username + IPv4:port registrar — the combo
        // that produced `sip:[172.16.0.101:5060]` and `user@domain@ip`.
        let credentials = aka::AkaCredentials::from_hex(
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            None,
            Some("cd63cb71954a9f4e48a5994e37a02baf"),
            "b9b9",
        )
        .unwrap();
        let aor = "sip:001019999999999@ims.mnc01.mcc001.3gppnetwork.org";
        let entry = RegistrantEntry::new(
            aor.to_string(),
            "sip:172.16.0.101:5060".to_string(),
            "172.16.0.101:5060".parse().unwrap(),
            Transport::Udp,
            RegistrantCredentials {
                username: "001019999999999@ims.mnc01.mcc001.3gppnetwork.org".to_string(),
                password: String::new(),
                realm: Some("ims.mnc01.mcc001.3gppnetwork.org".to_string()),
            },
            3600,
            None,
        )
        .with_aka(credentials, [0u8; 6]);
        manager.add(entry);

        let (message, _, _, _) = manager
            .build_register(aor, "100.65.0.3:5060".parse().unwrap(), &HashMap::new(), 3600)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);

        // Request-URI: IPv4:port, no brackets.
        assert!(
            raw.starts_with("REGISTER sip:172.16.0.101:5060 SIP/2.0"),
            "R-URI must not be bracketed: {raw}"
        );
        assert!(!raw.contains("sip:[172.16.0.101"), "{raw}");

        // Via carries rport (RFC 3581) so the P-CSCF can respond to the actual
        // source port (NAT / symmetric-response robustness).
        assert!(raw.contains(";branch="), "{raw}");
        assert!(raw.contains(";rport"), "Via must carry rport: {raw}");

        // Contact: single @, userpart only (domain stripped).
        assert!(
            raw.contains("Contact: <sip:001019999999999@100.65.0.3:5060>"),
            "Contact must be single-@: {raw}"
        );
        assert!(!raw.contains("3gppnetwork.org@100.65.0.3"), "{raw}");
    }

    fn make_aka_ipsec_entry(aor: &str) -> RegistrantEntry {
        make_aka_entry(aor).with_ipsec(UeIpsec::new(
            6100,
            6101,
            IntegrityAlgorithm::HmacSha1,
            EncryptionAlgorithm::Null,
        ))
    }

    #[test]
    fn allocate_ue_spi_pair_is_monotonic_and_paired() {
        let manager = make_manager();
        let (a0, a1) = manager.allocate_ue_spi_pair();
        let (b0, b1) = manager.allocate_ue_spi_pair();
        assert_eq!(a1, a0 + 1);
        assert_eq!(b1, b0 + 1);
        assert_eq!(b0, a0 + 2);
        // Above the default P-CSCF partition and well clear of the RFC 4303
        // reserved 1..255 range, but a normal magnitude (not 0x20000000).
        assert!(a0 >= 50_000);
    }

    #[test]
    fn build_register_ipsec_emits_security_client() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));

        let (message, _, _, _) = manager
            .build_register(AKA_AOR, "127.0.0.1:5060".parse().unwrap(), &HashMap::new(), 600000)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);

        // Handset-shaped Security-Client: mandatory prot=esp;mod=trans, and one
        // mechanism per offered algorithm (SHA-1 + MD5).
        assert!(raw.contains("Security-Client: ipsec-3gpp;prot=esp;mod=trans;"), "{raw}");
        assert!(raw.contains("alg=hmac-sha-1-96"));
        assert!(raw.contains("alg=hmac-md5-96"));
        assert!(raw.contains("ealg=null"));
        assert!(raw.contains("port-c=6100;port-s=6101"));
        assert!(raw.contains("Require: sec-agree"));
        assert!(raw.contains("Proxy-Require: sec-agree"));
        assert!(raw.contains("Supported: path, sec-agree"));
        assert!(raw.contains("Allow: INVITE, ACK, OPTIONS"));

        // SPIs were allocated (sane magnitude) and appear in the header.
        let entry = manager.entries.get(AKA_AOR).unwrap();
        let ipsec = entry.ue_ipsec.as_ref().unwrap();
        assert!(ipsec.spi_uc >= 50_000);
        assert_eq!(ipsec.spi_us, ipsec.spi_uc + 1);
        assert!(raw.contains(&format!("spi-c={}", ipsec.spi_uc)));
        assert!(raw.contains(&format!("spi-s={}", ipsec.spi_us)));
    }

    /// The user's SPI concern: the spi-c advertised in Security-Client MUST be
    /// the exact value installed as the UE inbound SA (`spi_uc`) — a mismatch
    /// silently breaks decryption of the protected REGISTER.
    #[test]
    fn advertised_security_client_spi_matches_installed_sa() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));
        let local = "127.0.0.1:5060".parse().unwrap();

        // Initial REGISTER allocates the SPIs.
        manager.build_register(AKA_AOR, local, &HashMap::new(), 600000).unwrap();
        // Record server answer + run the challenge so the SA descriptor exists.
        let server = crate::ipsec::parse_security_client(SECURITY_SERVER).unwrap();
        manager.store_security_server(AKA_AOR, &server, SECURITY_SERVER);
        let challenge = build_aka_challenge("ff9bb4d0b607");
        manager
            .build_register_aka(AKA_AOR, local, &HashMap::new(), &challenge, 600000, Some(SECURITY_SERVER))
            .unwrap();

        let advertised = manager.entries.get(AKA_AOR).unwrap().ue_ipsec.as_ref().unwrap().spi_uc;
        let sa = manager
            .ue_sa_pair(AKA_AOR, "127.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap(), Some(600000), SaProtocol::Any)
            .expect("SA descriptor");
        assert_eq!(advertised, sa.spi_uc, "advertised spi-c must equal installed UE inbound SA SPI");
        assert!(sa.spi_uc >= 256, "RFC 4303 §2.1: SPI must be >= 256");
    }

    #[test]
    fn build_register_aka_without_ipsec_has_no_security_client() {
        let manager = make_manager();
        manager.add(make_aka_entry(AKA_AOR)); // AKA but no IPsec

        let (message, _, _, _) = manager
            .build_register(AKA_AOR, "127.0.0.1:5060".parse().unwrap(), &HashMap::new(), 600000)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("Security-Client"), "{raw}");
        assert!(!raw.contains("sec-agree"), "{raw}");
    }

    #[test]
    fn deregister_does_not_reoffer_security_client() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));

        // expires == 0 → de-REGISTER must not carry a fresh Security-Client.
        let (message, _, _, _) = manager
            .build_register(AKA_AOR, "127.0.0.1:5060".parse().unwrap(), &HashMap::new(), 0)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("Security-Client"), "{raw}");
    }

    const SECURITY_SERVER: &str =
        "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=55555; spi-s=66666; port-c=5064; port-s=5066";

    /// Drive the full UE handshake message flow: initial REGISTER (allocates UE
    /// SPIs + Security-Client) → record Security-Server → protected REGISTER.
    #[test]
    fn build_register_aka_protected_carries_security_verify_and_targets_protected_port() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));
        let local = "127.0.0.1:5060".parse().unwrap();

        // Initial REGISTER allocates the UE SPIs (stored on the entry).
        manager.build_register(AKA_AOR, local, &HashMap::new(), 600000).unwrap();

        // Record the P-CSCF's Security-Server answer.
        let server = crate::ipsec::parse_security_client(SECURITY_SERVER).unwrap();
        manager.store_security_server(AKA_AOR, &server, SECURITY_SERVER);

        // Protected re-REGISTER.
        let challenge = build_aka_challenge("ff9bb4d0b607");
        let (message, _, destination, _) = manager
            .build_register_aka(AKA_AOR, local, &HashMap::new(), &challenge, 600000, Some(SECURITY_SERVER))
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);

        assert!(raw.contains(&format!("Security-Verify: {SECURITY_SERVER}")), "{raw}");
        // RFC 3329: Security-Client repeated on the protected request.
        assert!(raw.contains("Security-Client: ipsec-3gpp"), "{raw}");
        assert!(raw.contains("Authorization: Digest"));
        // Protected REGISTER targets the P-CSCF protected server port (5066),
        // not the initial 5060.
        assert_eq!(destination.port(), 5066, "must target pcscf_port_s");

        // CK/IK were stashed for the SA install.
        let entry = manager.entries.get(AKA_AOR).unwrap();
        let ipsec = entry.ue_ipsec.as_ref().unwrap();
        assert!(ipsec.ck.is_some());
        assert!(ipsec.ik.is_some());
        assert_eq!(ipsec.spi_pc, 55555);
        assert_eq!(ipsec.spi_ps, 66666);
        assert_eq!(ipsec.pcscf_port_s, 5066);
    }

    #[test]
    fn ue_sa_pair_built_after_challenge_and_server_answer() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));
        let local = "127.0.0.1:5060".parse().unwrap();
        manager.build_register(AKA_AOR, local, &HashMap::new(), 600000).unwrap();

        let ue_addr: IpAddr = "127.0.0.1".parse().unwrap();
        let pcscf_addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Before the server answer → no SA descriptor.
        assert!(manager
            .ue_sa_pair(AKA_AOR, ue_addr, pcscf_addr, Some(600000), SaProtocol::Any)
            .is_none());

        let server = crate::ipsec::parse_security_client(SECURITY_SERVER).unwrap();
        manager.store_security_server(AKA_AOR, &server, SECURITY_SERVER);
        // Still no CK/IK until a challenge runs.
        assert!(manager
            .ue_sa_pair(AKA_AOR, ue_addr, pcscf_addr, Some(600000), SaProtocol::Any)
            .is_none());

        // Run the challenge (stashes CK/IK).
        let challenge = build_aka_challenge("ff9bb4d0b607");
        manager
            .build_register_aka(AKA_AOR, local, &HashMap::new(), &challenge, 600000, Some(SECURITY_SERVER))
            .unwrap();

        let sa = manager
            .ue_sa_pair(AKA_AOR, ue_addr, pcscf_addr, Some(600000), SaProtocol::Any)
            .expect("SA descriptor ready");
        assert_eq!(sa.role, SaRole::Ue);
        assert_eq!(sa.ue_addr, ue_addr);
        assert_eq!(sa.pcscf_addr, pcscf_addr);
        assert_eq!(sa.spi_pc, 55555);
        assert_eq!(sa.spi_ps, 66666);
        assert_eq!(sa.pcscf_port_s, 5066);
        assert_eq!(sa.ue_port_c, 6100);
        // NULL encryption → empty encryption key; HMAC-SHA-1 integrity key is
        // the 128-bit IK zero-padded to 20 bytes (40 hex chars).
        assert!(sa.encryption_key.is_empty());
        assert_eq!(sa.integrity_key.len(), 40);
        assert!(sa.integrity_key.ends_with("00000000"));
    }

    #[test]
    fn ipsec_helpers_report_entry_state() {
        let manager = make_manager();
        manager.add(make_aka_ipsec_entry(AKA_AOR));
        manager.add(make_aka_entry("sip:plain@ims.mnc01.mcc001.3gppnetwork.org"));

        assert!(manager.is_ipsec_entry(AKA_AOR));
        assert!(!manager.is_ipsec_entry("sip:plain@ims.mnc01.mcc001.3gppnetwork.org"));
        assert_eq!(manager.ue_protected_client_port(AKA_AOR), Some(6100));
        assert_eq!(
            manager.ue_protected_client_port("sip:plain@ims.mnc01.mcc001.3gppnetwork.org"),
            None
        );
    }

    #[test]
    fn aka_mode_does_not_disturb_digest_entries() {
        // A digest entry's initial REGISTER must NOT gain an AKA Authorization.
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        let (message, _, _, _) = manager
            .build_register("sip:alice@carrier.com", "127.0.0.1:5060".parse().unwrap(), &HashMap::new(), 3600)
            .unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("Authorization"), "digest initial REGISTER has no auth: {raw}");
    }
}
