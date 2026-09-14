//! `listen:` transport listeners, `domain:`, and the DSCP helpers they use.

use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// DSCP / DiffServ — RFC 4594 signaling QoS
// ---------------------------------------------------------------------------

/// Parse a DSCP name (CS0–CS7, AF11–AF43, EF, BE) or a raw integer 0–63.
pub fn parse_dscp(value: &str) -> std::result::Result<u8, String> {
    match value.to_uppercase().as_str() {
        "CS0" | "BE" => Ok(0),
        "CS1" => Ok(8),
        "AF11" => Ok(10),
        "AF12" => Ok(12),
        "AF13" => Ok(14),
        "CS2" => Ok(16),
        "AF21" => Ok(18),
        "AF22" => Ok(20),
        "AF23" => Ok(22),
        "CS3" => Ok(24),
        "AF31" => Ok(26),
        "AF32" => Ok(28),
        "AF33" => Ok(30),
        "CS4" => Ok(32),
        "AF41" => Ok(34),
        "AF42" => Ok(36),
        "AF43" => Ok(38),
        "CS5" => Ok(40),
        "EF" => Ok(46),
        "CS6" => Ok(48),
        "CS7" => Ok(56),
        _ => value
            .parse::<u8>()
            .map_err(|_| format!("invalid DSCP value: {value}"))
            .and_then(|v| {
                if v <= 63 {
                    Ok(v)
                } else {
                    Err(format!("DSCP must be 0-63, got {v}"))
                }
            }),
    }
}

/// Convert a 6-bit DSCP value to the 8-bit TOS byte (RFC 2474 §3).
/// Default UDP receive-buffer floor: 1 MiB per listener socket.
///
/// Roughly 5x the usual kernel default, which is enough to ride out a
/// scheduler stall at the throughput siphon targets, while staying small
/// enough that `worker_count` sockets do not meaningfully dent a
/// memory-capped container's cgroup budget.
///
/// It is a floor rather than a fixed size precisely because it is a default:
/// a host tuned above it has an operator's decision behind that number, and a
/// shipped constant must not quietly override one.
fn default_udp_recv_buffer_bytes() -> usize {
    1024 * 1024
}

pub fn dscp_to_tos(dscp: u8) -> u32 {
    (dscp as u32) << 2
}

/// Default DSCP: CS3 (24) — RFC 4594 Signaling class for SIP.
fn default_dscp() -> Option<u8> {
    Some(24)
}

/// Serde deserializer accepting either a DSCP name string or a raw integer.
fn deserialize_dscp<'de, D>(deserializer: D) -> std::result::Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DscpValue {
        Int(u64),
        Str(String),
    }

    let value: Option<DscpValue> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(DscpValue::Int(n)) => {
            if n > 63 {
                Err(de::Error::custom(format!("DSCP must be 0-63, got {n}")))
            } else {
                Ok(Some(n as u8))
            }
        }
        Some(DscpValue::Str(s)) => parse_dscp(&s).map(Some).map_err(de::Error::custom),
    }
}

// ---------------------------------------------------------------------------
// Transport listeners
// ---------------------------------------------------------------------------

/// A listen entry: either a plain address string or a struct with an
/// optional advertised address (like OpenSIPS `socket ... as ...`).
///
/// ```yaml
/// listen:
///   tcp:
///     - "10.0.0.1:5060"                          # plain string
///     - address: "10.0.0.1:5061"                  # struct form
///       advertise: "sip.example.com"              #   with advertised host
/// ```
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum ListenEntry {
    /// Plain address string (e.g. `"10.0.0.1:5060"`).
    Plain(String),
    /// Address with optional advertised host and per-listener DSCP override.
    Extended {
        address: String,
        #[serde(default)]
        advertise: Option<String>,
        /// Per-listener DSCP override (0–63 or name like "CS3", "EF").
        #[serde(default, deserialize_with = "deserialize_dscp")]
        dscp: Option<u8>,
    },
}

impl ListenEntry {
    /// The bind address string.
    pub fn address(&self) -> &str {
        match self {
            ListenEntry::Plain(addr) => addr,
            ListenEntry::Extended { address, .. } => address,
        }
    }

    /// The advertised host (if configured).
    pub fn advertise(&self) -> Option<&str> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { advertise, .. } => advertise.as_deref(),
        }
    }

    /// Per-listener DSCP override (if configured).
    pub fn dscp(&self) -> Option<u8> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { dscp, .. } => *dscp,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    /// Global DSCP value applied to all listeners (default: CS3 = 24).
    /// Per-listener `dscp` in the extended form overrides this.
    /// Set to `0` or `"BE"` to disable marking.
    #[serde(default = "default_dscp", deserialize_with = "deserialize_dscp")]
    pub dscp: Option<u8>,
    /// Path MTU in bytes for the outbound UDP request path (RFC 3261 §18.1.1).
    /// When set, an outbound SIP *request* built for UDP whose serialised length
    /// exceeds `mtu - 200` is sent over TCP instead (if a TCP path to the
    /// destination is reachable), else it falls back to UDP with a warning.
    /// Default `None` (off) — existing UDP-at-any-size deployments are unchanged.
    /// `1280` (the IPv6 minimum MTU) is a safe dual-stack lower bound for IMS
    /// core legs. Responses follow the transport of the request they answer;
    /// the inbound side is unaffected.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Minimum receive-buffer size in bytes (`SO_RCVBUF`) for every UDP
    /// listener socket. Default 1 MiB.
    ///
    /// A **floor, not a target**: a host whose `net.core.rmem_default` already
    /// exceeds this keeps its larger buffer. Applying it unconditionally would
    /// shrink the queue on a tuned host, and silently, because an untouched
    /// socket reports `rmem_default` raw while an explicit request comes back
    /// doubled — so 1 MiB against a 4 MiB default lands at 2 MiB with nothing
    /// clamped and no warning to show for it.
    ///
    /// The kernel default (`net.core.rmem_default`, typically ~212 KB) is a
    /// few hundred milliseconds of headroom at IMS registration rates, so a
    /// scheduler stall on a busy box overflows the socket queue and the kernel
    /// drops datagrams silently — which a UAC sees as a retransmit, not an
    /// error, and which shows up as a sharp cliff rather than gradual
    /// degradation. `SO_REUSEPORT` gives one socket per worker, so the real
    /// cost is this value times the worker count.
    ///
    /// Socket buffers are charged to the process's cgroup, so raise this
    /// deliberately on a memory-capped deployment. `net.core.rmem_max` caps
    /// what the kernel will actually grant; siphon reads the value back and
    /// warns when it was clamped. `0` leaves the kernel default in place.
    #[serde(default = "default_udp_recv_buffer_bytes")]
    pub udp_recv_buffer_bytes: usize,
    #[serde(default)]
    pub udp: Vec<ListenEntry>,
    #[serde(default)]
    pub tcp: Vec<ListenEntry>,
    #[serde(default)]
    pub tls: Vec<ListenEntry>,
    /// WebSocket (ws://) — browser/WebRTC UEs.
    #[serde(default)]
    pub ws: Vec<ListenEntry>,
    /// Secure WebSocket (wss://) — browser/WebRTC UEs.
    #[serde(default)]
    pub wss: Vec<ListenEntry>,
    /// SCTP (RFC 4168) — used between IMS core nodes.
    #[serde(default)]
    pub sctp: Vec<ListenEntry>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            dscp: default_dscp(),
            mtu: None,
            udp_recv_buffer_bytes: default_udp_recv_buffer_bytes(),
            udp: Vec::new(),
            tcp: Vec::new(),
            tls: Vec::new(),
            ws: Vec::new(),
            wss: Vec::new(),
            sctp: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Network identity
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct DomainConfig {
    pub local: Vec<String>,
}
