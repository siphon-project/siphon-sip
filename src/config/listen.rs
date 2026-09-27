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

/// What a listener tells peers to use in Via / Record-Route / Contact: a host,
/// and optionally a port other than the one the socket binds.
///
/// The port exists for listeners behind a front that translates it: the front
/// owns the public port and forwards to a different inner one, so a header
/// naming the bound port points at a port nothing serves. Without a port the
/// bound port is advertised, which is what every listener did before.
///
/// Accepted forms (parsed once, at config load):
///
/// - `sip.example.com` / `192.0.2.10` / `2001:db8::1` / `[2001:db8::1]`: host only
/// - `sip.example.com:5061` / `192.0.2.10:5061`: host and port
/// - `[2001:db8::1]:5061`: IPv6 literal and port (the brackets are mandatory
///   with a port, RFC 3261 §25.1: `2001:db8::1:5061` is itself a valid address)
///
/// `host` keeps the spelling it was written in (a bracketed v6 literal stays
/// bracketed), so every consumer that formats it for SIP sees exactly what a
/// host-only `advertise` has always handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisedAddress {
    /// Host (FQDN or IP literal) to put in peer-facing headers.
    pub host: String,
    /// Port to put in peer-facing headers; `None` advertises the bound port.
    pub port: Option<u16>,
}

impl AdvertisedAddress {
    /// A host-only advertised address (the bound port is advertised).
    pub fn host_only(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
        }
    }

    /// Parse `host`, `host:port` or `[v6]:port`, rejecting anything that would
    /// put a malformed host or port on the wire.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        if value.is_empty() {
            return Err("must name a host, got an empty value".to_string());
        }
        if value.trim() != value {
            return Err(format!("'{value}' has leading or trailing whitespace"));
        }

        if let Some(rest) = value.strip_prefix('[') {
            let Some((inner, after)) = rest.split_once(']') else {
                return Err(format!("'{value}': unterminated '[' in an IPv6 literal"));
            };
            if inner.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!(
                    "'{value}': '{inner}' inside the brackets is not an IPv6 address"
                ));
            }
            let host = format!("[{inner}]");
            if after.is_empty() {
                return Ok(Self { host, port: None });
            }
            let Some(port) = after.strip_prefix(':') else {
                return Err(format!(
                    "'{value}': expected ':<port>' after the IPv6 literal, got '{after}'"
                ));
            };
            return Ok(Self {
                host,
                port: Some(parse_advertised_port(value, port)?),
            });
        }

        // A bare IP literal, v6 included: `2001:db8::1` is an address, never an
        // address plus a port, so it cannot carry one without brackets.
        if value.parse::<std::net::IpAddr>().is_ok() {
            return Ok(Self::host_only(value));
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => {
                return Err(format!(
                    "'{value}' is neither a host nor host:port (an IPv6 literal with a port \
                     must be bracketed, e.g. '[2001:db8::1]:5061')"
                ));
            }
            Some((host, port)) => (host, Some(parse_advertised_port(value, port)?)),
            None => (value, None),
        };
        validate_advertised_hostname(value, host)?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

impl std::fmt::Display for AdvertisedAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(
                formatter,
                "{}:{port}",
                crate::sip::uri::format_sip_host(&self.host)
            ),
            None => formatter.write_str(&self.host),
        }
    }
}

fn parse_advertised_port(value: &str, port: &str) -> std::result::Result<u16, String> {
    match port.parse::<u16>() {
        Ok(0) => Err(format!("'{value}': port 0 cannot be advertised")),
        Ok(port) => Ok(port),
        Err(_) => Err(format!("'{value}': '{port}' is not a port (1-65535)")),
    }
}

/// A non-literal host must be something a peer can put in a SIP URI: RFC 3261
/// §25.1 `hostname` characters (alphanumerics, `-` and `.`; `_` is tolerated for
/// the internal names operators do use), and not empty.
fn validate_advertised_hostname(value: &str, host: &str) -> std::result::Result<(), String> {
    if host.is_empty() {
        return Err(format!("'{value}' has a port but no host"));
    }
    if let Some(bad) = host.chars().find(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_'))
    }) {
        return Err(format!(
            "'{value}': '{bad}' is not valid in a hostname (use an FQDN or an IP literal)"
        ));
    }
    Ok(())
}

/// A listen entry: either a plain address string or a struct with an
/// optional advertised address (like OpenSIPS `socket ... as ...`).
///
/// ```yaml
/// listen:
///   tcp:
///     - "10.0.0.1:5060"                          # plain string
///     - address: "10.0.0.1:5061"                  # struct form
///       advertise: "sip.example.com"              #   with advertised host
///     - address: "10.0.0.1:15061"
///       advertise: "sip.example.com:5061"         #   host and the port a
///                                                 #   front translates to
/// ```
///
/// Deserialised through [`RawListenEntry`] so a malformed `advertise` fails the
/// load with its own message: an untagged enum reports only "did not match any
/// variant", which names neither the field nor the value.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(try_from = "RawListenEntry")]
pub enum ListenEntry {
    /// Plain address string (e.g. `"10.0.0.1:5060"`).
    Plain(String),
    /// Address with optional advertised host and per-listener DSCP override.
    Extended {
        address: String,
        /// What peers are told in Via / Record-Route / Contact: a host, and a
        /// port when a front translates it.
        advertise: Option<AdvertisedAddress>,
        /// Per-listener DSCP override (0–63 or name like "CS3", "EF").
        dscp: Option<u8>,
        /// Accept the HAProxy PROXY protocol on this listener, and take the
        /// client address from it (stream transports only).
        ///
        /// Off unless configured. `from` is mandatory when it is set and has no
        /// default: a header lets its sender claim any source address, and
        /// `security.trusted_cidrs` means something else entirely ("exempt from
        /// abuse controls"), so inheriting it would hand that power to every
        /// monitoring box listed there.
        proxy_protocol: Option<ProxyProtocolConfig>,
    },
}

/// The on-disk shape of a [`ListenEntry`], before `advertise` is parsed.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawListenEntry {
    Plain(String),
    Extended {
        address: String,
        #[serde(default)]
        advertise: Option<String>,
        #[serde(default, deserialize_with = "deserialize_dscp")]
        dscp: Option<u8>,
        #[serde(default)]
        proxy_protocol: Option<ProxyProtocolConfig>,
    },
}

impl TryFrom<RawListenEntry> for ListenEntry {
    type Error = String;

    fn try_from(raw: RawListenEntry) -> std::result::Result<Self, Self::Error> {
        match raw {
            RawListenEntry::Plain(address) => Ok(ListenEntry::Plain(address)),
            RawListenEntry::Extended {
                address,
                advertise,
                dscp,
                proxy_protocol,
            } => {
                let advertise = advertise
                    .map(|value| {
                        AdvertisedAddress::parse(&value)
                            .map_err(|error| format!("listen[{address}].advertise: {error}"))
                    })
                    .transpose()?;
                Ok(ListenEntry::Extended {
                    address,
                    advertise,
                    dscp,
                    proxy_protocol,
                })
            }
        }
    }
}

/// Per-listener PROXY protocol settings.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// Senders allowed to assert a client address. Validated at config load;
    /// an empty list is refused rather than silently accepting nobody.
    pub from: Vec<String>,
}

impl ListenEntry {
    /// The bind address string.
    pub fn address(&self) -> &str {
        match self {
            ListenEntry::Plain(addr) => addr,
            ListenEntry::Extended { address, .. } => address,
        }
    }

    /// The advertised host and optional port (if configured).
    pub fn advertise(&self) -> Option<&AdvertisedAddress> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { advertise, .. } => advertise.as_ref(),
        }
    }

    /// Per-listener DSCP override (if configured).
    pub fn dscp(&self) -> Option<u8> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { dscp, .. } => *dscp,
        }
    }

    /// PROXY protocol settings for this listener, when it sits behind a front.
    pub fn proxy_protocol(&self) -> Option<&ProxyProtocolConfig> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { proxy_protocol, .. } => proxy_protocol.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_address_host_only_keeps_the_bound_port() {
        let parsed = AdvertisedAddress::parse("sip.example.com").unwrap();
        assert_eq!(parsed, AdvertisedAddress::host_only("sip.example.com"));
        assert_eq!(parsed.port, None);
    }

    #[test]
    fn advertised_address_parses_host_and_port() {
        let parsed = AdvertisedAddress::parse("sip.example.com:5061").unwrap();
        assert_eq!(parsed.host, "sip.example.com");
        assert_eq!(parsed.port, Some(5061));

        let parsed = AdvertisedAddress::parse("192.0.2.10:15060").unwrap();
        assert_eq!(parsed.host, "192.0.2.10");
        assert_eq!(parsed.port, Some(15060));
    }

    #[test]
    fn advertised_address_parses_bracketed_ipv6_with_and_without_port() {
        let parsed = AdvertisedAddress::parse("[2001:db8::1]:5061").unwrap();
        assert_eq!(parsed.host, "[2001:db8::1]");
        assert_eq!(parsed.port, Some(5061));

        let parsed = AdvertisedAddress::parse("[2001:db8::1]").unwrap();
        assert_eq!(parsed.host, "[2001:db8::1]");
        assert_eq!(parsed.port, None);
    }

    #[test]
    fn advertised_address_bare_ip_literals_are_host_only() {
        // `2001:db8::1` is an address, never an address plus port 1.
        let parsed = AdvertisedAddress::parse("2001:db8::1").unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, None);
        let parsed = AdvertisedAddress::parse("203.0.113.10").unwrap();
        assert_eq!(parsed, AdvertisedAddress::host_only("203.0.113.10"));
    }

    #[test]
    fn advertised_address_rejects_malformed_values() {
        for bad in [
            "",
            " sip.example.com",
            "sip.example.com:",
            "sip.example.com:0",
            "sip.example.com:70000",
            "sip.example.com:abc",
            ":5061",
            "[2001:db8::1",
            "[not-v6]:5061",
            "[2001:db8::1]5061",
            "[2001:db8::1]:",
            "sip example.com",
            "sip:user@example.com",
            "2001:db8::zz:5061",
        ] {
            assert!(
                AdvertisedAddress::parse(bad).is_err(),
                "'{bad}' must be refused"
            );
        }
    }

    #[test]
    fn advertised_address_display_round_trips_through_parse() {
        for value in [
            "sip.example.com",
            "sip.example.com:5061",
            "[2001:db8::1]:5061",
            "2001:db8::1",
        ] {
            let parsed = AdvertisedAddress::parse(value).unwrap();
            assert_eq!(parsed.to_string(), value);
            assert_eq!(
                AdvertisedAddress::parse(&parsed.to_string()).unwrap(),
                parsed
            );
        }
    }
}
