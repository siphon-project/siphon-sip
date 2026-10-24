//! IMS / 5GC sections: `ipsec:` (TS 33.203), `isc:` (TS 29.228) and `sbi:`.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// IPsec (3GPP TS 33.203)
// ---------------------------------------------------------------------------

/// IPsec SA management configuration for P-CSCF.
#[derive(Debug, Deserialize, Clone)]
pub struct IpsecConfig {
    /// P-CSCF protected client ports: one port (`5064`), or a list
    /// (`[5064, 5068]`). Each SA pair takes one of them as its port_pc, never
    /// one another live pair of the same UE holds, so the port changes on
    /// every authenticated re-registration (TS 33.203 clause 7.4.0). With one
    /// port an old and a new set share it, as before.
    #[serde(default = "default_ipsec_port_c")]
    pub pcscf_port_c: ClientPorts,
    /// P-CSCF protected server port.
    #[serde(default = "default_ipsec_port_s")]
    pub pcscf_port_s: u16,
    /// XFRM backend.  ``"netlink"`` (default — direct kernel netlink,
    /// fastest) or ``"ip"`` (legacy ``/sbin/ip xfrm`` shell-out, used
    /// as a fallback when running in containers without
    /// CAP_NET_ADMIN-on-netlink or for parity with older deployments).
    #[serde(default = "default_ipsec_backend")]
    pub backend: IpsecBackend,
    /// First SPI of this instance's partition. The P-CSCF only allocates
    /// SPIs in `[start, start+count)`, so several siphon processes on one
    /// kernel can each take their own range. Unset means 10000. Must be at
    /// least 256: RFC 4303 §2.1 reserves 1 to 255.
    #[serde(default)]
    pub spi_range_start: Option<u32>,
    /// Number of SPIs in the partition. Each registered UE holds two (spi-c
    /// and spi-s), and a re-registration holds two more until the old pair
    /// is torn down, so the partition bounds concurrent IPsec registrations
    /// at about half of this. An allocation never reuses an SPI a live SA
    /// holds; with the partition full, `ipsec.allocate` fails instead.
    /// Default 4194304 (2^22, about two million UEs). At most 2^28, and
    /// `start + count - 1` must not pass `u32::MAX`.
    #[serde(default = "default_spi_range_count")]
    pub spi_range_count: u32,
    /// Host part siphon writes into the Path URI advertised by
    /// `request.add_pcscf_path(token)` (RFC 3327 §5 / TS 24.229
    /// §5.2.7.2 Path-token MT routing).  Must resolve back to *this*
    /// P-CSCF instance — typically the pod FQDN in a
    /// StatefulSet deployment so MT requests from the S-CSCF route to
    /// the instance that owns the inbound flow.  Optional; when unset,
    /// `add_pcscf_path()` errors at script time so the misconfiguration
    /// is caught loudly rather than producing unroutable Path URIs.
    #[serde(default)]
    pub path_host: Option<String>,
}

/// XFRM backend selection.  Defaults to `Netlink` on Linux (the only
/// platform where IPsec is meaningful).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpsecBackend {
    /// Direct XFRM netlink protocol — fastest, no shell-out.
    Netlink,
    /// Legacy `/sbin/ip xfrm` shell-out — used when netlink is
    /// unavailable (e.g. inside containers without netlink access).
    Ip,
}

fn default_ipsec_port_c() -> ClientPorts {
    ClientPorts::from(5064)
}

/// The P-CSCF's protected client ports (`ipsec.pcscf_port_c`), in the order
/// configured. Never empty once loaded: configuration refuses an empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPorts(Vec<u16>);

impl From<u16> for ClientPorts {
    fn from(port: u16) -> Self {
        Self(vec![port])
    }
}

impl From<Vec<u16>> for ClientPorts {
    fn from(ports: Vec<u16>) -> Self {
        Self(ports)
    }
}

impl<'de> Deserialize<'de> for ClientPorts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(u16),
            Many(Vec<u16>),
        }
        Ok(match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(port) => Self::from(port),
            OneOrMany::Many(ports) => Self(ports),
        })
    }
}

impl ClientPorts {
    /// The first port configured: the one a pair of a UE with no other pair
    /// takes, and the only one of a single-port configuration.
    pub fn first(&self) -> u16 {
        self.0.first().copied().unwrap_or(5064)
    }

    /// Every port, in the order configured.
    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    /// Whether `port` is one of them.
    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    /// Whether there is more than one, so a re-authentication can change
    /// port_pc (TS 33.203 clause 7.4.0).
    pub fn rotates(&self) -> bool {
        self.0.len() > 1
    }
}

fn default_ipsec_port_s() -> u16 {
    5066
}

fn default_ipsec_backend() -> IpsecBackend {
    IpsecBackend::Netlink
}

/// First SPI of the partition when `ipsec.spi_range_start` is unset.
pub const DEFAULT_SPI_RANGE_START: u32 = 10_000;

/// Default `ipsec.spi_range_count`: 2^22 SPIs, room for about two million
/// concurrently registered UEs at two SPIs each, in a 512 KiB bitmap.
pub const DEFAULT_SPI_RANGE_COUNT: u32 = 1 << 22;

fn default_spi_range_count() -> u32 {
    DEFAULT_SPI_RANGE_COUNT
}

impl IpsecConfig {
    /// The first SPI of the partition, with the default applied.
    pub fn effective_spi_range_start(&self) -> u32 {
        self.spi_range_start.unwrap_or(DEFAULT_SPI_RANGE_START)
    }

    /// Refuse an SPI partition that reaches into the reserved SPIs, runs past
    /// `u32::MAX`, cannot hold one pair, or is larger than one manager tracks.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_client_ports()?;
        let start = self.effective_spi_range_start();
        let count = self.spi_range_count;
        if start < crate::ipsec::MIN_SPI {
            return Err(format!(
                "ipsec.spi_range_start is {start}: SPIs below {} are reserved (RFC 4303 §2.1)",
                crate::ipsec::MIN_SPI
            ));
        }
        if !(2..=crate::ipsec::MAX_SPI_RANGE_COUNT).contains(&count) {
            return Err(format!(
                "ipsec.spi_range_count is {count}: it must be between 2 and {}",
                crate::ipsec::MAX_SPI_RANGE_COUNT
            ));
        }
        if u64::from(start) + u64::from(count) - 1 > u64::from(u32::MAX) {
            return Err(format!(
                "ipsec.spi_range_start {start} plus spi_range_count {count} runs past the largest SPI ({})",
                u32::MAX
            ));
        }
        Ok(())
    }

    /// [`validate`](Self::validate), then [`bind_client_ports`](Self::bind_client_ports)
    /// into `listen`: what loading a config does with its `ipsec:` block.
    pub fn load_into(&self, listen: &mut super::ListenConfig) -> crate::error::Result<()> {
        self.validate()
            .and_then(|()| self.bind_client_ports(listen))
            .map_err(crate::error::SiphonError::Config)
    }

    /// Refuse a protected client port set no pair can use: empty, a port
    /// listed twice, or one that is also the protected server port. A list
    /// may not name 5060 or 5061 either (TS 33.203 clause 7.1: "The ports
    /// port_ps and port_pc are different from the standard SIP ports 5060
    /// and 5061"); a single port is accepted as it always was.
    fn validate_client_ports(&self) -> Result<(), String> {
        let ports = self.pcscf_port_c.as_slice();
        if ports.is_empty() {
            return Err("ipsec.pcscf_port_c is an empty list: name at least one port".to_string());
        }
        for (index, port) in ports.iter().enumerate() {
            if *port == 0 {
                return Err("ipsec.pcscf_port_c: port 0 cannot be a protected port".to_string());
            }
            if ports[..index].contains(port) {
                return Err(format!("ipsec.pcscf_port_c lists port {port} twice"));
            }
            if *port == self.pcscf_port_s {
                return Err(format!(
                    "ipsec.pcscf_port_c: port {port} is also ipsec.pcscf_port_s; the protected \
                     client and server ports must differ (TS 33.203 clause 7.1)"
                ));
            }
            if self.pcscf_port_c.rotates() && (*port == 5060 || *port == 5061) {
                return Err(format!(
                    "ipsec.pcscf_port_c: port {port} is a standard SIP port, which a protected \
                     port must not be (TS 33.203 clause 7.1)"
                ));
            }
        }
        Ok(())
    }

    /// Bind every protected client port wherever the protected server port is
    /// bound, for a set of more than one: each SA pair sends from its own
    /// port_pc and receives the UE's responses on it, so each needs the UDP
    /// socket (and, where `pcscf_port_s` has a TCP listener, the TCP one) on
    /// the protected address. A port already listed there is kept as it is.
    ///
    /// Refused: a set of several ports with no `listen.udp` entry on
    /// `pcscf_port_s` at a concrete address to bind them at (a wildcard cannot
    /// be an SA selector), and a protected client port some listener binds on
    /// a wildcard address (it would take unprotected traffic on a protected
    /// port, TS 33.203 clause 7.1). A single port is left exactly as
    /// configured.
    pub fn bind_client_ports(&self, listen: &mut super::ListenConfig) -> Result<(), String> {
        if !self.pcscf_port_c.rotates() {
            return Ok(());
        }
        let mut bound_udp = false;
        for (transport, entries) in [("udp", &mut listen.udp), ("tcp", &mut listen.tcp)] {
            let addresses: Vec<std::net::SocketAddr> = entries
                .iter()
                .filter_map(|entry| entry.address().parse().ok())
                .collect();
            if let Some(wildcard) = addresses.iter().find(|address| {
                address.ip().is_unspecified() && self.pcscf_port_c.contains(address.port())
            }) {
                return Err(format!(
                    "listen.{transport}: {wildcard} binds a protected client port of \
                     ipsec.pcscf_port_c on a wildcard address; bind it to the protected address \
                     or leave it out, siphon binds every port of the list there"
                ));
            }
            let protected: Vec<std::net::IpAddr> = addresses
                .iter()
                .filter(|address| {
                    address.port() == self.pcscf_port_s && !address.ip().is_unspecified()
                })
                .map(std::net::SocketAddr::ip)
                .collect();
            bound_udp |= transport == "udp" && !protected.is_empty();
            for ip in protected {
                for port in self.pcscf_port_c.as_slice() {
                    let address = std::net::SocketAddr::new(ip, *port);
                    if !addresses.contains(&address) {
                        entries.push(super::ListenEntry::Plain(address.to_string()));
                    }
                }
            }
        }
        if !bound_udp {
            return Err(format!(
                "ipsec.pcscf_port_c lists {} ports, so siphon binds them where \
                 ipsec.pcscf_port_s ({}) is bound: add a listen.udp entry on port {} at the \
                 concrete address UEs send to",
                self.pcscf_port_c.as_slice().len(),
                self.pcscf_port_s,
                self.pcscf_port_s
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Initial Filter Criteria (3GPP TS 29.228)
// ---------------------------------------------------------------------------

/// Top-level `isc:` configuration for Initial Filter Criteria.
#[derive(Debug, Deserialize, Clone)]
pub struct IscConfig {
    /// Path to the iFC XML file containing ServiceProfile elements.
    pub ifc_xml_path: Option<String>,
    /// Inline iFC XML (alternative to file path).
    pub ifc_xml: Option<String>,
    /// Redis key prefix for iFC profile persistence (default: "siphon:ifc:").
    /// When the registrar backend is Redis, iFC profiles are automatically
    /// persisted and restored alongside registrations.
    #[serde(default = "default_ifc_key_prefix")]
    pub ifc_key_prefix: String,
    /// The shared iFC sets provisioned at this S-CSCF (TS 29.228 Annex B.2,
    /// TS 29.229 §7.1.1 `SiFC`), by the SharedIFCSetID a service profile
    /// names them with. Reloaded on `SIGHUP`. With at least one, Cx SAR
    /// advertises the `SiFC` feature so the HSS sends the ids.
    #[serde(default)]
    pub shared_ifc_sets: Vec<SharedIfcSetConfig>,
}

/// One shared iFC set: `<InitialFilterCriteria>` elements in the TS 29.228
/// Annex E form, from `file` or inline `xml`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SharedIfcSetConfig {
    /// The SharedIFCSetID (an integer of at least 0).
    pub id: u32,
    /// Path to the set's XML.
    pub file: Option<String>,
    /// The set's XML inline, when there is no `file`.
    pub xml: Option<String>,
}

fn default_ifc_key_prefix() -> String {
    "siphon:ifc:".to_owned()
}

// ---------------------------------------------------------------------------
// 5G Service-Based Interface (SBI)
// ---------------------------------------------------------------------------

/// Top-level `sbi:` configuration for 5G Service-Based Interface.
#[derive(Debug, Deserialize, Clone)]
pub struct SbiYamlConfig {
    /// NRF discovery endpoint URL.
    pub nrf_url: Option<String>,
    /// Default timeout for SBI requests in seconds.
    #[serde(default = "default_sbi_timeout")]
    pub timeout_secs: u64,
    /// OAuth2 client ID for NF authorization.
    pub oauth2_client_id: Option<String>,
    /// OAuth2 client secret.
    pub oauth2_client_secret: Option<String>,
    /// Npcf base URL (if not using NRF discovery).
    pub npcf_url: Option<String>,
    /// Nchf base URL (if not using NRF discovery).
    pub nchf_url: Option<String>,
    /// Nbsf_Management (BSF) base URL for `sbi.discover_pcf_binding()`.
    /// May equal the SCP/Npcf URL. When unset, `discover_pcf_binding` raises
    /// a clear "BSF not configured" error rather than silently defaulting.
    pub bsf_url: Option<String>,
    /// Per-discovery timeout for BSF lookups in milliseconds. Falls back to
    /// `timeout_secs` when unset.
    pub bsf_timeout_ms: Option<u64>,
    /// URL scheme ("http" | "https", default "http") used when deriving a PCF
    /// base URL from a `pcfFqdn` returned by the BSF.
    pub pcf_scheme: Option<String>,
    /// SBI communication model: "direct" (default — straight to the NF) or
    /// "indirect" (via the SCP, with `3gpp-Sbi-*` routing headers; TS 29.500
    /// §6.10). When "indirect", `npcf_url`/`bsf_url` point at the SCP.
    pub communication: Option<String>,
    /// Requester NF type advertised in Nbsf delegated discovery
    /// (`3gpp-Sbi-Discovery-requester-nf-type`) when communication is indirect.
    /// Default "AF" (a P-CSCF acts as an AF).
    pub requester_nf_type: Option<String>,
    /// Listen address for incoming PCF event notifications (e.g. "0.0.0.0:8080").
    pub notif_listen: Option<String>,
    /// The callback base URI the PCF reaches this node at, for example
    /// `http://192.0.2.10:8080/sbi/events`. Sent as `notifUri` on every N5
    /// create that does not pass its own `notif_uri`. TS 29.514 requires the
    /// attribute, and the listen address cannot stand in for it: it is often
    /// a wildcard, or sits behind an address translation.
    pub notif_uri: Option<String>,
}

fn default_sbi_timeout() -> u64 {
    5
}

impl SbiYamlConfig {
    pub fn to_sbi_config(&self) -> crate::sbi::SbiConfig {
        crate::sbi::SbiConfig {
            nrf_url: self.nrf_url.clone(),
            timeout_secs: self.timeout_secs,
            oauth2_client_id: self.oauth2_client_id.clone(),
            oauth2_client_secret: self.oauth2_client_secret.clone(),
        }
    }
}
