//! IMS / 5GC sections: `ipsec:` (TS 33.203), `isc:` (TS 29.228) and `sbi:`.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// IPsec (3GPP TS 33.203)
// ---------------------------------------------------------------------------

/// IPsec SA management configuration for P-CSCF.
#[derive(Debug, Deserialize, Clone)]
pub struct IpsecConfig {
    /// P-CSCF protected client port.
    #[serde(default = "default_ipsec_port_c")]
    pub pcscf_port_c: u16,
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

fn default_ipsec_port_c() -> u16 {
    5064
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
