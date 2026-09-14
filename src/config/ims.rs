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
    /// Optional SPI range for this siphon instance.  When set,
    /// `allocate_spi_pair()` only returns SPIs in `[start, start+count)`,
    /// letting multiple siphon processes coexist on the same kernel
    /// without colliding on SPI values.  When unset (default), siphon
    /// uses the historical wide range starting at 10000.
    #[serde(default)]
    pub spi_range_start: Option<u32>,
    /// Number of SPIs available in the partition (paired with
    /// `spi_range_start`).  Default 8192 — far more than any practical
    /// concurrent registration count.
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

fn default_spi_range_count() -> u32 {
    8192
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
