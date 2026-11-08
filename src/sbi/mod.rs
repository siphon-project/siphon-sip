//! 5G Service-Based Interface (SBI) client support.
//!
//! Provides typed HTTP/2 JSON clients for 5G core network functions:
//! - Npcf (Policy Control Function) — QoS policy authorization
//! - Nchf (Charging Function) — converged charging
//!
//! Uses `reqwest` for HTTP transport. Full NRF discovery and OAuth2
//! token management are planned for future implementation.

mod bearer;
#[cfg(test)]
mod bearer_tests;
pub mod nbsf;
pub mod nchf;
pub mod npcf;
mod tls;
pub use tls::SbiTlsConfig;

/// The header a static bearer token travels in (`sbi.bearer_token_header`):
/// `Authorization` for a producer that authenticates consumers itself, or
/// `Proxy-Authorization` for a token that identifies the consumer to the SCP
/// it sends through (RFC 9110 section 11.7.2), leaving `Authorization` to a
/// producer's access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SbiBearerHeader {
    #[default]
    Authorization,
    ProxyAuthorization,
}

/// SBI communication model (TS 29.500 §6.10).
///
/// - `Direct`: the NF Service Consumer sends requests straight to the target
///   NF (the configured `*_url` is the NF). No `3gpp-Sbi-*` routing headers.
/// - `Indirect`: requests traverse the SCP (the configured `*_url` is the SCP).
///   The consumer indicates the target via routing headers — Model C
///   (`3gpp-Sbi-Target-apiRoot`) for Npcf where the PCF is known from the BSF
///   binding, Model D (`3gpp-Sbi-Discovery-*`, delegated discovery) for Nbsf
///   where only the target NF type is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Communication {
    /// Direct to the target NF (default — today's behaviour).
    #[default]
    Direct,
    /// Indirect via the SCP, with 3GPP routing headers.
    Indirect,
}

impl Communication {
    /// Parse the `sbi.communication` config value. Anything other than a
    /// case-insensitive `"indirect"` is treated as `direct`.
    pub fn from_config_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "indirect" => Self::Indirect,
            _ => Self::Direct,
        }
    }

    /// Whether routing headers should be emitted.
    pub fn is_indirect(self) -> bool {
        matches!(self, Self::Indirect)
    }
}

/// Configuration for SBI client connections.
#[derive(Debug, Clone)]
pub struct SbiConfig {
    /// Outbound TLS trust and optional mutual authentication.
    pub tls: Option<SbiTlsConfig>,
    /// Static bearer credential file, loaded once by the manager.
    pub bearer_token_file: Option<String>,
    /// The header the bearer token is sent in.
    pub bearer_token_header: SbiBearerHeader,
    /// Peer URLs used for startup transport validation with bearer authentication.
    pub npcf_url: Option<String>,
    pub bsf_url: Option<String>,
    pub nchf_url: Option<String>,
    /// NRF discovery endpoint (optional, for service discovery).
    pub nrf_url: Option<String>,
    /// Default timeout for SBI requests in seconds.
    pub timeout_secs: u64,
    /// OAuth2 client credentials (optional).
    pub oauth2_client_id: Option<String>,
    pub oauth2_client_secret: Option<String>,
}

impl Default for SbiConfig {
    fn default() -> Self {
        Self {
            tls: None,
            bearer_token_file: None,
            bearer_token_header: SbiBearerHeader::Authorization,
            npcf_url: None,
            bsf_url: None,
            nchf_url: None,
            nrf_url: None,
            timeout_secs: 5,
            oauth2_client_id: None,
            oauth2_client_secret: None,
        }
    }
}

/// SBI client manager — holds HTTP clients for each NF type.
#[derive(Debug)]
pub struct SbiManager {
    config: SbiConfig,
    http_client: reqwest::Client,
    tls: tls::LoadedTls,
    bearer: bearer::LoadedBearer,
}

impl SbiManager {
    /// Load TLS and bearer token files and build the shared client, failing on invalid configuration.
    pub fn new(config: SbiConfig) -> Result<Self, String> {
        let bearer = bearer::LoadedBearer::load(&config)?;
        let tls = tls::LoadedTls::load(config.tls.as_ref())?;
        let http_client = tls.build(
            &config,
            &bearer,
            std::time::Duration::from_secs(config.timeout_secs),
        )?;
        Ok(Self {
            config,
            http_client,
            tls,
            bearer,
        })
    }

    /// Build a timeout-specific client using the already loaded TLS material.
    pub fn client_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<reqwest::Client, String> {
        self.tls.build(&self.config, &self.bearer, timeout)
    }

    /// Get the HTTP client for making SBI requests.
    pub fn client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Get the NRF URL if configured.
    pub fn nrf_url(&self) -> Option<&str> {
        self.config.nrf_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn communication_from_config_str() {
        assert_eq!(
            Communication::from_config_str("indirect"),
            Communication::Indirect
        );
        assert_eq!(
            Communication::from_config_str("INDIRECT"),
            Communication::Indirect
        );
        assert_eq!(
            Communication::from_config_str("direct"),
            Communication::Direct
        );
        assert_eq!(
            Communication::from_config_str("whatever"),
            Communication::Direct
        );
        // Default is Direct (today's behaviour, backward-compatible).
        assert_eq!(Communication::default(), Communication::Direct);
        assert!(Communication::Indirect.is_indirect());
        assert!(!Communication::Direct.is_indirect());
    }

    #[test]
    fn sbi_config_defaults() {
        let config = SbiConfig::default();
        assert!(config.nrf_url.is_none());
        assert_eq!(config.timeout_secs, 5);
        assert!(config.oauth2_client_id.is_none());
        assert!(config.oauth2_client_secret.is_none());
    }

    #[test]
    fn sbi_config_with_values() {
        let config = SbiConfig {
            nrf_url: Some("https://nrf.5gc.example.com".to_string()),
            timeout_secs: 10,
            oauth2_client_id: Some("siphon-pcscf".to_string()),
            oauth2_client_secret: Some("secret123".to_string()),
            ..Default::default()
        };
        assert_eq!(
            config.nrf_url.as_deref(),
            Some("https://nrf.5gc.example.com")
        );
        assert_eq!(config.timeout_secs, 10);
    }

    #[test]
    fn sbi_manager_creation() {
        let manager = SbiManager::new(SbiConfig::default()).unwrap();
        assert!(manager.nrf_url().is_none());
    }

    #[test]
    fn sbi_manager_with_nrf() {
        let config = SbiConfig {
            nrf_url: Some("https://nrf.local:8443".to_string()),
            ..Default::default()
        };
        let manager = SbiManager::new(config).unwrap();
        assert_eq!(manager.nrf_url(), Some("https://nrf.local:8443"));
    }
}
