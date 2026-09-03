//! Nbsf_Management — BSF (Binding Support Function) discovery (TS 29.521).
//!
//! Provides a typed client for the `pcfBindings` lookup. A P-CSCF keys the
//! lookup on the UE's IP (taken from the IPsec SA the SIP request arrived on)
//! to decide its policy interface per session:
//!
//! - **BSF `200 OK` + `PcfBinding`** ⇒ a 5G UE → use N5 (`Npcf_PolicyAuthorization`)
//!   addressed at the binding's PCF.
//! - **BSF `404 Not Found`** ⇒ no binding for this IP → a 4G UE → use Rx (Diameter).
//! - **`5xx` / timeout / transport / malformed body** ⇒ BSF unhealthy → [`BsfError`].
//!
//! The 200-vs-404 split is the whole contract: a clean miss is a 4G UE, **not**
//! an error, and is surfaced as `Ok(None)`.

use serde::Deserialize;

/// URL scheme used when deriving a PCF base URL from a discovered binding.
///
/// Defaults to plaintext HTTP to match the typical open5gs SBI deployment
/// (cleartext HTTP/2 on `:8080`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plaintext `http://`.
    Http,
    /// TLS `https://`.
    Https,
}

impl Scheme {
    /// Parse the `sbi.pcf_scheme` config value. Anything other than a
    /// case-insensitive `"https"` is treated as `http` (the safe default for
    /// the current SCP path).
    pub fn from_config_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "https" => Self::Https,
            _ => Self::Http,
        }
    }

    /// The URL prefix including `://`.
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Http => "http://",
            Self::Https => "https://",
        }
    }

    /// The default TCP port when an [`IpEndPoint`] omits one.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// Discovery key — exactly one is set per lookup (TS 29.521 §5.2.2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingQuery {
    /// UE IPv4 address → `?ipv4Addr=...`.
    Ipv4(String),
    /// UE IPv6 prefix (e.g. `2001:db8::/64`) → `?ipv6Prefix=...` (the `/` is
    /// percent-encoded to `%2F` on the wire).
    Ipv6Prefix(String),
}

/// IP endpoint of a network function (TS 29.571 §5.2.4.10).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpEndPoint {
    /// IPv4 address literal.
    #[serde(default)]
    pub ipv4_address: Option<String>,
    /// IPv6 address literal.
    #[serde(default)]
    pub ipv6_address: Option<String>,
    /// Transport protocol ("TCP" | "UDP").
    #[serde(default)]
    pub transport: Option<String>,
    /// Port number.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Single Network Slice Selection Assistance Information (TS 29.571 §5.4.4.2).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snssai {
    /// Slice/Service Type.
    #[serde(default)]
    pub sst: u8,
    /// Slice Differentiator (3 octets, hex string).
    #[serde(default)]
    pub sd: Option<String>,
}

/// PCF binding returned by the BSF (TS 29.521 §6.2.6.2.2).
///
/// Deserialized permissively — unknown vendor fields (open5gs and other BSF
/// may add some) are ignored, and every field defaults so a partial body still
/// parses.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PcfBinding {
    /// Subscription Permanent Identifier.
    #[serde(default)]
    pub supi: Option<String>,
    /// Generic Public Subscription Identifier.
    #[serde(default)]
    pub gpsi: Option<String>,
    /// UE IPv4 address bound to this PDU session.
    #[serde(default)]
    pub ipv4_addr: Option<String>,
    /// UE IPv6 prefix bound to this PDU session.
    #[serde(default)]
    pub ipv6_prefix: Option<String>,
    /// Data Network Name.
    #[serde(default)]
    pub dnn: Option<String>,
    /// FQDN of the bound PCF — preferred N5 target.
    #[serde(default)]
    pub pcf_fqdn: Option<String>,
    /// IP endpoints of the bound PCF — fallback N5 target.
    #[serde(default)]
    pub pcf_ip_end_points: Option<Vec<IpEndPoint>>,
    /// Diameter identity host of the bound PCF (Rx interworking).
    #[serde(default)]
    pub pcf_diam_host: Option<String>,
    /// Diameter realm of the bound PCF.
    #[serde(default)]
    pub pcf_diam_realm: Option<String>,
    /// Network slice this binding applies to.
    #[serde(default)]
    pub snssai: Option<Snssai>,
    /// PCF instance identifier.
    #[serde(default)]
    pub pcf_id: Option<String>,
    /// Binding level ("NF_INSTANCE" | "NF_SET").
    #[serde(default)]
    pub bind_level: Option<String>,
    /// Supported features bitstring.
    #[serde(default)]
    pub supp_feat: Option<String>,
}

impl PcfBinding {
    /// Base URL to address N5 at this PCF (TS 29.521 §4.2.2.2).
    ///
    /// Preference order:
    ///   1. `pcfFqdn` → `{scheme}{fqdn}`.
    ///   2. first usable `pcfIpEndPoints` entry → `{scheme}{ip}:{port}`
    ///      (IPv6 literals bracketed; default port by scheme when absent).
    ///
    /// Returns `None` for a degenerate binding with neither — the caller
    /// should treat that as a miss.
    pub fn pcf_base_url(&self, scheme: Scheme) -> Option<String> {
        if let Some(fqdn) = self.pcf_fqdn.as_deref() {
            let fqdn = fqdn.trim();
            if !fqdn.is_empty() {
                return Some(format!("{}{}", scheme.prefix(), fqdn));
            }
        }

        for endpoint in self.pcf_ip_end_points.iter().flatten() {
            if let Some(ipv4) = endpoint.ipv4_address.as_deref().map(str::trim) {
                if !ipv4.is_empty() {
                    let port = endpoint.port.unwrap_or_else(|| scheme.default_port());
                    return Some(format!("{}{}:{}", scheme.prefix(), ipv4, port));
                }
            }
            if let Some(ipv6) = endpoint.ipv6_address.as_deref().map(str::trim) {
                if !ipv6.is_empty() {
                    let port = endpoint.port.unwrap_or_else(|| scheme.default_port());
                    return Some(format!("{}[{}]:{}", scheme.prefix(), ipv6, port));
                }
            }
        }

        None
    }
}

/// Error from a BSF discovery call. Distinct from the Npcf `SbiError` so the
/// Python layer can raise a catchable `sbi.BsfError`. A `404` is **not** a
/// `BsfError` — it is a clean miss returned as `Ok(None)`.
#[derive(Debug)]
pub enum BsfError {
    /// Transport-level failure (connection refused, timeout, TLS, etc.).
    Transport(String),
    /// HTTP error status (5xx and any other non-200/404).
    Http(u16),
    /// `200 OK` body could not be deserialized into a [`PcfBinding`].
    Deserialization(String),
}

impl std::fmt::Display for BsfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) => write!(formatter, "BSF transport error: {message}"),
            Self::Http(code) => write!(formatter, "BSF HTTP error: {code}"),
            Self::Deserialization(message) => {
                write!(formatter, "BSF deserialization error: {message}")
            }
        }
    }
}

impl std::error::Error for BsfError {}

/// SCP delegated-discovery headers for Nbsf, Model D (TS 29.500 §5.2.3.2.4).
const DISCOVERY_TARGET_NF_TYPE_HEADER: &str = "3gpp-Sbi-Discovery-target-nf-type";
const DISCOVERY_SERVICE_NAMES_HEADER: &str = "3gpp-Sbi-Discovery-service-names";
const DISCOVERY_REQUESTER_NF_TYPE_HEADER: &str = "3gpp-Sbi-Discovery-requester-nf-type";

/// Nbsf_Management discovery client.
pub struct BsfClient {
    base_url: String,
    client: reqwest::Client,
    communication: crate::sbi::Communication,
    /// Requester NF type for the `3gpp-Sbi-Discovery-requester-nf-type` header
    /// in Indirect mode (the P-CSCF acts as an AF).
    requester_nf_type: String,
}

impl BsfClient {
    /// Create a new BSF client pointing at the given base URL (the BSF in
    /// `Direct` mode, the SCP in `Indirect` mode), reusing a shared pooled
    /// `reqwest::Client`. Defaults to `Direct` communication, requester `AF`.
    pub fn new(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            communication: crate::sbi::Communication::Direct,
            requester_nf_type: "AF".to_string(),
        }
    }

    /// Set the SBI communication model. `Indirect` routes via the SCP and emits
    /// the `3gpp-Sbi-Discovery-*` delegated-discovery headers (Model D).
    pub fn with_communication(mut self, communication: crate::sbi::Communication) -> Self {
        self.communication = communication;
        self
    }

    /// Set the requester NF type advertised in delegated discovery (default
    /// `"AF"`).
    pub fn with_requester_nf_type(mut self, requester_nf_type: &str) -> Self {
        self.requester_nf_type = requester_nf_type.to_string();
        self
    }

    /// The configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Look up the PCF binding for a UE IP (TS 29.521 §5.2.2.2.2).
    ///
    /// `Ok(Some(binding))` on `200`, `Ok(None)` on `404`, `Err(BsfError)` on
    /// anything else. In `Indirect` mode the request carries the
    /// `3gpp-Sbi-Discovery-*` headers so the SCP discovers the BSF via the NRF
    /// (Model D); the 200/404 contract reaching the caller is unchanged.
    pub async fn discover_binding(
        &self,
        key: &BindingQuery,
    ) -> Result<Option<PcfBinding>, BsfError> {
        let url = format!("{}/nbsf-management/v1/pcfBindings", self.base_url);
        let query: [(&str, &str); 1] = match key {
            BindingQuery::Ipv4(address) => [("ipv4Addr", address.as_str())],
            BindingQuery::Ipv6Prefix(prefix) => [("ipv6Prefix", prefix.as_str())],
        };

        let mut request = self.client.get(&url).query(&query);
        if self.communication.is_indirect() {
            request = request
                .header(DISCOVERY_TARGET_NF_TYPE_HEADER, "BSF")
                .header(DISCOVERY_SERVICE_NAMES_HEADER, "nbsf-management")
                .header(DISCOVERY_REQUESTER_NF_TYPE_HEADER, &self.requester_nf_type);
        }

        let response = request
            .send()
            .await
            .map_err(|error| BsfError::Transport(format!("{url}: {error}")))?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(BsfError::Http(status.as_u16()));
        }

        response
            .json::<PcfBinding>()
            .await
            .map(Some)
            .map_err(|error| BsfError::Deserialization(format!("{url}: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_BINDING_JSON: &str = r#"{
        "supi": "imsi-001010000000001",
        "gpsi": "msisdn-31600000001",
        "ipv4Addr": "10.45.0.7",
        "dnn": "ims",
        "snssai": {"sst": 1, "sd": "000001"},
        "pcfFqdn": "pcf01.5gc.example.org",
        "pcfIpEndPoints": [{"ipv4Address": "10.10.0.20", "transport": "TCP", "port": 8080}],
        "pcfId": "pcf-instance-1",
        "bindLevel": "NF_INSTANCE",
        "vendorSpecificField": "ignored"
    }"#;

    #[test]
    fn parses_full_binding_body() {
        let binding: PcfBinding = serde_json::from_str(FULL_BINDING_JSON).unwrap();
        assert_eq!(binding.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(binding.ipv4_addr.as_deref(), Some("10.45.0.7"));
        assert_eq!(binding.dnn.as_deref(), Some("ims"));
        assert_eq!(binding.pcf_fqdn.as_deref(), Some("pcf01.5gc.example.org"));
        let snssai = binding.snssai.as_ref().unwrap();
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd.as_deref(), Some("000001"));
        let endpoints = binding.pcf_ip_end_points.as_ref().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].ipv4_address.as_deref(), Some("10.10.0.20"));
        assert_eq!(endpoints[0].port, Some(8080));
    }

    #[test]
    fn parses_minimal_binding_body() {
        // Unknown fields ignored; everything else defaults.
        let binding: PcfBinding = serde_json::from_str(r#"{"supi": "imsi-1"}"#).unwrap();
        assert_eq!(binding.supi.as_deref(), Some("imsi-1"));
        assert!(binding.pcf_fqdn.is_none());
        assert!(binding.pcf_ip_end_points.is_none());
    }

    #[test]
    fn pcf_base_url_prefers_fqdn() {
        let binding: PcfBinding = serde_json::from_str(FULL_BINDING_JSON).unwrap();
        assert_eq!(
            binding.pcf_base_url(Scheme::Http).as_deref(),
            Some("http://pcf01.5gc.example.org")
        );
        assert_eq!(
            binding.pcf_base_url(Scheme::Https).as_deref(),
            Some("https://pcf01.5gc.example.org")
        );
    }

    #[test]
    fn pcf_base_url_falls_back_to_endpoint() {
        let json = r#"{
            "pcfIpEndPoints": [{"ipv4Address": "10.10.0.20", "transport": "TCP", "port": 8080}]
        }"#;
        let binding: PcfBinding = serde_json::from_str(json).unwrap();
        assert_eq!(
            binding.pcf_base_url(Scheme::Http).as_deref(),
            Some("http://10.10.0.20:8080")
        );
    }

    #[test]
    fn pcf_base_url_endpoint_default_port_by_scheme() {
        let json = r#"{"pcfIpEndPoints": [{"ipv4Address": "10.10.0.20"}]}"#;
        let binding: PcfBinding = serde_json::from_str(json).unwrap();
        assert_eq!(
            binding.pcf_base_url(Scheme::Http).as_deref(),
            Some("http://10.10.0.20:80")
        );
        assert_eq!(
            binding.pcf_base_url(Scheme::Https).as_deref(),
            Some("https://10.10.0.20:443")
        );
    }

    #[test]
    fn pcf_base_url_ipv6_endpoint_bracketed() {
        let json = r#"{"pcfIpEndPoints": [{"ipv6Address": "2001:db8::20", "port": 8080}]}"#;
        let binding: PcfBinding = serde_json::from_str(json).unwrap();
        assert_eq!(
            binding.pcf_base_url(Scheme::Http).as_deref(),
            Some("http://[2001:db8::20]:8080")
        );
    }

    #[test]
    fn pcf_base_url_none_when_degenerate() {
        let binding: PcfBinding = serde_json::from_str("{}").unwrap();
        assert!(binding.pcf_base_url(Scheme::Http).is_none());
    }

    #[test]
    fn scheme_from_config_str() {
        assert_eq!(Scheme::from_config_str("https"), Scheme::Https);
        assert_eq!(Scheme::from_config_str("HTTPS"), Scheme::Https);
        assert_eq!(Scheme::from_config_str("http"), Scheme::Http);
        assert_eq!(Scheme::from_config_str("whatever"), Scheme::Http);
    }

    #[test]
    fn bsf_error_display() {
        assert!(BsfError::Transport("refused".into())
            .to_string()
            .contains("refused"));
        assert!(BsfError::Http(503).to_string().contains("503"));
        assert!(BsfError::Deserialization("bad".into())
            .to_string()
            .contains("bad"));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = BsfClient::new("http://bsf.local:8080/", reqwest::Client::new());
        assert_eq!(client.base_url(), "http://bsf.local:8080");
    }

    // --- HTTP-behaviour tests against an axum mock on an ephemeral port ---

    use std::sync::{Arc, Mutex};

    /// Spawn an axum router on `127.0.0.1:0` and return its base URL.
    async fn spawn_mock(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn discover_200_returns_some() {
        use axum::routing::get;
        let router = axum::Router::new().route(
            "/nbsf-management/v1/pcfBindings",
            get(|| async { ([("content-type", "application/json")], FULL_BINDING_JSON) }),
        );
        let base = spawn_mock(router).await;
        let client = BsfClient::new(&base, reqwest::Client::new());
        let result = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap();
        let binding = result.expect("200 must yield Some(binding)");
        assert_eq!(binding.pcf_fqdn.as_deref(), Some("pcf01.5gc.example.org"));
    }

    #[tokio::test]
    async fn discover_404_returns_none() {
        use axum::routing::get;
        let router = axum::Router::new().route(
            "/nbsf-management/v1/pcfBindings",
            get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
        let base = spawn_mock(router).await;
        let client = BsfClient::new(&base, reqwest::Client::new());
        let result = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.99".into()))
            .await
            .unwrap();
        assert!(result.is_none(), "404 must yield Ok(None)");
    }

    #[tokio::test]
    async fn discover_500_returns_err() {
        use axum::routing::get;
        let router = axum::Router::new().route(
            "/nbsf-management/v1/pcfBindings",
            get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let base = spawn_mock(router).await;
        let client = BsfClient::new(&base, reqwest::Client::new());
        let error = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap_err();
        assert!(matches!(error, BsfError::Http(500)));
    }

    #[tokio::test]
    async fn discover_transport_error_when_unroutable() {
        // Port 9 (discard) refuses connections immediately on loopback.
        let client = BsfClient::new("http://127.0.0.1:9", reqwest::Client::new());
        let error = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap_err();
        assert!(matches!(error, BsfError::Transport(_)));
    }

    #[tokio::test]
    async fn ipv6_prefix_slash_percent_encoded_on_wire() {
        use axum::extract::RawQuery;
        use axum::routing::get;

        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_handler = Arc::clone(&captured);
        let router = axum::Router::new().route(
            "/nbsf-management/v1/pcfBindings",
            get(move |RawQuery(query): RawQuery| {
                let captured = Arc::clone(&captured_handler);
                async move {
                    if let Some(query) = query {
                        captured.lock().unwrap().push(query);
                    }
                    axum::http::StatusCode::NOT_FOUND
                }
            }),
        );
        let base = spawn_mock(router).await;
        let client = BsfClient::new(&base, reqwest::Client::new());
        let result = client
            .discover_binding(&BindingQuery::Ipv6Prefix("2001:db8::/64".into()))
            .await
            .unwrap();
        assert!(result.is_none());

        let queries = captured.lock().unwrap();
        assert_eq!(queries.len(), 1);
        let query = &queries[0];
        assert!(query.starts_with("ipv6Prefix="), "got: {query}");
        // The `/` of the /64 prefix MUST be percent-encoded (TS 29.521 wire).
        assert!(
            query.contains("%2F64"),
            "slash must be %2F encoded: {query}"
        );
    }

    /// Captured `(target-nf-type, service-names, requester-nf-type)` discovery
    /// header values (each None when absent) per request.
    type CapturedDiscoveryHeaders =
        Arc<Mutex<Vec<(Option<String>, Option<String>, Option<String>)>>>;

    /// A discovery router that records the `3gpp-Sbi-Discovery-*` headers
    /// (each None when absent) seen on the request, then 404s.
    fn capturing_discovery_router(captured: CapturedDiscoveryHeaders) -> axum::Router {
        use axum::http::HeaderMap;
        use axum::routing::get;
        axum::Router::new().route(
            "/nbsf-management/v1/pcfBindings",
            get(move |headers: HeaderMap| {
                let captured = Arc::clone(&captured);
                async move {
                    let get = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .map(|value| value.to_string())
                    };
                    captured.lock().unwrap().push((
                        get("3gpp-sbi-discovery-target-nf-type"),
                        get("3gpp-sbi-discovery-service-names"),
                        get("3gpp-sbi-discovery-requester-nf-type"),
                    ));
                    axum::http::StatusCode::NOT_FOUND
                }
            }),
        )
    }

    #[tokio::test]
    async fn indirect_discover_emits_delegated_discovery_headers() {
        let captured: CapturedDiscoveryHeaders = Arc::new(Mutex::new(Vec::new()));
        let scp = spawn_mock(capturing_discovery_router(Arc::clone(&captured))).await;
        let client = BsfClient::new(&scp, reqwest::Client::new())
            .with_communication(crate::sbi::Communication::Indirect);

        let result = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "404 still maps to Ok(None) in indirect mode"
        );

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (target_nf, service_names, requester_nf) = &captured[0];
        assert_eq!(target_nf.as_deref(), Some("BSF"));
        assert_eq!(service_names.as_deref(), Some("nbsf-management"));
        assert_eq!(requester_nf.as_deref(), Some("AF"));
    }

    #[tokio::test]
    async fn direct_discover_emits_no_discovery_headers() {
        let captured: CapturedDiscoveryHeaders = Arc::new(Mutex::new(Vec::new()));
        let bsf = spawn_mock(capturing_discovery_router(Arc::clone(&captured))).await;
        // Direct by default.
        let client = BsfClient::new(&bsf, reqwest::Client::new());

        let _ = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0],
            (None, None, None),
            "direct mode emits no discovery headers"
        );
    }

    #[tokio::test]
    async fn indirect_requester_nf_type_override() {
        let captured: CapturedDiscoveryHeaders = Arc::new(Mutex::new(Vec::new()));
        let scp = spawn_mock(capturing_discovery_router(Arc::clone(&captured))).await;
        let client = BsfClient::new(&scp, reqwest::Client::new())
            .with_communication(crate::sbi::Communication::Indirect)
            .with_requester_nf_type("PCF");

        let _ = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(captured[0].2.as_deref(), Some("PCF"));
    }

    /// Pin the spec-compliant resource path (TS 29.521): the request MUST hit
    /// `/nbsf-management/v1/pcfBindings`. A catch-all fallback records the
    /// actual path, independent of any mounted route, so a regression back to
    /// the old `bsf-management` typo is caught even if a mock route is changed
    /// in lockstep.
    #[tokio::test]
    async fn discover_uses_spec_compliant_nbsf_management_path() {
        use axum::extract::Request;

        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_handler = Arc::clone(&captured);
        let router = axum::Router::new().fallback(move |request: Request| {
            let captured = Arc::clone(&captured_handler);
            async move {
                captured
                    .lock()
                    .unwrap()
                    .push(request.uri().path().to_string());
                axum::http::StatusCode::NOT_FOUND
            }
        });
        let base = spawn_mock(router).await;
        let client = BsfClient::new(&base, reqwest::Client::new());

        let _ = client
            .discover_binding(&BindingQuery::Ipv4("10.45.0.7".into()))
            .await
            .unwrap();

        let paths = captured.lock().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "/nbsf-management/v1/pcfBindings");
    }
}
