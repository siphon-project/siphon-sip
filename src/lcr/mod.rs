//! Least-Cost Routing (LCR) — external HTTP JSON routing API client.
//!
//! LCR keeps the *rating decision* (which carrier, in what order, at what cost)
//! in an **external HTTP API**, not in siphon.  siphon asks the API, caches the
//! answer, and executes the returned ordered route set against its `gateway`
//! health/failover machinery — it is not a rating engine.
//!
//! Split of responsibility:
//! - **API owns cost order** (rate decks, prefix match, margin) — returned as an
//!   ordered [`Route`] list, cached with an API-controlled TTL.
//! - **siphon owns liveness + execution** — a [`Route`] may name a configured
//!   gateway group; siphon picks the healthy member, skips dead carriers, and
//!   drives sequential failover across the list on the B2BUA (dialog hygiene:
//!   each carrier attempt is a fresh B-leg dialog).
//!
//! LCR is **B2BUA-only** — see `docs/cookbook/least-cost-routing.md` for why
//! (Call-ID / dialog hygiene, per-carrier media, charging).
//!
//! The wire contract in this module is the single source of truth; the SDK
//! pydantic models in `sdk/siphon_sdk/lcr.py` mirror it, and the reference
//! server in `examples/lcr_api_server.py` implements it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::cache::CacheManager;

/// Contract version siphon sends in [`LcrRequest::version`] and expects the API
/// to understand.  Bump only on a breaking wire change.
pub const LCR_CONTRACT_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Reroute causes — which SIP response codes trigger failover to the next carrier
// ---------------------------------------------------------------------------

/// The built-in default set of SIP response codes that trigger LCR failover to
/// the next carrier: network / server-failure codes (a carrier down or out of
/// circuits, or a ring-timeout mapped to 408), **not** definitive call outcomes
/// (486 Busy, 603 Decline, 600, 487). Operators extend/override this globally
/// (`lcr.reroute_causes`), per gateway group (`gateway.groups[].reroute_causes`),
/// or per route (the API's `reroute_causes`), because some carriers don't play
/// nice with the standard codes.
pub fn default_reroute_causes() -> HashSet<u16> {
    [408, 500, 502, 503, 504].into_iter().collect()
}

static GLOBAL_REROUTE_CAUSES: OnceLock<HashSet<u16>> = OnceLock::new();

/// Install the process-wide reroute-cause set (from `lcr.reroute_causes`, else
/// [`default_reroute_causes`]). Called once at startup.
pub fn set_global_reroute_causes(causes: HashSet<u16>) {
    let _ = GLOBAL_REROUTE_CAUSES.set(causes);
}

/// Whether `status` is in the process-wide reroute set (falls back to
/// [`default_reroute_causes`] when unset).
pub fn global_reroute_contains(status: u16) -> bool {
    match GLOBAL_REROUTE_CAUSES.get() {
        Some(set) => set.contains(&status),
        None => default_reroute_causes().contains(&status),
    }
}

// ---------------------------------------------------------------------------
// Wire contract (siphon <-> external LCR API)
// ---------------------------------------------------------------------------

/// The query siphon `POST`s to the external LCR API for each new call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LcrRequest {
    /// Contract version ([`LCR_CONTRACT_VERSION`]).
    pub version: String,
    /// A-leg Call-ID (for the API's own correlation/logging).
    pub call_id: String,
    /// A-leg From URI.
    pub from: String,
    /// A-leg To URI.
    pub to: String,
    /// The number being dialed, normalized by the script before the query
    /// (canonical `+E.164` is recommended). This is what the API rates.
    pub dialed_number: String,
    /// Ingress context.
    pub source: LcrSource,
    /// Free-form script-supplied hints (customer id, rate-deck id, …).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

/// Ingress context on an [`LcrRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LcrSource {
    /// Source IP of the A-leg.
    pub ip: String,
    /// Ingress trunk / customer group the call arrived on, if the script knows
    /// it (e.g. from `call.from_gateway(...)`). Part of the cache key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trunk_group: Option<String>,
    /// A-leg transport (`udp` | `tcp` | `tls` | `ws` | `wss`).
    pub transport: String,
}

/// The ordered decision the external API returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LcrResponse {
    /// Carriers to try, cheapest/most-preferred first. Empty + `reject: None`
    /// means "no route" (the script should answer 4xx/5xx).
    #[serde(default)]
    pub routes: Vec<Route>,
    /// How long (seconds) siphon may cache this decision. `None` or `0` = do
    /// not cache. The API fully controls caching via this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u64>,
    /// When set, siphon rejects the call with this code/reason instead of
    /// dialing (an API-side block, e.g. no route / fraud / balance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject: Option<LcrReject>,
}

/// An API-side instruction to reject the call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LcrReject {
    /// SIP status code (e.g. 503, 403).
    pub code: u16,
    /// SIP reason phrase.
    pub reason: String,
}

/// One carrier attempt in an [`LcrResponse`]. At least one of `gateway_group` /
/// `next_hop` must be set (validated when the route is executed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Route {
    /// Opaque carrier identifier — carried into CDR/charging, never routed on.
    pub carrier_id: String,
    /// Configured `gateway:` group to route through. siphon resolves it to a
    /// healthy member at dial time (skipping the route if the whole group is
    /// down). Preferred over `next_hop` so carrier health-probing applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_group: Option<String>,
    /// Explicit next-hop URI (used when no `gateway_group`, or to pin the wire
    /// destination while `ruri` shapes the Request-URI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    /// R-URI override for this carrier (else the dialed number is kept). Full
    /// control over the number shape the carrier sees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruri: Option<String>,
    /// Tech-prefix / dial-prefix prepended to the B-leg R-URI userpart for this
    /// carrier (e.g. `"1010288"` or `"#31#"`). Many carriers key routing/billing
    /// on a prefix in front of the E.164 number. Prepended to `ruri`'s userpart
    /// when set, else the dialed number's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tech_prefix: Option<String>,
    /// Per-minute rate — carried into CDR/charging (not used for routing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<f64>,
    /// Rate currency (ISO 4217), e.g. `"USD"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Billing increment in seconds (e.g. 60 = per-minute, 1 = per-second).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_increment: Option<u32>,
    /// Minimum billable duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_duration: Option<u32>,
    /// Per-attempt ring timeout in seconds (else the call-level default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    /// Headers to inject on this carrier's B-leg INVITE (e.g. a carrier account
    /// token or routing tag). Applied after the header policy, so they always
    /// land on the wire.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    /// SIP response codes from *this* carrier that trigger failover to the next
    /// carrier. When set, overrides the per-gateway and global reroute sets for
    /// this route (for a carrier the API knows misbehaves — e.g. one that sends
    /// `404` when it means "no circuits"). Empty = fall back to the per-gateway
    /// then global set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reroute_causes: Vec<u16>,
}

impl Route {
    /// A route is routable if it names either a gateway group or a next-hop.
    pub fn is_routable(&self) -> bool {
        self.gateway_group.is_some() || self.next_hop.is_some() || self.ruri.is_some()
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Outcome of an LCR query.
#[derive(Debug, Clone, PartialEq)]
pub enum LcrOutcome {
    /// A decision — fresh from the API, from cache, or a synthesized fallback.
    Decision(LcrResponse),
    /// The API was unreachable and no fallback gateway group is configured.
    /// The script should answer a 5xx (siphon has no route to offer).
    Unavailable,
}

/// HTTP client for the external LCR API, with decision caching and a static
/// fallback. One `reqwest::Client` (internally pooled) is reused for all queries.
pub struct LcrClient {
    http: reqwest::Client,
    api_url: String,
    auth_header: Option<String>,
    cache: Option<Arc<CacheManager>>,
    cache_name: Option<String>,
    /// Default TTL used only when the API omits `cache_ttl_secs`.
    default_cache_ttl_secs: u64,
    fallback_gateway_group: Option<String>,
}

impl LcrClient {
    /// Build a client. `timeout_ms` bounds each query (set on the reqwest client).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_url: String,
        timeout_ms: u64,
        auth_header: Option<String>,
        cache: Option<Arc<CacheManager>>,
        cache_name: Option<String>,
        default_cache_ttl_secs: u64,
        fallback_gateway_group: Option<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();
        Self {
            http,
            api_url,
            auth_header,
            cache,
            cache_name,
            default_cache_ttl_secs,
            fallback_gateway_group,
        }
    }

    /// Cache key for a query: `{trunk_group}:{dialed_number}`. Full-number
    /// granularity — the API's `cache_ttl_secs` governs lifetime. (Prefix-level
    /// caching would require prefix knowledge, i.e. rating logic, which stays in
    /// the API.)
    fn cache_key(request: &LcrRequest) -> String {
        let trunk = request.source.trunk_group.as_deref().unwrap_or("-");
        format!("{trunk}:{}", request.dialed_number)
    }

    /// Synthesize a single-route fallback decision from the configured fallback
    /// gateway group, or `None` when none is configured.
    fn fallback_response(&self) -> Option<LcrResponse> {
        let group = self.fallback_gateway_group.as_ref()?;
        Some(LcrResponse {
            routes: vec![Route {
                carrier_id: format!("fallback:{group}"),
                gateway_group: Some(group.clone()),
                ..Route::default()
            }],
            cache_ttl_secs: None, // never cache a fallback
            reject: None,
        })
    }

    /// Query the external API, honoring cache and falling back on transport error.
    pub async fn route(&self, request: &LcrRequest) -> LcrOutcome {
        // 1. Cache lookup.
        if let (Some(cache), Some(name)) = (&self.cache, &self.cache_name) {
            let key = Self::cache_key(request);
            if let Some(json) = cache.fetch(name, &key).await {
                if let Ok(decision) = serde_json::from_str::<LcrResponse>(&json) {
                    return LcrOutcome::Decision(decision);
                }
            }
        }

        // 2. Live query.
        match self.query_api(request).await {
            Ok(decision) => {
                self.maybe_cache(request, &decision).await;
                LcrOutcome::Decision(decision)
            }
            Err(error) => {
                // On transport error / timeout / 5xx, degrade to the static
                // fallback group rather than failing the call outright.
                warn!(%error, url = %self.api_url, "lcr: API query failed");
                match self.fallback_response() {
                    Some(decision) => LcrOutcome::Decision(decision),
                    None => LcrOutcome::Unavailable,
                }
            }
        }
    }

    async fn query_api(&self, request: &LcrRequest) -> Result<LcrResponse, String> {
        let mut builder = self.http.post(&self.api_url).json(request);
        if let Some(auth) = &self.auth_header {
            builder = builder.header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = builder.send().await.map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status().as_u16()));
        }
        response
            .json::<LcrResponse>()
            .await
            .map_err(|error| error.to_string())
    }

    async fn maybe_cache(&self, request: &LcrRequest, decision: &LcrResponse) {
        let (Some(cache), Some(name)) = (&self.cache, &self.cache_name) else {
            return;
        };
        let ttl = decision.cache_ttl_secs.unwrap_or(self.default_cache_ttl_secs);
        if ttl == 0 {
            return; // API opted out of caching for this decision.
        }
        if let Ok(json) = serde_json::to_string(decision) {
            cache
                .store(name, &Self::cache_key(request), &json, Some(ttl))
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A response matching the documented JSON contract, verbatim.
    const SAMPLE_RESPONSE: &str = r#"{
        "routes": [
            { "carrier_id": "carrier-a",
              "gateway_group": "carrier-a-pool",
              "next_hop": "sip:10.0.0.1:5060",
              "ruri": "sip:+12025550123@carrier-a.net",
              "rate": 0.0042, "currency": "USD", "billing_increment": 60, "min_duration": 0,
              "timeout_secs": 12 },
            { "carrier_id": "carrier-b", "gateway_group": "carrier-b-pool", "rate": 0.0051 }
        ],
        "cache_ttl_secs": 300,
        "reject": null
    }"#;

    #[test]
    fn response_contract_round_trips() {
        let decision: LcrResponse = serde_json::from_str(SAMPLE_RESPONSE).expect("parse sample");
        assert_eq!(decision.routes.len(), 2);
        assert_eq!(decision.cache_ttl_secs, Some(300));
        assert!(decision.reject.is_none());

        let first = &decision.routes[0];
        assert_eq!(first.carrier_id, "carrier-a");
        assert_eq!(first.gateway_group.as_deref(), Some("carrier-a-pool"));
        assert_eq!(first.rate, Some(0.0042));
        assert_eq!(first.timeout_secs, Some(12));
        assert_eq!(first.ruri.as_deref(), Some("sip:+12025550123@carrier-a.net"));
        assert!(first.is_routable());

        // Second route: only carrier_id + group + rate; every other field defaults.
        let second = &decision.routes[1];
        assert_eq!(second.carrier_id, "carrier-b");
        assert!(second.next_hop.is_none());
        assert!(second.ruri.is_none());
        assert!(second.is_routable());

        // Re-serialize and re-parse — stable.
        let json = serde_json::to_string(&decision).expect("serialize");
        let reparsed: LcrResponse = serde_json::from_str(&json).expect("reparse");
        assert_eq!(decision, reparsed);
    }

    #[test]
    fn request_contract_serializes_expected_shape() {
        let request = LcrRequest {
            version: LCR_CONTRACT_VERSION.to_string(),
            call_id: "abc@host".to_string(),
            from: "sip:+31650001111@example.com".to_string(),
            to: "sip:+12025550123@example.com".to_string(),
            dialed_number: "+12025550123".to_string(),
            source: LcrSource {
                ip: "203.0.113.5".to_string(),
                trunk_group: Some("cust-trunks".to_string()),
                transport: "udp".to_string(),
            },
            attributes: HashMap::from([("customer_id".to_string(), "cust-42".to_string())]),
        };
        let value: serde_json::Value =
            serde_json::to_value(&request).expect("request to json value");
        assert_eq!(value["version"], "1");
        assert_eq!(value["dialed_number"], "+12025550123");
        assert_eq!(value["source"]["trunk_group"], "cust-trunks");
        assert_eq!(value["attributes"]["customer_id"], "cust-42");

        // Round-trips back to an equal request.
        let reparsed: LcrRequest = serde_json::from_value(value).expect("reparse request");
        assert_eq!(request, reparsed);
    }

    #[test]
    fn empty_attributes_and_none_trunk_are_omitted() {
        let request = LcrRequest {
            version: LCR_CONTRACT_VERSION.to_string(),
            call_id: "x".to_string(),
            from: "sip:a@h".to_string(),
            to: "sip:b@h".to_string(),
            dialed_number: "+100".to_string(),
            source: LcrSource {
                ip: "203.0.113.9".to_string(),
                trunk_group: None,
                transport: "tls".to_string(),
            },
            attributes: HashMap::new(),
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert!(!json.contains("attributes"), "empty attributes omitted");
        assert!(!json.contains("trunk_group"), "None trunk_group omitted");
    }

    #[test]
    fn cache_key_uses_trunk_and_number() {
        let mut request = LcrRequest {
            version: "1".to_string(),
            call_id: "x".to_string(),
            from: "sip:a@h".to_string(),
            to: "sip:b@h".to_string(),
            dialed_number: "+12025550123".to_string(),
            source: LcrSource {
                ip: "203.0.113.5".to_string(),
                trunk_group: Some("cust-42".to_string()),
                transport: "udp".to_string(),
            },
            attributes: HashMap::new(),
        };
        assert_eq!(LcrClient::cache_key(&request), "cust-42:+12025550123");
        request.source.trunk_group = None;
        assert_eq!(LcrClient::cache_key(&request), "-:+12025550123");
    }

    #[test]
    fn fallback_response_synthesizes_group_route() {
        let with_fallback = LcrClient::new(
            "http://lcr.invalid/route".to_string(),
            100,
            None,
            None,
            None,
            300,
            Some("emergency-pstn".to_string()),
        );
        let decision = with_fallback.fallback_response().expect("fallback present");
        assert_eq!(decision.routes.len(), 1);
        assert_eq!(decision.routes[0].gateway_group.as_deref(), Some("emergency-pstn"));
        assert_eq!(decision.routes[0].carrier_id, "fallback:emergency-pstn");
        assert!(decision.cache_ttl_secs.is_none());

        let without_fallback = LcrClient::new(
            "http://lcr.invalid/route".to_string(),
            100,
            None,
            None,
            None,
            300,
            None,
        );
        assert!(without_fallback.fallback_response().is_none());
    }

    #[test]
    fn default_reroute_causes_are_server_failures_only() {
        let causes = default_reroute_causes();
        assert!(causes.contains(&503));
        assert!(causes.contains(&408));
        assert!(causes.contains(&500));
        // Definitive call outcomes are NOT reroute causes by default.
        assert!(!causes.contains(&486)); // Busy Here
        assert!(!causes.contains(&603)); // Decline
        assert!(!causes.contains(&404)); // operators opt this in per carrier
    }

    #[test]
    fn route_per_carrier_fields_round_trip() {
        let json = r#"{ "carrier_id": "carrier-a", "gateway_group": "pool-a",
            "tech_prefix": "1010288", "headers": { "X-Account": "42" },
            "reroute_causes": [404, 503] }"#;
        let route: Route = serde_json::from_str(json).expect("parse route");
        assert_eq!(route.tech_prefix.as_deref(), Some("1010288"));
        assert_eq!(route.headers.get("X-Account").map(String::as_str), Some("42"));
        assert_eq!(route.reroute_causes, vec![404, 503]);

        let reparsed: Route =
            serde_json::from_str(&serde_json::to_string(&route).unwrap()).unwrap();
        assert_eq!(route, reparsed);

        // Absent per-carrier fields default cleanly (and are omitted on the wire).
        let minimal: Route =
            serde_json::from_str(r#"{ "carrier_id": "c", "next_hop": "sip:h" }"#).unwrap();
        assert!(minimal.tech_prefix.is_none());
        assert!(minimal.headers.is_empty());
        assert!(minimal.reroute_causes.is_empty());
        let wire = serde_json::to_string(&minimal).unwrap();
        assert!(!wire.contains("tech_prefix"));
        assert!(!wire.contains("reroute_causes"));
    }

    #[test]
    fn reject_only_response_parses() {
        let json = r#"{ "routes": [], "reject": { "code": 503, "reason": "No Route" } }"#;
        let decision: LcrResponse = serde_json::from_str(json).expect("parse reject");
        assert!(decision.routes.is_empty());
        let reject = decision.reject.expect("reject present");
        assert_eq!(reject.code, 503);
        assert_eq!(reject.reason, "No Route");
    }

    // --- LcrClient against an in-process mock HTTP server ---

    fn sample_request() -> LcrRequest {
        LcrRequest {
            version: LCR_CONTRACT_VERSION.to_string(),
            call_id: "c@h".to_string(),
            from: "sip:+13105550100@sbc".to_string(),
            to: "sip:+12025550123@sbc".to_string(),
            dialed_number: "+12025550123".to_string(),
            source: LcrSource {
                ip: "203.0.113.5".to_string(),
                trunk_group: Some("cust".to_string()),
                transport: "udp".to_string(),
            },
            attributes: HashMap::new(),
        }
    }

    /// Spawn a one-shot HTTP/1.1 server that returns `body` and return its URL.
    async fn spawn_mock_api(body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 8192];
                let _ = socket.read(&mut buffer).await; // drain the request
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        format!("http://{addr}/route")
    }

    /// A URL to a guaranteed-closed port (bind then drop) → connection refused.
    async fn closed_port_url() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}/route")
    }

    #[tokio::test]
    async fn client_returns_decision_from_api() {
        let url = spawn_mock_api(
            r#"{"routes":[{"carrier_id":"carrier-a","gateway_group":"pool-a","rate":0.004}],"cache_ttl_secs":0}"#,
        )
        .await;
        let client = LcrClient::new(url, 2000, None, None, None, 300, None);
        match client.route(&sample_request()).await {
            LcrOutcome::Decision(decision) => {
                assert_eq!(decision.routes.len(), 1);
                assert_eq!(decision.routes[0].carrier_id, "carrier-a");
                assert!(decision.reject.is_none());
            }
            LcrOutcome::Unavailable => panic!("expected a decision"),
        }
    }

    #[tokio::test]
    async fn client_surfaces_api_reject() {
        let url =
            spawn_mock_api(r#"{"routes":[],"reject":{"code":503,"reason":"No Route"}}"#).await;
        let client = LcrClient::new(url, 2000, None, None, None, 300, None);
        match client.route(&sample_request()).await {
            LcrOutcome::Decision(decision) => {
                let reject = decision.reject.expect("reject present");
                assert_eq!(reject.code, 503);
                assert!(decision.routes.is_empty());
            }
            LcrOutcome::Unavailable => panic!("expected a reject decision"),
        }
    }

    #[tokio::test]
    async fn client_falls_back_to_gateway_group_on_transport_error() {
        let url = closed_port_url().await;
        let client = LcrClient::new(url, 500, None, None, None, 300, Some("emergency".to_string()));
        match client.route(&sample_request()).await {
            LcrOutcome::Decision(decision) => {
                assert_eq!(decision.routes.len(), 1);
                assert_eq!(decision.routes[0].gateway_group.as_deref(), Some("emergency"));
                assert!(decision.cache_ttl_secs.is_none());
            }
            LcrOutcome::Unavailable => panic!("expected the fallback decision"),
        }
    }

    #[tokio::test]
    async fn client_unavailable_without_fallback() {
        let url = closed_port_url().await;
        let client = LcrClient::new(url, 500, None, None, None, 300, None);
        assert_eq!(
            client.route(&sample_request()).await,
            LcrOutcome::Unavailable
        );
    }
}
