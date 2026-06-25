//! Npcf_PolicyAuthorization — 5G QoS policy control (TS 29.514).
//!
//! Provides a typed client for creating, updating, and deleting app sessions
//! via the PCF policy authorization API. Used by P-CSCF to request QoS
//! resources for IMS media sessions.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Media sub-component describing an individual IP flow within a media
/// component (TS 29.514 §5.6.2.8). Serialized with the exact 3GPP wire names —
/// `fNum`, `fDescs`, `fStatus`, `flowUsage` — not a `camelCase` of the Rust
/// field names, which the PCF would silently ignore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaSubComponent {
    /// Flow number identifying this sub-component within the media component
    /// (`fNum`, required — also the key in the parent `medSubComps` map).
    #[serde(rename = "fNum")]
    pub f_num: u32,
    /// IPFilterRule flow descriptions (`fDescs`, e.g.
    /// "permit in ip from any to 10.0.0.1 20000"; 1–2 entries).
    #[serde(rename = "fDescs", default, skip_serializing_if = "Option::is_none")]
    pub f_descs: Option<Vec<String>>,
    /// Flow status (`fStatus`): "ENABLED", "DISABLED", "ENABLED-UPLINK",
    /// "ENABLED-DOWNLINK", "REMOVED".
    #[serde(rename = "fStatus", default, skip_serializing_if = "Option::is_none")]
    pub f_status: Option<String>,
    /// Flow usage (`flowUsage`): "NO_INFO", "RTCP", "AF_SIGNALLING".
    #[serde(
        rename = "flowUsage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub flow_usage: Option<String>,
}

/// Media component for QoS policy (TS 29.514 §5.6.2.7). Serialized with the
/// exact 3GPP wire names — `medCompN`, `medType`, `fStatus`, `codecs`,
/// `medSubComps`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaComponent {
    /// Ordinal number identifying this media component (`medCompN`, required —
    /// also the key in the parent `medComponents` map).
    #[serde(rename = "medCompN")]
    pub med_comp_n: u32,
    /// Media type (`medType`): "AUDIO", "VIDEO", "APPLICATION", etc.
    #[serde(rename = "medType")]
    pub med_type: String,
    /// Flow status (`fStatus`): "ENABLED", "DISABLED", "ENABLED-UPLINK",
    /// "ENABLED-DOWNLINK", "REMOVED".
    #[serde(rename = "fStatus")]
    pub f_status: String,
    /// Codec descriptions (`codecs`, SDP per RFC 4566; 1–2 entries).
    #[serde(rename = "codecs", default, skip_serializing_if = "Option::is_none")]
    pub codecs: Option<Vec<String>>,
    /// Media sub-components describing individual IP flows (`medSubComps`), a
    /// map keyed by the sub-component's `fNum` (TS 29.514 §5.6.2.7) — NOT an
    /// array.
    #[serde(
        rename = "medSubComps",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub med_sub_comps: Option<IndexMap<String, MediaSubComponent>>,
}

/// Event subscription for PCF notifications (TS 29.514).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSubscription {
    /// Event type (e.g. "UP_PATH_CH_EVENT", "PLMN_CH_EVENT", "QOS_NOTIF").
    pub event: String,
    /// Notification method: "EVENT_DETECTION", "ONE_TIME", "PERIODIC".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notif_method: Option<String>,
}

/// Request data for an app-session create (TS 29.514 §5.6.2.3,
/// `AppSessionContextReqData`).
///
/// On the wire this is **nested under `ascReqData`** inside the top-level
/// `AppSessionContext` (see [`AppSessionContextBody`]) — the PCF reads
/// `ascReqData.ueIpv4` to match the SM policy, so a flat (un-enveloped) body
/// produces a session that is created but never bound to the UE's bearer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionContextReqData {
    /// Application Function application identifier (`afAppId`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub af_app_id: Option<String>,
    /// Media components describing the session's media flows (`medComponents`),
    /// a map keyed by each component's `medCompN` (TS 29.514 §5.6.2.3) — NOT an
    /// array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub med_components: Option<IndexMap<String, MediaComponent>>,
    /// SIP Call-ID for correlation with SIP signaling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sip_call_id: Option<String>,
    /// Subscription Permanent Identifier (`supi`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    /// UE IPv4 address (`ueIpv4`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ipv4: Option<String>,
    /// UE IPv6 address (`ueIpv6`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ue_ipv6: Option<String>,
    /// Data Network Name (`dnn`, APN equivalent in 5GC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnn: Option<String>,
    /// Event subscriptions for PCF notifications (`evSubsc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ev_subsc: Option<EventSubscription>,
    /// Notification URI (`notifUri`) — callback endpoint for PCF events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notif_uri: Option<String>,
    /// Supported features (`suppFeat`, feature negotiation bitstring).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Top-level POST body for an app-session create (TS 29.514 §5.6.2.2,
/// `AppSessionContext`). The request data is carried under `ascReqData`.
#[derive(Debug, Serialize)]
struct AppSessionContextBody<'a> {
    #[serde(rename = "ascReqData")]
    asc_req_data: &'a AppSessionContextReqData,
}

// The inbound PCF event notification (TS 29.514 `EventsNotification`) is NOT
// modelled as a typed struct here. It is a large, evolving document
// (`evSubsUri`, `evNotifs`, `qosMonReports`, `succResourcAllocReports`,
// `accessType`, …) and the `@sbi.on_event` handler receives it verbatim as a
// JSON dict — see `server::pcf_notification_body_to_json`. A typed projection
// would silently drop fields the script needs (notably the required
// `evSubsUri` correlation key) and `422` any notification whose inner shape we
// failed to model exactly.

/// Result of a successful app-session create (`201 Created`).
///
/// Per TS 29.514 §4.2.2.2 the assigned `appSessionId` is carried **only** in
/// the `Location` header — not in the response body — so the id is derived from
/// the last path segment of `location`. `location` is the replica-independent
/// resource URI; the script persists it and hands it back on teardown so
/// `update`/`delete` reach the same PCF even from a different siphon replica.
#[derive(Debug, Clone)]
pub struct CreatedAppSession {
    /// PCF-assigned session id (last path segment of the `Location` header).
    pub app_session_id: String,
    /// Whether the create was accepted (`true` on a `2xx`). Finer-grained
    /// per-component authorization, if ever needed, lives in `ascRespData`.
    pub authorized: bool,
    /// Absolute app-session resource URI (`Location` header), if present.
    pub location: Option<String>,
}

/// SBI error type.
#[derive(Debug)]
pub enum SbiError {
    /// Transport-level error (connection refused, timeout, etc.).
    Transport(String),
    /// HTTP error with status code.
    HttpError(u16),
    /// Failed to deserialize the response body.
    Deserialization(String),
}

impl std::fmt::Display for SbiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) => write!(formatter, "SBI transport error: {message}"),
            Self::HttpError(code) => write!(formatter, "SBI HTTP error: {code}"),
            Self::Deserialization(message) => {
                write!(formatter, "SBI deserialization error: {message}")
            }
        }
    }
}

impl std::error::Error for SbiError {}

/// HTTP header carrying the target NF apiRoot for SCP indirect communication,
/// Model C (TS 29.500 §5.2.3.2.2).
const TARGET_APIROOT_HEADER: &str = "3gpp-Sbi-Target-apiRoot";

/// Npcf client for policy authorization.
pub struct NpcfClient {
    base_url: String,
    client: reqwest::Client,
    communication: crate::sbi::Communication,
}

impl NpcfClient {
    /// Create a new Npcf client pointing at the given base URL (the PCF in
    /// `Direct` mode, the SCP in `Indirect` mode). Defaults to `Direct`.
    pub fn new(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            communication: crate::sbi::Communication::Direct,
        }
    }

    /// Set the SBI communication model. `Indirect` routes via the SCP and emits
    /// the `3gpp-Sbi-Target-apiRoot` header (Model C).
    pub fn with_communication(mut self, communication: crate::sbi::Communication) -> Self {
        self.communication = communication;
        self
    }

    /// Create a new app session (POST /npcf-policyauthorization/v1/app-sessions).
    ///
    /// `target` overrides the base URL for this one call — used to address the
    /// N5 transaction at a BSF-discovered PCF (`pcfFqdn`) instead of the
    /// configured SCP/fallback. `None` posts to `self.base_url` (today's
    /// VoLTE-via-SCP path, byte-for-byte unchanged).
    ///
    /// Returns the `Location` header (the absolute resource URI) and the
    /// `appSessionId` derived from it, so the caller can address the same
    /// session on teardown.
    pub async fn create_app_session(
        &self,
        target: Option<&str>,
        request_data: &AppSessionContextReqData,
    ) -> Result<CreatedAppSession, SbiError> {
        // The PCF this session belongs to (the per-call target, else base_url).
        // Used as the apiRoot in Indirect mode and to resolve a relative
        // Location in either mode.
        let target_apiroot = target
            .map(|target| target.trim_end_matches('/'))
            .unwrap_or(&self.base_url);

        let (url, send_target_header) = match self.communication {
            // Direct: POST straight at the target PCF.
            crate::sbi::Communication::Direct => (
                format!("{target_apiroot}/npcf-policyauthorization/v1/app-sessions"),
                false,
            ),
            // Indirect (Model C): POST to the SCP, target carried in the header.
            crate::sbi::Communication::Indirect => (
                format!("{}/npcf-policyauthorization/v1/app-sessions", self.base_url),
                true,
            ),
        };

        // TS 29.514 §5.6.2.2: the request data is nested under `ascReqData`.
        let body = AppSessionContextBody {
            asc_req_data: request_data,
        };
        let mut request = self.client.post(&url).json(&body);
        if send_target_header {
            request = request.header(TARGET_APIROOT_HEADER, target_apiroot);
        }
        let response = request
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }

        // The created resource id lives in the Location header only (the 201
        // body is `AppSessionContext` with `ascRespData`, never a flat
        // `{appSessionId,…}`), so we never parse the body. Resolve a relative
        // Location against the target PCF apiRoot (the resource lives on the
        // PCF, not the SCP).
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(|location| resolve_location(target_apiroot, location));

        let app_session_id = location
            .as_deref()
            .map(app_session_id_from_location)
            .unwrap_or_default();

        Ok(CreatedAppSession {
            app_session_id,
            authorized: true,
            location,
        })
    }

    /// Delete an app session.
    ///
    /// `session_ref` is either a bare app-session id (resolved against
    /// `self.base_url`, the legacy behaviour) or an absolute resource URI
    /// (`http(s)://…`, used verbatim — the replica-independent teardown path).
    pub async fn delete_app_session(&self, session_ref: &str) -> Result<(), SbiError> {
        let (url, target_apiroot) = self.resolve_session_request(session_ref);
        let mut request = self.client.delete(&url);
        if let Some(ref apiroot) = target_apiroot {
            request = request.header(TARGET_APIROOT_HEADER, apiroot);
        }
        let response = request
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() && response.status().as_u16() != 204 {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }
        Ok(())
    }

    /// Update an app session (PATCH the resource).
    ///
    /// Used for media renegotiation (re-INVITE/UPDATE) to modify QoS.
    /// `session_ref` follows the same id-or-absolute-URI rule as
    /// [`delete_app_session`].
    ///
    /// Per TS 29.514 §4.2.3.2 the modify operation is a JSON merge-patch
    /// (`application/merge-patch+json`) whose body is the patchable subset of
    /// the request data **flat** (no `ascReqData` envelope, unlike create).
    /// Returns `Ok(())` on any `2xx`; the response body (the updated
    /// `AppSessionContext`) is not parsed.
    pub async fn update_app_session(
        &self,
        session_ref: &str,
        request_data: &AppSessionContextReqData,
    ) -> Result<(), SbiError> {
        let (url, target_apiroot) = self.resolve_session_request(session_ref);
        let patch_body = serde_json::to_vec(request_data)
            .map_err(|error| SbiError::Deserialization(error.to_string()))?;
        let mut request = self
            .client
            .patch(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/merge-patch+json")
            .body(patch_body);
        if let Some(ref apiroot) = target_apiroot {
            request = request.header(TARGET_APIROOT_HEADER, apiroot);
        }
        let response = request
            .send()
            .await
            .map_err(|error| SbiError::Transport(error.to_string()))?;

        if !response.status().is_success() {
            return Err(SbiError::HttpError(response.status().as_u16()));
        }
        Ok(())
    }

    /// Resolve a session reference to a concrete request URL plus an optional
    /// `3gpp-Sbi-Target-apiRoot` value.
    ///
    /// - `Direct`: absolute references are used verbatim; a bare id is appended
    ///   to `self.base_url`'s app-sessions collection. No target header.
    /// - `Indirect`: send to the SCP (`self.base_url`). An absolute resource
    ///   URI is split into apiRoot (→ header) and path (→ appended to the SCP);
    ///   a bare id targets the SCP collection with no specific PCF.
    fn resolve_session_request(&self, session_ref: &str) -> (String, Option<String>) {
        match self.communication {
            crate::sbi::Communication::Direct => {
                if is_absolute_http_url(session_ref) {
                    (session_ref.to_string(), None)
                } else {
                    (
                        format!(
                            "{}/npcf-policyauthorization/v1/app-sessions/{}",
                            self.base_url, session_ref
                        ),
                        None,
                    )
                }
            }
            crate::sbi::Communication::Indirect => {
                if let Some((apiroot, path)) = apiroot_and_path(session_ref) {
                    (format!("{}{}", self.base_url, path), Some(apiroot))
                } else {
                    (
                        format!(
                            "{}/npcf-policyauthorization/v1/app-sessions/{}",
                            self.base_url, session_ref
                        ),
                        None,
                    )
                }
            }
        }
    }

    /// Get the base URL this client is configured to use.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// Whether a string is an absolute `http`/`https` URL.
fn is_absolute_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

/// Split an absolute `http(s)` URL into its apiRoot (`{scheme}://{authority}`)
/// and the remaining path (`/...`, empty if none). Returns `None` for a
/// non-absolute reference (a bare id).
fn apiroot_and_path(value: &str) -> Option<(String, String)> {
    let scheme_end = value.find("://")? + 3;
    let (scheme_host, rest) = value.split_at(scheme_end);
    // `rest` is `authority[/path...]`; the apiRoot stops at the first `/`.
    match rest.find('/') {
        Some(slash) => {
            let authority = &rest[..slash];
            let path = &rest[slash..];
            Some((format!("{scheme_host}{authority}"), path.to_string()))
        }
        None => Some((value.to_string(), String::new())),
    }
}

/// Derive the `appSessionId` from a (resolved) app-session resource URI — the
/// last non-empty path segment (TS 29.514 §4.2.2.2:
/// `{apiRoot}/npcf-policyauthorization/v1/app-sessions/{appSessionId}`).
///
/// Also the id-or-absolute-URI normalizer used by the Python binding to echo a
/// bare `app_session_id` back from an `update_session` whose ref may be the
/// absolute `app_session_uri`.
pub(crate) fn app_session_id_from_location(location: &str) -> String {
    location
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Resolve a (possibly relative) `Location` header against the base URL the
/// request was sent to. Absolute Locations are returned verbatim.
fn resolve_location(base: &str, location: &str) -> String {
    if is_absolute_http_url(location) {
        location.to_string()
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            location.trim_start_matches('/')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the `medComponents` map keyed by each component's `medCompN`,
    /// mirroring what the Python binding does before a create/update.
    fn components_map(components: Vec<MediaComponent>) -> IndexMap<String, MediaComponent> {
        components
            .into_iter()
            .map(|component| (component.med_comp_n.to_string(), component))
            .collect()
    }

    #[test]
    fn media_component_serialization() {
        let media_component = MediaComponent {
            med_comp_n: 1,
            med_type: "AUDIO".to_string(),
            f_status: "ENABLED".to_string(),
            codecs: Some(vec!["PCMU".to_string()]),
            med_sub_comps: None,
        };
        let json = serde_json::to_string(&media_component).unwrap();
        // Exact 3GPP wire names — a `camelCase` of the Rust fields would be
        // silently ignored by the PCF (TS 29.514 §5.6.2.7).
        assert!(json.contains("\"medCompN\":1"), "{json}");
        assert!(json.contains("\"medType\":\"AUDIO\""), "{json}");
        assert!(json.contains("\"fStatus\":\"ENABLED\""), "{json}");
        assert!(json.contains("\"codecs\":[\"PCMU\"]"), "{json}");
        // The pre-spec names must NOT appear.
        assert!(!json.contains("mediaComponentNumber"), "{json}");
        assert!(!json.contains("codecData"), "{json}");
    }

    #[test]
    fn media_component_deserialization() {
        let json = r#"{
            "medCompN": 2,
            "medType": "VIDEO",
            "fStatus": "DISABLED",
            "codecs": null
        }"#;
        let media_component: MediaComponent = serde_json::from_str(json).unwrap();
        assert_eq!(media_component.med_comp_n, 2);
        assert_eq!(media_component.med_type, "VIDEO");
        assert!(media_component.codecs.is_none());
    }

    #[test]
    fn app_session_context_serialization() {
        let request_data = AppSessionContextReqData {
            af_app_id: Some("siphon".to_string()),
            med_components: Some(components_map(vec![MediaComponent {
                med_comp_n: 1,
                med_type: "AUDIO".to_string(),
                f_status: "ENABLED".to_string(),
                codecs: None,
                med_sub_comps: None,
            }])),
            sip_call_id: Some("call-123@siphon.local".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&request_data).unwrap();
        assert!(json.contains("afAppId"));
        assert!(json.contains("sipCallId"));
        assert!(json.contains("medComponents"));
        // The media components are an object keyed by medCompN, not an array.
        assert!(json.contains("\"medComponents\":{\"1\":{"), "{json}");
    }

    /// The headline regression: the POST body MUST nest the request data under
    /// `ascReqData` (TS 29.514 §5.6.2.2). A flat body created a session the PCF
    /// never bound to the UE (ueIpv4 read as null).
    #[test]
    fn create_body_nests_request_data_under_asc_req_data() {
        let request_data = AppSessionContextReqData {
            af_app_id: Some("IMS Services".to_string()),
            ue_ipv4: Some("100.65.0.4".to_string()),
            supi: Some("imsi-001010000000001".to_string()),
            ..Default::default()
        };
        let body = AppSessionContextBody {
            asc_req_data: &request_data,
        };
        let value = serde_json::to_value(&body).unwrap();
        // ueIpv4 lives under ascReqData, not at the top level.
        assert!(value.get("ueIpv4").is_none(), "{value}");
        let asc = value.get("ascReqData").expect("ascReqData envelope");
        assert_eq!(asc.get("ueIpv4").and_then(|v| v.as_str()), Some("100.65.0.4"));
        assert_eq!(asc.get("afAppId").and_then(|v| v.as_str()), Some("IMS Services"));
        assert_eq!(
            asc.get("supi").and_then(|v| v.as_str()),
            Some("imsi-001010000000001")
        );
    }

    #[test]
    fn app_session_id_derived_from_location_path() {
        assert_eq!(
            app_session_id_from_location(
                "http://pcf01:8080/npcf-policyauthorization/v1/app-sessions/sess-abc-123"
            ),
            "sess-abc-123"
        );
        // Trailing slash tolerated.
        assert_eq!(
            app_session_id_from_location("http://pcf01/a/b/sess-xyz/"),
            "sess-xyz"
        );
        // A bare id normalizes to itself (used by update_session echo).
        assert_eq!(app_session_id_from_location("sess-bare"), "sess-bare");
    }

    #[test]
    fn sbi_error_display() {
        let transport_error = SbiError::Transport("connection refused".to_string());
        assert!(transport_error.to_string().contains("connection refused"));

        let http_error = SbiError::HttpError(503);
        assert!(http_error.to_string().contains("503"));

        let deser_error = SbiError::Deserialization("missing field".to_string());
        assert!(deser_error.to_string().contains("missing field"));
    }

    #[test]
    fn npcf_client_base_url_trimmed() {
        let client = NpcfClient::new("https://pcf.5gc.example.com/", reqwest::Client::new());
        assert_eq!(client.base_url(), "https://pcf.5gc.example.com");
    }

    #[test]
    fn npcf_client_base_url_no_trailing_slash() {
        let client = NpcfClient::new("https://pcf.5gc.example.com", reqwest::Client::new());
        assert_eq!(client.base_url(), "https://pcf.5gc.example.com");
    }

    #[test]
    fn app_session_context_with_extended_fields() {
        let mut sub_comps = IndexMap::new();
        sub_comps.insert(
            "1".to_string(),
            MediaSubComponent {
                f_num: 1,
                f_descs: Some(vec!["permit in ip from any to 10.0.0.1 20000".to_string()]),
                f_status: Some("ENABLED".to_string()),
                flow_usage: None,
            },
        );
        let request_data = AppSessionContextReqData {
            af_app_id: Some("siphon".to_string()),
            med_components: Some(components_map(vec![MediaComponent {
                med_comp_n: 1,
                med_type: "AUDIO".to_string(),
                f_status: "ENABLED".to_string(),
                codecs: None,
                med_sub_comps: Some(sub_comps),
            }])),
            sip_call_id: Some("call-456@siphon".to_string()),
            supi: Some("imsi-001010000000001".to_string()),
            ue_ipv4: Some("10.0.0.1".to_string()),
            dnn: Some("ims".to_string()),
            ev_subsc: Some(EventSubscription {
                event: "UP_PATH_CH_EVENT".to_string(),
                notif_method: Some("EVENT_DETECTION".to_string()),
            }),
            notif_uri: Some("http://pcscf:8080/sbi/events".to_string()),
            supp_feat: Some("1".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&request_data).unwrap();
        assert!(json.contains("supi"));
        assert!(json.contains("ueIpv4"));
        assert!(json.contains("dnn"));
        assert!(json.contains("evSubsc"));
        assert!(json.contains("notifUri"));
        assert!(json.contains("medSubComps"));
        assert!(json.contains("fDescs"));
        // medSubComps is a map keyed by fNum.
        assert!(json.contains("\"medSubComps\":{\"1\":{"), "{json}");

        // Roundtrip
        let parsed: AppSessionContextReqData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(parsed.ue_ipv4.as_deref(), Some("10.0.0.1"));
        assert_eq!(parsed.dnn.as_deref(), Some("ims"));
        let components = parsed.med_components.as_ref().unwrap();
        let sub_comps = components["1"].med_sub_comps.as_ref().unwrap();
        assert_eq!(sub_comps["1"].f_num, 1);
    }

    #[test]
    fn app_session_context_minimal_deserialization() {
        // Empty object — every field defaults to None.
        let json = r#"{}"#;
        let request_data: AppSessionContextReqData = serde_json::from_str(json).unwrap();
        assert!(request_data.af_app_id.is_none());
        assert!(request_data.supi.is_none());
        assert!(request_data.ue_ipv4.is_none());
        assert!(request_data.med_components.is_none());
    }

    #[test]
    fn is_absolute_http_url_detects_scheme() {
        assert!(is_absolute_http_url("http://pcf/x"));
        assert!(is_absolute_http_url("https://pcf/x"));
        assert!(!is_absolute_http_url("sess-abc-123"));
        assert!(!is_absolute_http_url("/npcf-policyauthorization/v1/app-sessions/1"));
    }

    #[test]
    fn resolve_session_request_direct_bare_id_against_base() {
        let client = NpcfClient::new("http://scp.local:8080", reqwest::Client::new());
        let (url, target) = client.resolve_session_request("sess-1");
        assert_eq!(
            url,
            "http://scp.local:8080/npcf-policyauthorization/v1/app-sessions/sess-1"
        );
        assert!(target.is_none());
    }

    #[test]
    fn resolve_session_request_direct_absolute_uri_verbatim() {
        let client = NpcfClient::new("http://scp.local:8080", reqwest::Client::new());
        let absolute = "http://pcf01.5gc:8080/npcf-policyauthorization/v1/app-sessions/abc";
        let (url, target) = client.resolve_session_request(absolute);
        assert_eq!(url, absolute);
        assert!(target.is_none());
    }

    #[test]
    fn resolve_session_request_indirect_absolute_splits_apiroot_and_path() {
        let client = NpcfClient::new("http://scp:8080", reqwest::Client::new())
            .with_communication(crate::sbi::Communication::Indirect);
        let absolute = "http://pcf01.5gc:8080/npcf-policyauthorization/v1/app-sessions/abc";
        let (url, target) = client.resolve_session_request(absolute);
        // Sent to the SCP at the resource path; PCF carried in the header.
        assert_eq!(
            url,
            "http://scp:8080/npcf-policyauthorization/v1/app-sessions/abc"
        );
        assert_eq!(target.as_deref(), Some("http://pcf01.5gc:8080"));
    }

    #[test]
    fn apiroot_and_path_splits_correctly() {
        assert_eq!(
            apiroot_and_path("http://pcf01:8080/npcf/v1/x"),
            Some(("http://pcf01:8080".to_string(), "/npcf/v1/x".to_string()))
        );
        assert_eq!(
            apiroot_and_path("https://pcf01/"),
            Some(("https://pcf01".to_string(), "/".to_string()))
        );
        assert_eq!(
            apiroot_and_path("https://pcf01"),
            Some(("https://pcf01".to_string(), String::new()))
        );
        assert_eq!(apiroot_and_path("sess-bare-id"), None);
    }

    #[test]
    fn resolve_location_relative_and_absolute() {
        assert_eq!(
            resolve_location(
                "http://pcf01:8080",
                "/npcf-policyauthorization/v1/app-sessions/x"
            ),
            "http://pcf01:8080/npcf-policyauthorization/v1/app-sessions/x"
        );
        assert_eq!(
            resolve_location("http://pcf01:8080", "http://other/abs/x"),
            "http://other/abs/x"
        );
    }

    /// Spawn an axum router on `127.0.0.1:0` and return its base URL.
    async fn spawn_mock(router: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    fn create_router() -> axum::Router {
        use axum::routing::post;
        axum::Router::new().route(
            "/npcf-policyauthorization/v1/app-sessions",
            post(|| async {
                (
                    axum::http::StatusCode::CREATED,
                    [(
                        "location",
                        "/npcf-policyauthorization/v1/app-sessions/sess-xyz",
                    )],
                    r#"{"appSessionId": "sess-xyz", "authorized": true}"#,
                )
            }),
        )
    }

    #[tokio::test]
    async fn create_posts_to_target_not_base_url() {
        let base = spawn_mock(create_router()).await;
        // Base URL is unroutable; only the per-call target is reachable. If
        // the call ignored `target` it would fail with a transport error.
        let client = NpcfClient::new("http://127.0.0.1:9", reqwest::Client::new());
        let request_data = AppSessionContextReqData {
            af_app_id: Some("IMS Services".to_string()),
            ..Default::default()
        };
        let created = client
            .create_app_session(Some(&base), &request_data)
            .await
            .expect("create against target must succeed");
        // appSessionId derived from the Location header (not the body).
        assert_eq!(created.app_session_id, "sess-xyz");
        assert!(created.authorized);
        // Location resolved against the target base.
        assert_eq!(
            created.location.as_deref(),
            Some(
                format!("{base}/npcf-policyauthorization/v1/app-sessions/sess-xyz").as_str()
            )
        );
    }

    #[tokio::test]
    async fn create_none_target_posts_to_base_url() {
        let base = spawn_mock(create_router()).await;
        let client = NpcfClient::new(&base, reqwest::Client::new());
        let created = client
            .create_app_session(None, &AppSessionContextReqData::default())
            .await
            .expect("create against base must succeed");
        assert!(created.authorized);
        assert_eq!(
            created.location.as_deref(),
            Some(
                format!("{base}/npcf-policyauthorization/v1/app-sessions/sess-xyz").as_str()
            )
        );
    }

    // --- Indirect communication (SCP, Model C: 3gpp-Sbi-Target-apiRoot) ---

    use std::sync::{Arc, Mutex};

    fn empty_context() -> AppSessionContextReqData {
        AppSessionContextReqData::default()
    }

    /// A create router that records the `3gpp-Sbi-Target-apiRoot` header value
    /// (None when absent) seen on each request.
    fn capturing_create_router(captured: Arc<Mutex<Vec<Option<String>>>>) -> axum::Router {
        use axum::http::HeaderMap;
        use axum::routing::post;
        axum::Router::new().route(
            "/npcf-policyauthorization/v1/app-sessions",
            post(move |headers: HeaderMap| {
                let captured = Arc::clone(&captured);
                async move {
                    let target = headers
                        .get("3gpp-sbi-target-apiroot")
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.to_string());
                    captured.lock().unwrap().push(target);
                    (
                        axum::http::StatusCode::CREATED,
                        [(
                            "location",
                            "/npcf-policyauthorization/v1/app-sessions/sess-xyz",
                        )],
                        r#"{"appSessionId": "sess-xyz", "authorized": true}"#,
                    )
                }
            }),
        )
    }

    #[tokio::test]
    async fn create_indirect_posts_to_scp_with_target_apiroot_header() {
        let captured: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let scp = spawn_mock(capturing_create_router(Arc::clone(&captured))).await;
        let client = NpcfClient::new(&scp, reqwest::Client::new())
            .with_communication(crate::sbi::Communication::Indirect);

        let created = client
            // pcf_uri (the per-call target) becomes the target apiRoot header.
            .create_app_session(Some("http://pcf01.5gc:8080"), &empty_context())
            .await
            .expect("indirect create must succeed");

        assert_eq!(created.app_session_id, "sess-xyz");
        // Location resolves against the PCF apiRoot, not the SCP.
        assert_eq!(
            created.location.as_deref(),
            Some("http://pcf01.5gc:8080/npcf-policyauthorization/v1/app-sessions/sess-xyz")
        );
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].as_deref(), Some("http://pcf01.5gc:8080"));
    }

    #[tokio::test]
    async fn create_direct_sends_no_target_apiroot_header() {
        let captured: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let pcf = spawn_mock(capturing_create_router(Arc::clone(&captured))).await;
        // Direct by default.
        let client = NpcfClient::new(&pcf, reqwest::Client::new());

        client
            .create_app_session(None, &empty_context())
            .await
            .expect("direct create must succeed");

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0].is_none(),
            "direct mode must not send 3gpp-Sbi-Target-apiRoot"
        );
    }

    /// A create router that records the raw request body it received.
    fn body_capturing_router(captured: Arc<Mutex<Option<serde_json::Value>>>) -> axum::Router {
        use axum::routing::post;
        axum::Router::new().route(
            "/npcf-policyauthorization/v1/app-sessions",
            post(move |body: axum::body::Bytes| {
                let captured = Arc::clone(&captured);
                async move {
                    *captured.lock().unwrap() = serde_json::from_slice(&body).ok();
                    (
                        axum::http::StatusCode::CREATED,
                        [(
                            "location",
                            "/npcf-policyauthorization/v1/app-sessions/sess-xyz",
                        )],
                        "",
                    )
                }
            }),
        )
    }

    /// End-to-end: the on-the-wire POST body nests the data under `ascReqData`
    /// (with `ueIpv4` reachable by the PCF) and carries `medComponents` as an
    /// object keyed by `medCompN`. Guards both reported symptoms at once.
    #[tokio::test]
    async fn create_wire_body_has_asc_req_data_and_med_components_map() {
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let pcf = spawn_mock(body_capturing_router(Arc::clone(&captured))).await;
        let client = NpcfClient::new(&pcf, reqwest::Client::new());

        let request_data = AppSessionContextReqData {
            af_app_id: Some("IMS Services".to_string()),
            ue_ipv4: Some("100.65.0.4".to_string()),
            med_components: Some(components_map(vec![MediaComponent {
                med_comp_n: 1,
                med_type: "AUDIO".to_string(),
                f_status: "ENABLED".to_string(),
                codecs: None,
                med_sub_comps: None,
            }])),
            ..Default::default()
        };
        client
            .create_app_session(None, &request_data)
            .await
            .expect("create must succeed");

        let body = captured.lock().unwrap().clone().expect("captured body");
        let asc = body.get("ascReqData").expect("body must nest ascReqData");
        assert_eq!(
            asc.get("ueIpv4").and_then(|v| v.as_str()),
            Some("100.65.0.4"),
            "ueIpv4 must be reachable under ascReqData: {body}"
        );
        // medComponents must be an object keyed by medCompN, not an array.
        let med = asc.get("medComponents").expect("medComponents present");
        assert!(med.is_object(), "medComponents must be a map: {body}");
        assert_eq!(
            med.get("1").and_then(|c| c.get("medCompN")).and_then(|v| v.as_u64()),
            Some(1),
            "component keyed by medCompN: {body}"
        );
    }
}
