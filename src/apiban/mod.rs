//! APIBAN community blocklist integration.
//!
//! Periodically polls the APIBAN REST API to fetch IPs known for SIP abuse
//! (scanners, brute-forcers, toll fraud) and feeds them into the transport ACL.
//!
//! API docs: <https://apiban.org/doc.html>

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashSet;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::config::ApiBanConfig;

/// Batch size returned by APIBAN per request.
const APIBAN_BATCH_SIZE: usize = 250;

/// Sentinel ID for the first full fetch.
const INITIAL_ID: &str = "100";

/// Base URL for the APIBAN API.
const APIBAN_BASE_URL: &str = "https://apiban.org/api";

/// JSON response from the APIBAN `/banned` endpoint.
#[derive(Debug, Deserialize)]
struct ApiBanResponse {
    #[serde(rename = "ID")]
    id: String,
    ipaddress: Option<Vec<String>>,
}

/// Client that polls APIBAN and maintains a shared set of banned IPs.
pub struct ApiBanClient {
    api_key: String,
    interval: Duration,
    banned: Arc<DashSet<IpAddr>>,
    client: reqwest::Client,
    /// Optional kernel-firewall handle — fetched IPs are also pushed to the
    /// nf_tables set (permanently; the blocklist carries no per-IP TTL).
    firewall: Option<crate::firewall::KernelFirewall>,
}

impl ApiBanClient {
    /// Create a new client from config. The banned set is empty until `start()` is called.
    pub fn new(config: &ApiBanConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            api_key: config.api_key.clone(),
            interval: Duration::from_secs(config.interval_secs),
            banned: Arc::new(DashSet::new()),
            client,
            firewall: None,
        })
    }

    /// Returns the shared banned IP set for ACL integration.
    pub fn banned(&self) -> Arc<DashSet<IpAddr>> {
        Arc::clone(&self.banned)
    }

    /// Attach a kernel-firewall handle so fetched IPs are also programmed into
    /// the nf_tables set, on top of the userspace ACL set.
    pub fn with_firewall(mut self, firewall: Option<crate::firewall::KernelFirewall>) -> Self {
        self.firewall = firewall;
        self
    }

    /// Spawn the background polling task. Returns a `JoinHandle` for the poll loop.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.poll_loop().await;
        })
    }

    async fn poll_loop(self) {
        let mut last_id = INITIAL_ID.to_string();

        info!(
            interval_secs = self.interval.as_secs(),
            "APIBAN client started"
        );

        loop {
            match self.fetch_all(&mut last_id).await {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            new_entries = count,
                            total = self.banned.len(),
                            "APIBAN blocklist updated"
                        );
                    } else {
                        debug!("APIBAN: no new bans");
                    }
                }
                Err(error) => {
                    error!(%error, "APIBAN fetch failed, will retry next interval");
                }
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Fetch all new entries since `last_id`, paginating in batches of 250.
    /// Updates `last_id` to the most recent ID returned.
    /// Returns the number of new IPs added.
    async fn fetch_all(&self, last_id: &mut String) -> Result<usize, ApiBanError> {
        let mut total_added = 0;

        loop {
            let url = format!(
                "{}/{}/banned/{}",
                APIBAN_BASE_URL, self.api_key, last_id
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(ApiBanError::Http)?;

            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(ApiBanError::InvalidApiKey);
            }

            let body = response.text().await.map_err(ApiBanError::Http)?;

            // APIBAN returns a plain text message when there are no new bans
            if body.contains("no new bans") {
                break;
            }

            if !status.is_success() {
                return Err(ApiBanError::BadStatus(status.as_u16(), body));
            }

            let parsed: ApiBanResponse =
                serde_json::from_str(&body).map_err(ApiBanError::Json)?;

            let addresses = parsed.ipaddress.unwrap_or_default();
            let batch_size = addresses.len();

            for ip_str in &addresses {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip_address) => {
                        if self.banned.insert(ip_address) {
                            total_added += 1;
                            if let Some(firewall) = &self.firewall {
                                firewall.ban_permanent(ip_address);
                            }
                        }
                    }
                    Err(_) => {
                        warn!(ip = %ip_str, "APIBAN: skipping invalid IP address");
                    }
                }
            }

            *last_id = parsed.id;

            // If fewer than BATCH_SIZE returned, we have all entries
            if batch_size < APIBAN_BATCH_SIZE {
                break;
            }
        }

        Ok(total_added)
    }
}

/// Errors from the APIBAN client.
#[derive(Debug, thiserror::Error)]
pub enum ApiBanError {
    #[error("HTTP request failed: {0}")]
    Http(reqwest::Error),
    #[error("invalid API key (401 Unauthorized)")]
    InvalidApiKey,
    #[error("unexpected status {0}: {1}")]
    BadStatus(u16, String),
    #[error("JSON parse error: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_response() {
        let json = r#"{"ID":"12345","ipaddress":["1.2.3.4","5.6.7.8","2001:db8::1"]}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "12345");
        let addresses = response.ipaddress.unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], "1.2.3.4");
        assert_eq!(addresses[1], "5.6.7.8");
        assert_eq!(addresses[2], "2001:db8::1");
    }

    #[test]
    fn parse_empty_ipaddress_list() {
        let json = r#"{"ID":"99999","ipaddress":[]}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "99999");
        assert!(response.ipaddress.unwrap().is_empty());
    }

    #[test]
    fn parse_null_ipaddress() {
        let json = r#"{"ID":"100"}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "100");
        assert!(response.ipaddress.is_none());
    }

    #[test]
    fn ip_parsing_valid_v4_and_v6() {
        let banned = DashSet::new();

        let addresses = vec![
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
            "2001:db8::1".to_string(),
        ];

        for ip_str in &addresses {
            if let Ok(ip_address) = ip_str.parse::<IpAddr>() {
                banned.insert(ip_address);
            }
        }

        assert_eq!(banned.len(), 3);
        assert!(banned.contains(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(banned.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(banned.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn ip_parsing_skips_invalid() {
        let banned = DashSet::new();

        let addresses = vec![
            "1.2.3.4".to_string(),
            "not-an-ip".to_string(),
            "999.999.999.999".to_string(),
            "5.6.7.8".to_string(),
        ];

        for ip_str in &addresses {
            if let Ok(ip_address) = ip_str.parse::<IpAddr>() {
                banned.insert(ip_address);
            }
        }

        assert_eq!(banned.len(), 2);
        assert!(banned.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(banned.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn duplicate_ips_not_counted() {
        let banned = DashSet::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(banned.insert(ip)); // first insert → true
        assert!(!banned.insert(ip)); // duplicate → false
        assert_eq!(banned.len(), 1);
    }

    #[test]
    fn no_new_bans_detection() {
        // The actual APIBAN response when there are no new bans
        let body = r#"{"ID":"none","ipaddress":"no new bans"}"#;
        assert!(body.contains("no new bans"));

        // Normal response with IPs should not trigger the check
        let body = r#"{"ID":"12345","ipaddress":["1.2.3.4"]}"#;
        assert!(!body.contains("no new bans"));
    }
}
