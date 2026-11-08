//! Startup-only loading and validation of static bearer credentials.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, PROXY_AUTHORIZATION};

/// The loaded credential never exposes its contents through Debug.
#[derive(Default)]
pub(super) struct LoadedBearer(Option<(HeaderName, HeaderValue)>);

impl std::fmt::Debug for LoadedBearer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("LoadedBearer")
            .field(&self.0.as_ref().map(|(name, _)| (name, "[REDACTED]")))
            .finish()
    }
}

impl LoadedBearer {
    pub(super) fn load(config: &super::SbiConfig) -> Result<Self, String> {
        let Some(path) = &config.bearer_token_file else {
            return Ok(Self::default());
        };
        for (name, endpoint) in [
            ("npcf_url", &config.npcf_url),
            ("bsf_url", &config.bsf_url),
            ("nchf_url", &config.nchf_url),
            ("nrf_url", &config.nrf_url),
        ] {
            if let Some(endpoint) = endpoint {
                validate_endpoint(name, endpoint)?;
            }
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|error| format!("SBI bearer token file '{path}': {error}"))?;
        let token = contents.trim();
        // RFC 6750: 1*(ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/") *"=".
        let unpadded = token.trim_end_matches('=');
        if unpadded.is_empty()
            || !unpadded.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
            })
        {
            return Err(format!(
                "SBI bearer token file '{path}': expected a nonempty RFC 6750 b64token"
            ));
        }
        let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| format!("SBI bearer token file '{path}': invalid header value"))?;
        header.set_sensitive(true);
        let name = match config.bearer_token_header {
            super::SbiBearerHeader::Authorization => AUTHORIZATION,
            super::SbiBearerHeader::ProxyAuthorization => PROXY_AUTHORIZATION,
        };
        Ok(Self(Some((name, header))))
    }

    pub(super) fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        let Some((name, header)) = &self.0 else {
            return builder;
        };
        let mut headers = HeaderMap::new();
        headers.insert(name.clone(), header.clone());
        // reqwest defaults fill only vacant entries, preserving explicit credentials.
        builder.default_headers(headers)
    }
}

fn validate_endpoint(name: &str, endpoint: &str) -> Result<(), String> {
    let error = || {
        format!(
            "sbi.{name}: bearer authentication requires HTTPS (HTTP is allowed only for loopback hosts)"
        )
    };
    let url = reqwest::Url::parse(endpoint).map_err(|_| error())?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(error())
    }
}
