//! Startup-only loading of SBI trust anchors and client identity.

use serde::Deserialize;

/// Optional outbound SBI TLS settings. Certificate paths use config env expansion.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "TlsFields")]
pub struct SbiTlsConfig {
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub trust_public_roots: bool,
}

#[derive(Deserialize)]
struct TlsFields {
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    #[serde(default = "public_roots_default")]
    trust_public_roots: bool,
}

fn public_roots_default() -> bool {
    true
}

impl TryFrom<TlsFields> for SbiTlsConfig {
    type Error = String;

    fn try_from(fields: TlsFields) -> Result<Self, Self::Error> {
        // An empty path is unset, so a configuration can take each one from
        // the environment (`ca: "${SBI_CA_FILE:-}"`) and leave it out there.
        let set = |path: Option<String>| path.filter(|path| !path.trim().is_empty());
        let config = Self {
            ca: set(fields.ca),
            cert: set(fields.cert),
            key: set(fields.key),
            trust_public_roots: fields.trust_public_roots,
        };
        config.validate()?;
        Ok(config)
    }
}

impl SbiTlsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.cert.is_some() != self.key.is_some() {
            return Err(format!(
                "sbi.tls.cert and sbi.tls.key must be supplied together (cert={:?}, key={:?})",
                self.cert, self.key
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct LoadedTls {
    roots: Vec<reqwest::Certificate>,
    identity: Option<reqwest::Identity>,
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("SBI TLS file '{path}': {error}"))
}

impl LoadedTls {
    pub(super) fn load(config: Option<&SbiTlsConfig>) -> Result<Self, String> {
        use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

        let mut loaded = Self::default();
        let Some(config) = config else {
            return Ok(loaded);
        };
        config.validate()?;
        if let Some(path) = &config.ca {
            loaded.roots = reqwest::Certificate::from_pem_bundle(&read(path)?)
                .map_err(|error| format!("SBI TLS CA file '{path}': {error}"))?;
            if loaded.roots.is_empty() {
                return Err(format!("SBI TLS CA file '{path}': no certificates found"));
            }
        }
        if let (Some(cert), Some(key)) = (&config.cert, &config.key) {
            let mut pem = read(cert)?;
            let chain = CertificateDer::pem_slice_iter(&pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("SBI TLS certificate file '{cert}': {error}"))?;
            if chain.is_empty() {
                return Err(format!(
                    "SBI TLS certificate file '{cert}': no certificates found"
                ));
            }
            let key_pem = read(key)?;
            PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|error| format!("SBI TLS key file '{key}': {error}"))?;
            pem.push(b'\n');
            pem.extend_from_slice(&key_pem);
            loaded.identity = Some(reqwest::Identity::from_pem(&pem).map_err(|error| {
                format!("SBI TLS certificate '{cert}' and key '{key}': {error}")
            })?);
        }
        Ok(loaded)
    }

    pub(super) fn build(
        &self,
        config: &super::SbiConfig,
        bearer: &super::bearer::LoadedBearer,
        timeout: std::time::Duration,
    ) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder().timeout(timeout);
        if let Some(tls) = &config.tls {
            builder = builder.tls_built_in_root_certs(tls.trust_public_roots);
        }
        for root in &self.roots {
            builder = builder.add_root_certificate(root.clone());
        }
        if let Some(identity) = &self.identity {
            builder = builder.identity(identity.clone());
        }
        bearer.apply(builder).build().map_err(|error| {
            // reqwest's Display omits the underlying TLS error; Debug includes it.
            format!(
                "SBI HTTP client construction failed (TLS files {:?}): {error:?}",
                config.tls
            )
        })
    }
}

#[cfg(test)]
mod empty_path_tests {
    use super::SbiTlsConfig;

    #[test]
    fn an_empty_path_is_unset_so_a_configuration_can_take_it_from_the_environment() {
        let config: SbiTlsConfig = serde_saphyr::from_str("ca: \"\"\ncert: \"\"\nkey: \"  \"\n")
            .expect("empty paths are unset");
        assert_eq!((config.ca, config.cert, config.key), (None, None, None));
        assert!(config.trust_public_roots);
    }

    #[test]
    fn a_certificate_without_its_key_is_still_refused() {
        assert!(
            serde_saphyr::from_str::<SbiTlsConfig>("cert: /run/tls/tls.crt\nkey: \"\"\n").is_err()
        );
    }
}
