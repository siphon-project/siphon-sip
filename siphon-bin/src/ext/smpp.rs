//! SMPP 3.4 extension wiring (compiled only with `--features smpp`).
//!
//! Resolves the SMPP sub-config referenced by `extensions.smpp` in siphon.yaml,
//! then registers the scriptable `smpp` namespace and the SMPP runtime task onto
//! the builder. This is the template every path-configured extension follows —
//! `ext/http.rs` will be a near-copy (swap `smpp`→`http`, `SmppConfig`→
//! `HttpConfig`, and the namespace name(s)).

use siphon::config::Config;
use siphon::SiphonServer;
use siphon_smpp::SmppConfig;

/// Register the `smpp` namespace + runtime task if `extensions.smpp` resolves to
/// a loadable config file. Any problem (missing path, inline form, load error)
/// is logged and SMPP is left disabled rather than aborting startup.
pub fn register(builder: SiphonServer, config: &Config) -> SiphonServer {
    let Some(path) = config.extension_path("smpp") else {
        if config.extension_config("smpp").is_some() {
            tracing::error!(
                target: "siphon",
                "extensions.smpp must reference a path to an smpp.yaml \
                 (inline form not yet supported); SMPP disabled"
            );
        }
        return builder;
    };

    match SmppConfig::from_file(path) {
        Ok(cfg) => builder
            .register_namespace_with("smpp", siphon_smpp::namespace(cfg.clone()))
            .register_task(siphon_smpp::task(cfg)),
        Err(error) => {
            tracing::error!(
                target: "siphon",
                path = %path.display(),
                "smpp extension config failed to load: {error}; SMPP disabled"
            );
            builder
        }
    }
}
