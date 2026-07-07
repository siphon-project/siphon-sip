//! HTTP/HTTPS extension wiring (compiled only with `--features http`).
//!
//! Resolves the HTTP sub-config referenced by `extensions.http` in siphon.yaml,
//! then registers the scriptable `http` namespace and the HTTP runtime task onto
//! the builder. Structurally identical to `ext/smpp.rs` — the SMPP module is the
//! template every path-configured extension follows.

use siphon::config::Config;
use siphon::SiphonServer;
use siphon_http::HttpConfig;

/// Register the `http` namespace + runtime task if `extensions.http` resolves to
/// a loadable config file. Any problem (missing path, inline form, load error)
/// is logged and HTTP is left disabled rather than aborting startup.
pub fn register(builder: SiphonServer, config: &Config) -> SiphonServer {
    let Some(path) = config.extension_path("http") else {
        if config.extension_config("http").is_some() {
            tracing::error!(
                target: "siphon",
                "extensions.http must reference a path to an http.yaml \
                 (inline form not yet supported); HTTP disabled"
            );
        }
        return builder;
    };

    match HttpConfig::from_file(path) {
        Ok(cfg) => builder
            .register_namespace_with("http", siphon_http::namespace(cfg.clone()))
            .register_task(siphon_http::task(cfg)),
        Err(error) => {
            tracing::error!(
                target: "siphon",
                path = %path.display(),
                "http extension config failed to load: {error}; HTTP disabled"
            );
            builder
        }
    }
}
