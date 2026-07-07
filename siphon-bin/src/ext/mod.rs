//! Opt-in extension composition layer.
//!
//! [`register_all`] registers every compiled-in extension module onto the
//! [`SiphonServer`] builder. Each module is gated behind its own cargo feature
//! (off by default); when a feature is off but the operator still configured an
//! `extensions.<name>` block, a loud warning is emitted and the module is
//! skipped — the same contract as siphon's `sctp` feature.
//!
//! ## Adding a module (the `smpp` / `http` modules are the templates)
//!
//! 1. Add the optional dep + feature to `Cargo.toml`
//!    (e.g. `foo = ["dep:siphon-foo"]`).
//! 2. Add `src/ext/foo.rs` (a near-copy of [`smpp`] / [`http`]).
//! 3. Wire three lines below: the `register_foo` call inside [`register_all`],
//!    plus the feature-on `pub use` and the feature-off shim.

use siphon::config::Config;
use siphon::SiphonServer;

/// Register every compiled-in extension module onto the builder, in a stable
/// order. Modules whose feature is disabled either no-op or warn (see each
/// module's feature-off shim below).
pub fn register_all(mut builder: SiphonServer, config: &Config) -> SiphonServer {
    builder = register_smpp(builder, config);
    builder = register_http(builder, config);
    builder
}

#[cfg(feature = "smpp")]
mod smpp;
#[cfg(feature = "smpp")]
pub use smpp::register as register_smpp;

#[cfg(not(feature = "smpp"))]
pub fn register_smpp(builder: SiphonServer, config: &Config) -> SiphonServer {
    warn_unwired(config, "smpp", "smpp");
    builder
}

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "http")]
pub use http::register as register_http;

#[cfg(not(feature = "http"))]
pub fn register_http(builder: SiphonServer, config: &Config) -> SiphonServer {
    warn_unwired(config, "http", "http");
    builder
}

/// Feature-off shim helper: if a module's `extensions.<key>` block is present in
/// the config but its cargo `feature` was not compiled in, warn loudly so the
/// misconfiguration is visible rather than silently ignored.
#[allow(dead_code)] // unused when every extension feature is enabled
fn warn_unwired(config: &Config, key: &str, feature: &str) {
    if config.extension_config(key).is_some() {
        tracing::warn!(
            target: "siphon",
            "config has `extensions.{key}` but this binary was built without the \
             `{feature}` feature; it is disabled. Rebuild with `--features {feature}`."
        );
    }
}
