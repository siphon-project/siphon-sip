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
//!    (e.g. `foo = ["dep:siphon-foo"]`), and to the `full` aggregate.
//! 2. Add `src/ext/foo.rs` (a near-copy of [`smpp`] / [`http`]).
//! 3. Wire three lines below: the `register_foo` call inside [`register_all`],
//!    plus the feature-on `pub use` and the feature-off shim.
//!
//! ## Two module shapes
//!
//! - **One namespace** ([`smpp`], [`http`]): the addon hands over a single
//!   Python object and the module registers it with
//!   `SiphonServer::register_namespace_with(name, factory)`, which
//!   collision-checks the name against siphon's built-ins.
//! - **Several namespaces plus top-level symbols** ([`sigtran`]): the addon
//!   mounts its own contents onto the `siphon` package module through
//!   `SiphonServer::register_module_extension(name, hook)`. Use this only when a
//!   single named attribute genuinely cannot carry the surface — the hook picks
//!   its own attribute names and is therefore not collision-checked.

use siphon::config::Config;
use siphon::SiphonServer;

/// Register every compiled-in extension module onto the builder, in a stable
/// order. Modules whose feature is disabled either no-op or warn (see each
/// module's feature-off shim below).
pub fn register_all(mut builder: SiphonServer, config: &Config) -> SiphonServer {
    builder = register_smpp(builder, config);
    builder = register_http(builder, config);
    builder = register_sigtran(builder, config);
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

#[cfg(feature = "sigtran")]
mod sigtran;
#[cfg(feature = "sigtran")]
pub use sigtran::register as register_sigtran;

#[cfg(not(feature = "sigtran"))]
pub fn register_sigtran(builder: SiphonServer, config: &Config) -> SiphonServer {
    warn_unwired(config, "sigtran", "sigtran");
    builder
}

/// Emit an extension-layer startup diagnostic.
///
/// This whole module runs at *builder* time — `register_all` is called before
/// `SiphonServer::run()`, which is what installs the tracing subscriber. A
/// `tracing::warn!`/`error!` here therefore has no subscriber to reach and is
/// dropped on the floor, which silently voided the "loud on mismatch" contract:
/// a binary with `extensions.<name>` pointing at a missing file started up
/// perfectly quiet, with the module disabled. So these go to stderr, the same
/// place siphon's own pre-subscriber startup failures print.
pub(crate) fn startup_diagnostic(message: &str) {
    eprintln!("siphon: {message}");
}

/// Feature-off shim helper: if a module's `extensions.<key>` block is present in
/// the config but its cargo `feature` was not compiled in, warn loudly so the
/// misconfiguration is visible rather than silently ignored.
#[allow(dead_code)] // unused when every extension feature is enabled
fn warn_unwired(config: &Config, key: &str, feature: &str) {
    if config.extension_config(key).is_some() {
        startup_diagnostic(&format!(
            "config has `extensions.{key}` but this binary was built without the \
             `{feature}` feature; it is disabled. Rebuild with `--features {feature}`."
        ));
    }
}
