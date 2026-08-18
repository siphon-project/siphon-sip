use siphon::config::Config;
use siphon::SiphonServer;
use siphon_sigtran::Config as SigtranConfig;

/// Register the SIGTRAN namespaces + runtime task if `extensions.sigtran`
/// resolves to a loadable config file. Any problem (missing path, inline form,
/// load error) is logged and SIGTRAN is left disabled rather than aborting
/// startup.
///
/// Three seams, in the order siphon-sigtran's contract requires:
///
/// 1. `configure_from` builds the process-wide node from `sigtran.yaml`. It runs
///    here, at builder time, so the node exists before the script loads and the
///    script's decorators register into the very node the task later drives.
/// 2. `register` mounts `ss7` / `gsm_map` / `gsm_cap` / `inap`, the shared types,
///    `SigtranError` and the module functions onto the `siphon` package module.
///    This is a *module* extension rather than a namespace registration
///    (`register_namespace_with`) because the surface is four namespaces plus
///    top-level symbols, not one named object.
/// 3. `task` boots the live SCTP transport, attaches the dialogue engine and the
///    origination drain, and holds them for the process lifetime. It runs after
///    the script has loaded, so the routing tables and termination handlers the
///    script programmed are in place before the wire comes up.
pub fn register(builder: SiphonServer, config: &Config) -> SiphonServer {
    let Some(path) = config.extension_path("sigtran") else {
        if config.extension_config("sigtran").is_some() {
            super::startup_diagnostic(
                "extensions.sigtran must reference a path to a sigtran.yaml \
                 (inline form not yet supported); SIGTRAN disabled",
            );
        }
        return builder;
    };

    match SigtranConfig::load(path) {
        Ok(cfg) => {
            siphon_sigtran::python::configure_from(&cfg);
            builder
                .register_module_extension("sigtran", siphon_sigtran::python::register)
                .register_task(siphon_sigtran::python::task(cfg))
        }
        Err(error) => {
            super::startup_diagnostic(&format!(
                "sigtran extension config {} failed to load: {error}; SIGTRAN disabled",
                path.display()
            ));
            builder
        }
    }
}
