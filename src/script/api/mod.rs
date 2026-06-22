//! Python API — the `siphon` module that scripts import from.
//!
//! This module injects the pure-Python `siphon` package into `sys.modules`
//! so that user scripts can write `from siphon import proxy, b2bua, log`.
//!
//! The registry (`_siphon_registry`) is a separate module that decorators
//! write into; the Rust engine reads it after script execution.

pub mod auth;
pub mod cache;
pub mod call;
pub mod cdr;
pub mod diameter;
pub mod gateway;
pub mod ipsec;
pub mod isc;
pub mod li;
pub mod log;
pub mod metrics;
pub mod presence;
pub mod proxy_utils;
pub mod qos;
pub mod registrant;
pub mod registrar;
pub mod reply;
pub mod request;
pub mod rtpengine;
pub mod sbi;
pub mod sdp;
pub mod sip_uri;
pub mod srs;
pub mod stir;
pub mod subscribe_state;
pub mod timer;

use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::error::{Result, SiphonError};

/// Names reserved for built-in siphon namespaces. Registering a host
/// namespace with one of these names is a hard error.
pub const BUILT_IN_NAMESPACE_NAMES: &[&str] = &[
    "proxy",
    "registrar",
    "auth",
    "log",
    "cache",
    "metrics",
    "sdp",
    "timer",
    "isc",
    "b2bua",
    "rtpengine",
    "gateway",
    "cdr",
    "registration",
    "li",
    "diameter",
    "presence",
    "sbi",
    "srs",
    "subscribe_state",
    "ipsec",
    "qos",
    "stir",
];

/// Host-registered Python namespaces. Populated by `SiphonServer` at
/// startup, before the script engine is created. Read every time
/// `install_siphon_module()` runs (i.e. on each script load / reload).
static USER_NAMESPACES: Mutex<Vec<(String, Py<PyAny>)>> = Mutex::new(Vec::new());

/// Tuple of (auth, registrar, log, proxy_utils, cache) singletons.
type SingletonTuple = (Py<PyAny>, Py<PyAny>, Py<PyAny>, Py<PyAny>, Py<PyAny>);

/// Rust-backed singletons: (auth, registrar, log, proxy_utils, cache).
static RUST_SINGLETONS: OnceLock<SingletonTuple> = OnceLock::new();

/// Optional RTPEngine singleton — set only when `media.rtpengine` is configured.
static RTPENGINE_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional gateway singleton — set only when `gateway` is configured.
static GATEWAY_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional CDR singleton — set only when `cdr` is configured and enabled.
static CDR_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional registration singleton — set only when `registrant` is configured.
static REGISTRATION_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional LI singleton — set only when `lawful_intercept` is configured.
static LI_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional Diameter singleton — set only when `diameter` is configured.
static DIAMETER_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional presence singleton — set only when presence is needed.
static PRESENCE_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Metrics singleton — always available (like log).
static METRICS_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// SDP namespace singleton — always available (stateless parser, no config needed).
static SDP_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// QoS namespace singleton — always available (stateless SDP→IPFilterRule helper).
static QOS_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional ISC singleton — always available (iFC store for per-user + global rules).
static ISC_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional SBI singleton — set only when `sbi` is configured.
static SBI_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

static TIMER_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

static SUBSCRIBE_STATE_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional IPsec singleton — set only when `ipsec` is configured (P-CSCF role).
static IPSEC_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// Optional STIR/SHAKEN singleton — set only when `stir` is configured.
static STIR_SINGLETON: OnceLock<Py<PyAny>> = OnceLock::new();

/// The IfcStore Arc — stored so the backend can wire Redis persistence.
static IFC_STORE_ARC: OnceLock<std::sync::Arc<crate::ifc::IfcStore>> = OnceLock::new();

/// Get the shared IfcStore (set during iFC initialization).
pub fn ifc_store_arc() -> Option<&'static std::sync::Arc<crate::ifc::IfcStore>> {
    IFC_STORE_ARC.get()
}

/// The Registrar Arc — stored so the dispatcher can subscribe to change events.
static REGISTRAR_ARC: OnceLock<std::sync::Arc<crate::registrar::Registrar>> = OnceLock::new();

/// Get the shared Registrar (set during `set_rust_singletons`).
pub fn registrar_arc() -> Option<&'static std::sync::Arc<crate::registrar::Registrar>> {
    REGISTRAR_ARC.get()
}

/// The unified stream-connection registry — stored so `Flow.is_alive` can do a
/// real cross-transport liveness lookup (is this UE's stream connection still
/// open on this process?).  Set once at server startup.
static STREAM_CONNECTIONS: OnceLock<crate::transport::StreamConnections> = OnceLock::new();

/// Get the shared stream-connection registry.  `None` in unit tests / headless
/// contexts that never wired transports — callers stay conservative there.
pub fn stream_connections() -> Option<&'static crate::transport::StreamConnections> {
    STREAM_CONNECTIONS.get()
}

/// Set the shared stream-connection registry (idempotent — first writer wins).
pub fn set_stream_connections(registry: crate::transport::StreamConnections) {
    let _ = STREAM_CONNECTIONS.set(registry);
}

/// Store Rust-backed singletons for injection into the siphon module.
///
/// Must be called once at startup, before any user script is loaded.
/// After this, every call to `install_siphon_module()` will automatically
/// replace the Python stubs with these Rust objects.
pub fn set_rust_singletons(
    python: Python<'_>,
    py_auth: auth::PyAuth,
    py_registrar: registrar::PyRegistrar,
    py_log: log::PyLogNamespace,
    py_proxy_utils: proxy_utils::PyProxyUtils,
    py_cache: cache::PyCacheNamespace,
) -> Result<()> {
    // Store the Registrar Arc for event subscription before converting to Py<PyAny>.
    let _ = REGISTRAR_ARC.set(std::sync::Arc::clone(py_registrar.registrar()));

    let auth_py: Py<PyAny> = Py::new(python, py_auth)
        .map_err(|error| SiphonError::Script(format!("Py::new(auth): {error}")))?
        .into_any();
    let reg_py: Py<PyAny> = Py::new(python, py_registrar)
        .map_err(|error| SiphonError::Script(format!("Py::new(registrar): {error}")))?
        .into_any();
    let log_py: Py<PyAny> = Py::new(python, py_log)
        .map_err(|error| SiphonError::Script(format!("Py::new(log): {error}")))?
        .into_any();
    let proxy_utils_py: Py<PyAny> = Py::new(python, py_proxy_utils)
        .map_err(|error| SiphonError::Script(format!("Py::new(proxy_utils): {error}")))?
        .into_any();
    let cache_py: Py<PyAny> = Py::new(python, py_cache)
        .map_err(|error| SiphonError::Script(format!("Py::new(cache): {error}")))?
        .into_any();

    let _ = RUST_SINGLETONS.set((auth_py, reg_py, log_py, proxy_utils_py, cache_py));
    Ok(())
}

/// Store the RTPEngine singleton for injection into the siphon module.
///
/// Called at startup only when `media.rtpengine` is configured.
pub fn set_rtpengine_singleton(
    python: Python<'_>,
    py_rtpengine: rtpengine::PyRtpEngine,
) -> Result<()> {
    let rtpengine_py: Py<PyAny> = Py::new(python, py_rtpengine)
        .map_err(|error| SiphonError::Script(format!("Py::new(rtpengine): {error}")))?
        .into_any();
    let _ = RTPENGINE_SINGLETON.set(rtpengine_py);
    Ok(())
}

/// Store the CDR singleton for injection into the siphon module.
///
/// Called at startup only when `cdr` is configured and enabled.
pub fn set_cdr_singleton(
    python: Python<'_>,
    py_cdr: cdr::PyCdrNamespace,
) -> Result<()> {
    let cdr_py: Py<PyAny> = Py::new(python, py_cdr)
        .map_err(|error| SiphonError::Script(format!("Py::new(cdr): {error}")))?
        .into_any();
    let _ = CDR_SINGLETON.set(cdr_py);
    Ok(())
}

/// Store the gateway singleton for injection into the siphon module.
///
/// Called at startup only when `gateway` is configured.
pub fn set_gateway_singleton(
    python: Python<'_>,
    py_gateway: gateway::PyGateway,
) -> Result<()> {
    let gateway_py: Py<PyAny> = Py::new(python, py_gateway)
        .map_err(|error| SiphonError::Script(format!("Py::new(gateway): {error}")))?
        .into_any();
    let _ = GATEWAY_SINGLETON.set(gateway_py);
    Ok(())
}

/// Store the registration singleton for injection into the siphon module.
///
/// Called at startup only when `registrant` is configured.
pub fn set_registration_singleton(
    python: Python<'_>,
    py_registration: registrant::PyRegistration,
) -> Result<()> {
    let registration_py: Py<PyAny> = Py::new(python, py_registration)
        .map_err(|error| SiphonError::Script(format!("Py::new(registration): {error}")))?
        .into_any();
    let _ = REGISTRATION_SINGLETON.set(registration_py);
    Ok(())
}

/// Store the LI singleton for injection into the siphon module.
///
/// Called at startup only when `lawful_intercept` is configured and enabled.
pub fn set_li_singleton(
    python: Python<'_>,
    py_li: li::PyLiNamespace,
) -> Result<()> {
    let li_py: Py<PyAny> = Py::new(python, py_li)
        .map_err(|error| SiphonError::Script(format!("Py::new(li): {error}")))?
        .into_any();
    let _ = LI_SINGLETON.set(li_py);
    Ok(())
}

/// Store the Diameter singleton for injection into the siphon module.
///
/// Called at startup only when `diameter` is configured.
pub fn set_diameter_singleton(
    python: Python<'_>,
    py_diameter: diameter::PyDiameter,
) -> Result<()> {
    let diameter_py: Py<PyAny> = Py::new(python, py_diameter)
        .map_err(|error| SiphonError::Script(format!("Py::new(diameter): {error}")))?
        .into_any();
    let _ = DIAMETER_SINGLETON.set(diameter_py);
    Ok(())
}

/// Store the SBI singleton for injection into the siphon module.
///
/// Called at startup only when `sbi` with `npcf_url` is configured.
pub fn set_sbi_singleton(
    python: Python<'_>,
    py_sbi: sbi::PySbi,
) -> Result<()> {
    let sbi_py: Py<PyAny> = Py::new(python, py_sbi)
        .map_err(|error| SiphonError::Script(format!("Py::new(sbi): {error}")))?
        .into_any();
    let _ = SBI_SINGLETON.set(sbi_py);
    Ok(())
}

/// Wire the Diameter manager into the already-stored PyAuth singleton.
///
/// Called after the Diameter manager is created in main.rs (which happens
/// after `set_rust_singletons`).
pub fn wire_auth_diameter_manager(
    python: Python<'_>,
    manager: std::sync::Arc<crate::diameter::DiameterManager>,
) {
    if let Some((auth_py, _, _, _, _)) = RUST_SINGLETONS.get() {
        let auth_bound = auth_py.bind(python);
        match auth_bound.cast::<auth::PyAuth>() {
            Ok(py_cell) => {
                let mut py_auth = py_cell.borrow_mut();
                py_auth.set_diameter_manager(manager);
            }
            Err(error) => {
                tracing::warn!("failed to downcast auth singleton for Diameter wiring: {error}");
            }
        }
    }
}

/// Store the presence singleton for injection into the siphon module.
///
/// Called at startup when the presence subsystem is available.
pub fn set_presence_singleton(
    python: Python<'_>,
    py_presence: presence::PyPresence,
) -> Result<()> {
    let presence_py: Py<PyAny> = Py::new(python, py_presence)
        .map_err(|error| SiphonError::Script(format!("Py::new(presence): {error}")))?
        .into_any();
    let _ = PRESENCE_SINGLETON.set(presence_py);
    Ok(())
}

/// Store the metrics singleton for injection into the siphon module.
///
/// Always called at startup (metrics are always available, like log).
pub fn set_metrics_singleton(
    python: Python<'_>,
    py_metrics: metrics::PyMetricsNamespace,
) -> Result<()> {
    let metrics_py: Py<PyAny> = Py::new(python, py_metrics)
        .map_err(|error| SiphonError::Script(format!("Py::new(metrics): {error}")))?
        .into_any();
    let _ = METRICS_SINGLETON.set(metrics_py);
    Ok(())
}

/// Store the SDP namespace singleton for injection into the siphon module.
///
/// Always called at startup — stateless parser, no config needed.
pub fn set_sdp_singleton(python: Python<'_>) -> Result<()> {
    let sdp_py: Py<PyAny> = Py::new(python, sdp::PySdpNamespace::new())
        .map_err(|error| SiphonError::Script(format!("Py::new(sdp): {error}")))?
        .into_any();
    let _ = SDP_SINGLETON.set(sdp_py);
    Ok(())
}

/// Store the QoS namespace singleton for injection into the siphon module.
///
/// Always available — stateless SDP→IPFilterRule helper, no config needed.
pub fn set_qos_singleton(python: Python<'_>) -> Result<()> {
    let qos_py: Py<PyAny> = Py::new(python, qos::PyQosNamespace::new())
        .map_err(|error| SiphonError::Script(format!("Py::new(qos): {error}")))?
        .into_any();
    let _ = QOS_SINGLETON.set(qos_py);
    Ok(())
}

/// Store the timer namespace singleton for injection into the siphon module.
///
/// Always called at startup — timers are always available, no config needed.
pub fn set_timer_singleton(python: Python<'_>) -> Result<()> {
    let timer_py: Py<PyAny> = Py::new(python, timer::PyTimerNamespace::new())
        .map_err(|error| SiphonError::Script(format!("Py::new(timer): {error}")))?
        .into_any();
    let _ = TIMER_SINGLETON.set(timer_py);
    Ok(())
}

/// Store the ``proxy.subscribe_state`` singleton for injection into the
/// siphon module.  Injected onto ``proxy`` as ``subscribe_state``
/// (alongside ``_utils``).
pub fn set_subscribe_state_singleton(
    python: Python<'_>,
    py_namespace: subscribe_state::PySubscribeState,
) -> Result<()> {
    let ns_py: Py<PyAny> = Py::new(python, py_namespace)
        .map_err(|error| SiphonError::Script(format!("Py::new(subscribe_state): {error}")))?
        .into_any();
    let _ = SUBSCRIBE_STATE_SINGLETON.set(ns_py);
    Ok(())
}

/// Store the IPsec singleton for injection into the siphon module.
///
/// Called at startup only when `ipsec` is configured (i.e. siphon is
/// running as a P-CSCF).  Wires the existing `IpsecManager` and the
/// configured shared protected ports into the Python ``ipsec`` namespace.
pub fn set_ipsec_singleton(
    python: Python<'_>,
    py_ipsec: ipsec::PyIpsec,
) -> Result<()> {
    let ipsec_py: Py<PyAny> = Py::new(python, py_ipsec)
        .map_err(|error| SiphonError::Script(format!("Py::new(ipsec): {error}")))?
        .into_any();
    let _ = IPSEC_SINGLETON.set(ipsec_py);
    Ok(())
}

/// Store the STIR/SHAKEN singleton for injection into the siphon module.
///
/// Called at startup only when `stir` is configured. Wires the shared
/// [`crate::stir::StirService`] into the Python `stir` namespace.
pub fn set_stir_singleton(python: Python<'_>, py_stir: stir::PyStir) -> Result<()> {
    let stir_py: Py<PyAny> = Py::new(python, py_stir)
        .map_err(|error| SiphonError::Script(format!("Py::new(stir): {error}")))?
        .into_any();
    let _ = STIR_SINGLETON.set(stir_py);
    Ok(())
}

/// Store the ISC singleton for injection into the siphon module.
///
/// Always called at startup — the iFC store is always available (even if
/// no global iFCs are configured, per-user profiles can be stored dynamically).
pub fn set_isc_singleton(
    python: Python<'_>,
    py_isc: isc::PyIsc,
    store: std::sync::Arc<crate::ifc::IfcStore>,
) -> Result<()> {
    let isc_py: Py<PyAny> = Py::new(python, py_isc)
        .map_err(|error| SiphonError::Script(format!("Py::new(isc): {error}")))?
        .into_any();
    let _ = ISC_SINGLETON.set(isc_py);
    let _ = IFC_STORE_ARC.set(store);
    Ok(())
}

/// Register a host-provided Python namespace under `name`.
///
/// The supplied object becomes accessible to user scripts via
/// `from siphon import <name>`. Called once per namespace by
/// `SiphonServer::run_async()` before the script engine is created.
///
/// Errors if `name` collides with a built-in namespace
/// (see `BUILT_IN_NAMESPACE_NAMES`) or duplicates a previously-registered
/// host namespace.
pub fn set_user_namespace(name: &str, py_obj: Py<PyAny>) -> Result<()> {
    if BUILT_IN_NAMESPACE_NAMES.contains(&name) {
        return Err(SiphonError::Script(format!(
            "user namespace '{name}' collides with a built-in siphon namespace"
        )));
    }
    let mut guard = USER_NAMESPACES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.iter().any(|(existing, _)| existing == name) {
        return Err(SiphonError::Script(format!(
            "user namespace '{name}' is already registered"
        )));
    }
    guard.push((name.to_owned(), py_obj));
    Ok(())
}

/// Test-only: clear all host-registered namespaces. Lets each test exercise
/// `set_user_namespace` from a known-empty state.
#[cfg(test)]
pub fn clear_user_namespaces() {
    let mut guard = USER_NAMESPACES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clear();
}

/// Ensure the `_siphon_registry` module exists in `sys.modules`.
///
/// Idempotent — safe to call multiple times.
pub fn ensure_registry(python: Python<'_>) -> Result<()> {
    let sys = python
        .import("sys")
        .map_err(|error| SiphonError::Script(format!("import sys: {error}")))?;
    let modules = sys
        .getattr("modules")
        .map_err(|error| SiphonError::Script(format!("sys.modules: {error}")))?;

    let registry_name = "_siphon_registry";
    if let Ok(existing) = modules.get_item(registry_name) {
        if !existing.is_none() {
            return Ok(());
        }
    }

    let registry_source = CString::new(include_str!("registry.py"))
        .map_err(|error| SiphonError::Script(format!("registry source CString: {error}")))?;
    let file_name = CString::new("_siphon_registry.py")
        .map_err(|error| SiphonError::Script(format!("registry file name CString: {error}")))?;
    let module_cname = CString::new(registry_name)
        .map_err(|error| SiphonError::Script(format!("registry module name CString: {error}")))?;
    let module = PyModule::from_code(python, &registry_source, &file_name, &module_cname)
        .map_err(|error| {
            SiphonError::Script(format!("registry module: {error}"))
        })?;

    modules
        .set_item(registry_name, &module)
        .map_err(|error| SiphonError::Script(format!("sys.modules insert: {error}")))?;

    Ok(())
}

/// Install the `siphon` Python package into `sys.modules`.
///
/// Creates (or recreates) the module each time. If Rust singletons have been
/// registered via `set_rust_singletons()`, they replace the Python stubs
/// before any user script can import them.
pub fn install_siphon_module(python: Python<'_>) -> Result<()> {
    let source = CString::new(include_str!("siphon_package.py"))
        .map_err(|error| SiphonError::Script(format!("siphon package source CString: {error}")))?;
    let file_name = CString::new("siphon/__init__.py")
        .map_err(|error| SiphonError::Script(format!("siphon file name CString: {error}")))?;
    let module_name = CString::new("siphon")
        .map_err(|error| SiphonError::Script(format!("siphon module name CString: {error}")))?;

    let module = PyModule::from_code(python, &source, &file_name, &module_name)
        .map_err(|error| {
            SiphonError::Script(format!("failed to create siphon module: {error}"))
        })?;

    // Register pyclasses as top-level attributes on the `siphon` module
    // so scripts can `from siphon import Transform, SecurityOffer, …`
    // without going through a singleton.  Without these, the types are
    // defined but unreachable from Python — `Transform.HmacSha1_96Null`
    // can't be evaluated because there's no `Transform` symbol in scope.
    module
        .add_class::<ipsec::PyTransform>()
        .map_err(|error| SiphonError::Script(format!("add_class Transform: {error}")))?;
    module
        .add_class::<ipsec::PySecurityOffer>()
        .map_err(|error| SiphonError::Script(format!("add_class SecurityOffer: {error}")))?;
    module
        .add_class::<ipsec::PyAuthVectorHandle>()
        .map_err(|error| SiphonError::Script(format!("add_class AuthVectorHandle: {error}")))?;
    module
        .add_class::<ipsec::PyPendingSA>()
        .map_err(|error| SiphonError::Script(format!("add_class PendingSA: {error}")))?;
    module
        .add_class::<ipsec::PySecurityServerParams>()
        .map_err(|error| SiphonError::Script(format!("add_class SecurityServerParams: {error}")))?;
    module
        .add_class::<ipsec::PySAHandle>()
        .map_err(|error| SiphonError::Script(format!("add_class SAHandle: {error}")))?;
    // Path-token MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2):
    // `Flow` is the opaque view returned by `request.flow` and
    // `Contact.flow`.  Scripts pass it to `request.relay(flow=...)` to
    // reach the UE on the captured inbound flow without DNS-resolving
    // the Contact URI.
    module
        .add_class::<registrar::PyFlow>()
        .map_err(|error| SiphonError::Script(format!("add_class Flow: {error}")))?;

    // If Rust singletons are available, inject them now — before any user
    // script does `from siphon import auth`.
    if let Some((auth_py, reg_py, log_py, proxy_utils_py, cache_py)) = RUST_SINGLETONS.get() {
        module
            .setattr("auth", auth_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr auth: {error}")))?;
        module
            .setattr("registrar", reg_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr registrar: {error}")))?;
        module
            .setattr("log", log_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr log: {error}")))?;
        module
            .setattr("cache", cache_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr cache: {error}")))?;

        // Inject proxy utilities onto the existing proxy namespace
        let proxy_ns = module
            .getattr("proxy")
            .map_err(|error| SiphonError::Script(format!("getattr proxy: {error}")))?;
        proxy_ns
            .setattr("_utils", proxy_utils_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr proxy._utils: {error}")))?;
    }

    // Inject the subscribe_state singleton onto `proxy` independently of
    // RUST_SINGLETONS — subscribe_state has no dependency on auth/registrar/log
    // and gating it under that tuple would mean dropping the Rust namespace
    // (and silently leaving the Python stub bound) any time auth/registrar
    // singletons aren't yet wired (e.g. tests, or re-entrant install paths).
    if let Some(subscribe_state_py) = SUBSCRIBE_STATE_SINGLETON.get() {
        let proxy_ns = module
            .getattr("proxy")
            .map_err(|error| SiphonError::Script(format!("getattr proxy: {error}")))?;
        proxy_ns
            .setattr("subscribe_state", subscribe_state_py.bind(python))
            .map_err(|error| {
                SiphonError::Script(format!("setattr proxy.subscribe_state: {error}"))
            })?;
    }

    // Inject optional RTPEngine singleton (only when media.rtpengine is configured).
    if let Some(rtpengine_py) = RTPENGINE_SINGLETON.get() {
        module
            .setattr("rtpengine", rtpengine_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr rtpengine: {error}")))?;
    }

    // Inject optional gateway singleton.
    if let Some(gateway_py) = GATEWAY_SINGLETON.get() {
        module
            .setattr("gateway", gateway_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr gateway: {error}")))?;
    }

    // Inject optional CDR singleton.
    if let Some(cdr_py) = CDR_SINGLETON.get() {
        module
            .setattr("cdr", cdr_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr cdr: {error}")))?;
    }

    // Inject optional registration singleton.
    if let Some(registration_py) = REGISTRATION_SINGLETON.get() {
        module
            .setattr("registration", registration_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr registration: {error}")))?;
    }

    // Inject optional LI singleton.
    if let Some(li_py) = LI_SINGLETON.get() {
        module
            .setattr("li", li_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr li: {error}")))?;
    }

    // Inject optional Diameter singleton.
    if let Some(diameter_py) = DIAMETER_SINGLETON.get() {
        module
            .setattr("diameter", diameter_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr diameter: {error}")))?;
    }

    // Inject optional presence singleton.
    if let Some(presence_py) = PRESENCE_SINGLETON.get() {
        module
            .setattr("presence", presence_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr presence: {error}")))?;
    }

    // Inject metrics singleton (always available).
    if let Some(metrics_py) = METRICS_SINGLETON.get() {
        module
            .setattr("metrics", metrics_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr metrics: {error}")))?;
    }

    // Inject SDP namespace singleton (always available — stateless parser).
    if let Some(sdp_py) = SDP_SINGLETON.get() {
        module
            .setattr("sdp", sdp_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr sdp: {error}")))?;
    }

    // Inject QoS namespace singleton (always available — stateless helper).
    if let Some(qos_py) = QOS_SINGLETON.get() {
        module
            .setattr("qos", qos_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr qos: {error}")))?;
    }

    // Inject timer namespace singleton (always available — runtime scheduler).
    if let Some(timer_py) = TIMER_SINGLETON.get() {
        module
            .setattr("timer", timer_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr timer: {error}")))?;
    }

    // Inject ISC singleton (always available — iFC store).
    if let Some(isc_py) = ISC_SINGLETON.get() {
        module
            .setattr("isc", isc_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr isc: {error}")))?;
    }

    // Inject optional SBI singleton.
    if let Some(sbi_py) = SBI_SINGLETON.get() {
        module
            .setattr("sbi", sbi_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr sbi: {error}")))?;
    }

    // Inject optional IPsec singleton (P-CSCF role).
    if let Some(ipsec_py) = IPSEC_SINGLETON.get() {
        module
            .setattr("ipsec", ipsec_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr ipsec: {error}")))?;
    }

    // Inject optional STIR/SHAKEN singleton.
    if let Some(stir_py) = STIR_SINGLETON.get() {
        module
            .setattr("stir", stir_py.bind(python))
            .map_err(|error| SiphonError::Script(format!("setattr stir: {error}")))?;
    }

    // Inject host-registered user namespaces. These were validated against
    // BUILT_IN_NAMESPACE_NAMES at registration time, so they cannot shadow
    // a built-in.
    {
        let guard = USER_NAMESPACES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (name, py_obj) in guard.iter() {
            module
                .setattr(name.as_str(), py_obj.bind(python))
                .map_err(|error| {
                    SiphonError::Script(format!("setattr {name} (user namespace): {error}"))
                })?;
        }
    }

    let sys = python
        .import("sys")
        .map_err(|error| SiphonError::Script(format!("import sys: {error}")))?;
    let modules = sys
        .getattr("modules")
        .map_err(|error| SiphonError::Script(format!("sys.modules: {error}")))?;

    modules
        .set_item("siphon", &module)
        .map_err(|error| SiphonError::Script(format!("sys.modules['siphon'] = ...: {error}")))?;

    Ok(())
}
