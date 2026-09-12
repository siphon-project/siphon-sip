//! A byte-for-byte snapshot of the Python surface scripts are written against.
//!
//! The 1.9.0 module split moves tens of thousands of lines between files. Every
//! one of those PRs claims "no behaviour change", and for Rust internals the
//! compiler and the test suite say so. The scripting API has no such proof: a
//! `#[pymethods]` block that loses a method, a `#[pyo3(signature)]` whose
//! default drifts, or a `///` that stops being a docstring are all silent — the
//! crate still builds, every Rust test still passes, and scripts break in
//! production.
//!
//! So this records the surface and compares against a committed fixture. A
//! refactor PR that changes it has changed the contract, and has to say so and
//! mirror it into `sdk/siphon_sdk/`.
//!
//! Regenerate deliberately, never to make the test pass:
//!
//! ```text
//! UPDATE_PYTHON_SURFACE=1 PYO3_PYTHON=python3 cargo test --lib surface_snapshot
//! ```
//!
//! and read the diff before committing it.

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyString};
    use pyo3::PyTypeInfo;

    const FIXTURE: &str = "tests/fixtures/python_surface.json";

    /// Every `#[pyclass]` in `script/api`, keyed by its Python name.
    ///
    /// Most are not module attributes — they are reached as the type of
    /// something a handler is handed (`request`, `call`, a `Contact`) — so
    /// walking `siphon` alone would miss them and a lost method on `PyRequest`
    /// would sail through.
    ///
    /// Adding a `#[pyclass]` means adding it here. `every_pyclass_is_listed`
    /// below fails if you forget.
    fn pyclass_types(python: Python<'_>) -> Vec<(String, Bound<'_, pyo3::PyAny>)> {
        macro_rules! types {
            ($($ty:ty),* $(,)?) => {
                vec![$({
                    let object = <$ty as PyTypeInfo>::type_object(python);
                    // The runtime name, not the Rust one: what a script sees.
                    let name = object
                        .name()
                        .map(|name| name.to_string())
                        .unwrap_or_else(|_| stringify!($ty).to_string());
                    (name, object.into_any())
                }),*]
            };
        }

        types![
            super::super::auth::PyAuth,
            super::super::b2bua::PyB2buaControl,
            super::super::cache::PyCacheNamespace,
            super::super::call::PyByeInitiator,
            super::super::call::PyCall,
            super::super::call::PyMediaHandle,
            super::super::cdr::PyCdrNamespace,
            super::super::diameter::PyDiameter,
            super::super::diameter::PyEventSink,
            super::super::diameter_server::PyDiameterAnswer,
            super::super::diameter_server::PyDiameterRequest,
            super::super::diameter_server::PyInboundPeer,
            super::super::diameter_server::PyPeer,
            super::super::diameter_server::PyPeerPool,
            super::super::gateway::PyDestination,
            super::super::gateway::PyGateway,
            super::super::ipsec::PyAuthVectorHandle,
            super::super::ipsec::PyIpsec,
            super::super::ipsec::PyPendingSA,
            super::super::ipsec::PySAHandle,
            super::super::ipsec::PySecurityOffer,
            super::super::ipsec::PySecurityServerParams,
            super::super::ipsec::PyTransform,
            super::super::isc::PyIsc,
            super::super::lcr::PyLcr,
            super::super::lcr::PyLcrDecision,
            super::super::lcr::PyRoute,
            super::super::li::PyLiNamespace,
            super::super::log::PyLogNamespace,
            super::super::metrics::PyCounter,
            super::super::metrics::PyCounterChild,
            super::super::metrics::PyGauge,
            super::super::metrics::PyGaugeChild,
            super::super::metrics::PyHistogram,
            super::super::metrics::PyHistogramChild,
            super::super::metrics::PyMetricsNamespace,
            super::super::numbers::PyNumber,
            super::super::numbers::PyNumbersNamespace,
            super::super::presence::PyPresence,
            super::super::proxy_utils::PyProxyUtils,
            super::super::qos::PyQosNamespace,
            super::super::registrant::PyRegistration,
            super::super::registrar::PyContact,
            super::super::registrar::PyFlow,
            super::super::registrar::PyRegistrar,
            super::super::reply::PyReply,
            super::super::request::PyRequest,
            super::super::rtpengine::PyRtpEngine,
            super::super::sbi::PySbi,
            super::super::sdp::PyMediaSection,
            super::super::sdp::PySdp,
            super::super::sdp::PySdpNamespace,
            super::super::sip_uri::PySipUri,
            super::super::srs::PyParticipant,
            super::super::srs::PyRecordingMetadata,
            super::super::srs::PySrsSession,
            super::super::srs::PyStreamInfo,
            super::super::stir::PyStir,
            super::super::stir::StirResult,
            super::super::subscribe_state::PySubscribeHandle,
            super::super::subscribe_state::PySubscribeState,
            super::super::timer::PyTimerHandle,
            super::super::timer::PyTimerNamespace,
        ]
    }

    /// Renders the pyclass surface, plus the module's attribute names, as
    /// sorted JSON.
    ///
    /// Records, per member: the descriptor kind (so a method silently becoming
    /// a property is caught), `__text_signature__` (so a changed default or a
    /// dropped kwarg is caught) and the first docstring line (so a `///` that
    /// stops reaching Python is caught).
    ///
    /// The module is recorded by attribute *name* only, deliberately. Its
    /// members are not stable within one test binary: `siphon.registration` and
    /// `proxy.subscribe_state` are Python stubs until something installs the
    /// Rust singleton over them, and other tests in this process do exactly
    /// that, so walking them made this guard pass alone and fail in the full
    /// run. The types below carry the real contract — every namespace a script
    /// touches is one of them (`siphon.auth` is `PyAuth`, `proxy._utils` is
    /// `PyProxyUtils`) — so nothing is lost but the pure-Python decorators
    /// defined in `siphon_package.py`, which are version-controlled and show up
    /// as a source diff on their own.
    const DESCRIBE: &str = r#"
import json

def _entry(attr):
    out = {"kind": type(attr).__name__}
    sig = getattr(attr, "__text_signature__", None)
    if sig:
        out["sig"] = sig
    doc = getattr(attr, "__doc__", None)
    if doc:
        # First non-empty line only: the full text is the SDK's business, and
        # rewrapping a paragraph should not read as an API change.
        for line in doc.strip().splitlines():
            line = line.strip()
            if line:
                out["doc"] = line
                break
    return out

def _members(obj):
    out = {}
    for name in sorted(dir(obj)):
        if name.startswith("_"):
            continue
        try:
            attr = getattr(obj, name)
        except Exception as error:
            out[name] = {"kind": "<unreadable: %s>" % type(error).__name__}
            continue
        out[name] = _entry(attr)
    return out

surface = {"module_attributes": [], "types": {}}

import siphon
surface["module_attributes"] = sorted(
    name for name in dir(siphon) if not name.startswith("_")
)

for name in sorted(_surface_types):
    surface["types"][name] = _members(_surface_types[name])

_surface_json = json.dumps(surface, indent=2, sort_keys=True)
"#;

    fn capture_surface() -> String {
        Python::initialize();
        Python::attach(|python| {
            crate::script::api::ensure_registry(python).expect("ensure registry");
            crate::script::api::install_siphon_module(python).expect("install siphon module");

            let globals = PyDict::new(python);
            let types = PyDict::new(python);
            for (name, object) in pyclass_types(python) {
                types.set_item(name, object).expect("set type");
            }
            globals.set_item("_surface_types", types).expect("set map");

            let code = CString::new(DESCRIBE).expect("CString");
            python
                .run(code.as_c_str(), Some(&globals), None)
                .expect("surface introspection must run");

            globals
                .get_item("_surface_json")
                .expect("get result")
                .expect("result present")
                .cast::<PyString>()
                .expect("result is a str")
                .to_string_lossy()
                .into_owned()
        })
    }

    /// The guard the split runs against.
    #[test]
    fn python_surface_is_unchanged() {
        let captured = capture_surface();

        if std::env::var("UPDATE_PYTHON_SURFACE").as_deref() == Ok("1") {
            std::fs::create_dir_all("tests/fixtures").expect("create fixture dir");
            std::fs::write(FIXTURE, format!("{captured}\n")).expect("write fixture");
            eprintln!("wrote {FIXTURE} — read the diff before committing it");
            return;
        }

        let expected = std::fs::read_to_string(FIXTURE).unwrap_or_else(|error| {
            panic!(
                "{FIXTURE} is missing ({error}). Generate it with \
                 UPDATE_PYTHON_SURFACE=1 cargo test --lib surface_snapshot"
            )
        });

        if expected.trim() == captured.trim() {
            return;
        }

        // A whole-file diff of a few thousand lines of JSON helps nobody; name
        // the entries that actually moved.
        let before: serde_json::Value =
            serde_json::from_str(&expected).expect("fixture is valid JSON");
        let after: serde_json::Value =
            serde_json::from_str(&captured).expect("capture is valid JSON");

        let mut differences = Vec::new();

        let names = |value: &serde_json::Value| -> Vec<String> {
            value
                .get("module_attributes")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let (before_names, after_names) = (names(&before), names(&after));
        for name in &before_names {
            if !after_names.contains(name) {
                differences.push(format!("siphon.{name}: REMOVED from the module"));
            }
        }
        for name in &after_names {
            if !before_names.contains(name) {
                differences.push(format!("siphon.{name}: ADDED to the module"));
            }
        }

        for section in ["types"] {
            let before_section = before.get(section).and_then(|v| v.as_object());
            let after_section = after.get(section).and_then(|v| v.as_object());
            let (Some(before_section), Some(after_section)) = (before_section, after_section)
            else {
                differences.push(format!("{section}: section missing"));
                continue;
            };
            for key in before_section.keys() {
                match after_section.get(key) {
                    None => differences.push(format!("{section}.{key}: REMOVED")),
                    Some(value) if value != &before_section[key] => {
                        differences.push(format!("{section}.{key}: CHANGED"))
                    }
                    Some(_) => {}
                }
            }
            for key in after_section.keys() {
                if !before_section.contains_key(key) {
                    differences.push(format!("{section}.{key}: ADDED"));
                }
            }
        }

        panic!(
            "the Python surface moved:\n  {}\n\nA refactor must not change it. If the change is \
             intended, mirror it into sdk/siphon_sdk/ and regenerate with \
             UPDATE_PYTHON_SURFACE=1 cargo test --lib surface_snapshot",
            differences.join("\n  ")
        );
    }

    /// The list above is hand-maintained, so it can silently fall behind. This
    /// counts `#[pyclass]` in the source and fails if the two disagree — the
    /// same source-scanning trick the module-boundary guard uses.
    #[test]
    fn every_pyclass_is_listed() {
        let mut in_source = Vec::new();
        let directory = std::path::Path::new("src/script/api");
        for entry in std::fs::read_dir(directory).expect("read script/api") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read source");
            for (index, line) in source.lines().enumerate() {
                if !line.trim_start().starts_with("#[pyclass") {
                    continue;
                }
                // The declaration follows the attribute, possibly after further
                // attributes (`#[derive(...)]`).
                let declaration = source
                    .lines()
                    .skip(index + 1)
                    .find(|candidate| {
                        let candidate = candidate.trim_start();
                        candidate.starts_with("pub struct ") || candidate.starts_with("pub enum ")
                    })
                    .unwrap_or_default();
                let name = declaration
                    .trim_start()
                    .trim_start_matches("pub struct ")
                    .trim_start_matches("pub enum ")
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if !name.is_empty() {
                    in_source.push(name);
                }
            }
        }
        in_source.sort();
        in_source.dedup();

        let listed = Python::attach(|python| pyclass_types(python).len());

        assert_eq!(
            in_source.len(),
            listed,
            "src/script/api declares {} #[pyclass] types but pyclass_types() lists {}. \
             A type missing from that list is a type the surface snapshot cannot see. \
             Declared: {:?}",
            in_source.len(),
            listed,
            in_source,
        );
    }
}
