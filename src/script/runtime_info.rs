//! Which Python interpreter this process embeds.
//!
//! The interpreter is fixed when siphon is compiled (PyO3 links the
//! `libpython` that `PYO3_PYTHON` pointed at), so installing another Python
//! afterwards changes nothing and there is no runtime switch. A build against
//! a GIL interpreter runs every handler serialised, which looks like any other
//! siphon until it is under load. Logging the interpreter at startup makes
//! that visible.

use pyo3::prelude::*;
use tracing::{info, warn};

/// The embedded interpreter, as it reports itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntime {
    /// Release, e.g. `3.14.0` or `3.14.0rc2`.
    pub version: String,
    /// Built with `--disable-gil` (the `t` ABI flag, PEP 703).
    pub free_threaded: bool,
    /// The GIL is active right now. Always true on a GIL build; on a
    /// free-threaded build it is true when `PYTHON_GIL=1` is set or an
    /// imported extension module turned it back on.
    pub gil_enabled: bool,
    /// `sys.base_prefix`, the installation the standard library loads from.
    pub prefix: String,
}

impl PythonRuntime {
    /// Read the interpreter's own description of itself.
    pub fn detect(python: Python<'_>) -> PyResult<Self> {
        let sys = python.import("sys")?;
        let full_version: String = sys.getattr("version")?.extract()?;
        let version = full_version
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let abi_flags: String = sys.getattr("abiflags")?.extract()?;
        // `sys._is_gil_enabled` arrived in 3.13; before that there is always a GIL.
        let gil_enabled = if sys.hasattr("_is_gil_enabled")? {
            sys.call_method0("_is_gil_enabled")?.extract()?
        } else {
            true
        };
        Ok(Self {
            version,
            free_threaded: abi_flags.contains('t'),
            gil_enabled,
            prefix: sys.getattr("base_prefix")?.extract()?,
        })
    }

    /// Why this interpreter caps handler parallelism, or `None` when it does not.
    pub fn concern(&self) -> Option<&'static str> {
        match (self.gil_enabled, self.free_threaded) {
            (false, _) => None,
            (true, true) => Some(
                "free-threaded python is running with the GIL enabled (PYTHON_GIL=1, or an \
                 imported extension module re-enabled it): script handlers do not run in parallel",
            ),
            (true, false) => Some(
                "this interpreter has a GIL, so script handlers do not run in parallel. For throughput, \
                 rebuild siphon against free-threaded CPython (PYO3_PYTHON=python3.14t)",
            ),
        }
    }

    /// Log the interpreter: `info` when handlers run in parallel, `warn` when
    /// the GIL serialises them.
    pub fn log(&self) {
        match self.concern() {
            None => info!(
                version = %self.version,
                free_threaded = self.free_threaded,
                gil_enabled = self.gil_enabled,
                prefix = %self.prefix,
                "python runtime"
            ),
            Some(concern) => warn!(
                version = %self.version,
                free_threaded = self.free_threaded,
                gil_enabled = self.gil_enabled,
                prefix = %self.prefix,
                "python runtime: {concern}"
            ),
        }
    }
}

/// Log the embedded interpreter. Call once the script is loaded, so a GIL
/// re-enabled by one of the script's imports is reported.
pub fn log_python_runtime() {
    match Python::attach(PythonRuntime::detect) {
        Ok(runtime) => runtime.log(),
        Err(error) => warn!("could not determine the python runtime: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(free_threaded: bool, gil_enabled: bool) -> PythonRuntime {
        PythonRuntime {
            version: "3.14.0".to_owned(),
            free_threaded,
            gil_enabled,
            prefix: "/usr".to_owned(),
        }
    }

    #[test]
    fn detect_matches_the_linked_interpreter() {
        Python::initialize();
        Python::attach(|python| {
            let detected = PythonRuntime::detect(python).unwrap();
            let linked = python.version_info();
            assert!(
                detected
                    .version
                    .starts_with(&format!("{}.{}.", linked.major, linked.minor)),
                "version {:?} is not {}.{}",
                detected.version,
                linked.major,
                linked.minor
            );
            assert!(!detected.version.contains(' '));
            assert!(!detected.prefix.is_empty());
            // The build flavour, from the interpreter's build configuration
            // instead of the ABI flag `detect` reads.
            let built_without_gil = python
                .import("sysconfig")
                .unwrap()
                .call_method1("get_config_var", ("Py_GIL_DISABLED",))
                .unwrap()
                .is_truthy()
                .unwrap();
            assert_eq!(detected.free_threaded, built_without_gil);
            if !detected.free_threaded {
                assert!(detected.gil_enabled, "a GIL build always has the GIL");
            }
        });
    }

    #[test]
    fn no_concern_without_a_gil() {
        assert_eq!(runtime(true, false).concern(), None);
    }

    #[test]
    fn gil_build_points_at_the_rebuild() {
        let concern = runtime(false, true).concern().unwrap();
        assert!(concern.contains("PYO3_PYTHON=python3.14t"), "{concern}");
    }

    #[test]
    fn free_threaded_build_with_the_gil_back_on_says_so() {
        let concern = runtime(true, true).concern().unwrap();
        assert!(concern.contains("PYTHON_GIL=1"), "{concern}");
        assert_ne!(Some(concern), runtime(false, true).concern());
    }

    #[test]
    fn log_does_not_panic_for_any_state() {
        for (free_threaded, gil_enabled) in [(true, false), (true, true), (false, true)] {
            runtime(free_threaded, gil_enabled).log();
        }
        Python::initialize();
        log_python_runtime();
    }
}
