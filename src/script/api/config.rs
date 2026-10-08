//! PyO3 `config` namespace: read access to the `script_config:` document.
//!
//! Every call converts the value it returns into new Python objects. Nothing a
//! script is handed is shared with another thread or with the snapshot it came
//! from, so a handler that mutates what it got changes only its own copy, and
//! on free-threaded Python there is no shared `dict` or `list` to guard. The
//! cost is proportional to the size of what is asked for: name the narrowest
//! key (`routes.default.gateway`), not the whole table, on a per-message path.

use std::sync::Arc;

use pyo3::exceptions::PyLookupError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_yaml_ng::Value;

use crate::script::script_config::{lookup, ScriptConfigStore};

/// Operator-supplied configuration for the script.
///
/// Injected as ``siphon.config`` at startup and always available. Without a
/// ``script_config:`` key in ``siphon.yaml`` the document is empty.
#[pyclass(name = "ScriptConfig", frozen)]
pub struct PyScriptConfig {
    store: Arc<ScriptConfigStore>,
}

impl PyScriptConfig {
    pub fn new(store: Arc<ScriptConfigStore>) -> Self {
        Self { store }
    }
}

#[pymethods]
impl PyScriptConfig {
    /// Return the value at ``key``, or ``default`` when it is not set.
    ///
    /// Args:
    ///     key: a dotted path into the document, e.g. ``"routes.default"``.
    ///         Each segment is a mapping key or a zero-based sequence index.
    ///         ``""`` is the whole document.
    ///     default: returned when the path does not resolve.
    ///
    /// Returns:
    ///     Plain data (``dict``, ``list``, ``str``, ``int``, ``float``,
    ///     ``bool`` or ``None``) as a new copy on every call. A key that is
    ///     set to ``null`` returns ``None``, not ``default``.
    ///
    /// ```python
    /// gateway = config.get("routes.default.gateway", "carrier-a")
    /// ```
    #[pyo3(signature = (key, default=None))]
    fn get(
        &self,
        python: Python<'_>,
        key: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let snapshot = self.store.snapshot();
        match lookup(&snapshot, key) {
            Ok(value) => yaml_to_py(python, value),
            Err(_) => Ok(default.unwrap_or_else(|| python.None())),
        }
    }

    /// Return the value at ``key``, or raise when it is not set.
    ///
    /// Args:
    ///     key: a dotted path into the document, as for ``get``.
    ///
    /// Returns:
    ///     The value, as a new copy on every call.
    ///
    /// Raises:
    ///     LookupError: the path does not resolve, or resolves to ``null``.
    ///         The message names the key and the segment it stopped at.
    ///
    /// ```python
    /// routes = config.require("routes.prefixes")
    /// ```
    fn require(&self, python: Python<'_>, key: &str) -> PyResult<Py<PyAny>> {
        let snapshot = self.store.snapshot();
        match lookup(&snapshot, key) {
            Ok(Value::Null) => Err(PyLookupError::new_err(format!(
                "script_config key {key:?} is set to null"
            ))),
            Ok(value) => yaml_to_py(python, value),
            Err(error) => Err(PyLookupError::new_err(error.to_string())),
        }
    }
}

/// Convert a YAML value into new Python objects.
fn yaml_to_py(python: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    Ok(match value {
        Value::Null => python.None(),
        Value::Bool(flag) => flag.into_pyobject(python)?.to_owned().into_any().unbind(),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.into_pyobject(python)?.into_any().unbind()
            } else if let Some(integer) = number.as_u64() {
                integer.into_pyobject(python)?.into_any().unbind()
            } else if let Some(float) = number.as_f64() {
                float.into_pyobject(python)?.into_any().unbind()
            } else {
                python.None()
            }
        }
        Value::String(text) => text.as_str().into_pyobject(python)?.into_any().unbind(),
        Value::Sequence(items) => {
            let list = PyList::empty(python);
            for item in items {
                list.append(yaml_to_py(python, item)?)?;
            }
            list.into_any().unbind()
        }
        Value::Mapping(mapping) => {
            let dict = PyDict::new(python);
            for (key, child) in mapping {
                dict.set_item(yaml_to_py(python, key)?, yaml_to_py(python, child)?)?;
            }
            dict.into_any().unbind()
        }
        // Refused when the document is loaded; the content is the honest
        // reading if one is ever met here.
        Value::Tagged(tagged) => yaml_to_py(python, &tagged.value)?,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    const DOCUMENT: &str = concat!(
        "routes:\n",
        "  default:\n",
        "    gateway: carrier-a\n",
        "    weight: 10\n",
        "  prefixes:\n",
        "    - prefix: \"+1555\"\n",
        "      gateway: carrier-b\n",
        "country_codes:\n",
        "  31: nl\n",
        "limits:\n",
        "  ratio: 0.5\n",
        "  enabled: true\n",
        "  ceiling: 18446744073709551615\n",
        "  note: ~\n",
    );

    fn namespace(yaml: &str) -> PyScriptConfig {
        let document: Value = serde_yaml_ng::from_str(yaml).unwrap();
        PyScriptConfig::new(Arc::new(ScriptConfigStore::inline(document).unwrap()))
    }

    /// Run `source` with the namespace bound as `config`.
    fn run(namespace: PyScriptConfig, source: &str) {
        Python::initialize();
        Python::attach(|python| {
            let globals = PyDict::new(python);
            globals
                .set_item("config", Py::new(python, namespace).unwrap())
                .unwrap();
            let code = CString::new(source).unwrap();
            if let Err(error) = python.run(code.as_c_str(), Some(&globals), None) {
                panic!("script failed: {error}");
            }
        });
    }

    #[test]
    fn get_returns_plain_python_data() {
        run(
            namespace(DOCUMENT),
            r#"
assert config.get("routes.default.gateway") == "carrier-a"
assert config.get("routes.default.weight") == 10
assert type(config.get("routes.default.weight")) is int
assert config.get("limits.ratio") == 0.5
assert config.get("limits.enabled") is True
assert config.get("limits.ceiling") == 18446744073709551615
assert config.get("routes.default") == {"gateway": "carrier-a", "weight": 10}
assert type(config.get("routes.default")) is dict
assert config.get("routes.prefixes") == [{"prefix": "+1555", "gateway": "carrier-b"}]
assert type(config.get("routes.prefixes")) is list
assert config.get("routes.prefixes.0.gateway") == "carrier-b"
assert config.get("country_codes") == {31: "nl"}
assert config.get("country_codes.31") == "nl"
assert set(config.get("")) == {"routes", "country_codes", "limits"}
"#,
        );
    }

    #[test]
    fn get_returns_the_default_for_a_missing_key() {
        run(
            namespace(DOCUMENT),
            r#"
assert config.get("routes.backup") is None
assert config.get("routes.backup", "carrier-z") == "carrier-z"
assert config.get("routes.backup", default={"gateway": "carrier-z"}) == {"gateway": "carrier-z"}
assert config.get("routes.prefixes.9", "none") == "none"
"#,
        );
    }

    #[test]
    fn get_returns_the_default_for_a_path_through_a_scalar() {
        run(
            namespace(DOCUMENT),
            r#"
assert config.get("routes.default.gateway.host", "unset") == "unset"
"#,
        );
    }

    #[test]
    fn get_returns_none_for_an_explicit_null_not_the_default() {
        run(
            namespace(DOCUMENT),
            r#"
assert config.get("limits.note", "fallback") is None
"#,
        );
    }

    #[test]
    fn get_hands_out_a_copy_each_time() {
        run(
            namespace(DOCUMENT),
            r#"
first = config.get("routes.default")
first["gateway"] = "changed-by-the-script"
first["added"] = True
assert config.get("routes.default") == {"gateway": "carrier-a", "weight": 10}

prefixes = config.get("routes.prefixes")
prefixes.clear()
assert len(config.get("routes.prefixes")) == 1
"#,
        );
    }

    #[test]
    fn require_returns_the_value() {
        run(
            namespace(DOCUMENT),
            r#"
assert config.require("routes.default.gateway") == "carrier-a"
assert config.require("routes.prefixes")[0]["prefix"] == "+1555"
"#,
        );
    }

    #[test]
    fn require_raises_naming_the_missing_key() {
        run(
            namespace(DOCUMENT),
            r#"
try:
    config.require("routes.backup.gateway")
except LookupError as error:
    assert str(error) == (
        'script_config key "routes.backup.gateway" is not set (no "backup" under "routes")'
    ), str(error)
else:
    raise AssertionError("require() returned for a missing key")
"#,
        );
    }

    #[test]
    fn require_raises_for_a_path_through_a_scalar() {
        run(
            namespace(DOCUMENT),
            r#"
try:
    config.require("routes.default.gateway.host")
except LookupError as error:
    assert '"routes.default.gateway" is a string' in str(error), str(error)
else:
    raise AssertionError("require() returned for a path through a scalar")
"#,
        );
    }

    #[test]
    fn require_raises_for_an_explicit_null() {
        run(
            namespace(DOCUMENT),
            r#"
try:
    config.require("limits.note")
except LookupError as error:
    assert str(error) == 'script_config key "limits.note" is set to null', str(error)
else:
    raise AssertionError("require() returned for a null")
"#,
        );
    }

    #[test]
    fn an_empty_document_misses_everything() {
        run(
            PyScriptConfig::new(Arc::new(ScriptConfigStore::empty())),
            r#"
assert config.get("routes") is None
assert config.get("routes", []) == []
assert config.get("") == {}
try:
    config.require("routes")
except LookupError:
    pass
else:
    raise AssertionError("require() returned on an empty document")
"#,
        );
    }

    #[test]
    fn a_reload_is_visible_to_the_next_call() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("routes.yaml");
        std::fs::write(&path, "gateway: carrier-a\n").unwrap();
        let store = Arc::new(ScriptConfigStore::from_file(&path).unwrap());

        Python::initialize();
        Python::attach(|python| {
            let config = Py::new(python, PyScriptConfig::new(Arc::clone(&store))).unwrap();
            let read = |python: Python<'_>| -> String {
                config
                    .bind(python)
                    .call_method1("require", ("gateway",))
                    .unwrap()
                    .extract()
                    .unwrap()
            };
            assert_eq!(read(python), "carrier-a");

            std::fs::write(&path, "gateway: carrier-b\n").unwrap();
            store.reload();
            assert_eq!(read(python), "carrier-b");

            std::fs::write(&path, "gateway: [unterminated\n").unwrap();
            store.reload();
            assert_eq!(read(python), "carrier-b", "the last good document serves");
        });
    }
}
