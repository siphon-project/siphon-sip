//! Keyword arguments an event handler receives only when it accepts them.
//!
//! An event that grows a value its handlers did not always get (a
//! registration change's `sequence`, a media event's per-call `scope`) cannot
//! simply pass it: every handler written before it existed would then raise a
//! `TypeError` on the unexpected keyword. So the keyword goes only to a handler
//! whose signature binds it, by name or through `**kwargs`, and every other
//! handler is called exactly as it always was.

use pyo3::call::PyCallArgs;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Whether `handler`, called with `positional` arguments, also accepts a `name`
/// keyword (named, or through `**kwargs`). `false` when its signature cannot be
/// read (a builtin).
fn signature_accepts<'py>(
    python: Python<'py>,
    handler: &Bound<'py, PyAny>,
    positional: usize,
    name: &str,
) -> bool {
    let keywords = PyDict::new(python);
    if keywords.set_item(name, python.None()).is_err() {
        return false;
    }
    let Ok(signature) = python
        .import("inspect")
        .and_then(|inspect| inspect.call_method1("signature", (handler,)))
    else {
        return false;
    };
    let Ok(placeholders) = pyo3::types::PyTuple::new(python, vec![python.None(); positional])
    else {
        return false;
    };
    signature
        .call_method("bind", placeholders, Some(&keywords))
        .is_ok()
}

/// What [`accepts_keyword`] decided for one handler: the handler itself, held so
/// its address stays unique for as long as the entry exists, and the verdict per
/// (positional count, keyword name).
type KeywordVerdicts = (Py<PyAny>, Vec<(usize, Box<str>, bool)>);

static KEYWORD_VERDICTS: std::sync::OnceLock<dashmap::DashMap<usize, KeywordVerdicts>> =
    std::sync::OnceLock::new();

/// Handlers remembered at most. A script has a handful; the bound only stops a
/// stream of transient callables from growing the table.
const KEYWORD_VERDICTS_LIMIT: usize = 4096;

fn keyword_verdicts() -> &'static dashmap::DashMap<usize, KeywordVerdicts> {
    KEYWORD_VERDICTS.get_or_init(dashmap::DashMap::new)
}

/// Drop the remembered verdicts. Called on script reload, where the handlers
/// they describe are replaced.
pub(crate) fn clear_keyword_verdicts() {
    if let Some(table) = KEYWORD_VERDICTS.get() {
        table.clear();
    }
}

/// [`signature_accepts`], decided once per handler. Reading a signature
/// (`inspect.signature` and a `bind`) is far dearer than a lookup, and this runs
/// for every message an event handler is called for, on the synchronous path.
pub fn accepts_keyword<'py>(
    python: Python<'py>,
    handler: &Bound<'py, PyAny>,
    positional: usize,
    name: &str,
) -> bool {
    let key = handler.as_ptr() as usize;
    if let Some(entry) = keyword_verdicts().get(&key) {
        if let Some((_, _, verdict)) = entry
            .1
            .iter()
            .find(|(count, known, _)| *count == positional && &**known == name)
        {
            return *verdict;
        }
    }
    let verdict = signature_accepts(python, handler, positional, name);
    let table = keyword_verdicts();
    if table.len() < KEYWORD_VERDICTS_LIMIT || table.contains_key(&key) {
        table
            .entry(key)
            .or_insert_with(|| (handler.clone().unbind(), Vec::new()))
            .1
            .push((positional, name.into(), verdict));
    }
    verdict
}

/// `{name: value}` when `handler`, called with `positional` arguments, also
/// accepts a `name` keyword (named, or through `**kwargs`); `None` when it does
/// not, or when its signature cannot be read (a builtin).
pub fn accepted_keyword<'py, V>(
    python: Python<'py>,
    handler: &Bound<'py, PyAny>,
    positional: usize,
    name: &str,
    value: V,
) -> Option<Bound<'py, PyDict>>
where
    V: IntoPyObject<'py>,
{
    if !accepts_keyword(python, handler, positional, name) {
        return None;
    }
    let keywords = PyDict::new(python);
    keywords.set_item(name, value).ok()?;
    Some(keywords)
}

/// Call `handler` with `arguments` (`positional` of them), adding `name=value`
/// when there is a value and the handler accepts it ([`accepted_keyword`]).
/// Without a value, or for a handler that does not take the keyword, the call
/// is the plain positional one it always was.
pub fn call_with_optional_keyword<'py, A, V>(
    python: Python<'py>,
    handler: &Bound<'py, PyAny>,
    arguments: A,
    positional: usize,
    name: &str,
    value: Option<V>,
) -> PyResult<Bound<'py, PyAny>>
where
    A: PyCallArgs<'py>,
    V: IntoPyObject<'py>,
{
    match value.and_then(|value| accepted_keyword(python, handler, positional, name, value)) {
        Some(keywords) => handler.call(arguments, Some(&keywords)),
        None => handler.call1(arguments),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn handler<'py>(python: Python<'py>, source: &str) -> Bound<'py, PyAny> {
        let globals = PyDict::new(python);
        let code = CString::new(source).expect("no NUL");
        python
            .run(code.as_c_str(), Some(&globals), None)
            .expect("the handler compiles");
        globals
            .get_item("handler")
            .expect("a lookup")
            .expect("a handler")
    }

    #[test]
    fn a_handler_that_names_the_keyword_gets_it() {
        Python::initialize();
        Python::attach(|python| {
            let named = handler(python, "def handler(a, b, scope=None):\n    return scope\n");
            let result =
                call_with_optional_keyword(python, &named, ("x", "y"), 2, "scope", Some("orig"))
                    .expect("called");
            assert_eq!(result.extract::<String>().expect("a str"), "orig");

            let through_kwargs = handler(
                python,
                "def handler(a, b, **extra):\n    return extra.get('scope')\n",
            );
            let result = call_with_optional_keyword(
                python,
                &through_kwargs,
                ("x", "y"),
                2,
                "scope",
                Some("term"),
            )
            .expect("called");
            assert_eq!(result.extract::<String>().expect("a str"), "term");
        });
    }

    #[test]
    fn a_handler_without_the_keyword_is_called_as_it_always_was() {
        Python::initialize();
        Python::attach(|python| {
            let plain = handler(python, "def handler(a, b):\n    return a + b\n");
            let result =
                call_with_optional_keyword(python, &plain, ("x", "y"), 2, "scope", Some("orig"))
                    .expect("called without the keyword");
            assert_eq!(result.extract::<String>().expect("a str"), "xy");

            // No value: not even a handler that takes the keyword is given it.
            let named = handler(
                python,
                "def handler(a, b, scope='unset'):\n    return scope\n",
            );
            let result =
                call_with_optional_keyword::<_, &str>(python, &named, ("x", "y"), 2, "scope", None)
                    .expect("called");
            assert_eq!(result.extract::<String>().expect("a str"), "unset");
            assert!(accepted_keyword(python, &plain, 2, "scope", "orig").is_none());
        });
    }

    /// The signature is read once per handler, not once per call.
    #[test]
    fn the_signature_is_read_once_per_handler() {
        Python::initialize();
        Python::attach(|python| {
            let counted = handler(
                python,
                concat!(
                    "import inspect\n",
                    "reads = []\n",
                    "class Counted:\n",
                    "    @property\n",
                    "    def __signature__(self):\n",
                    "        reads.append(1)\n",
                    "        return inspect.Signature([\n",
                    "            inspect.Parameter('a', inspect.Parameter.POSITIONAL_OR_KEYWORD),\n",
                    "            inspect.Parameter('b', inspect.Parameter.POSITIONAL_OR_KEYWORD),\n",
                    "            inspect.Parameter('leg', inspect.Parameter.KEYWORD_ONLY, default=None),\n",
                    "        ])\n",
                    "    def __call__(self, a, b, leg=None):\n",
                    "        return leg\n",
                    "handler = Counted()\n",
                ),
            );
            for _ in 0..5 {
                assert!(accepted_keyword(python, &counted, 2, "leg", "caller").is_some());
            }
            // A second keyword name is its own question, asked once too.
            assert!(!accepts_keyword(python, &counted, 2, "other"));
            assert!(!accepts_keyword(python, &counted, 2, "other"));
            let globals = counted
                .getattr("__call__")
                .and_then(|call| call.getattr("__globals__"))
                .expect("the module globals");
            let count = globals
                .get_item("reads")
                .and_then(|list| list.len())
                .expect("the read counter");
            assert_eq!(count, 2, "one read for `leg`, one for `other`");
        });
    }
}
