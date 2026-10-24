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
    let keywords = PyDict::new(python);
    keywords.set_item(name, value).ok()?;
    let signature = python
        .import("inspect")
        .and_then(|inspect| inspect.call_method1("signature", (handler,)))
        .ok()?;
    let placeholders = pyo3::types::PyTuple::new(python, vec![python.None(); positional]).ok()?;
    signature
        .call_method("bind", placeholders, Some(&keywords))
        .ok()
        .map(|_| keywords)
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
}
