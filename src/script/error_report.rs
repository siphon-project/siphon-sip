//! Render a Python exception for the log: where it was raised, and the
//! traceback that led there.
//!
//! `PyErr`'s own `Display` is `TypeError: message` and nothing else, which
//! names neither the script nor the line. Every handler-failure log line goes
//! through [`describe`] instead.

use pyo3::prelude::*;
use pyo3::types::PyTraceback;

/// `file:line in function` for the frame that raised — the innermost entry of
/// the traceback, which is the last Python line that ran. An exception raised
/// by a `siphon` API call has no Python frame of its own, so this lands on the
/// script line that made the call.
fn raise_site(traceback: &Bound<'_, PyTraceback>) -> PyResult<String> {
    let mut innermost = traceback.clone().into_any();
    loop {
        let next = innermost.getattr("tb_next")?;
        if next.is_none() {
            break;
        }
        innermost = next;
    }
    let line: u32 = innermost.getattr("tb_lineno")?.extract()?;
    let code = innermost.getattr("tb_frame")?.getattr("f_code")?;
    let file: String = code.getattr("co_filename")?.extract()?;
    let function: String = code.getattr("co_qualname")?.extract()?;
    Ok(format!("{file}:{line} in {function}"))
}

/// The standard `Traceback (most recent call last):` block, chained
/// exceptions (`raise … from …`) included.
fn formatted_traceback(python: Python<'_>, error: &PyErr) -> PyResult<String> {
    let lines: Vec<String> = python
        .import("traceback")?
        .call_method1("format_exception", (error.value(python),))?
        .extract()?;
    Ok(lines.concat())
}

/// One log-ready description of a Python exception.
///
/// The first line is the exception with the raise site appended, so a
/// line-oriented log search still finds script and line number; the traceback
/// follows on the lines after it. An exception that carries no traceback (one
/// built in Rust that never passed through a Python frame) is rendered as its
/// `Display` alone, and so is anything the `traceback` module fails to format —
/// reporting an error must never fail.
pub fn describe(python: Python<'_>, error: &PyErr) -> String {
    let Some(traceback) = error.traceback(python) else {
        return error.to_string();
    };
    let summary = match raise_site(&traceback) {
        Ok(site) => format!("{error} (at {site})"),
        Err(_) => error.to_string(),
    };
    match formatted_traceback(python, error) {
        Ok(trace) => format!("{summary}\n{}", trace.trim_end()),
        Err(_) => summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::inline_dispatch::run_coroutine;
    use pyo3::exceptions::PyValueError;
    use pyo3::types::PyModule;
    use std::ffi::CString;

    const SOURCE: &str = "\
import asyncio


def helper(value):
    return bytes(value)


def sync_handler():
    helper('not a number')


async def inline_handler():
    helper('not a number')


async def suspending_handler():
    await asyncio.sleep(0)
    helper('not a number')


def chained_handler():
    try:
        helper('not a number')
    except TypeError as error:
        raise RuntimeError('routing failed') from error
";

    fn probe(python: Python<'_>) -> Bound<'_, PyModule> {
        PyModule::from_code(
            python,
            &CString::new(SOURCE).unwrap(),
            &CString::new("/etc/siphon/error_report_probe.py").unwrap(),
            &CString::new("error_report_probe").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn sync_handler_error_names_script_line_and_function() {
        Python::initialize();
        Python::attach(|python| {
            let error = probe(python)
                .getattr("sync_handler")
                .unwrap()
                .call0()
                .unwrap_err();
            let described = describe(python, &error);
            let first_line = described.lines().next().unwrap();
            assert!(first_line.starts_with("TypeError: "), "{first_line}");
            assert!(
                first_line.ends_with("(at /etc/siphon/error_report_probe.py:5 in helper)"),
                "{first_line}"
            );
            assert!(
                described.contains("Traceback (most recent call last):"),
                "{described}"
            );
            // The frame that called into the failing one is what tells the
            // author which handler it was.
            assert!(
                described.contains(
                    "File \"/etc/siphon/error_report_probe.py\", line 9, in sync_handler"
                ),
                "{described}"
            );
        });
    }

    #[test]
    fn inline_async_handler_error_keeps_the_traceback() {
        Python::initialize();
        Python::attach(|python| {
            let coroutine = probe(python)
                .getattr("inline_handler")
                .unwrap()
                .call0()
                .unwrap();
            let error = run_coroutine(python, &coroutine).unwrap_err();
            let described = describe(python, &error);
            assert!(
                described.contains("(at /etc/siphon/error_report_probe.py:5 in helper)"),
                "{described}"
            );
            assert!(
                described.contains("line 13, in inline_handler"),
                "{described}"
            );
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suspending_async_handler_error_keeps_the_traceback() {
        Python::initialize();
        Python::attach(|python| {
            let coroutine = probe(python)
                .getattr("suspending_handler")
                .unwrap()
                .call0()
                .unwrap();
            let error = run_coroutine(python, &coroutine).unwrap_err();
            let described = describe(python, &error);
            assert!(
                described.contains("(at /etc/siphon/error_report_probe.py:5 in helper)"),
                "{described}"
            );
            assert!(
                described.contains("line 18, in suspending_handler"),
                "{described}"
            );
        });
    }

    #[test]
    fn chained_exception_shows_its_cause() {
        Python::initialize();
        Python::attach(|python| {
            let error = probe(python)
                .getattr("chained_handler")
                .unwrap()
                .call0()
                .unwrap_err();
            let described = describe(python, &error);
            let first_line = described.lines().next().unwrap();
            assert_eq!(
                first_line,
                "RuntimeError: routing failed \
                 (at /etc/siphon/error_report_probe.py:25 in chained_handler)"
            );
            assert!(
                described.contains("The above exception was the direct cause"),
                "{described}"
            );
            assert!(described.contains("line 5, in helper"), "{described}");
        });
    }

    #[test]
    fn error_without_traceback_is_its_display() {
        Python::initialize();
        Python::attach(|python| {
            let error = PyValueError::new_err("built in rust");
            assert_eq!(describe(python, &error), "ValueError: built in rust");
        });
    }
}
