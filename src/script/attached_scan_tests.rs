//! Source gates for code that runs attached to the interpreter, by context.
//!
//! `script::blocking`'s scans flag a wait by its spelling wherever it is. These
//! flag what is wrong because of *where* it is, which a lint cannot see:
//!
//! - an attach inside an awaitable's future body (it runs on a tokio worker);
//! - a blocking wait inside code that runs attached: a `#[pymethods]` /
//!   `#[pyfunction]` body or a `Python::attach` closure, outside any
//!   `detach(...)` inside it.
//!
//! Text-based over a copy of each file with comments and string literals
//! blanked, so a brace or a keyword in either cannot throw the matching off.
//! What this cannot see: a wait reached through a call (a pymethod calling a
//! Rust function that blocks), and a lock guard held across an attach. Those
//! are what the `stop_the_world_tests` regression tests and the clippy
//! `disallowed-methods` list are for.

use std::path::{Path, PathBuf};

/// Blank comments, string and char literals, keeping every newline and every
/// byte offset, so brackets and words left are code.
fn mask(source: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for byte in out.iter_mut().take(to).skip(from) {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    while index < bytes.len() {
        let rest = &bytes[index..];
        if rest.starts_with(b"//") {
            let end = rest
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            blank(&mut out, index, end);
            index = end;
        } else if rest.starts_with(b"/*") {
            let end = find(bytes, index + 2, b"*/").map_or(bytes.len(), |end| end + 2);
            blank(&mut out, index, end);
            index = end;
        } else if rest.starts_with(b"r#") || rest.starts_with(b"r\"") {
            let preceded_by_word =
                index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
            let hashes = rest[1..].iter().take_while(|&&byte| byte == b'#').count();
            if preceded_by_word || rest.get(1 + hashes) != Some(&b'"') {
                index += 1;
                continue;
            }
            let mut close = vec![b'"'];
            close.extend(std::iter::repeat_n(b'#', hashes));
            let body = index + 2 + hashes;
            let end = find(bytes, body, &close).map_or(bytes.len(), |end| end + close.len());
            blank(&mut out, body, end.saturating_sub(close.len()));
            index = end;
        } else if rest[0] == b'"' {
            let mut end = index + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, index + 1, end.min(bytes.len()));
            index = end + 1;
        } else if rest[0] == b'\'' {
            // A char literal ('x', '\n', '\''), not a lifetime.
            let literal = match rest.get(1) {
                Some(b'\\') => rest.iter().skip(2).position(|&b| b == b'\'').map(|p| p + 3),
                Some(_) if rest.get(2) == Some(&b'\'') => Some(3),
                _ => None,
            };
            match literal {
                Some(length) => {
                    blank(&mut out, index + 1, index + length - 1);
                    index += length;
                }
                None => index += 1,
            }
        } else {
            index += 1;
        }
    }
    out
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// The index of the bracket closing the one at `open`.
fn closing(masked: &[u8], open: usize) -> usize {
    let (opener, closer) = match masked[open] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        _ => (b'{', b'}'),
    };
    let mut depth = 0usize;
    for (offset, &byte) in masked[open..].iter().enumerate() {
        if byte == opener {
            depth += 1;
        } else if byte == closer {
            depth -= 1;
            if depth == 0 {
                return open + offset;
            }
        }
    }
    masked.len()
}

/// Every `(start, end)` span of the code after each occurrence of `marker`,
/// from the first `open` bracket after it to its closing one.
fn spans_after(masked: &[u8], marker: &[u8], open: u8) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(at) = find(masked, from, marker) {
        from = at + marker.len();
        // A marker that ends in the bracket opens the span itself.
        let start = if marker.last() == Some(&open) {
            Some(from - 1)
        } else {
            masked[from..]
                .iter()
                .position(|&byte| byte == open)
                .map(|offset| from + offset)
        };
        if let Some(start) = start {
            spans.push((start, closing(masked, start)));
        }
    }
    spans
}

fn line_of(source: &[u8], offset: usize) -> usize {
    source[..offset]
        .iter()
        .filter(|&&byte| byte == b'\n')
        .count()
        + 1
}

/// Production Rust under `src/`: test files and inline test modules dropped.
fn production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut directories: Vec<PathBuf> = vec![root.join("src")];
    let mut sources = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("source directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("under the manifest directory")
                .to_string_lossy()
                .replace('\\', "/");
            let is_test_file = relative.ends_with("tests.rs")
                || relative.ends_with("_harness.rs")
                || relative.ends_with("test_support.rs")
                || relative.ends_with("test_dispatcher.rs");
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") || is_test_file {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("source file is readable");
            let production = source
                .split("#[cfg(test)]\nmod ")
                .next()
                .unwrap_or("")
                .to_string();
            sources.push((relative, production));
        }
    }
    sources.sort();
    sources
}

const FUTURE_MARKERS: [&[u8]; 4] = [
    b"awaitable(",
    b"future_into_py(",
    b"future_into_py_with_locals(",
    b"tokio::spawn(",
];

/// An attach in a future runs on whichever tokio worker polls it. Build the
/// Python value in the completion step instead (`script::Deferred`), or hand
/// the work to the executor.
#[test]
fn no_future_attaches_to_the_interpreter() {
    let mut offenders = Vec::new();
    for (path, source) in production_sources() {
        let masked = mask(&source);
        for marker in FUTURE_MARKERS {
            for (start, end) in spans_after(&masked, marker, b'{') {
                // `async move { .. }` directly after the marker: the future.
                let head = String::from_utf8_lossy(&masked[start.saturating_sub(16)..start]);
                if !head.contains("async") {
                    continue;
                }
                let body = &masked[start..end];
                let mut from = 0;
                while let Some(at) = find(body, from, b"Python::attach(") {
                    // A job handed to the executor attaches on the executor.
                    let before = &body[..at];
                    let in_job = [
                        &b"try_run("[..],
                        b"run_queued(",
                        b"run_classified(",
                        b"spawn(move ||",
                    ]
                    .iter()
                    .any(|job| find(before, 0, job).is_some());
                    if !in_job {
                        offenders
                            .push(format!("{path}:{}", line_of(source.as_bytes(), start + at)));
                    }
                    from = at + 1;
                }
            }
        }
    }
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "these futures attach to the interpreter on a tokio worker; build the \
         value in the completion step (script::Deferred) or run the Python part \
         on the executor: {offenders:?}"
    );
}

/// Waits that park a thread outright. On an attached thread each one holds a
/// garbage collection's stop-the-world open for as long as it waits.
const BLOCKING: [&str; 12] = [
    "blocking_recv(",
    "blocking_send(",
    "blocking_lock(",
    "blocking_read(",
    "blocking_write(",
    "thread::sleep(",
    "recv_timeout(",
    "Condvar",
    "to_socket_addrs(",
    "TcpStream::connect",
    ".block_on(",
    "block_in_place(",
];

/// Attached code that waits must release the interpreter first.
#[test]
fn nothing_attached_waits_without_releasing_the_interpreter() {
    let mut offenders = Vec::new();
    for (path, source) in production_sources() {
        let masked = mask(&source);
        let mut attached = spans_after(&masked, b"Python::attach(", b'(');
        attached.extend(spans_after(&masked, b"#[pymethods]", b'{'));
        attached.extend(spans_after(&masked, b"#[pyfunction]", b'{'));
        // Released inside the attached code: `detach(..)`, the helpers.
        let mut released = spans_after(&masked, b".detach(", b'(');
        released.extend(spans_after(&masked, b"released(", b'('));
        released.extend(spans_after(&masked, b"detach_block_on(", b'('));
        let text = String::from_utf8_lossy(&masked);
        for needle in BLOCKING {
            for (at, _) in text.match_indices(needle) {
                let inside = |spans: &[(usize, usize)]| {
                    spans.iter().any(|&(start, end)| start < at && at < end)
                };
                if inside(&attached) && !inside(&released) {
                    offenders.push(format!(
                        "{path}:{} {needle}",
                        line_of(source.as_bytes(), at)
                    ));
                }
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "these waits run attached to the interpreter: release it around the \
         wait (python.detach / script::blocking::released): {offenders:?}"
    );
}

#[test]
fn the_mask_blanks_strings_and_comments_but_keeps_offsets() {
    let source = "let a = \"{ Python::attach(\"; // }\nlet b = '{'; /* ( */ x(1)";
    let masked = String::from_utf8(mask(source)).expect("ascii");
    assert_eq!(masked.len(), source.len());
    assert!(!masked.contains("Python::attach"));
    assert_eq!(masked.matches('{').count(), 0);
    assert!(masked.contains("x(1)"));
    assert_eq!(masked.lines().count(), source.lines().count());
}

#[test]
fn a_detach_inside_an_attach_releases_what_it_wraps() {
    let source = "fn f() { Python::attach(|py| { py.detach(|| x.block_on(y)); z.block_on(w) }) }";
    let masked = mask(source);
    let attached = spans_after(&masked, b"Python::attach(", b'(');
    let released = spans_after(&masked, b".detach(", b'(');
    let inner = source.find("x.block_on").expect("inner wait");
    let outer = source.find("z.block_on").expect("outer wait");
    let inside = |spans: &[(usize, usize)], at: usize| {
        spans.iter().any(|&(start, end)| start < at && at < end)
    };
    assert!(inside(&attached, inner) && inside(&released, inner));
    assert!(inside(&attached, outer) && !inside(&released, outer));
}

/// Calls that run Python, or may. A thread that makes one while holding a
/// Rust lock can park for a garbage collection's stop-the-world with the lock
/// held; every attached thread then waiting on that lock never reaches a safe
/// point, and the collection never ends. Taking and releasing references
/// (`clone_ref`, moving a `Py`) is not in the list: it runs no Python.
const PYTHON_WORK: [&str; 17] = [
    ".call0(",
    ".call1(",
    ".call(",
    "call_method",
    ".getattr(",
    ".setattr(",
    ".import(",
    ".extract",
    ".str()",
    "Py::new(",
    "PyErr::from_value(",
    "into_value(",
    "into_pyobject(",
    "cancelled_error(",
    "invalid_state(",
    "helpers(",
    "demote(",
];

/// The lines of `source` that do Python work inside the scope of a guard
/// taken with `locked(..)`: to the end of the enclosing block for a guard
/// bound with `let`, to the end of the statement for a temporary.
fn python_work_under_a_lock(source: &str) -> Vec<(usize, &'static str)> {
    let masked = mask(source);
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = find(&masked, from, b"locked(") {
        from = at + 1;
        let word_before =
            at > 0 && (masked[at - 1].is_ascii_alphanumeric() || masked[at - 1] == b'_');
        if word_before {
            continue;
        }
        let call_end = closing(&masked, at + b"locked".len());
        let after = masked[call_end + 1..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .map(|offset| call_end + 1 + offset);
        let statement_start = masked[..at]
            .iter()
            .rposition(|&byte| matches!(byte, b';' | b'{' | b'}'))
            .map_or(0, |index| index + 1);
        let bound = after.is_some_and(|index| masked[index] == b';')
            && String::from_utf8_lossy(&masked[statement_start..at]).contains("let ");
        let scope_end = if bound {
            // The block the binding lives in.
            let mut depth = 0usize;
            let mut open = None;
            for index in (0..at).rev() {
                match masked[index] {
                    b'}' => depth += 1,
                    b'{' if depth == 0 => {
                        open = Some(index);
                        break;
                    }
                    b'{' => depth -= 1,
                    _ => {}
                }
            }
            open.map_or(masked.len(), |open| closing(&masked, open))
        } else {
            // The statement: a temporary lives to its end, a block that
            // follows on the way (`if let .. = locked(..) { .. }`) included.
            let mut index = call_end + 1;
            loop {
                match masked.get(index) {
                    None | Some(b';' | b')' | b']' | b'}' | b',') => break index,
                    Some(b'{') => break closing(&masked, index),
                    Some(b'(' | b'[') => index = closing(&masked, index) + 1,
                    Some(_) => index += 1,
                }
            }
        };
        let scope = String::from_utf8_lossy(&masked[call_end..scope_end.min(masked.len())]);
        for needle in PYTHON_WORK {
            for (offset, _) in scope.match_indices(needle) {
                found.push((line_of(source.as_bytes(), call_end + offset), needle));
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// Direct dispatch keeps its state behind plain mutexes that attached threads
/// take. None of them is held across Python.
#[test]
fn direct_dispatch_runs_no_python_under_its_locks() {
    let mut offenders = Vec::new();
    for (path, source) in production_sources() {
        if !path.starts_with("src/script/direct/") {
            continue;
        }
        for (line, needle) in python_work_under_a_lock(&source) {
            offenders.push(format!("{path}:{line} {needle}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "Python work while a direct-dispatch lock is held; copy what is needed \
         out, release the lock, then make the Python object: {offenders:?}"
    );
}

/// The scan sees the shape it is there for (an exception built while a bound
/// guard is alive, and under a temporary guard), and passes the fix.
#[test]
fn the_lock_scan_tells_python_work_under_a_guard_from_work_after_it() {
    let held = "fn read(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {\n\
                    let inner = locked(&self.inner);\n\
                    match &inner.state {\n\
                        State::Done(value) => Ok(value.clone_ref(python)),\n\
                        State::Cancelled => Err(cancelled_error(python)),\n\
                    }\n\
                }\n";
    assert_eq!(
        python_work_under_a_lock(held),
        vec![(5, "cancelled_error(")]
    );
    let temporary = "fn name(&self, python: Python<'_>) -> PyResult<()> {\n\
                         if let Some(name) = locked(&self.name).as_ref() {\n\
                             name.bind(python).call0()?;\n\
                         }\n\
                         Ok(())\n\
                     }\n";
    assert_eq!(python_work_under_a_lock(temporary), vec![(3, ".call0(")]);
    let released = "fn read(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {\n\
                        let read = {\n\
                            let inner = locked(&self.inner);\n\
                            inner.cancelled\n\
                        };\n\
                        let taken = locked(&self.slot).take();\n\
                        if read { return Err(cancelled_error(python)); }\n\
                        taken.ok_or_else(|| invalid_state(python))\n\
                    }\n";
    assert!(python_work_under_a_lock(released).is_empty());
}
