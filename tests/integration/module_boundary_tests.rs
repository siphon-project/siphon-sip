//! Layering rules the 1.9.0 module split depends on, enforced by reading the
//! source.
//!
//! The split moves the B2BUA orchestration out of `dispatcher.rs` into
//! `src/dispatcher/b2bua/**` rather than into `src/b2bua/`, and the whole
//! argument for that rests on a direction: `src/b2bua/` is per-call state and
//! pure protocol logic, `dispatcher` is the I/O orchestration that drives it.
//! That direction is currently true and nothing enforces it, so the first PR
//! that adds a `use crate::dispatcher::…` to `src/b2bua/` would quietly invert
//! it and the split would lose its rationale mid-series.
//!
//! Rust cannot express "this module may not depend on that one" — a crate is
//! one dependency unit and every `mod` can see every other. So this reads the
//! files, the same way `packaging_tests` already checks what ships.

use std::path::{Path, PathBuf};

/// A directory that may not name a module, and why.
struct Boundary {
    /// Directory under `src/`, relative.
    root: &'static str,
    /// The path fragment that must not appear in it.
    forbidden: &'static str,
    /// What the rule protects, printed on failure.
    reason: &'static str,
}

const BOUNDARIES: &[Boundary] = &[
    Boundary {
        root: "b2bua",
        forbidden: "crate::dispatcher",
        reason: "src/b2bua/ is per-call state and pure protocol logic; the orchestration that \
                 drives it lives in the dispatcher. Depending on the dispatcher from here \
                 inverts that and makes CallActorStore drag in transport, script, rtpengine, \
                 diameter, cdr and li. Put the orchestration in src/dispatcher/b2bua/ instead.",
    },
    Boundary {
        root: "proxy",
        forbidden: "crate::dispatcher",
        reason: "src/proxy/ holds session state and pure helpers; the proxy handlers live in \
                 the dispatcher, same shape as b2bua.",
    },
    Boundary {
        root: "siprec",
        forbidden: "crate::dispatcher",
        reason: "src/siprec/ is the SRC role; the dispatcher's SIPREC glue belongs in \
                 src/dispatcher/siprec.rs.",
    },
    Boundary {
        root: "srs",
        forbidden: "crate::dispatcher",
        reason: "src/srs/ is the SRS role; see siprec.",
    },
    Boundary {
        root: "transport",
        forbidden: "crate::script::api",
        reason: "the transport layer must not reach into the PyO3 binding layer. The IPsec \
                 runtime lookups it needs live in crate::ipsec::runtime; script::api::ipsec \
                 only installs them.",
    },
];

/// Strip `//` and `/* */` so an intra-doc link like
/// ``[`crate::dispatcher::foo`]`` in a doc comment is not read as a dependency.
/// Deliberately crude: it can only ever blank out more than it should, which
/// makes the guard miss a violation rather than invent one, and a real `use`
/// never lives inside a comment.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_block = false;
    let mut in_line = false;
    let mut in_string = false;

    while let Some(current) = chars.next() {
        if in_line {
            if current == '\n' {
                in_line = false;
                out.push('\n');
            }
            continue;
        }
        if in_block {
            if current == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if in_string {
            if current == '\\' {
                chars.next();
            } else if current == '"' {
                in_string = false;
            }
            out.push(current);
            continue;
        }
        match (current, chars.peek()) {
            ('/', Some('/')) => in_line = true,
            ('/', Some('*')) => {
                chars.next();
                in_block = true;
            }
            ('"', _) => {
                in_string = true;
                out.push(current);
            }
            _ => out.push(current),
        }
    }
    out
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn module_boundaries_hold() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();

    for boundary in BOUNDARIES {
        let root = src.join(boundary.root);
        let files = rust_files(&root);
        assert!(
            !files.is_empty(),
            "boundary names src/{}, which has no .rs files — the rule is silently \
             covering nothing. Fix the path or drop the entry.",
            boundary.root
        );

        for file in files {
            let source = std::fs::read_to_string(&file).expect("read source");
            let code = strip_comments(&source);
            for (number, line) in code.lines().enumerate() {
                if line.contains(boundary.forbidden) {
                    let shown = file
                        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(&file)
                        .display();
                    violations.push(format!(
                        "{}:{}\n    names `{}`\n    {}",
                        shown,
                        number + 1,
                        boundary.forbidden,
                        boundary.reason
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{} module-boundary violation(s):\n\n{}\n",
        violations.len(),
        violations.join("\n\n")
    );
}
