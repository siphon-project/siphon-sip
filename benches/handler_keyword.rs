//! Criterion perf gate for the optional keyword a handler is called with.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench handler_keyword`.
//!
//! `@b2bua.on_info` (`leg=`) and the media event handlers (`scope=`) are called
//! on the synchronous per-message path, and whether a handler declares the
//! keyword is decided once per handler, not once per call. The ids are a call
//! of a handler that declares it, one that does not, and one taking `**kwargs`,
//! each through [`call_with_optional_keyword`]; reading the signature again on
//! every call would show here as an order of magnitude.
#![allow(clippy::disallowed_methods)] // test, bench and example code may block

use criterion::{criterion_group, criterion_main, Criterion};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use siphon::script::handler_keyword::call_with_optional_keyword;
use std::ffi::CString;
use std::hint::black_box;

const HANDLERS: &str = "\
def declares(call, request, leg=None):\n    return leg\n\
def plain(call, request):\n    return None\n\
def keywords(call, request, **extra):\n    return extra\n";

fn bench_handler_keyword(criterion: &mut Criterion) {
    Python::initialize();
    Python::attach(|python| {
        let globals = PyDict::new(python);
        let source = CString::new(HANDLERS).expect("no NUL");
        python
            .run(source.as_c_str(), Some(&globals), None)
            .expect("the handlers compile");
        let handler = |name: &str| {
            globals
                .get_item(name)
                .expect("a lookup")
                .expect("a handler")
        };
        let declares = handler("declares");
        let plain = handler("plain");
        let keywords = handler("keywords");

        let mut group = criterion.benchmark_group("handler_keyword");
        for (id, callable) in [
            ("declares_the_keyword", &declares),
            ("does_not_declare_it", &plain),
            ("takes_kwargs", &keywords),
        ] {
            group.bench_function(id, |bencher| {
                bencher.iter(|| {
                    black_box(
                        call_with_optional_keyword(
                            python,
                            callable,
                            (black_box(1_u8), black_box(2_u8)),
                            2,
                            "leg",
                            Some("caller"),
                        )
                        .expect("called"),
                    )
                });
            });
        }
        group.finish();
    });
}

criterion_group!(benches, bench_handler_keyword);
criterion_main!(benches);
