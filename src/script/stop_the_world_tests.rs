//! Harness for regression tests of the attached-and-blocked deadlock.
//!
//! The bug these tests guard against does not fail, it hangs: a thread that
//! blocks while attached to the interpreter wedges the next garbage
//! collection's stop-the-world (free-threaded CPython), or keeps the GIL from
//! the thread that would release it (a GIL build). Either way every thread that
//! touches Python afterwards parks for good, the test runner included.
//!
//! So a scenario runs in a child copy of the test binary, filtered down to the
//! one test, and the parent kills the child when it outlives its budget. A
//! regression then fails the parent's assertion instead of hanging CI, and the
//! wedged interpreter dies with the child.
//!
//! Both interpreter builds deadlock on the same code, through different
//! mechanisms, so the scenarios run on either; [`interpreter_build`] names the
//! one in use in the failure message.

use pyo3::prelude::*;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHILD_MARKER: &str = "SIPHON_STOP_THE_WORLD_CHILD";

/// Run the calling test's scenario in a child process.
///
/// `test_path` is the test's full path inside the crate, e.g.
/// `concat!(module_path!(), "::my_test")`. Returns `true` in the child, where
/// the caller runs the scenario and returns normally on success; returns
/// `false` in the parent after asserting the child passed within `budget`.
pub(crate) fn in_child(test_path: &str, budget: Duration) -> bool {
    if std::env::var_os(CHILD_MARKER).is_some() {
        return true;
    }
    // `module_path!()` starts with the crate name; the test filter does not.
    let filter = test_path
        .split_once("::")
        .map_or(test_path, |(_, rest)| rest);
    let executable = std::env::current_exe().expect("the test binary path");
    let mut child = Command::new(executable)
        .args([filter, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_MARKER, "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the scenario child starts");

    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("the child can be polled") {
            let mut output = String::new();
            if let Some(mut stdout) = child.stdout.take() {
                let _ = std::io::Read::read_to_string(&mut stdout, &mut output);
            }
            assert!(
                status.success(),
                "{filter} failed in its child process ({status}) on a {} \
                 interpreter:\n{output}",
                interpreter_build()
            );
            // A filter that matched nothing exits 0 too; insist it ran.
            assert!(
                output.contains(&format!("test {filter} ... ok")),
                "{filter} did not run in its child process:\n{output}"
            );
            return false;
        }
        if started.elapsed() > budget {
            // By PID: only this child, never anything matched by name.
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{filter} hung for {budget:?} on a {} interpreter: a thread blocked \
                 while attached to the interpreter, so the stop-the-world (or the \
                 GIL) never came back",
                interpreter_build()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `"free-threaded"` or `"GIL"`, for messages.
pub(crate) fn interpreter_build() -> &'static str {
    pyo3::Python::initialize();
    let gil_enabled = pyo3::Python::attach(|python| {
        python
            .import("sys")
            .and_then(|sys| sys.getattr("_is_gil_enabled"))
            .and_then(|check| check.call0())
            .and_then(|enabled| enabled.extract::<bool>())
            .unwrap_or(true)
    });
    if gil_enabled {
        "GIL"
    } else {
        "free-threaded"
    }
}

/// A thread that keeps asking for a stop-the-world: it makes cyclic garbage and
/// collects it until `stop` is set. On a free-threaded build every collection
/// waits for each attached thread to reach a safe point, which is exactly what
/// a thread blocked while attached never does.
pub(crate) fn collect_garbage_until(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let source = std::ffi::CString::new(
            "import gc\nfor _ in range(200):\n    a = []\n    a.append(a)\ngc.collect()\n",
        )
        .expect("collector source");
        while !stop.load(Ordering::Relaxed) {
            pyo3::Python::attach(|python| {
                let _ = python.run(source.as_c_str(), None, None);
            });
        }
    })
}

/// `script::blocking::released` decides whether to detach from
/// `PyGILState_Check`, which CPython turns into a constant 1 once a
/// sub-interpreter exists (the gilstate check is switched off). Then
/// `released` would "detach" a thread that is not attached. These pin the two
/// halves of why that does not happen: the check reads true values in this
/// process, and siphon itself never creates a sub-interpreter.
#[cfg(test)]
mod released_premise {
    use pyo3::prelude::*;

    fn gil_state_check() -> i32 {
        // SAFETY: reads only this thread's own thread state; defined before
        // and after interpreter initialisation.
        unsafe { pyo3::ffi::PyGILState_Check() }
    }

    #[test]
    fn the_gil_state_check_tells_attached_from_detached() {
        Python::initialize();
        let on_a_fresh_thread = std::thread::spawn(gil_state_check)
            .join()
            .expect("probe thread");
        assert_eq!(on_a_fresh_thread, 0, "a thread that never attached reads 0");

        let (attached, released) = Python::attach(|_| {
            (
                gil_state_check(),
                crate::script::blocking::released(gil_state_check),
            )
        });
        assert_eq!(attached, 1, "an attached thread reads 1");
        assert_eq!(released, 0, "released() really detaches");
    }

    #[test]
    fn siphon_never_creates_a_sub_interpreter() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut directories = vec![root];
        let mut offenders = Vec::new();
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("source directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    directories.push(path);
                    continue;
                }
                let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
                    continue;
                };
                if extension != "rs" && extension != "py" {
                    continue;
                }
                if path.ends_with("stop_the_world_tests.rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("source");
                for needle in [
                    "Py_NewInterpreter",
                    "Py_NewInterpreterFromConfig",
                    "concurrent.interpreters",
                    "_interpreters",
                ] {
                    if source.contains(needle) {
                        offenders.push(format!("{}: {needle}", path.display()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a sub-interpreter switches CPython's gilstate check off, after \
             which `script::blocking::released` cannot tell an attached thread: \
             {offenders:?}"
        );
    }
}
