//! Run a test's scenario in a process of its own, bounded by a deadline.
//!
//! For the scenarios that load the whole process: a garbage-collection storm,
//! or an executor backlog of thousands of handlers. In the shared test binary
//! they would slow or wedge the tests around them, and a regression that
//! wedges the process for good would hang the run. Here the test re-runs
//! itself as a child, and the parent kills it and fails once the deadline
//! passes, so a regression fails in seconds instead.

use std::io::Read as _;
use std::time::{Duration, Instant};

/// Set in the child process, to the name of the test it is to run.
const CHILD: &str = "SIPHON_TEST_OWN_PROCESS";

/// Run `scenario` in a child process re-running the test `name` (its full path,
/// as `cargo test --exact` takes it), and fail unless it passes within
/// `deadline`. In the child itself, run `scenario`.
pub(super) fn run_in_own_process(name: &str, deadline: Duration, scenario: fn()) {
    if std::env::var(CHILD).is_ok_and(|child| child == name) {
        return scenario();
    }
    let mut child = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the scenario's process starts");
    // Drained on threads of their own, so a chatty child never blocks on a
    // full pipe and looks wedged.
    let drain = |stream: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut stream) = stream {
                let _ = stream.read_to_string(&mut text);
            }
            text
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|out| Box::new(out) as Box<dyn std::io::Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|err| Box::new(err) as Box<dyn std::io::Read + Send>),
    );
    let ends_by = Instant::now() + deadline;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child can be waited on") {
            break Some(status);
        }
        if Instant::now() >= ends_by {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let output = format!(
        "{}{}",
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default()
    );
    let output: String = output
        .lines()
        .filter(|line| !line.contains("SyntaxWarning"))
        .collect::<Vec<_>>()
        .join("\n");
    match status {
        Some(status) => assert!(status.success(), "the scenario failed:\n{output}"),
        None => panic!(
            "the scenario's process was still running after {}s: wedged\n{output}",
            deadline.as_secs()
        ),
    }
}
