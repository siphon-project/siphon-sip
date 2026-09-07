//! Running blocking Rust-API futures from synchronous script handlers without
//! stalling the free-threaded interpreter.

use std::future::Future;

/// Drive `future` to completion, blocking the current handler thread, with the
/// Python interpreter **released** for the duration.
///
/// # Why this is mandatory (free-threaded CPython 3.14t)
///
/// Script handlers run *attached* to the interpreter. The cyclic GC performs a
/// stop-the-world that pauses every attached thread at a safe point. A handler
/// that parks in a blocking Rust-API call (Diameter to the HSS/PCRF, an HTTP
/// HA1 fetch, …) **while still attached** can never reach that safe point, so
/// the next thread to allocate cyclic garbage — which Python does constantly —
/// blocks behind the GC, stalling every other handler. Depending on which
/// thread can release the block, the stall is either transient (intermittent
/// failures, e.g. a second REGISTER that "doesn't come in") or, when the only
/// thread that could complete the blocked call is itself caught in the
/// stop-the-world, a permanent engine-wide deadlock.
///
/// Releasing the interpreter with [`pyo3::Python::detach`] for the blocking
/// window puts this thread at a GC safe point; [`tokio::task::block_in_place`]
/// keeps the tokio worker pool from starving while we block.
///
/// # Requirements
///
/// Call only from a thread that holds a Python thread state — every siphon
/// worker does (persistent attach on the executor / tokio threads), and
/// `Python::attach` re-attaches cheaply when one is already held. `future` and
/// its output must not hold Python references (`Ungil`); blocking Rust-API
/// futures never do.
pub(crate) fn detach_block_on<F>(future: F) -> F::Output
where
    F: Future + pyo3::marker::Ungil + Send,
    F::Output: pyo3::marker::Ungil + Send,
{
    pyo3::Python::attach(|python| {
        python.detach(move || {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
        })
    })
}

#[cfg(test)]
mod tests {
    /// Every blocking Rust-API call reachable from a script handler must go
    /// through [`detach_block_on`], never a bare `block_in_place` +
    /// `block_on`. The two compile identically and behave identically on an
    /// idle box, which is exactly why the rule cannot be enforced by review:
    /// the bare form only diverges once the cyclic GC happens to stop the
    /// world while a handler is parked in it, and then it is an engine-wide
    /// deadlock rather than a slow call.
    ///
    /// This drifted once already — three of the twenty-one Diameter methods
    /// were written with the bare form while every sibling in the same file
    /// used the wrapper — so guard it at the source level over the whole
    /// namespace directory, including files that do not exist yet. Anything
    /// in `script::api` that genuinely has to stay attached (driving the
    /// interpreter rather than blocking on Rust) does not belong in a
    /// handler-reachable method in the first place.
    #[test]
    fn no_script_api_method_blocks_while_attached_to_the_interpreter() {
        let api_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/script/api");
        let entries = std::fs::read_dir(&api_dir).expect("script api directory is readable");

        let mut offenders = Vec::new();
        for entry in entries {
            let path = entry.expect("directory entry is readable").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("source file is readable");
            if source.contains("block_in_place") {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<unknown>")
                    .to_string();
                offenders.push(name);
            }
        }

        assert!(
            offenders.is_empty(),
            "these script::api files call block_in_place directly instead of \
             going through detach_block_on, so a handler parked in one of them \
             can never reach a GC safe point and the next thread to allocate \
             cyclic garbage deadlocks behind the stop-the-world: {offenders:?}"
        );
    }
}
