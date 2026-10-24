//! The Python-side allocation gauge.

/// Refresh the Python-side allocation gauge from `sys.getallocatedblocks()`.
///
/// Python objects live in CPython's own allocator (mimalloc on free-threaded
/// builds), which jemalloc — and therefore [`super::update_memory_stats`] — cannot
/// see. This is the leak signal for the Python side: a script accumulating
/// objects, or a leaked `Py<>` reference. Cheap; called on the cleanup tick,
/// on a tokio worker, so the sample is taken on the script executor: an attach
/// on the worker parks it through a collection's stop-the-world.
pub fn update_python_stats() {
    use pyo3::prelude::*;
    let Some(metrics) = super::metrics() else {
        return;
    };
    crate::script::py_executor::spawn(move || {
        let sys = crate::script::attach::attach(|python| -> PyResult<i64> {
            python
                .import("sys")?
                .call_method0("getallocatedblocks")?
                .extract()
        });
        if let Ok(blocks) = sys {
            metrics.python_allocated_blocks.set(blocks);
        }
    });
}
