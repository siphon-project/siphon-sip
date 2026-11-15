//! PyO3 wrapper for the `tasks` namespace: running several awaitables of one
//! handler at the same time.
//!
//! ```python
//! from siphon import diameter, tasks
//!
//! @diameter.on_request("ULR")
//! async def on_update_location(request):
//!     profile, vectors = await tasks.gather(
//!         load_profile(request),                    # a coroutine of the script
//!         diameter.send_request(vector_request()),  # a siphon awaitable
//!     )
//!     return build_answer(request, profile, vectors)
//! ```
//!
//! `asyncio.gather` gives the same results, but it makes an asyncio task for
//! every coroutine, and a handler that uses it is run as an asyncio task
//! itself from then on (`docs/handler-execution-model.md`). `tasks.gather`
//! keeps the handler and its coroutines on the path siphon steps itself for
//! as long as they await only siphon's awaitables.

use pyo3::prelude::*;
use pyo3::types::PyTuple;

/// The `tasks` namespace: `gather`.
#[pyclass(name = "TasksNamespace", frozen)]
#[derive(Default)]
pub struct PyTasksNamespace;

impl PyTasksNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyTasksNamespace {
    /// Run `awaitables` at the same time and return their results as a list,
    /// in argument order.
    ///
    /// Each argument is a coroutine, an awaitable a siphon API returned, or
    /// anything else `await` accepts. Await the result in the handler that
    /// made it.
    ///
    /// If one raises, the others are cancelled and `gather` raises that
    /// exception (`asyncio.gather` leaves the others running). With
    /// `return_exceptions=True` nothing is cancelled and an exception is that
    /// argument's result. Cancelling the handler, or its timeout, cancels
    /// every argument still running.
    ///
    /// ```python
    /// profile, location = await tasks.gather(load_profile(imsi), load_location(imsi))
    /// ```
    #[pyo3(signature = (*awaitables, return_exceptions=false))]
    fn gather<'py>(
        &self,
        python: Python<'py>,
        awaitables: &Bound<'py, PyTuple>,
        return_exceptions: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::script::runner::gather(python, awaitables, return_exceptions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outside a handler siphon steps itself the namespace is
    /// `asyncio.gather`: the results come back in argument order, and an
    /// exception is a result only when asked for.
    #[test]
    fn outside_a_direct_step_gather_is_asyncio_gather() {
        Python::initialize();
        Python::attach(|python| {
            let namespace = Py::new(python, PyTasksNamespace::new()).expect("a namespace");
            let globals = pyo3::types::PyDict::new(python);
            globals
                .set_item("tasks", namespace)
                .expect("the namespace is set");
            python
                .run(
                    c"
import asyncio

async def value(x):
    await asyncio.sleep(0)
    return x

async def boom():
    raise ValueError('boom')

async def main():
    ordered = await tasks.gather(value(1), value(2), value(3))
    empty = await tasks.gather()
    kept = await tasks.gather(value(1), boom(), return_exceptions=True)
    try:
        await tasks.gather(value(1), boom())
    except ValueError as error:
        raised = str(error)
    return ordered, empty, type(kept[1]).__name__, raised

result = asyncio.new_event_loop().run_until_complete(main())
",
                    Some(&globals),
                    None,
                )
                .expect("the script runs");
            let result: (Vec<i64>, Vec<i64>, String, String) = globals
                .get_item("result")
                .expect("read")
                .expect("set")
                .extract()
                .expect("the shape");
            assert_eq!(
                result,
                (
                    vec![1, 2, 3],
                    vec![],
                    "ValueError".to_string(),
                    "boom".to_string()
                )
            );
        });
    }
}
