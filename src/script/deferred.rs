//! A future's result whose Python conversion waits for the completion step.
//!
//! An awaitable script API is a Rust future driven on a tokio worker. Building
//! its Python result inside the future (`Python::attach` in the body) attaches
//! that worker: during a garbage collection's stop-the-world the attach parks,
//! and once every worker has parked on one nothing polls the reactor, so the
//! futures the collection is waiting behind never finish.
//!
//! `pyo3_async_runtimes::tokio::future_into_py` already converts the future's
//! output with `IntoPyObject` in its completion step, which it runs off the
//! workers (`spawn_blocking`). [`Deferred`] moves the conversion there: the
//! future returns the closure that builds the value, not the value.

use pyo3::prelude::*;

type Build = Box<dyn for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>> + Send>;

/// A Python value to be built when the awaitable completes.
pub(crate) struct Deferred(Build);

impl Deferred {
    /// Build the value with `build`, in the completion step.
    pub(crate) fn new<F>(build: F) -> Self
    where
        F: for<'py> FnOnce(Python<'py>) -> PyResult<Bound<'py, PyAny>> + Send + 'static,
    {
        Self(Box::new(build))
    }

    /// Build a value of any convertible type with `build`, in the completion
    /// step: the body of what used to be a `Python::attach` in the future.
    pub(crate) fn build<T, F>(build: F) -> Self
    where
        F: FnOnce(Python<'_>) -> PyResult<T> + Send + 'static,
        T: for<'py> IntoPyObject<'py>,
    {
        Self::new(move |python| {
            use pyo3::IntoPyObjectExt;
            build(python)?.into_bound_py_any(python)
        })
    }

    /// `None`.
    pub(crate) fn none() -> Self {
        Self::new(|python| Ok(python.None().into_bound(python)))
    }
}

impl<'py> IntoPyObject<'py> for Deferred {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, python: Python<'py>) -> PyResult<Self::Output> {
        (self.0)(python)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_is_built_on_conversion() {
        Python::initialize();
        let deferred = Deferred::new(|python| Ok(7_i64.into_pyobject(python)?.into_any()));
        let value = Python::attach(|python| {
            deferred
                .into_pyobject(python)
                .and_then(|bound| bound.extract::<i64>())
        });
        assert_eq!(value.ok(), Some(7));
    }

    #[test]
    fn none_converts_to_none() {
        Python::initialize();
        let is_none = Python::attach(|python| {
            Deferred::none()
                .into_pyobject(python)
                .map(|bound| bound.is_none())
        });
        assert_eq!(is_none.ok(), Some(true));
    }

    #[test]
    fn a_build_error_is_the_conversion_error() {
        Python::initialize();
        let failed = Python::attach(|python| {
            Deferred::new(|_| Err(pyo3::exceptions::PyValueError::new_err("bad")))
                .into_pyobject(python)
                .is_err()
        });
        assert!(failed);
    }
}
