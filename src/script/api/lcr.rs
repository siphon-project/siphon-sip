//! PyO3 wrapper for the `lcr` namespace — B2BUA-only Least-Cost Routing.
//!
//! Scripts call `await lcr.route(call)` from `@b2bua.on_invite` to ask the
//! external LCR API for an ordered carrier decision, then hand the routes to
//! `call.route(...)` for sequential failover. See
//! `docs/cookbook/least-cost-routing.md`.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::lcr::{LcrClient, LcrOutcome, LcrReject, LcrResponse, Route};

use super::call::PyCall;

/// One carrier attempt in an LCR decision (read-only view of [`Route`]).
#[pyclass(name = "Route", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyRoute {
    inner: Route,
}

impl PyRoute {
    /// Wrap a contract [`Route`].
    pub fn from_route(route: Route) -> Self {
        Self { inner: route }
    }

    /// The underlying contract route (consumed by `call.route(...)`).
    pub fn inner(&self) -> &Route {
        &self.inner
    }
}

#[pymethods]
impl PyRoute {
    /// Opaque carrier identifier — carry into CDR / charging, never route on it.
    #[getter]
    fn carrier_id(&self) -> &str {
        &self.inner.carrier_id
    }

    /// Configured `gateway:` group siphon resolves to a healthy member at dial
    /// time (skips the carrier if the group is entirely down).
    #[getter]
    fn gateway_group(&self) -> Option<&str> {
        self.inner.gateway_group.as_deref()
    }

    /// Explicit next-hop URI, if the decision pinned one.
    #[getter]
    fn next_hop(&self) -> Option<&str> {
        self.inner.next_hop.as_deref()
    }

    /// R-URI override for this carrier (e.g. a tech-prefixed number).
    #[getter]
    fn ruri(&self) -> Option<&str> {
        self.inner.ruri.as_deref()
    }

    /// Tech-prefix / dial-prefix prepended to the B-leg R-URI userpart.
    #[getter]
    fn tech_prefix(&self) -> Option<&str> {
        self.inner.tech_prefix.as_deref()
    }

    /// Extra headers injected on this carrier's B-leg INVITE.
    #[getter]
    fn headers(&self) -> HashMap<String, String> {
        self.inner.headers.clone()
    }

    /// Per-carrier reroute causes (SIP codes that fail over to the next carrier).
    #[getter]
    fn reroute_causes(&self) -> Vec<u16> {
        self.inner.reroute_causes.clone()
    }

    /// Per-minute rate (for CDR / charging).
    #[getter]
    fn rate(&self) -> Option<f64> {
        self.inner.rate
    }

    /// Rate currency (ISO 4217).
    #[getter]
    fn currency(&self) -> Option<&str> {
        self.inner.currency.as_deref()
    }

    /// Billing increment in seconds (60 = per-minute, 1 = per-second).
    #[getter]
    fn billing_increment(&self) -> Option<u32> {
        self.inner.billing_increment
    }

    /// Minimum billable duration in seconds.
    #[getter]
    fn min_duration(&self) -> Option<u32> {
        self.inner.min_duration
    }

    /// Per-attempt ring timeout in seconds (else the call-level default).
    #[getter]
    fn timeout_secs(&self) -> Option<u32> {
        self.inner.timeout_secs
    }

    /// Whether this route names a gateway group, next-hop, or R-URI.
    fn is_routable(&self) -> bool {
        self.inner.is_routable()
    }

    fn __repr__(&self) -> String {
        format!(
            "Route(carrier_id={:?}, gateway_group={:?}, next_hop={:?}, rate={:?})",
            self.inner.carrier_id, self.inner.gateway_group, self.inner.next_hop, self.inner.rate
        )
    }
}

/// The ordered decision returned by `await lcr.route(call)`.
#[pyclass(name = "LcrDecision", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyLcrDecision {
    inner: LcrResponse,
}

impl PyLcrDecision {
    pub fn from_response(response: LcrResponse) -> Self {
        Self { inner: response }
    }
}

#[pymethods]
impl PyLcrDecision {
    /// Ordered carriers, cheapest/most-preferred first. Hand to `call.route()`.
    #[getter]
    fn routes(&self) -> Vec<PyRoute> {
        self.inner
            .routes
            .iter()
            .cloned()
            .map(PyRoute::from_route)
            .collect()
    }

    /// The API-side reject, as a dict `{"code": int, "reason": str}` or `None`.
    /// When set, answer the call with this code instead of routing.
    #[getter]
    fn reject(&self, python: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.inner.reject {
            Some(LcrReject { code, reason }) => {
                let dict = PyDict::new(python);
                dict.set_item("code", code)?;
                dict.set_item("reason", reason)?;
                Ok(Some(dict.into_any().unbind()))
            }
            None => Ok(None),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "LcrDecision(routes={}, reject={})",
            self.inner.routes.len(),
            self.inner.reject.is_some()
        )
    }
}

/// The `lcr` namespace object injected as `siphon.lcr`.
#[pyclass(name = "LcrNamespace")]
pub struct PyLcr {
    client: Arc<LcrClient>,
}

impl PyLcr {
    pub fn new(client: Arc<LcrClient>) -> Self {
        Self { client }
    }
}

#[pymethods]
impl PyLcr {
    /// Query the external LCR API for a routing decision — **B2BUA-only**.
    ///
    /// ```python
    /// @b2bua.on_invite
    /// async def route(call):
    ///     decision = await lcr.route(call, trunk_group="cust-trunks")
    ///     if decision is None:            # API unreachable, no fallback
    ///         call.reject(503, "Route Unavailable")
    ///         return
    ///     if decision.reject:
    ///         call.reject(decision.reject["code"], decision.reject["reason"])
    ///         return
    ///     call.route(decision.routes)      # sequential failover
    /// ```
    ///
    /// Returns an `LcrDecision`, or `None` when the API is unreachable and no
    /// `fallback_gateway_group` is configured (answer a 5xx). `trunk_group`
    /// tags the ingress trunk (part of the cache key); `attributes` are
    /// free-form hints forwarded to the API.
    #[pyo3(signature = (call, trunk_group=None, attributes=None))]
    fn route<'py>(
        &self,
        python: Python<'py>,
        call: PyRef<'_, PyCall>,
        trunk_group: Option<String>,
        attributes: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut attribute_map: HashMap<String, String> = HashMap::new();
        if let Some(dict) = attributes {
            for (key, value) in dict.iter() {
                attribute_map.insert(key.extract::<String>()?, value.extract::<String>()?);
            }
        }
        let request = call.lcr_request(trunk_group, attribute_map)?;
        let client = Arc::clone(&self.client);
        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            match client.route(&request).await {
                LcrOutcome::Decision(response) => Ok(Some(PyLcrDecision::from_response(response))),
                LcrOutcome::Unavailable => Ok(None),
            }
        })
    }
}
