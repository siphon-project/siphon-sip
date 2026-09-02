//! PyO3 wrapper for the gateway dispatcher — exposed to Python as `gateway`.
//!
//! Scripts use:
//! ```python
//! from siphon import gateway
//!
//! # Simple select (uses group's default algorithm)
//! gw = gateway.select("carriers")
//! if gw:
//!     request.relay(gw.uri)
//!
//! # Hash-based sticky sessions
//! gw = gateway.select("sbc-pool", key=request.call_id)
//!
//! # Filter by attrs
//! gw = gateway.select("carriers", attrs={"region": "us-east"})
//!
//! # List all destinations
//! for dest in gateway.list("carriers"):
//!     log.info(f"{dest.uri}: healthy={dest.healthy}")
//!
//! # Dynamic group creation
//! gateway.add_group("overflow", [
//!     {"uri": "sip:gw3.carrier.com", "weight": 2},
//!     {"uri": "sip:gw4.carrier.com"},
//! ], algorithm="weighted")
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::gateway::{
    extract_address_from_uri, resolve_address, Algorithm, Destination, DispatcherGroup,
    DispatcherManager,
};
use crate::transport::Transport;

/// Python-visible gateway namespace.
#[pyclass(name = "GatewayNamespace", skip_from_py_object)]
pub struct PyGateway {
    inner: Arc<DispatcherManager>,
}

impl PyGateway {
    pub fn new(manager: Arc<DispatcherManager>) -> Self {
        Self { inner: manager }
    }
}

#[pymethods]
impl PyGateway {
    /// Select a destination from a named group.
    ///
    /// Args:
    ///     group_name: Name of the dispatcher group (e.g. "carriers").
    ///     key: Optional hash key for sticky sessions (e.g. call_id). Used by hash algorithm.
    ///     attrs: Optional dict of attribute filters (e.g. {"region": "us-east"}).
    ///
    /// Returns a `Destination` object or `None` if no healthy destination matches.
    #[pyo3(signature = (group_name, /, key=None, attrs=None))]
    fn select(
        &self,
        group_name: &str,
        key: Option<&str>,
        attrs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Option<PyDestination>> {
        let attr_filter = match attrs {
            Some(dict) => {
                let mut map = HashMap::new();
                for (k, v) in dict.iter() {
                    map.insert(k.extract::<String>()?, v.extract::<String>()?);
                }
                Some(map)
            }
            None => None,
        };

        Ok(self
            .inner
            .select(group_name, key, attr_filter.as_ref())
            .map(|dest| PyDestination::from_destination(&dest)))
    }

    /// List all destinations in a group.
    ///
    /// Returns a list of `Destination` objects with current health status.
    fn list(&self, group_name: &str) -> Vec<PyDestination> {
        match self.inner.get_group(group_name) {
            Some(group) => group
                .list_destinations()
                .into_iter()
                .map(|dest| PyDestination::from_destination(&dest))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get status of all destinations in a group.
    ///
    /// Returns a list of (uri, is_healthy) tuples.
    fn status(&self, group_name: &str) -> Vec<(String, bool)> {
        match self.inner.get_group(group_name) {
            Some(group) => group.status(),
            None => Vec::new(),
        }
    }

    /// List all group names.
    fn groups(&self) -> Vec<String> {
        self.inner.group_names()
    }

    /// Dynamically add a new dispatcher group from Python.
    ///
    /// Args:
    ///     name: Group name.
    ///     destinations: List of dicts with keys: uri (required), address, weight, priority, transport, attrs.
    ///     algorithm: Load-balancing algorithm ("round_robin", "weighted", "hash"). Default: "weighted".
    ///     probe: Enable health probing. Default: false for dynamic groups.
    ///
    /// Example:
    ///     gateway.add_group("overflow", [
    ///         {"uri": "sip:gw3.carrier.com", "address": "10.0.0.3:5060", "weight": 2},
    ///         {"uri": "sip:gw4.carrier.com", "address": "10.0.0.4:5060"},
    ///     ], algorithm="weighted")
    #[pyo3(signature = (name, destinations, /, algorithm="weighted", probe=false))]
    fn add_group(
        &self,
        name: &str,
        destinations: Vec<Bound<'_, PyDict>>,
        algorithm: &str,
        probe: bool,
    ) -> PyResult<()> {
        let algo = Algorithm::from_str(algorithm).unwrap_or(Algorithm::Weighted);

        let mut dests = Vec::new();
        for dict in &destinations {
            let uri: String = dict
                .get_item("uri")?
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err("destination dict must have 'uri' key")
                })?
                .extract()?;

            let address_str: String = dict
                .get_item("address")?
                .map(|v| v.extract::<String>())
                .transpose()?
                .unwrap_or_else(|| extract_address_from_uri(&uri));

            let address = resolve_address(&address_str).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "cannot resolve address '{address_str}': {e}"
                ))
            })?;

            let weight: u32 = dict
                .get_item("weight")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(1);

            let priority: u32 = dict
                .get_item("priority")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(1);

            let transport_str: String = dict
                .get_item("transport")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or_else(|| "udp".to_string());

            let transport = match transport_str.as_str() {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                _ => Transport::Udp,
            };

            let attrs: HashMap<String, String> = dict
                .get_item("attrs")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or_default();

            dests.push(
                Destination::new(uri, address, transport, weight, priority).with_attrs(attrs),
            );
        }

        let probe_config = crate::gateway::ProbeConfig {
            enabled: probe,
            ..Default::default()
        };

        self.inner.add_group(
            DispatcherGroup::new(name.to_string(), algo, dests).with_probe_config(probe_config),
        );

        Ok(())
    }

    /// Remove a group by name.
    fn remove_group(&self, name: &str) -> bool {
        self.inner.remove_group(name)
    }

    /// Manually mark a destination as down.
    fn mark_down(&self, group_name: &str, uri: &str) -> bool {
        match self.inner.get_group(group_name) {
            Some(group) => group.mark_down(uri),
            None => false,
        }
    }

    /// Manually mark a destination as up.
    fn mark_up(&self, group_name: &str, uri: &str) -> bool {
        match self.inner.get_group(group_name) {
            Some(group) => group.mark_up(uri),
            None => false,
        }
    }
}

/// Python-visible destination returned from gateway.select() and gateway.list().
#[pyclass(name = "Destination", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct PyDestination {
    /// The SIP URI to route to.
    #[pyo3(get)]
    uri: String,
    /// The socket address as a string.
    #[pyo3(get)]
    address: String,
    /// Whether the destination is healthy.
    #[pyo3(get)]
    healthy: bool,
    /// Weight for load balancing.
    #[pyo3(get)]
    weight: u32,
    /// Priority tier (lower = higher priority).
    #[pyo3(get)]
    priority: u32,
    /// User-defined attributes.
    #[pyo3(get)]
    attrs: HashMap<String, String>,
}

impl PyDestination {
    fn from_destination(dest: &Destination) -> Self {
        // Bake transport into the URI so call.dial(gw.uri) uses the right
        // protocol.  Only needed when transport != UDP (the SIP default)
        // and the URI doesn't already carry a ;transport= parameter.
        let uri = if dest.transport != Transport::Udp
            && !dest.uri.to_lowercase().contains(";transport=")
        {
            let param = match dest.transport {
                Transport::Tcp => ";transport=tcp",
                Transport::Tls => ";transport=tls",
                Transport::WebSocket => ";transport=ws",
                Transport::WebSocketSecure => ";transport=wss",
                Transport::Sctp => ";transport=sctp",
                Transport::Udp => unreachable!(),
            };
            format!("{}{}", dest.uri, param)
        } else {
            dest.uri.clone()
        };

        Self {
            uri,
            address: dest.address().to_string(),
            healthy: dest.is_healthy(),
            weight: dest.weight,
            priority: dest.priority,
            attrs: dest.attrs.clone(),
        }
    }
}

#[pymethods]
impl PyDestination {
    fn __str__(&self) -> &str {
        &self.uri
    }

    fn __repr__(&self) -> String {
        format!(
            "Destination(uri={}, healthy={}, weight={}, priority={})",
            self.uri, self.healthy, self.weight, self.priority
        )
    }

    fn __bool__(&self) -> bool {
        self.healthy
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{Algorithm, Destination, DispatcherGroup};
    use crate::transport::Transport;

    fn make_gateway() -> PyGateway {
        let manager = Arc::new(DispatcherManager::new());

        let attrs_east = HashMap::from([("region".to_string(), "us-east".to_string())]);

        manager.add_group(DispatcherGroup::new(
            "carriers".to_string(),
            Algorithm::Weighted,
            vec![
                Destination::new(
                    "sip:gw1.carrier.com".to_string(),
                    "10.0.0.1:5060".parse().unwrap(),
                    Transport::Udp,
                    3,
                    1,
                )
                .with_attrs(attrs_east),
                Destination::new(
                    "sip:gw2.carrier.com".to_string(),
                    "10.0.0.2:5060".parse().unwrap(),
                    Transport::Udp,
                    1,
                    1,
                ),
            ],
        ));

        manager.add_group(DispatcherGroup::new(
            "sbc-pool".to_string(),
            Algorithm::Hash,
            vec![
                Destination::new(
                    "sip:sbc1.example.com".to_string(),
                    "10.1.0.1:5060".parse().unwrap(),
                    Transport::Udp,
                    1,
                    1,
                ),
                Destination::new(
                    "sip:sbc2.example.com".to_string(),
                    "10.1.0.2:5060".parse().unwrap(),
                    Transport::Udp,
                    1,
                    1,
                ),
            ],
        ));

        PyGateway::new(manager)
    }

    #[test]
    fn select_returns_destination() {
        let gw = make_gateway();
        let result = gw.select("carriers", None, None).unwrap();
        assert!(result.is_some());
        let dest = result.unwrap();
        assert!(!dest.uri.is_empty());
        assert!(dest.healthy);
    }

    #[test]
    fn select_nonexistent_group() {
        let gw = make_gateway();
        let result = gw.select("nonexistent", None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn select_with_key_is_sticky() {
        let gw = make_gateway();
        let first = gw
            .select("sbc-pool", Some("call-id-123"), None)
            .unwrap()
            .unwrap();

        for _ in 0..10 {
            let result = gw
                .select("sbc-pool", Some("call-id-123"), None)
                .unwrap()
                .unwrap();
            assert_eq!(result.uri, first.uri);
        }
    }

    #[test]
    fn list_returns_all_destinations() {
        let gw = make_gateway();
        let dests = gw.list("carriers");
        assert_eq!(dests.len(), 2);
        assert_eq!(dests[0].weight, 3);
        assert_eq!(dests[1].weight, 1);
    }

    #[test]
    fn list_nonexistent_group_returns_empty() {
        let gw = make_gateway();
        assert!(gw.list("nonexistent").is_empty());
    }

    #[test]
    fn status_returns_all() {
        let gw = make_gateway();
        let status = gw.status("carriers");
        assert_eq!(status.len(), 2);
        assert!(status[0].1);
    }

    #[test]
    fn groups_returns_names() {
        let gw = make_gateway();
        let mut names = gw.groups();
        names.sort();
        assert_eq!(names, vec!["carriers", "sbc-pool"]);
    }

    #[test]
    fn mark_down_and_up() {
        let gw = make_gateway();
        assert!(gw.mark_down("carriers", "sip:gw1.carrier.com"));

        let status = gw.status("carriers");
        let gw1 = status
            .iter()
            .find(|(uri, _)| uri == "sip:gw1.carrier.com")
            .unwrap();
        assert!(!gw1.1);

        assert!(gw.mark_up("carriers", "sip:gw1.carrier.com"));
        let status = gw.status("carriers");
        let gw1 = status
            .iter()
            .find(|(uri, _)| uri == "sip:gw1.carrier.com")
            .unwrap();
        assert!(gw1.1);
    }

    #[test]
    fn remove_group_works() {
        let gw = make_gateway();
        assert!(gw.remove_group("carriers"));
        assert!(!gw.remove_group("carriers"));
        assert!(gw.list("carriers").is_empty());
    }

    #[test]
    fn destination_str_and_repr() {
        let dest = PyDestination {
            uri: "sip:gw1.carrier.com".to_string(),
            address: "10.0.0.1:5060".to_string(),
            healthy: true,
            weight: 3,
            priority: 1,
            attrs: HashMap::new(),
        };
        assert_eq!(dest.__str__(), "sip:gw1.carrier.com");
        assert!(dest.__repr__().contains("weight=3"));
        assert!(dest.__bool__());
    }

    #[test]
    fn destination_bool_reflects_health() {
        let healthy = PyDestination {
            uri: "sip:up.example.com".to_string(),
            address: "10.0.0.1:5060".to_string(),
            healthy: true,
            weight: 1,
            priority: 1,
            attrs: HashMap::new(),
        };
        assert!(healthy.__bool__());

        let unhealthy = PyDestination {
            uri: "sip:down.example.com".to_string(),
            address: "10.0.0.2:5060".to_string(),
            healthy: false,
            weight: 1,
            priority: 1,
            attrs: HashMap::new(),
        };
        assert!(!unhealthy.__bool__());
    }

    #[test]
    fn destination_attrs_exposed() {
        let gw = make_gateway();
        let dests = gw.list("carriers");
        let gw1 = &dests[0];
        assert_eq!(gw1.attrs.get("region").unwrap(), "us-east");
    }

    #[test]
    fn from_destination_bakes_transport_into_uri() {
        let dest = Destination::new(
            "sip:trunk.example.com".to_string(),
            "10.0.0.1:5061".parse().unwrap(),
            Transport::Tls,
            1,
            1,
        );
        let py = PyDestination::from_destination(&dest);
        assert_eq!(py.uri, "sip:trunk.example.com;transport=tls");
    }

    #[test]
    fn from_destination_udp_no_transport_param() {
        let dest = Destination::new(
            "sip:gw.example.com".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            1,
            1,
        );
        let py = PyDestination::from_destination(&dest);
        assert_eq!(py.uri, "sip:gw.example.com");
    }

    #[test]
    fn from_destination_preserves_existing_transport() {
        let dest = Destination::new(
            "sip:gw.example.com;transport=tcp".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Tcp,
            1,
            1,
        );
        let py = PyDestination::from_destination(&dest);
        assert_eq!(py.uri, "sip:gw.example.com;transport=tcp");
    }
}
