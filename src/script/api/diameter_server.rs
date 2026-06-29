//! Python bindings for the server mode Diameter path.
//!
//! Exposes the pyclasses the `@diameter.on_request` handler works with:
//!   - [`PyDiameterRequest`] — the inbound request: read-only header attrs,
//!     AVP get/set/remove/insert/iter over the lossless [`DiameterMsg`] tree,
//!     `reject(code)`, and async `forward_to(peer, …)`.
//!   - [`PyDiameterAnswer`] — the answer returned to the script (from a backend
//!     relay or a synthesized error), with the same AVP accessors.
//!   - [`PyPeer`] — a chosen backend peer (from a pool pick).
//!   - [`PyPeerPool`] — round-robin / weighted / sticky selection.
//!   - [`PyInboundPeer`] — the authenticated sender's identity (`req.peer`).
//!
//! AVP values round-trip per dictionary type: text → `str`, Unsigned32/
//! Enumerated/Integer32/Unsigned64 → `int`, everything else → `bytes`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

use crate::diameter::codec::{Avp, AvpData, DiameterMsg};
use crate::diameter::dictionary::{self, AvpType};
use crate::diameter::pool::PeerPool;
use crate::diameter::{forward, DiameterClient};

// ── AVP value conversions ───────────────────────────────────────────────────

fn avp_type(code: u32, vendor: u32) -> Option<AvpType> {
    dictionary::lookup_avp(code, vendor).map(|def| def.data_type)
}

/// Convert an AVP's value to a Python object, typed by the dictionary.
///
/// Grouped AVPs surface as a list of `(code, value, vendor)` tuples, applied
/// recursively (so `value` is itself such a list for nested groups). This is
/// the exact shape `set_avp` accepts, so a group read out can be set back in.
fn avp_to_py<'py>(py: Python<'py>, code: u32, vendor: u32, avp: &Avp) -> PyResult<Bound<'py, PyAny>> {
    match &avp.value {
        AvpData::Grouped(children) => {
            let list = PyList::empty(py);
            for child in children {
                let child_value = avp_to_py(py, child.code, child.vendor, child)?;
                list.append((child.code, child_value, child.vendor))?;
            }
            Ok(list.into_any())
        }
        AvpData::Raw(bytes) => match avp_type(code, vendor) {
            Some(AvpType::UTF8String) | Some(AvpType::DiameterIdentity) => {
                Ok(String::from_utf8_lossy(bytes).into_owned().into_pyobject(py)?.into_any())
            }
            Some(AvpType::Unsigned32) | Some(AvpType::Enumerated) => {
                let value = avp.as_u32().unwrap_or(0);
                Ok(value.into_pyobject(py)?.into_any())
            }
            Some(AvpType::Integer32) => {
                let value = if bytes.len() >= 4 {
                    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    0
                };
                Ok(value.into_pyobject(py)?.into_any())
            }
            Some(AvpType::Unsigned64) => {
                let value = if bytes.len() >= 8 {
                    u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ])
                } else {
                    0
                };
                Ok(value.into_pyobject(py)?.into_any())
            }
            // OctetString, Address, Time, Grouped-as-raw, unknown → bytes.
            _ => Ok(PyBytes::new(py, bytes).into_any()),
        },
    }
}

/// Encode a Python value into AVP raw bytes, typed by the dictionary. Falls
/// back to OctetString semantics (bytes/str) for unknown codes.
fn py_to_avp_raw(code: u32, vendor: u32, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    match avp_type(code, vendor) {
        Some(AvpType::UTF8String) | Some(AvpType::DiameterIdentity) => {
            let text: String = value.extract()?;
            Ok(text.into_bytes())
        }
        Some(AvpType::Unsigned32) | Some(AvpType::Enumerated) => {
            let number: u32 = value.extract()?;
            Ok(number.to_be_bytes().to_vec())
        }
        Some(AvpType::Integer32) => {
            let number: i32 = value.extract()?;
            Ok(number.to_be_bytes().to_vec())
        }
        Some(AvpType::Unsigned64) => {
            let number: u64 = value.extract()?;
            Ok(number.to_be_bytes().to_vec())
        }
        _ => {
            // OctetString / Address / unknown: accept bytes or str.
            if let Ok(bytes) = value.extract::<Vec<u8>>() {
                Ok(bytes)
            } else {
                let text: String = value.extract()?;
                Ok(text.into_bytes())
            }
        }
    }
}

/// Resolve an AVP code from an `int | str` Python argument.
fn resolve_code(arg: &Bound<'_, PyAny>) -> PyResult<(u32, u32)> {
    if let Ok(code) = arg.extract::<u32>() {
        return Ok((code, 0));
    }
    let name: String = arg.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("AVP must be an int code or a str name")
    })?;
    match dictionary::lookup_by_name(&name) {
        Some(def) => Ok((def.code, def.vendor_id)),
        None => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown AVP name: {name}"
        ))),
    }
}

// ── PyInboundPeer (req.peer) ────────────────────────────────────────────────

/// Identity of the authenticated peer that sent the inbound request.
#[pyclass(name = "DiameterInboundPeer", skip_from_py_object)]
#[derive(Clone)]
pub struct PyInboundPeer {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub tenant: String,
    #[pyo3(get)]
    pub addr: String,
    #[pyo3(get)]
    pub transport: String,
}

// ── PyPeer (backend, from a pool pick) ──────────────────────────────────────

/// A backend peer chosen from a [`PyPeerPool`]. Truthy when its connection is
/// `Open`. Pass to [`PyDiameterRequest::forward_to`] (so it must stay
/// extractable from Python — opt into the `FromPyObject` derive explicitly).
#[pyclass(name = "DiameterPeer", from_py_object)]
#[derive(Clone)]
pub struct PyPeer {
    pub(crate) client: Arc<DiameterClient>,
    name: String,
    tenant: String,
}

#[pymethods]
impl PyPeer {
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }
    #[getter]
    fn tenant(&self) -> &str {
        &self.tenant
    }
    #[getter]
    fn addr(&self) -> String {
        let config = self.client.peer().config();
        format!("{}:{}", config.host, config.port)
    }
    fn __bool__(&self) -> bool {
        self.client.peer().is_open()
    }
}

// ── PyPeerPool ──────────────────────────────────────────────────────────────

/// Backend peer pool exposed to Python (`diameter.peer_pool(...)`).
#[pyclass(name = "DiameterPeerPool")]
pub struct PyPeerPool {
    pool: Arc<PeerPool>,
}

impl PyPeerPool {
    pub fn new(pool: Arc<PeerPool>) -> Self {
        Self { pool }
    }
}

fn peer_from_named(tenant: &str, named: Option<(String, Arc<DiameterClient>)>) -> Option<PyPeer> {
    named.map(|(name, client)| PyPeer {
        client,
        name,
        tenant: tenant.to_string(),
    })
}

#[pymethods]
impl PyPeerPool {
    fn pick_round_robin(&self) -> Option<PyPeer> {
        peer_from_named(self.pool.tenant(), self.pool.pick_round_robin_named())
    }

    #[pyo3(signature = (weights))]
    fn pick_weighted(&self, weights: HashMap<String, u32>) -> Option<PyPeer> {
        peer_from_named(self.pool.tenant(), self.pool.pick_weighted_named(&weights))
    }

    #[pyo3(signature = (key, ttl_secs=300.0))]
    fn pick_sticky(&self, key: &str, ttl_secs: f64) -> Option<PyPeer> {
        let ttl = Duration::from_secs_f64(ttl_secs.max(0.0));
        peer_from_named(self.pool.tenant(), self.pool.pick_sticky_named(key, ttl))
    }

    #[getter]
    fn live_count(&self) -> usize {
        self.pool.live_count()
    }
}

// ── Shared AVP-accessor helpers over a DiameterMsg ──────────────────────────

fn msg_get_avp<'py>(
    py: Python<'py>,
    msg: &DiameterMsg,
    code: u32,
    vendor: u32,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    match msg.find(code, vendor) {
        Some(avp) => Ok(Some(avp_to_py(py, code, vendor, avp)?)),
        None => Ok(None),
    }
}

fn msg_iter_avps<'py>(py: Python<'py>, msg: &DiameterMsg) -> PyResult<Bound<'py, PyList>> {
    let mut rows: Vec<(u32, u32, Bound<'py, PyAny>)> = Vec::with_capacity(msg.avps.len());
    for avp in &msg.avps {
        rows.push((avp.code, avp.vendor, avp_to_py(py, avp.code, avp.vendor, avp)?));
    }
    PyList::new(py, rows)
}

/// Build an [`Avp`] from a Python value, supporting nested grouped
/// construction. A `list` value is a Grouped AVP whose elements are child
/// specs — `(code_or_name, value)` or `(code_or_name, value, vendor)` tuples —
/// and each child `value` may itself be a list (a nested group). Any other
/// value (str / int / bytes) is a leaf, encoded per the dictionary type.
fn build_avp(code: u32, vendor: u32, value: &Bound<'_, PyAny>) -> PyResult<Avp> {
    if let Ok(list) = value.cast::<PyList>() {
        let mut children = Vec::with_capacity(list.len());
        for item in list.iter() {
            children.push(build_child_spec(&item)?);
        }
        let mut flags = crate::diameter::codec::AVP_FLAG_MANDATORY;
        if vendor != 0 {
            flags |= crate::diameter::codec::AVP_FLAG_VENDOR;
        }
        return Ok(Avp {
            code,
            vendor,
            flags,
            value: AvpData::Grouped(children),
        });
    }
    let raw = py_to_avp_raw(code, vendor, value)?;
    Ok(Avp::raw(code, vendor, raw))
}

/// Parse one grouped child spec — a `(code_or_name, value)` or
/// `(code_or_name, value, vendor)` tuple — into an [`Avp`].
fn build_child_spec(spec: &Bound<'_, PyAny>) -> PyResult<Avp> {
    let tuple = spec.cast::<PyTuple>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "grouped AVP children must be (code, value) or (code, value, vendor) tuples",
        )
    })?;
    if tuple.len() < 2 {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "grouped AVP child tuple needs at least (code, value)",
        ));
    }
    let (code, name_vendor) = resolve_code(&tuple.get_item(0)?)?;
    let value = tuple.get_item(1)?;
    let explicit_vendor = if tuple.len() >= 3 {
        tuple.get_item(2)?.extract::<u32>().unwrap_or(0)
    } else {
        0
    };
    let vendor = if explicit_vendor != 0 {
        explicit_vendor
    } else {
        name_vendor
    };
    build_avp(code, vendor, &value)
}

// ── PyDiameterAnswer ────────────────────────────────────────────────────────

/// The answer the Diameter server returns upstream. Returned by `forward_to` / `reject`,
/// or constructable for a fully script-built answer.
#[pyclass(name = "DiameterAnswer")]
pub struct PyDiameterAnswer {
    pub(crate) msg: Arc<Mutex<DiameterMsg>>,
}

impl PyDiameterAnswer {
    pub(crate) fn from_msg(msg: DiameterMsg) -> Self {
        Self {
            msg: Arc::new(Mutex::new(msg)),
        }
    }

    /// Serialize the answer to wire bytes (used by the dispatch layer to ship
    /// it back over the inbound connection).
    pub(crate) fn to_wire(&self) -> PyResult<Vec<u8>> {
        let msg = self
            .msg
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("lock: {error}")))?;
        Ok(msg.to_wire())
    }
}

#[pymethods]
impl PyDiameterAnswer {
    #[getter]
    fn result_code(&self) -> PyResult<Option<u32>> {
        let msg = self
            .msg
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("lock: {error}")))?;
        Ok(msg
            .find(dictionary::avp::RESULT_CODE, 0)
            .and_then(|avp| avp.as_u32()))
    }

    #[getter]
    fn command_code(&self) -> PyResult<u32> {
        Ok(self.lock()?.command_code)
    }

    #[getter]
    fn is_error(&self) -> PyResult<bool> {
        Ok(self.lock()?.is_error())
    }

    #[pyo3(signature = (code, vendor=0))]
    fn get_avp<'py>(
        &self,
        py: Python<'py>,
        code: u32,
        vendor: u32,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let guard = self.lock()?;
        msg_get_avp(py, &guard, code, vendor)
    }

    fn iter_avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        msg_iter_avps(py, &guard)
    }

    #[pyo3(signature = (code_or_name, value, vendor=0))]
    fn set_avp(
        &self,
        code_or_name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
        vendor: u32,
    ) -> PyResult<()> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        let avp = build_avp(code, vendor, value)?;
        let mut msg = self.lock_mut()?;
        msg.remove(code, vendor);
        msg.avps.push(avp);
        Ok(())
    }

    #[pyo3(signature = (code, vendor=0))]
    fn remove_avp(&self, code: u32, vendor: u32) -> PyResult<usize> {
        Ok(self.lock_mut()?.remove(code, vendor))
    }
}

impl PyDiameterAnswer {
    fn lock(&self) -> PyResult<std::sync::MutexGuard<'_, DiameterMsg>> {
        self.msg
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("lock: {error}")))
    }
    fn lock_mut(&self) -> PyResult<std::sync::MutexGuard<'_, DiameterMsg>> {
        self.lock()
    }
}

// ── PyDiameterRequest ───────────────────────────────────────────────────────

/// The inbound request passed to `@diameter.on_request`.
#[pyclass(name = "DiameterRequest")]
pub struct PyDiameterRequest {
    msg: Arc<Mutex<DiameterMsg>>,
    inbound_hbh: u32,
    inbound_e2e: u32,
    peer: PyInboundPeer,
    local_origin_host: String,
    local_origin_realm: String,
}

impl PyDiameterRequest {
    /// Construct from a decoded inbound message + the authenticated peer
    /// identity + the Diameter server's own identity (for Route-Record + answers).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        msg: DiameterMsg,
        peer: PyInboundPeer,
        local_origin_host: String,
        local_origin_realm: String,
    ) -> Self {
        let inbound_hbh = msg.hop_by_hop;
        let inbound_e2e = msg.end_to_end;
        Self {
            msg: Arc::new(Mutex::new(msg)),
            inbound_hbh,
            inbound_e2e,
            peer,
            local_origin_host,
            local_origin_realm,
        }
    }

    fn lock(&self) -> PyResult<std::sync::MutexGuard<'_, DiameterMsg>> {
        self.msg
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("lock: {error}")))
    }
}

#[pymethods]
impl PyDiameterRequest {
    #[getter]
    fn application_id(&self) -> PyResult<u32> {
        Ok(self.lock()?.application_id)
    }

    #[getter]
    fn application_name(&self) -> PyResult<Option<String>> {
        let app = self.lock()?.application_id;
        Ok(dictionary::app_name_by_id(app).map(|name| name.to_string()))
    }

    #[getter]
    fn command_code(&self) -> PyResult<u32> {
        Ok(self.lock()?.command_code)
    }

    #[getter]
    fn command_name(&self) -> PyResult<String> {
        let msg = self.lock()?;
        Ok(crate::diameter::codec::command_name(msg.command_code, msg.is_request()).to_string())
    }

    #[getter]
    fn session_id(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::SESSION_ID))
    }

    #[getter]
    fn origin_host(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::ORIGIN_HOST))
    }

    #[getter]
    fn origin_realm(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::ORIGIN_REALM))
    }

    #[getter]
    fn dest_realm(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::DESTINATION_REALM))
    }

    #[getter]
    fn dest_host(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::DESTINATION_HOST))
    }

    #[getter]
    fn is_request(&self) -> PyResult<bool> {
        Ok(self.lock()?.is_request())
    }

    #[getter]
    fn is_proxiable(&self) -> PyResult<bool> {
        Ok(self.lock()?.is_proxiable())
    }

    #[getter]
    fn peer(&self) -> PyInboundPeer {
        self.peer.clone()
    }

    #[pyo3(signature = (code, vendor=0))]
    fn get_avp<'py>(
        &self,
        py: Python<'py>,
        code: u32,
        vendor: u32,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let guard = self.lock()?;
        msg_get_avp(py, &guard, code, vendor)
    }

    fn iter_avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        msg_iter_avps(py, &guard)
    }

    #[pyo3(signature = (code_or_name, value, vendor=0))]
    fn set_avp(
        &self,
        code_or_name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
        vendor: u32,
    ) -> PyResult<()> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        let avp = build_avp(code, vendor, value)?;
        let mut msg = self.lock()?;
        msg.remove(code, vendor);
        msg.avps.push(avp);
        Ok(())
    }

    #[pyo3(signature = (code_or_name, value, vendor=0))]
    fn insert_avp(
        &self,
        code_or_name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
        vendor: u32,
    ) -> PyResult<()> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        let avp = build_avp(code, vendor, value)?;
        self.lock()?.avps.push(avp);
        Ok(())
    }

    #[pyo3(signature = (code, vendor=0))]
    fn remove_avp(&self, code: u32, vendor: u32) -> PyResult<usize> {
        Ok(self.lock()?.remove(code, vendor))
    }

    /// IMSI from the User-Name AVP, if present.
    fn extract_imsi(&self) -> PyResult<Option<String>> {
        Ok(self.lock()?.get_str(dictionary::avp::USER_NAME))
    }

    /// Build an answer for this request carrying `result_code` and the local
    /// identity, then populate it with `set_avp` and return it. Use this to
    /// **serve** a request locally (e.g. siphon acting as the HSS answering an
    /// AIR/ULR): siphon transports the message; the script builds the answer.
    ///
    /// The envelope is seeded with Session-Id (echoed), Result-Code,
    /// Origin-Host/Realm, and the request's hop-by-hop / end-to-end. Add the
    /// application AVPs (including grouped ones) with `set_avp`.
    #[pyo3(signature = (result_code=2001, error_message=None))]
    fn answer(&self, result_code: u32, error_message: Option<String>) -> PyResult<PyDiameterAnswer> {
        let request = self.lock()?;
        let answer = forward::build_answer(
            &request,
            &self.local_origin_host,
            &self.local_origin_realm,
            result_code,
            error_message.as_deref(),
        );
        Ok(PyDiameterAnswer::from_msg(answer))
    }

    /// Build an error answer for this request (alias of `answer` kept for
    /// readability when refusing). Sets the E-bit for 3xxx/5xxx codes.
    #[pyo3(signature = (result_code, error_message=None))]
    fn reject(&self, result_code: u32, error_message: Option<String>) -> PyResult<PyDiameterAnswer> {
        self.answer(result_code, error_message)
    }

    /// Relay this request to `peer` and await the answer. On loop detection,
    /// unreachable backend, or timeout, resolves to a synthesized error answer
    /// (3005 / 3002 / 3004) so the handler can simply `return` it.
    #[pyo3(signature = (peer, identity=None, timeout_secs=10.0))]
    fn forward_to<'py>(
        &self,
        py: Python<'py>,
        peer: PyPeer,
        identity: Option<(String, String)>,
        timeout_secs: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Snapshot everything out of `self` before the async block (no Python
        // objects may be held across the await).
        let mut tree = self.lock()?.clone();
        let local_origin_host = self.local_origin_host.clone();
        let local_origin_realm = self.local_origin_realm.clone();
        let inbound_hbh = self.inbound_hbh;
        let inbound_e2e = self.inbound_e2e;
        let client = Arc::clone(&peer.client);
        let timeout = Duration::from_secs_f64(timeout_secs.max(0.1));

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Optional topology hiding.
            if let Some((origin_host, origin_realm)) = identity {
                forward::rewrite_origin(&mut tree, &origin_host, &origin_realm);
            }

            // Loop detection + Route-Record append.
            if let Err(error) = forward::prepare_forward(&mut tree, &local_origin_host) {
                let answer = forward::build_answer(
                    &tree,
                    &local_origin_host,
                    &local_origin_realm,
                    error.result_code(),
                    Some(&error.to_string()),
                );
                return Ok(PyDiameterAnswer::from_msg(answer));
            }

            // Fresh outbound hop-by-hop; End-to-End is preserved.
            tree.hop_by_hop = client.peer().next_hbh();
            let wire = tree.to_wire();

            match client.peer().send_request_timeout(wire, timeout).await {
                Ok(answer_message) => {
                    // Rebuild the lossless tree from the answer's raw bytes and
                    // restore the inbound hbh/e2e so it correlates upstream.
                    match DiameterMsg::from_wire(&answer_message.raw) {
                        Ok(mut answer_tree) => {
                            answer_tree.hop_by_hop = inbound_hbh;
                            answer_tree.end_to_end = inbound_e2e;
                            Ok(PyDiameterAnswer::from_msg(answer_tree))
                        }
                        Err(_) => {
                            let answer = forward::build_answer(
                                &tree,
                                &local_origin_host,
                                &local_origin_realm,
                                dictionary::DIAMETER_UNABLE_TO_DELIVER,
                                Some("malformed answer from backend"),
                            );
                            Ok(PyDiameterAnswer::from_msg(answer))
                        }
                    }
                }
                Err(reason) => {
                    let result_code = if reason.contains("timed out") {
                        dictionary::DIAMETER_TOO_BUSY
                    } else {
                        dictionary::DIAMETER_UNABLE_TO_DELIVER
                    };
                    let answer = forward::build_answer(
                        &tree,
                        &local_origin_host,
                        &local_origin_realm,
                        result_code,
                        Some(&reason),
                    );
                    Ok(PyDiameterAnswer::from_msg(answer))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{FLAG_PROXIABLE, FLAG_REQUEST};

    fn sample_request_msg() -> DiameterMsg {
        DiameterMsg {
            flags: FLAG_REQUEST | FLAG_PROXIABLE,
            command_code: 272,
            application_id: dictionary::RO_APP_ID,
            hop_by_hop: 0x1111,
            end_to_end: 0x2222,
            avps: vec![
                Avp::utf8(dictionary::avp::SESSION_ID, 0, "mme;5;5"),
                Avp::utf8(dictionary::avp::ORIGIN_HOST, 0, "mme.epc.example.org"),
                Avp::utf8(dictionary::avp::DESTINATION_REALM, 0, "epc.example.org"),
                Avp::utf8(dictionary::avp::USER_NAME, 0, "001010000000001"),
            ],
        }
    }

    fn py_request() -> PyDiameterRequest {
        PyDiameterRequest::new(
            sample_request_msg(),
            PyInboundPeer {
                name: "mme".into(),
                tenant: "default".into(),
                addr: "10.0.0.5:5000".into(),
                transport: "tcp".into(),
            },
            "dra.epc.example.org".into(),
            "epc.example.org".into(),
        )
    }

    #[test]
    fn header_attrs_and_extract_imsi() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            let request = py_request();
            assert_eq!(request.command_code().unwrap(), 272);
            assert_eq!(request.session_id().unwrap().as_deref(), Some("mme;5;5"));
            assert_eq!(
                request.origin_host().unwrap().as_deref(),
                Some("mme.epc.example.org")
            );
            assert_eq!(request.dest_realm().unwrap().as_deref(), Some("epc.example.org"));
            assert!(request.is_request().unwrap());
            assert!(request.is_proxiable().unwrap());
            assert_eq!(
                request.extract_imsi().unwrap().as_deref(),
                Some("001010000000001")
            );
        });
    }

    #[test]
    fn get_set_remove_avp_roundtrip() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = py_request();

            // get_avp on a text AVP → str
            let origin = request
                .get_avp(py, dictionary::avp::ORIGIN_HOST, 0)
                .unwrap()
                .unwrap();
            let origin_str: String = origin.extract().unwrap();
            assert_eq!(origin_str, "mme.epc.example.org");

            // set_avp by name, then read back
            let value = "scscf.epc.example.org".into_pyobject(py).unwrap().into_any();
            request
                .set_avp(
                    &"Destination-Host".into_pyobject(py).unwrap().into_any(),
                    &value,
                    0,
                )
                .unwrap();
            let dest_host = request.dest_host().unwrap();
            assert_eq!(dest_host.as_deref(), Some("scscf.epc.example.org"));

            // remove_avp
            assert_eq!(request.remove_avp(dictionary::avp::DESTINATION_HOST, 0).unwrap(), 1);
            assert!(request.dest_host().unwrap().is_none());
        });
    }

    #[test]
    fn iter_avps_lists_all() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = py_request();
            let rows = request.iter_avps(py).unwrap();
            assert_eq!(rows.len(), 4);
        });
    }

    #[test]
    fn answer_then_build_nested_grouped_avp() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = py_request();
            let answer = request.answer(2001, None).unwrap();
            assert_eq!(answer.result_code().unwrap(), Some(2001));
            assert!(!answer.is_error().unwrap()); // 2001 → no E-bit

            // Build Authentication-Info → E-UTRAN-Vector → {RAND,XRES,AUTN,KASME}
            // entirely from Python value shapes (the script owns S6a semantics).
            let vector = PyList::empty(py);
            vector.append(("RAND", PyBytes::new(py, &[0x11u8; 16]))).unwrap();
            vector.append(("XRES", PyBytes::new(py, &[0x22u8; 8]))).unwrap();
            vector.append(("AUTN", PyBytes::new(py, &[0x33u8; 16]))).unwrap();
            vector.append(("KASME", PyBytes::new(py, &[0x44u8; 32]))).unwrap();
            let auth_info = PyList::empty(py);
            auth_info.append(("E-UTRAN-Vector", &vector)).unwrap();

            let name = "Authentication-Info".into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, auth_info.as_any(), 0).unwrap();

            // Round-trip through the wire and navigate the lossless tree.
            let wire = answer.to_wire().unwrap();
            let msg = DiameterMsg::from_wire(&wire).unwrap();
            let ai = msg
                .find(dictionary::avp::AUTHENTICATION_INFO, dictionary::VENDOR_3GPP)
                .expect("Authentication-Info present");
            let eutran = match &ai.value {
                AvpData::Grouped(children) => children
                    .iter()
                    .find(|c| c.code == dictionary::avp::E_UTRAN_VECTOR)
                    .expect("E-UTRAN-Vector present"),
                _ => panic!("Authentication-Info must be grouped"),
            };
            match &eutran.value {
                AvpData::Grouped(leaves) => {
                    let kasme = leaves
                        .iter()
                        .find(|c| c.code == dictionary::avp::KASME)
                        .unwrap();
                    assert_eq!(kasme.raw_bytes(), Some(&[0x44u8; 32][..]));
                }
                _ => panic!("E-UTRAN-Vector must be grouped"),
            }

            // And read it back through the Python-facing API as a nested list.
            let read = answer
                .get_avp(py, dictionary::avp::AUTHENTICATION_INFO, dictionary::VENDOR_3GPP)
                .unwrap()
                .unwrap();
            let list = read.cast::<PyList>().unwrap();
            assert_eq!(list.len(), 1); // one E-UTRAN-Vector child
        });
    }

    #[test]
    fn reject_builds_error_answer() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            let request = py_request();
            let answer = request
                .reject(dictionary::DIAMETER_UNABLE_TO_DELIVER, Some("no route".into()))
                .unwrap();
            assert_eq!(
                answer.result_code().unwrap(),
                Some(dictionary::DIAMETER_UNABLE_TO_DELIVER)
            );
            assert!(answer.is_error().unwrap());
            // Echoes the request command + session.
            assert_eq!(answer.command_code().unwrap(), 272);
        });
    }
}
