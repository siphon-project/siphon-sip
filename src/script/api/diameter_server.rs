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
//! Enumerated/Integer32/Unsigned64 → `int`, everything else → `bytes`. A Time
//! AVP reads as its four octets and is set from those or from an `int` of
//! Unix seconds.

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
fn avp_to_py<'py>(
    py: Python<'py>,
    code: u32,
    vendor: u32,
    avp: &Avp,
) -> PyResult<Bound<'py, PyAny>> {
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
                Ok(String::from_utf8_lossy(bytes)
                    .into_owned()
                    .into_pyobject(py)?
                    .into_any())
            }
            // A TBCD-string (MSISDN / SC-Address / SGSN-Number /
            // MME-Number-for-MT-SMS / MSC-Number) → the E.164 digit string,
            // every octet of it a pair of digits.
            Some(AvpType::TbcdString) => {
                let digits = crate::diameter::codec::decode_tbcd_digits(bytes);
                Ok(digits.into_pyobject(py)?.into_any())
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
        Some(AvpType::TbcdString) => {
            // A str is an E.164 digit string, sent as the TBCD digits and
            // nothing else; bytes are taken as the octets to send.
            if let Ok(digits) = value.extract::<String>() {
                Ok(crate::diameter::codec::encode_tbcd_digits(&digits))
            } else {
                let bytes: Vec<u8> = value.extract()?;
                Ok(bytes)
            }
        }
        Some(AvpType::Time) if value.is_instance_of::<pyo3::types::PyInt>() => {
            // Unix seconds, written as seconds since 1900 (RFC 6733 clause
            // 4.3.1). The four octets themselves are taken below, as before.
            let unix_seconds: u64 = value.extract()?;
            let seconds = unix_seconds.wrapping_add(crate::diameter::codec::NTP_UNIX_EPOCH_OFFSET)
                & 0xFFFF_FFFF;
            Ok((seconds as u32).to_be_bytes().to_vec())
        }
        _ => {
            // OctetString / Address / Time / unknown: accept bytes or str.
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

/// One AVP of a message with its fields by name, as `avps()` lists them.
///
/// `iter_avps` yields `(code, vendor, value)` tuples and the members of a
/// grouped AVP are `(code, value, vendor)` tuples, so a handler that unpacks
/// one in the order of the other compares a value with a vendor id. Here the
/// fields are attributes, the same at every level: the `value` of a grouped
/// AVP is a list of `DiameterAvp`.
#[pyclass(name = "DiameterAvp", frozen, skip_from_py_object)]
pub struct PyDiameterAvp {
    /// The AVP code.
    #[pyo3(get)]
    code: u32,
    /// The Vendor-Id, 0 for a base AVP.
    #[pyo3(get)]
    vendor: u32,
    /// The dictionary name, or None for an AVP the dictionary does not know.
    #[pyo3(get)]
    name: Option<String>,
    /// The value as `get_avp` returns it, or for a grouped AVP a list of
    /// `DiameterAvp`.
    #[pyo3(get)]
    value: Py<PyAny>,
}

#[pymethods]
impl PyDiameterAvp {
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let name = match &self.name {
            Some(name) => format!("'{name}'"),
            None => "None".to_string(),
        };
        Ok(format!(
            "DiameterAvp(name={name}, code={}, vendor={}, value={})",
            self.code,
            self.vendor,
            self.value.bind(py).repr()?
        ))
    }
}

fn named_avp(py: Python<'_>, avp: &Avp) -> PyResult<Py<PyDiameterAvp>> {
    let value = match &avp.value {
        AvpData::Grouped(children) => named_avps(py, children)?.into_any().unbind(),
        AvpData::Raw(_) => avp_to_py(py, avp.code, avp.vendor, avp)?.unbind(),
    };
    Py::new(
        py,
        PyDiameterAvp {
            code: avp.code,
            vendor: avp.vendor,
            name: dictionary::lookup_avp(avp.code, avp.vendor).map(|def| def.name.to_string()),
            value,
        },
    )
}

fn named_avps<'py>(py: Python<'py>, avps: &[Avp]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for avp in avps {
        list.append(named_avp(py, avp)?)?;
    }
    Ok(list)
}

fn msg_iter_avps<'py>(py: Python<'py>, msg: &DiameterMsg) -> PyResult<Bound<'py, PyList>> {
    let mut rows: Vec<(u32, u32, Bound<'py, PyAny>)> = Vec::with_capacity(msg.avps.len());
    for avp in &msg.avps {
        rows.push((
            avp.code,
            avp.vendor,
            avp_to_py(py, avp.code, avp.vendor, avp)?,
        ));
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
        // The dictionary decides the M bit of a group as of any other AVP:
        // the restoration groups of TS 29.229 table 6.3.1 never carry it.
        let mut flags = if dictionary::avp_is_mandatory(code, vendor) {
            crate::diameter::codec::AVP_FLAG_MANDATORY
        } else {
            0
        };
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

/// Parse one grouped child spec — a `(code_or_name, value)`,
/// `(code_or_name, value, vendor)` or `(code_or_name, value, vendor,
/// mandatory)` tuple — into an [`Avp`]. `mandatory` sets or clears the M bit
/// the dictionary would give, for an AVP it does not know (a table that marks
/// the M bit "must not" for it, TS 29.272 table 7.3.1/1 CLR-Flags for one).
pub(crate) fn build_child_spec(spec: &Bound<'_, PyAny>) -> PyResult<Avp> {
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
    let mut avp = build_avp(code, vendor, &value)?;
    if tuple.len() >= 4 {
        let mandatory: bool = tuple.get_item(3)?.extract()?;
        avp.flags = if mandatory {
            avp.flags | crate::diameter::codec::AVP_FLAG_MANDATORY
        } else {
            avp.flags & !crate::diameter::codec::AVP_FLAG_MANDATORY
        };
    }
    Ok(avp)
}

// ── PyDiameterAnswer ────────────────────────────────────────────────────────

/// The answer the Diameter server returns upstream. Returned by `forward_to` / `reject`,
/// or constructable for a fully script-built answer.
#[pyclass(name = "DiameterAnswer")]
pub struct PyDiameterAnswer {
    pub(crate) msg: Arc<Mutex<DiameterMsg>>,
    /// The (code, vendor) of the AVPs `DiameterRequest.answer` copied from
    /// the request and the script has not touched since. The first
    /// `insert_avp` of one replaces the copy, so a script that adds the AVP
    /// itself does not end up with two.
    copied_from_request: Mutex<Vec<(u32, u32)>>,
}

/// The AVPs an answer takes from its request. Every answer of the 3GPP
/// applications lists Vendor-Specific-Application-Id and Auth-Session-State,
/// with the values of the request: both as required on Cx and Sh (TS 29.229
/// clause 6.1, TS 29.329 clause 6.1), Auth-Session-State as required and the
/// other as optional on S6a, S6c and SGd (TS 29.272 clause 7.2, TS 29.338
/// clauses 5.3.2 and 6.3.2).
const APPLICATION_AVPS: [u32; 2] = [
    dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID,
    dictionary::avp::AUTH_SESSION_STATE,
];

impl PyDiameterAnswer {
    pub(crate) fn from_msg(msg: DiameterMsg) -> Self {
        Self {
            msg: Arc::new(Mutex::new(msg)),
            copied_from_request: Mutex::new(Vec::new()),
        }
    }

    /// An answer a handler is about to fill in, with the application AVPs of
    /// `request` copied into the places the commands list them in:
    /// Vendor-Specific-Application-Id after Session-Id, Auth-Session-State
    /// before Origin-Host. A protocol error (3xxx) gets neither: it is the
    /// generic answer-message of RFC 6733 section 7.2.
    fn for_handler(request: &DiameterMsg, mut answer: DiameterMsg, result_code: u32) -> Self {
        let mut copied = Vec::new();
        if !(3000..4000).contains(&result_code) {
            for code in APPLICATION_AVPS {
                let Some(avp) = request.find(code, 0) else {
                    continue;
                };
                let before = if code == dictionary::avp::AUTH_SESSION_STATE {
                    dictionary::avp::ORIGIN_HOST
                } else {
                    dictionary::avp::RESULT_CODE
                };
                let position = answer
                    .avps
                    .iter()
                    .position(|existing| existing.code == before && existing.vendor == 0)
                    .unwrap_or(answer.avps.len());
                answer.avps.insert(position, avp.clone());
                copied.push((code, 0));
            }
        }
        Self {
            msg: Arc::new(Mutex::new(answer)),
            copied_from_request: Mutex::new(copied),
        }
    }

    /// Forget that `(code, vendor)` was copied from the request, because the
    /// script is now setting it. Returns whether it was.
    fn take_copied(&self, code: u32, vendor: u32) -> PyResult<bool> {
        let mut copied = self
            .copied_from_request
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!("lock: {error}")))?;
        let before = copied.len();
        copied.retain(|entry| *entry != (code, vendor));
        Ok(copied.len() != before)
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

    #[pyo3(signature = (code_or_name, vendor=0))]
    fn get_avp<'py>(
        &self,
        py: Python<'py>,
        code_or_name: &Bound<'_, PyAny>,
        vendor: u32,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        let guard = self.lock()?;
        msg_get_avp(py, &guard, code, vendor)
    }

    /// The top-level AVPs as `(code, vendor, value)` tuples, in wire order.
    ///
    /// **The members of a grouped AVP are in another order**: its `value` is
    /// a list of `(code, value, vendor)` tuples, the shape `set_avp` takes
    /// for a child. Unpacking one in the order of the other compares a value
    /// with a vendor id and matches nothing. `avps()` lists the same AVPs
    /// with the fields by name.
    fn iter_avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        msg_iter_avps(py, &guard)
    }

    /// The top-level AVPs as `DiameterAvp` objects, in wire order: `.code`,
    /// `.vendor`, `.name` (None when the dictionary does not know the AVP)
    /// and `.value`, which for a grouped AVP is a list of `DiameterAvp`.
    ///
    /// ```python,ignore
    /// for avp in request.avps():
    ///     if avp.name == "Deregistration-Reason":
    ///         reason = {member.name: member.value for member in avp.value}
    /// ```
    fn avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        named_avps(py, &guard.avps)
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
        let mut avp = build_avp(code, vendor, value)?;
        // TS 29.229 §7.2.1: Supported-Features "within an answer application
        // message ... shall never have the 'M' bit set" (in a request it has).
        if code == dictionary::avp::SUPPORTED_FEATURES && vendor == dictionary::VENDOR_3GPP {
            avp.flags &= !crate::diameter::codec::AVP_FLAG_MANDATORY;
        }
        self.take_copied(code, vendor)?;
        let mut msg = self.lock_mut()?;
        msg.remove(code, vendor);
        msg.avps.push(avp);
        Ok(())
    }

    /// Append an AVP, keeping the ones already there with its code and vendor.
    ///
    /// ``set_avp`` replaces: it removes every AVP of that code and vendor
    /// first, so it cannot build an answer that carries the same AVP more
    /// than once at the top level. Call ``insert_avp`` once per occurrence
    /// for those, in the order they should go on the wire. The arguments are
    /// the ones ``set_avp`` takes.
    ///
    /// ```python,ignore
    /// answer = req.answer(2001)
    /// answer.set_avp("SIP-Number-Auth-Items", len(vectors))
    /// for vector in vectors:
    ///     answer.insert_avp("SIP-Auth-Data-Item", vector)
    /// ```
    ///
    /// One exception: the first ``insert_avp`` of an AVP that
    /// ``request.answer()`` copied from the request
    /// (Vendor-Specific-Application-Id, Auth-Session-State) replaces that
    /// copy, so adding it yourself does not send it twice.
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
        let replaces_copy = self.take_copied(code, vendor)?;
        let mut msg = self.lock_mut()?;
        if replaces_copy {
            msg.remove(code, vendor);
        }
        msg.avps.push(avp);
        Ok(())
    }

    #[pyo3(signature = (code_or_name, vendor=0))]
    fn remove_avp(&self, code_or_name: &Bound<'_, PyAny>, vendor: u32) -> PyResult<usize> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        self.take_copied(code, vendor)?;
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

    #[pyo3(signature = (code_or_name, vendor=0))]
    fn get_avp<'py>(
        &self,
        py: Python<'py>,
        code_or_name: &Bound<'_, PyAny>,
        vendor: u32,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
        let guard = self.lock()?;
        msg_get_avp(py, &guard, code, vendor)
    }

    /// The top-level AVPs as `(code, vendor, value)` tuples, in wire order.
    ///
    /// **The members of a grouped AVP are in another order**: its `value` is
    /// a list of `(code, value, vendor)` tuples, the shape `set_avp` takes
    /// for a child. Unpacking one in the order of the other compares a value
    /// with a vendor id and matches nothing. `avps()` lists the same AVPs
    /// with the fields by name.
    fn iter_avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        msg_iter_avps(py, &guard)
    }

    /// The top-level AVPs as `DiameterAvp` objects, in wire order: `.code`,
    /// `.vendor`, `.name` (None when the dictionary does not know the AVP)
    /// and `.value`, which for a grouped AVP is a list of `DiameterAvp`.
    ///
    /// ```python,ignore
    /// for avp in request.avps():
    ///     if avp.name == "Deregistration-Reason":
    ///         reason = {member.name: member.value for member in avp.value}
    /// ```
    fn avps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let guard = self.lock()?;
        named_avps(py, &guard.avps)
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

    #[pyo3(signature = (code_or_name, vendor=0))]
    fn remove_avp(&self, code_or_name: &Bound<'_, PyAny>, vendor: u32) -> PyResult<usize> {
        let (code, name_vendor) = resolve_code(code_or_name)?;
        let vendor = if vendor != 0 { vendor } else { name_vendor };
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
    /// Origin-Host/Realm, and the request's hop-by-hop / end-to-end. It also
    /// carries the request's Vendor-Specific-Application-Id and
    /// Auth-Session-State when the request has them, which the answers of
    /// the 3GPP applications list, unless `result_code` is a protocol error
    /// (3xxx). Setting either yourself replaces the copy. Add the other
    /// application AVPs (including grouped ones) with `set_avp`, or with
    /// `insert_avp` for an AVP the answer carries more than once.
    #[pyo3(signature = (result_code=2001, error_message=None))]
    fn answer(
        &self,
        result_code: u32,
        error_message: Option<String>,
    ) -> PyResult<PyDiameterAnswer> {
        let request = self.lock()?;
        let answer = forward::build_answer(
            &request,
            &self.local_origin_host,
            &self.local_origin_realm,
            result_code,
            error_message.as_deref(),
        );
        Ok(PyDiameterAnswer::for_handler(&request, answer, result_code))
    }

    /// Build an answer that refuses this request (alias of `answer` kept for
    /// readability when refusing). The E-bit is set for a protocol error
    /// (3xxx) and for nothing else: a permanent failure (5xxx) a handler
    /// answers is an answer of the command (RFC 6733 section 7.1.5).
    #[pyo3(signature = (result_code, error_message=None))]
    fn reject(
        &self,
        result_code: u32,
        error_message: Option<String>,
    ) -> PyResult<PyDiameterAnswer> {
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
                let answer = forward::build_error_answer(
                    &tree,
                    &local_origin_host,
                    &local_origin_realm,
                    error.result_code(),
                    &error.to_string(),
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
                            let answer = forward::build_error_answer(
                                &tree,
                                &local_origin_host,
                                &local_origin_realm,
                                dictionary::DIAMETER_UNABLE_TO_DELIVER,
                                "malformed answer from backend",
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
                    let answer = forward::build_error_answer(
                        &tree,
                        &local_origin_host,
                        &local_origin_realm,
                        result_code,
                        &reason,
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
            "diam.epc.example.org".into(),
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
            assert_eq!(
                request.dest_realm().unwrap().as_deref(),
                Some("epc.example.org")
            );
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

            // get_avp on a text AVP by NAME → str (exercises the name overload)
            let origin = request
                .get_avp(py, &"Origin-Host".into_pyobject(py).unwrap().into_any(), 0)
                .unwrap()
                .unwrap();
            let origin_str: String = origin.extract().unwrap();
            assert_eq!(origin_str, "mme.epc.example.org");

            // set_avp by name, then read back
            let value = "scscf.epc.example.org"
                .into_pyobject(py)
                .unwrap()
                .into_any();
            request
                .set_avp(
                    &"Destination-Host".into_pyobject(py).unwrap().into_any(),
                    &value,
                    0,
                )
                .unwrap();
            let dest_host = request.dest_host().unwrap();
            assert_eq!(dest_host.as_deref(), Some("scscf.epc.example.org"));

            // remove_avp by NAME (exercises the name overload)
            assert_eq!(
                request
                    .remove_avp(&"Destination-Host".into_pyobject(py).unwrap().into_any(), 0)
                    .unwrap(),
                1
            );
            assert!(request.dest_host().unwrap().is_none());
        });
    }

    /// RFC 6733 section 4.5 lists four base AVPs with M under "MUST NOT".
    /// A script that sets one gets it without the bit, at the top level and
    /// inside a group.
    #[test]
    fn a_script_set_avp_that_must_not_be_mandatory_carries_no_m_bit() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = py_request().answer(5012, None).unwrap();
            let text = "why".into_pyobject(py).unwrap().into_any();
            for name in ["Error-Message", "Product-Name"] {
                answer
                    .set_avp(&name.into_pyobject(py).unwrap().into_any(), &text, 0)
                    .unwrap();
            }
            // Error-Reporting-Host, by its code.
            answer
                .set_avp(&294u32.into_pyobject(py).unwrap().into_any(), &text, 0)
                .unwrap();
            let revision = 1u32.into_pyobject(py).unwrap().into_any();
            answer
                .set_avp(&267u32.into_pyobject(py).unwrap().into_any(), &revision, 0)
                .unwrap();
            // Result-Code keeps its M bit.
            let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
            for code in [281, 294, 269, 267] {
                assert_eq!(msg.find(code, 0).unwrap().flags, 0, "{code}");
            }
            assert_eq!(
                msg.find(dictionary::avp::RESULT_CODE, 0).unwrap().flags,
                crate::diameter::codec::AVP_FLAG_MANDATORY
            );
        });
    }

    #[test]
    fn tbcd_avp_encodes_the_digits_alone_and_reads_back_e164() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = py_request();

            // set_avp by name with a plain E.164 digit string (the natural
            // Python value) — MSISDN resolves to (701, 3GPP) by name.
            let msisdn = "31612345678".into_pyobject(py).unwrap().into_any();
            request
                .set_avp(&"MSISDN".into_pyobject(py).unwrap().into_any(), &msisdn, 0)
                .unwrap();

            // get_avp returns the DECODED digit string (str), not raw bytes.
            let read = request
                .get_avp(py, &"MSISDN".into_pyobject(py).unwrap().into_any(), 0)
                .unwrap()
                .unwrap();
            let digits: String = read.extract().unwrap();
            assert_eq!(digits, "31612345678");

            // On the wire it is the TBCD digits and nothing else (TS 29.329
            // clause 6.3.2): 6 octets, no leading indicator. Exercise the
            // answer path too (same build_avp / py_to_avp_raw).
            let answer = request.answer(2001, None).unwrap();
            answer
                .set_avp(&"MSISDN".into_pyobject(py).unwrap().into_any(), &msisdn, 0)
                .unwrap();
            let wire = answer.to_wire().unwrap();
            let msg = DiameterMsg::from_wire(&wire).unwrap();
            let avp = msg
                .find(dictionary::avp::MSISDN, dictionary::VENDOR_3GPP)
                .expect("MSISDN present on the answer");
            assert_eq!(
                avp.raw_bytes(),
                Some(&[0x13u8, 0x16, 0x32, 0x54, 0x76, 0xF8][..]),
            );
        });
    }

    /// The octets a peer sends for 19995550100, 49000000001 and 39000000001
    /// start with 0x91, 0x94 and 0x93. Those are digits: a handler reading
    /// the AVP gets the whole number, country code included.
    #[test]
    fn tbcd_avp_keeps_a_first_octet_with_its_top_bit_set() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = py_request();
            for (octets, digits) in [
                ([0x91u8, 0x99, 0x55, 0x05, 0x01, 0xf0], "19995550100"),
                ([0x94, 0x00, 0x00, 0x00, 0x00, 0xf1], "49000000001"),
                ([0x93, 0x00, 0x00, 0x00, 0x00, 0xf1], "39000000001"),
            ] {
                for name in [
                    "MSISDN",
                    "SC-Address",
                    "SGSN-Number",
                    "MME-Number-for-MT-SMS",
                    "MSC-Number",
                ] {
                    // Bytes go in as given, as when a value is relayed.
                    let raw = PyBytes::new(py, &octets).into_any();
                    request
                        .set_avp(&name.into_pyobject(py).unwrap().into_any(), &raw, 0)
                        .unwrap();
                    let read = request
                        .get_avp(py, &name.into_pyobject(py).unwrap().into_any(), 0)
                        .unwrap()
                        .unwrap();
                    let read: String = read.extract().unwrap();
                    assert_eq!(read, digits, "{name}");
                }
            }
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

    // ── avps(): every field by name ──────────────────────────────────────

    /// A Cx Registration-Termination-Request with a top-level 3GPP AVP and a
    /// grouped one, the way a handler receives it.
    fn registration_termination_with_a_reason() -> PyDiameterRequest {
        let reason = Avp {
            code: 615,
            vendor: dictionary::VENDOR_3GPP,
            flags: crate::diameter::codec::AVP_FLAG_MANDATORY
                | crate::diameter::codec::AVP_FLAG_VENDOR,
            value: AvpData::Grouped(vec![
                Avp::u32(616, dictionary::VENDOR_3GPP, 0),
                Avp::utf8(617, dictionary::VENDOR_3GPP, "subscription ended"),
            ]),
        };
        PyDiameterRequest::new(
            DiameterMsg {
                flags: FLAG_REQUEST | FLAG_PROXIABLE,
                command_code: dictionary::CMD_REGISTRATION_TERMINATION,
                application_id: dictionary::CX_APP_ID,
                hop_by_hop: 1,
                end_to_end: 2,
                avps: vec![
                    Avp::utf8(dictionary::avp::SESSION_ID, 0, "hss;1;1"),
                    Avp::utf8(
                        dictionary::avp::PUBLIC_IDENTITY,
                        dictionary::VENDOR_3GPP,
                        "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
                    ),
                    reason,
                    // An AVP the dictionary does not know.
                    Avp::raw(59_999, 99_999, vec![0xde, 0xad]),
                ],
            },
            PyInboundPeer {
                name: "hss".into(),
                tenant: "default".into(),
                addr: "192.0.2.7:3868".into(),
                transport: "tcp".into(),
            },
            "scscf.ims.mnc001.mcc001.3gppnetwork.org".into(),
            "ims.mnc001.mcc001.3gppnetwork.org".into(),
        )
    }

    /// The two documented tuple shapes, pinned side by side because they
    /// differ: `iter_avps` yields `(code, vendor, value)` at the top level,
    /// and the members of a grouped AVP are `(code, value, vendor)`, which is
    /// the shape `set_avp` takes for a child. Neither can change without
    /// breaking scripts, which is why `avps` exists.
    #[test]
    fn iter_avps_and_group_members_keep_their_documented_tuple_orders() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = registration_termination_with_a_reason();
            let rows = request.iter_avps(py).unwrap();

            let (code, vendor, value): (u32, u32, String) =
                rows.get_item(1).unwrap().extract().unwrap();
            assert_eq!((code, vendor), (601, 10415));
            assert!(value.starts_with("sip:"));

            let (code, vendor, members): (u32, u32, Bound<'_, PyList>) =
                rows.get_item(2).unwrap().extract().unwrap();
            assert_eq!((code, vendor), (615, 10415));
            let (member_code, member_value, member_vendor): (u32, u32, u32) =
                members.get_item(0).unwrap().extract().unwrap();
            assert_eq!((member_code, member_value, member_vendor), (616, 0, 10415));
        });
    }

    /// `avps()` names the fields, the same way at every level, so no handler
    /// has to remember which position holds the vendor.
    #[test]
    fn avps_names_every_field_at_every_level() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let request = Py::new(py, registration_termination_with_a_reason()).unwrap();
            let avps = request.bind(py).call_method0("avps").unwrap();
            assert_eq!(avps.len().unwrap(), 4);
            let number = |avp: &Bound<'_, PyAny>, field: &str| -> u32 {
                avp.getattr(field).unwrap().extract().unwrap()
            };
            let text = |avp: &Bound<'_, PyAny>, field: &str| -> String {
                avp.getattr(field).unwrap().extract().unwrap()
            };

            let session = avps.get_item(0).unwrap();
            assert_eq!(number(&session, "code"), 263);
            assert_eq!(number(&session, "vendor"), 0);
            assert_eq!(text(&session, "name"), "Session-Id");
            assert_eq!(text(&session, "value"), "hss;1;1");

            let identity = avps.get_item(1).unwrap();
            assert_eq!(number(&identity, "code"), 601);
            assert_eq!(number(&identity, "vendor"), 10415);
            assert_eq!(text(&identity, "name"), "Public-Identity");
            assert_eq!(
                text(&identity, "value"),
                "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
            );

            // A grouped AVP: its value is a list of the same objects.
            let reason = avps.get_item(2).unwrap();
            assert_eq!(text(&reason, "name"), "Deregistration-Reason");
            let members = reason.getattr("value").unwrap();
            assert_eq!(members.len().unwrap(), 2);
            let code = members.get_item(0).unwrap();
            assert_eq!(number(&code, "code"), 616);
            assert_eq!(number(&code, "vendor"), 10415);
            assert_eq!(text(&code, "name"), "Reason-Code");
            assert_eq!(number(&code, "value"), 0);
            let info = members.get_item(1).unwrap();
            assert_eq!(number(&info, "code"), 617);
            assert_eq!(number(&info, "vendor"), 10415);
            assert_eq!(text(&info, "value"), "subscription ended");

            // An AVP the dictionary does not know has no name and raw bytes.
            let unknown = avps.get_item(3).unwrap();
            assert_eq!(number(&unknown, "code"), 59_999);
            assert_eq!(number(&unknown, "vendor"), 99_999);
            assert!(unknown.getattr("name").unwrap().is_none());
            let bytes: Vec<u8> = unknown.getattr("value").unwrap().extract().unwrap();
            assert_eq!(bytes, [0xde, 0xad]);

            assert_eq!(
                identity.repr().unwrap().to_string(),
                "DiameterAvp(name='Public-Identity', code=601, vendor=10415, \
                 value='sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org')"
            );
        });
    }

    #[test]
    fn an_answer_lists_its_avps_the_same_way() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = registration_termination_with_a_reason()
                .answer(2001, None)
                .unwrap();
            let answer = Py::new(py, answer).unwrap();
            let avps = answer.bind(py).call_method0("avps").unwrap();
            let names: Vec<Option<String>> = avps
                .try_iter()
                .unwrap()
                .map(|avp| avp.unwrap().getattr("name").unwrap().extract().unwrap())
                .collect();
            assert_eq!(
                names,
                ["Session-Id", "Result-Code", "Origin-Host", "Origin-Realm"]
                    .map(|name| Some(name.to_string()))
            );
        });
    }

    /// An answer that starts with the application AVPs of its request lists
    /// them like any other, the group with its members by name.
    #[test]
    fn an_answer_lists_the_avps_it_copied_from_the_request() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = Py::new(py, cx_request().answer(2001, None).unwrap()).unwrap();
            let avps = answer.bind(py).call_method0("avps").unwrap();
            let names: Vec<Option<String>> = avps
                .try_iter()
                .unwrap()
                .map(|avp| avp.unwrap().getattr("name").unwrap().extract().unwrap())
                .collect();
            assert_eq!(
                names,
                [
                    "Session-Id",
                    "Vendor-Specific-Application-Id",
                    "Result-Code",
                    "Auth-Session-State",
                    "Origin-Host",
                    "Origin-Realm"
                ]
                .map(|name| Some(name.to_string()))
            );
            let application = avps.get_item(1).unwrap().getattr("value").unwrap();
            let member = application.get_item(1).unwrap();
            let field = |name: &str| member.getattr(name).unwrap();
            assert_eq!(
                field("name")
                    .extract::<Option<String>>()
                    .unwrap()
                    .as_deref(),
                Some("Auth-Application-Id")
            );
            assert_eq!(field("vendor").extract::<u32>().unwrap(), 0);
            assert_eq!(field("value").extract::<u32>().unwrap(), 16_777_216);
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
            vector
                .append(("RAND", PyBytes::new(py, &[0x11u8; 16])))
                .unwrap();
            vector
                .append(("XRES", PyBytes::new(py, &[0x22u8; 8])))
                .unwrap();
            vector
                .append(("AUTN", PyBytes::new(py, &[0x33u8; 16])))
                .unwrap();
            vector
                .append(("KASME", PyBytes::new(py, &[0x44u8; 32])))
                .unwrap();
            let auth_info = PyList::empty(py);
            auth_info.append(("E-UTRAN-Vector", &vector)).unwrap();

            let name = "Authentication-Info".into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, auth_info.as_any(), 0).unwrap();

            // Round-trip through the wire and navigate the lossless tree.
            let wire = answer.to_wire().unwrap();
            let msg = DiameterMsg::from_wire(&wire).unwrap();
            let ai = msg
                .find(
                    dictionary::avp::AUTHENTICATION_INFO,
                    dictionary::VENDOR_3GPP,
                )
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

            // And read it back through the Python-facing API as a nested list,
            // resolving the AVP by NAME (exercises the name overload).
            let read = answer
                .get_avp(
                    py,
                    &"Authentication-Info".into_pyobject(py).unwrap().into_any(),
                    dictionary::VENDOR_3GPP,
                )
                .unwrap()
                .unwrap();
            let list = read.cast::<PyList>().unwrap();
            assert_eq!(list.len(), 1); // one E-UTRAN-Vector child
        });
    }

    #[test]
    fn a_time_avp_is_set_from_unix_seconds_or_from_its_four_octets() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = py_request().answer(2001, None).unwrap();
            // Key-ExpiryTime (TS 29.109 clause 6.3.1.5), 2026-01-01T01:00:00Z.
            // On the wire a Time is seconds since 1900 (RFC 6733 clause 4.3.1).
            let name = "Key-ExpiryTime".into_pyobject(py).unwrap().into_any();
            let seconds = 1_767_229_200u64.into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, &seconds, 0).unwrap();
            let read = |answer: &PyDiameterAnswer| {
                let message = answer.msg.lock().unwrap();
                let avp = message.find(404, 10415).expect("Key-ExpiryTime").clone();
                (avp.flags, avp.raw_bytes().map(<[u8]>::to_vec))
            };
            assert_eq!(read(&answer), (0xc0, Some(vec![0xed, 0x00, 0x45, 0x90])));

            // The octets themselves, as before.
            let octets = PyBytes::new(py, &[0xed, 0x00, 0x37, 0x80]).into_any();
            answer.set_avp(&name, &octets, 0).unwrap();
            assert_eq!(read(&answer), (0xc0, Some(vec![0xed, 0x00, 0x37, 0x80])));
        });
    }

    #[test]
    fn an_avp_whose_specification_forbids_the_m_bit_is_built_without_it() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            // GUSS-Timestamp: "V" under Must, "M" under Must not (TS 29.109
            // Table 6.1).
            let answer = py_request().answer(2001, None).unwrap();
            let name = "GUSS-Timestamp".into_pyobject(py).unwrap().into_any();
            let seconds = 1_767_225_600u64.into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, &seconds, 0).unwrap();
            let message = answer.msg.lock().unwrap();
            let avp = message.find(409, 10415).expect("GUSS-Timestamp");
            assert_eq!(avp.flags, 0x80);
            assert_eq!(avp.raw_bytes(), Some(&[0xed, 0x00, 0x37, 0x80][..]));
            // Every other AVP keeps the M bit.
            drop(message);
            let name = "GBA-Type".into_pyobject(py).unwrap().into_any();
            let value = 1u32.into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, &value, 0).unwrap();
            let message = answer.msg.lock().unwrap();
            assert_eq!(message.find(410, 10415).expect("GBA-Type").flags, 0xc0);
        });
    }

    /// TS 29.229 §7.2.1: "within an answer application message the AVP shall
    /// never have the 'M' bit set", and table 6.3.1 has Feature-List-ID and
    /// Feature-List, and the restoration groups, without it. A grouped AVP a
    /// script builds follows the dictionary like any other.
    #[test]
    fn supported_features_and_restoration_groups_in_an_answer_carry_no_m_bit() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = py_request().answer(2001, None).unwrap();
            let features = PyList::new(
                py,
                [
                    PyTuple::new(
                        py,
                        [
                            266u32.into_pyobject(py).unwrap().into_any(),
                            10415u32.into_pyobject(py).unwrap().into_any(),
                        ],
                    )
                    .unwrap(),
                    PyTuple::new(
                        py,
                        [
                            629u32.into_pyobject(py).unwrap().into_any(),
                            1u32.into_pyobject(py).unwrap().into_any(),
                            10415u32.into_pyobject(py).unwrap().into_any(),
                        ],
                    )
                    .unwrap(),
                    PyTuple::new(
                        py,
                        [
                            630u32.into_pyobject(py).unwrap().into_any(),
                            5u32.into_pyobject(py).unwrap().into_any(),
                            10415u32.into_pyobject(py).unwrap().into_any(),
                        ],
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
            let name = "Supported-Features".into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, features.as_any(), 10415).unwrap();
            let group = PyList::new(
                py,
                [PyTuple::new(
                    py,
                    [
                        1u32.into_pyobject(py).unwrap().into_any(),
                        "alice@example.com".into_pyobject(py).unwrap().into_any(),
                    ],
                )
                .unwrap()],
            )
            .unwrap();
            answer
                .set_avp(
                    &647u32.into_pyobject(py).unwrap().into_any(),
                    group.as_any(),
                    10415,
                )
                .unwrap();

            let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
            let supported = msg.find(628, 10415).expect("Supported-Features");
            assert_eq!(supported.flags, 0x80, "V, never M in an answer");
            let members = match &supported.value {
                AvpData::Grouped(children) => children.clone(),
                AvpData::Raw(bytes) => crate::diameter::codec::parse_avps(bytes).unwrap(),
            };
            for member in &members {
                let want = if member.code == 266 { 0x40 } else { 0x80 };
                assert_eq!(member.flags, want, "member {}", member.code);
            }
            assert_eq!(
                msg.find(647, 10415)
                    .expect("Associated-Registered-Identities")
                    .flags,
                0x80
            );
        });
    }

    /// The AVPs of the base protocol and of an application that go out
    /// without the M bit follow one rule (`dictionary::avp_is_mandatory`): an
    /// answer a script gives one of each carries neither with it on the wire,
    /// and the vendor AVP keeps its V bit.
    #[test]
    fn base_and_application_avps_without_the_m_bit_share_an_answer() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = py_request().answer(5012, None).unwrap();
            let text = "why".into_pyobject(py).unwrap().into_any();
            let name = "Error-Message".into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, &text, 0).unwrap();
            let name = "GUSS-Timestamp".into_pyobject(py).unwrap().into_any();
            let seconds = 1_767_225_600u64.into_pyobject(py).unwrap().into_any();
            answer.set_avp(&name, &seconds, 0).unwrap();

            let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
            assert!(
                !msg.is_error(),
                "5012 from a handler is an answer of the command"
            );
            assert_eq!(msg.find(281, 0).expect("Error-Message").flags, 0);
            assert_eq!(msg.find(409, 10415).expect("GUSS-Timestamp").flags, 0x80);
            assert_eq!(
                msg.find(dictionary::avp::RESULT_CODE, 0).unwrap().flags,
                crate::diameter::codec::AVP_FLAG_MANDATORY
            );
        });
    }

    #[test]
    fn reject_builds_error_answer() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            let request = py_request();
            let answer = request
                .reject(
                    dictionary::DIAMETER_UNABLE_TO_DELIVER,
                    Some("no route".into()),
                )
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

    // ── DiameterAnswer.insert_avp: a repeated top-level AVP ─────────────────

    /// A Cx Multimedia-Auth-Request (TS 29.229), the request whose answer
    /// carries one SIP-Auth-Data-Item per authentication vector.
    fn py_multimedia_auth_request() -> PyDiameterRequest {
        PyDiameterRequest::new(
            DiameterMsg {
                flags: FLAG_REQUEST | FLAG_PROXIABLE,
                command_code: dictionary::CMD_MULTIMEDIA_AUTH,
                application_id: dictionary::CX_APP_ID,
                hop_by_hop: 0x1111,
                end_to_end: 0x2222,
                avps: vec![
                    Avp::utf8(
                        dictionary::avp::SESSION_ID,
                        0,
                        "scscf.ims.mnc001.mcc001.3gppnetwork.org;7;7",
                    ),
                    Avp::utf8(
                        dictionary::avp::ORIGIN_HOST,
                        0,
                        "scscf.ims.mnc001.mcc001.3gppnetwork.org",
                    ),
                    Avp {
                        code: dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID,
                        vendor: 0,
                        flags: crate::diameter::codec::AVP_FLAG_MANDATORY,
                        value: AvpData::Grouped(vec![
                            Avp::u32(dictionary::avp::VENDOR_ID, 0, dictionary::VENDOR_3GPP),
                            Avp::u32(
                                dictionary::avp::AUTH_APPLICATION_ID,
                                0,
                                dictionary::CX_APP_ID,
                            ),
                        ]),
                    },
                    Avp::u32(dictionary::avp::AUTH_SESSION_STATE, 0, 1),
                ],
            },
            PyInboundPeer {
                name: "scscf".into(),
                tenant: "default".into(),
                addr: "192.0.2.5:5000".into(),
                transport: "tcp".into(),
            },
            "hss.ims.mnc001.mcc001.3gppnetwork.org".into(),
            "ims.mnc001.mcc001.3gppnetwork.org".into(),
        )
    }

    /// SIP-Item-Number (TS 29.229 §6.3.14), the ordinal of one item.
    const SIP_ITEM_NUMBER: u32 = 613;

    /// One SIP-Auth-Data-Item as a script writes it: a list of child tuples.
    fn auth_data_item<'py>(py: Python<'py>, item_number: u32) -> Bound<'py, PyList> {
        let fill = item_number as u8;
        let item = PyList::empty(py);
        item.append(("SIP-Item-Number", item_number)).unwrap();
        item.append(("SIP-Authentication-Scheme", "Digest-AKAv1-MD5"))
            .unwrap();
        item.append(("SIP-Authenticate", PyBytes::new(py, &[fill; 32])))
            .unwrap();
        item.append(("SIP-Authorization", PyBytes::new(py, &[fill; 8])))
            .unwrap();
        item.append(("Confidentiality-Key", PyBytes::new(py, &[fill; 16])))
            .unwrap();
        item.append(("Integrity-Key", PyBytes::new(py, &[fill; 16])))
            .unwrap();
        item
    }

    /// A Multimedia-Auth-Answer with `vectors` SIP-Auth-Data-Item AVPs, each
    /// appended with `insert_avp`.
    fn multimedia_auth_answer(py: Python<'_>, vectors: u32) -> PyDiameterAnswer {
        let answer = py_multimedia_auth_request().answer(2001, None).unwrap();
        let name = |name: &str| name.into_pyobject(py).unwrap().into_any();
        let set = |avp: &str, value: Bound<'_, PyAny>| {
            answer.set_avp(&name(avp), &value, 0).unwrap();
        };
        set(
            "User-Name",
            "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
                .into_pyobject(py)
                .unwrap()
                .into_any(),
        );
        set(
            "Public-Identity",
            "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
                .into_pyobject(py)
                .unwrap()
                .into_any(),
        );
        set(
            "SIP-Number-Auth-Items",
            vectors.into_pyobject(py).unwrap().into_any(),
        );
        for item_number in 1..=vectors {
            answer
                .insert_avp(
                    &name("SIP-Auth-Data-Item"),
                    auth_data_item(py, item_number).as_any(),
                    0,
                )
                .unwrap();
        }
        answer
    }

    /// The SIP-Item-Number of every top-level SIP-Auth-Data-Item on the wire,
    /// in wire order.
    fn item_numbers_on_the_wire(answer: &PyDiameterAnswer) -> Vec<Option<u32>> {
        let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
        msg.find_all(dictionary::avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP)
            .map(|item| match &item.value {
                AvpData::Grouped(children) => children
                    .iter()
                    .find(|child| child.code == SIP_ITEM_NUMBER)
                    .and_then(Avp::as_u32),
                AvpData::Raw(_) => panic!("SIP-Auth-Data-Item must be grouped"),
            })
            .collect()
    }

    #[test]
    fn answer_insert_avp_appends_a_repeated_top_level_avp() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = multimedia_auth_answer(py, 2);
            // Both are on the wire, in the order they were appended.
            assert_eq!(item_numbers_on_the_wire(&answer), vec![Some(1), Some(2)]);
            // And what the envelope was seeded with is still there, once.
            let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
            assert_eq!(msg.find_all(dictionary::avp::RESULT_CODE, 0).count(), 1);
            assert_eq!(msg.find_all(dictionary::avp::SESSION_ID, 0).count(), 1);
        });
    }

    #[test]
    fn answer_insert_avp_takes_a_code_and_a_vendor_like_set_avp() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = py_multimedia_auth_request().answer(2001, None).unwrap();
            let code = dictionary::avp::SIP_AUTH_DATA_ITEM
                .into_pyobject(py)
                .unwrap()
                .into_any();
            for item_number in [5, 6, 7] {
                answer
                    .insert_avp(
                        &code,
                        auth_data_item(py, item_number).as_any(),
                        dictionary::VENDOR_3GPP,
                    )
                    .unwrap();
            }
            assert_eq!(
                item_numbers_on_the_wire(&answer),
                vec![Some(5), Some(6), Some(7)]
            );
        });
    }

    #[test]
    fn answer_set_avp_still_replaces() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let answer = multimedia_auth_answer(py, 2);
            let name = "SIP-Auth-Data-Item".into_pyobject(py).unwrap().into_any();

            // set_avp removes every AVP of that code and vendor, then adds one.
            answer
                .set_avp(&name, auth_data_item(py, 9).as_any(), 0)
                .unwrap();
            assert_eq!(item_numbers_on_the_wire(&answer), vec![Some(9)]);
            answer
                .set_avp(&name, auth_data_item(py, 3).as_any(), 0)
                .unwrap();
            assert_eq!(item_numbers_on_the_wire(&answer), vec![Some(3)]);

            // insert_avp after it appends to what set_avp left.
            answer
                .insert_avp(&name, auth_data_item(py, 4).as_any(), 0)
                .unwrap();
            assert_eq!(item_numbers_on_the_wire(&answer), vec![Some(3), Some(4)]);

            // remove_avp takes all of them and says how many.
            assert_eq!(answer.remove_avp(&name, 0).unwrap(), 2);
            assert!(item_numbers_on_the_wire(&answer).is_empty());
        });
    }

    // ── answer(): the application AVPs of the request ───────────────────

    /// Vendor-Specific-Application-Id for Cx, octet by octet (RFC 6733
    /// section 6.11): code 260 with M, length 32, holding Vendor-Id (266)
    /// 10415 and Auth-Application-Id (258) 16777216.
    const CX_VENDOR_SPECIFIC_APPLICATION_ID: [u8; 32] = [
        0x00, 0x00, 0x01, 0x04, 0x40, 0x00, 0x00, 0x20, // 260, M, length 32
        0x00, 0x00, 0x01, 0x0a, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x28, 0xaf, // Vendor-Id
        0x00, 0x00, 0x01, 0x02, 0x40, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00, // Auth-App-Id
    ];

    /// Auth-Session-State NO_STATE_MAINTAINED (RFC 6733 section 8.11): code
    /// 277 with M, length 12, value 1.
    const AUTH_SESSION_STATE_NO_STATE: [u8; 12] = [
        0x00, 0x00, 0x01, 0x15, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01,
    ];

    /// A Cx Registration-Termination-Request as a peer sends it, written out
    /// by hand: the header, Session-Id, and `application_avps` in between
    /// that and Origin-Host.
    fn registration_termination_request(application_avps: &[&[u8]]) -> PyDiameterRequest {
        let mut avps = Vec::new();
        // Session-Id (263, M), "hss;7;7": length 15, one octet of padding.
        avps.extend_from_slice(&[0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x0f]);
        avps.extend_from_slice(b"hss;7;7\0");
        for avp in application_avps {
            avps.extend_from_slice(avp);
        }
        // Origin-Host (264, M), "hss.example.com": length 23, one of padding.
        avps.extend_from_slice(&[0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x17]);
        avps.extend_from_slice(b"hss.example.com\0");

        let length = (20 + avps.len()) as u32;
        let mut wire = vec![0x01];
        wire.extend_from_slice(&length.to_be_bytes()[1..]);
        // Request and proxiable, command 304, application 16777216.
        wire.extend_from_slice(&[0xc0, 0x00, 0x01, 0x30, 0x01, 0x00, 0x00, 0x00]);
        wire.extend_from_slice(&[0x00, 0x00, 0x0b, 0x3a, 0x00, 0x00, 0x10, 0xea]);
        wire.extend_from_slice(&avps);

        PyDiameterRequest::new(
            DiameterMsg::from_wire(&wire).unwrap(),
            PyInboundPeer {
                name: "hss".into(),
                tenant: "default".into(),
                addr: "192.0.2.7:3868".into(),
                transport: "tcp".into(),
            },
            "scscf.ims.mnc001.mcc001.3gppnetwork.org".into(),
            "ims.mnc001.mcc001.3gppnetwork.org".into(),
        )
    }

    fn cx_request() -> PyDiameterRequest {
        registration_termination_request(&[
            &CX_VENDOR_SPECIFIC_APPLICATION_ID,
            &AUTH_SESSION_STATE_NO_STATE,
        ])
    }

    fn top_level_codes(answer: &PyDiameterAnswer) -> Vec<u32> {
        let wire = answer.to_wire().unwrap();
        let msg = DiameterMsg::from_wire(&wire).unwrap();
        msg.avps.iter().map(|avp| avp.code).collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Every answer of the 3GPP applications lists these two (TS 29.229
    /// clause 6.1.10 for this command: `{ Vendor-Specific-Application-Id }`
    /// and `{ Auth-Session-State }`), with the values the request has.
    #[test]
    fn answer_carries_the_application_avps_of_the_request() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            for result_code in [2001, 5012] {
                let answer = cx_request().answer(result_code, None).unwrap();
                let wire = answer.to_wire().unwrap();
                assert!(contains(&wire, &CX_VENDOR_SPECIFIC_APPLICATION_ID));
                assert!(contains(&wire, &AUTH_SESSION_STATE_NO_STATE));
                // In the order the command lists them.
                assert_eq!(
                    top_level_codes(&answer),
                    [263, 260, 268, 277, 264, 296],
                    "{result_code}"
                );
            }
            let refusal = cx_request().reject(5012, None).unwrap();
            assert_eq!(top_level_codes(&refusal), [263, 260, 268, 277, 264, 296]);
        });
    }

    #[test]
    fn answer_copies_only_what_the_request_has() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            let bare = registration_termination_request(&[]);
            assert_eq!(
                top_level_codes(&bare.answer(2001, None).unwrap()),
                [263, 268, 264, 296]
            );
            let stateless = registration_termination_request(&[&AUTH_SESSION_STATE_NO_STATE]);
            assert_eq!(
                top_level_codes(&stateless.answer(2001, None).unwrap()),
                [263, 268, 277, 264, 296]
            );
        });
    }

    /// A protocol error goes out as the generic answer-message of RFC 6733
    /// section 7.2, which lists neither.
    #[test]
    fn a_protocol_error_answer_carries_no_application_avps() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            let answer = cx_request().reject(3002, None).unwrap();
            assert_eq!(top_level_codes(&answer), [263, 268, 264, 296]);
        });
    }

    /// The header E bit and the application AVPs part at the same line. A
    /// permanent failure a handler answers is an answer of the command (RFC
    /// 6733 section 7.1.5): no E bit, both AVPs. A protocol error is the
    /// answer-message of section 7.2: the E bit, neither AVP. Error-Message
    /// goes out without the M bit in both.
    #[test]
    fn the_e_bit_and_the_application_avps_part_at_protocol_errors() {
        pyo3::Python::initialize();
        Python::attach(|_py| {
            for (result_code, error, codes) in [
                (5012, false, &[263, 260, 268, 277, 264, 296, 281][..]),
                (3002, true, &[263, 268, 264, 296, 281][..]),
            ] {
                let answer = cx_request()
                    .answer(result_code, Some("why".into()))
                    .unwrap();
                let msg = DiameterMsg::from_wire(&answer.to_wire().unwrap()).unwrap();
                assert_eq!(msg.is_error(), error, "{result_code}");
                let sent: Vec<u32> = msg.avps.iter().map(|avp| avp.code).collect();
                assert_eq!(sent, codes, "{result_code}");
                assert_eq!(msg.find(281, 0).unwrap().flags, 0, "{result_code}");
            }
        });
    }

    /// A script that sets one of them itself, with `set_avp` or with
    /// `insert_avp`, ends up with its own and not with two.
    #[test]
    fn a_script_setting_an_application_avp_does_not_duplicate_it() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let name = |name: &str| name.into_pyobject(py).unwrap().into_any();
            let state = 0u32.into_pyobject(py).unwrap().into_any();
            let application = PyList::empty(py);
            application.append(("Vendor-Id", 10415u32)).unwrap();
            application
                .append(("Auth-Application-Id", 16_777_216u32))
                .unwrap();

            let count = |answer: &PyDiameterAnswer, code: u32| {
                let wire = answer.to_wire().unwrap();
                DiameterMsg::from_wire(&wire)
                    .unwrap()
                    .find_all(code, 0)
                    .count()
            };

            let answer = cx_request().answer(2001, None).unwrap();
            answer
                .set_avp(&name("Auth-Session-State"), &state, 0)
                .unwrap();
            answer
                .set_avp(
                    &name("Vendor-Specific-Application-Id"),
                    application.as_any(),
                    0,
                )
                .unwrap();
            assert_eq!(count(&answer, 277), 1);
            assert_eq!(count(&answer, 260), 1);
            let state_read: u32 = answer
                .get_avp(py, &name("Auth-Session-State"), 0)
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(state_read, 0, "the script's value, not the request's");

            let answer = cx_request().answer(2001, None).unwrap();
            answer
                .insert_avp(&name("Auth-Session-State"), &state, 0)
                .unwrap();
            answer
                .insert_avp(
                    &name("Vendor-Specific-Application-Id"),
                    application.as_any(),
                    0,
                )
                .unwrap();
            assert_eq!(count(&answer, 277), 1);
            assert_eq!(count(&answer, 260), 1);

            // Only the copy `answer()` made gives way. What the script
            // inserted stays, so it can still repeat an AVP on purpose.
            answer
                .insert_avp(
                    &name("Vendor-Specific-Application-Id"),
                    application.as_any(),
                    0,
                )
                .unwrap();
            assert_eq!(count(&answer, 260), 2);

            // Removing the copy and inserting again is not a replacement.
            let answer = cx_request().answer(2001, None).unwrap();
            assert_eq!(
                answer.remove_avp(&name("Auth-Session-State"), 0).unwrap(),
                1
            );
            assert_eq!(count(&answer, 277), 0);
        });
    }

    /// What a subscriber-server script writes to answer a Multimedia-Auth-Request
    /// for a SIP Digest subscriber (TS 29.228 tables 6.3.4, 6.3.5 and 6.3.7):
    /// every AVP by its name, the grouped ones as lists of children.
    const SIP_DIGEST_ANSWER_SOURCE: &str = "def build(request):\n    answer = request.answer(2001)\n    answer.set_avp('User-Name', '001010000000001@ims.mnc001.mcc001.3gppnetwork.org')\n    answer.set_avp('Public-Identity', 'sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org')\n    answer.set_avp('SIP-Number-Auth-Items', 1)\n    answer.insert_avp('SIP-Auth-Data-Item', [\n        ('SIP-Authentication-Scheme', 'SIP Digest'),\n        ('SIP-Digest-Authenticate', [\n            ('Digest-Realm', 'digest.example.org'),\n            ('Digest-Algorithm', 'MD5'),\n            ('Digest-QoP', 'auth'),\n            ('Digest-HA1', '3d78807defe7de2157e2b0b6573a855f'),\n            ('Alternate-Digest-Algorithm', 'SHA-256'),\n            ('Alternate-Digest-HA1', '7987c64c30e25f1b74be53f966b49b90f2808aa92faf9a00262392d7b4794232'),\n        ]),\n    ])\n    return answer\n";

    fn sip_digest_answer(py: Python<'_>) -> Vec<u8> {
        let script = pyo3::types::PyModule::from_code(
            py,
            &std::ffi::CString::new(SIP_DIGEST_ANSWER_SOURCE).unwrap(),
            &std::ffi::CString::new("_sip_digest_answer.py").unwrap(),
            &std::ffi::CString::new("_sip_digest_answer").unwrap(),
        )
        .unwrap();
        let request = Py::new(py, py_multimedia_auth_request()).unwrap();
        let answer = script.getattr("build").unwrap().call1((request,)).unwrap();
        let answer = answer.cast::<PyDiameterAnswer>().unwrap().borrow();
        answer.to_wire().unwrap()
    }

    /// TS 29.229 table 6.3.0.1: the digest attributes inside
    /// SIP-Digest-Authenticate are the RFC 5090 ones, codes 104, 110, 111 and
    /// 121 without a vendor, and the grouped AVP and the alternate pair are
    /// 3GPP ones, 635, 662 and 663. A script reaches all of them by name.
    #[test]
    fn a_script_builds_a_sip_digest_answer_by_avp_name() {
        pyo3::Python::initialize();
        let wire = Python::attach(sip_digest_answer);

        let msg = DiameterMsg::from_wire(&wire).unwrap();
        let item = msg
            .find_all(dictionary::avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP)
            .next()
            .expect("SIP-Auth-Data-Item");
        let AvpData::Grouped(children) = &item.value else {
            panic!("SIP-Auth-Data-Item must be grouped");
        };
        let digest = children
            .iter()
            .find(|child| (child.code, child.vendor) == (635, dictionary::VENDOR_3GPP))
            .expect("SIP-Digest-Authenticate, 635 of vendor 10415");
        let AvpData::Grouped(members) = &digest.value else {
            panic!("SIP-Digest-Authenticate must be grouped");
        };
        let found: Vec<(u32, u32)> = members
            .iter()
            .map(|member| (member.code, member.vendor))
            .collect();
        assert_eq!(
            found,
            vec![
                (104, 0),
                (111, 0),
                (110, 0),
                (121, 0),
                (662, dictionary::VENDOR_3GPP),
                (663, dictionary::VENDOR_3GPP),
            ]
        );

        // And the decoder of the client side names them back.
        let decoded = crate::diameter::codec::decode_diameter(&wire).unwrap();
        let digest = &decoded.avps["SIP-Auth-Data-Item"]["SIP-Digest-Authenticate"];
        assert_eq!(digest["Digest-Realm"], "digest.example.org");
        assert_eq!(digest["Digest-QoP"], "auth");
        assert_eq!(digest["Digest-Algorithm"], "MD5");
        assert_eq!(digest["Digest-HA1"], "3d78807defe7de2157e2b0b6573a855f");
        assert_eq!(digest["Alternate-Digest-Algorithm"], "SHA-256");
    }

    /// Emit that answer as hex for `scripts/validate_diameter_cx_requests.sh`
    /// to feed to tshark, which reads SIP-Digest-Authenticate with its own
    /// dictionary.
    #[test]
    fn emit_sip_digest_answer_for_external_dissection() {
        let Ok(directory) = std::env::var("SIPHON_CX_REQUESTS_HEX_DIR") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        pyo3::Python::initialize();
        let wire = Python::attach(sip_digest_answer);
        let mut dump = String::new();
        for (offset, chunk) in wire.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        std::fs::write(format!("{directory}/maa_sip_digest_script.hex"), dump)
            .expect("hex dump must be writable");
    }

    /// Emit a Multimedia-Auth-Answer with two SIP-Auth-Data-Item AVPs as hex
    /// for [`scripts/validate_diameter_answer_avps.sh`] to feed to tshark.
    ///
    /// The tests above read the answer back with the decoder that shares a
    /// dictionary with the encoder. tshark decodes the same bytes with its own.
    #[test]
    fn emit_answer_with_repeated_avp_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_DIAMETER_ANSWER_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        pyo3::Python::initialize();
        let wire = Python::attach(|py| multimedia_auth_answer(py, 2).to_wire().unwrap());

        // `text2pcap`'s hex-dump form: an offset, then the octets.
        let mut dump = String::new();
        for (offset, chunk) in wire.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }
}
