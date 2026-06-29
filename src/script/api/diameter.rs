//! PyO3 wrapper for Diameter peer management — exposed to Python as `diameter`.
//!
//! Scripts use:
//! ```python
//! from siphon import diameter
//!
//! # Check if a peer is connected
//! if diameter.is_connected("hss1"):
//!     log.info("HSS peer is up")
//!
//! # Cx: query HSS for S-CSCF assignment (I-CSCF)
//! result = diameter.cx_uar("sip:alice@ims.example.com", "ims.example.com")
//! if result:
//!     scscf = result["server_name"]
//!
//! # Cx: confirm server assignment after REGISTER auth (S-CSCF)
//! result = diameter.cx_sar("sip:alice@ims.example.com", "sip:scscf.ims.example.com:6060")
//! if result:
//!     ifc_xml = result.get("user_data")
//!
//! # Cx: locate serving S-CSCF for non-REGISTER requests (I-CSCF)
//! result = diameter.cx_lir("sip:alice@ims.example.com")
//!
//! # Rx: request QoS resources from PCRF (P-CSCF).  See the project docs for
//! # the full media_components shape; here's a minimal one-component example.
//! result = diameter.rx_aar(
//!     framed_ip="10.0.0.1",
//!     media_components=[{
//!         "number": 1,
//!         "media_type": "audio",
//!         "flows": [{
//!             "number": 1,
//!             "descriptions": [
//!                 "permit out 17 from 10.0.0.1 50000 to 10.0.0.2 30000",
//!                 "permit in 17 from 10.0.0.2 30000 to 10.0.0.1 50000",
//!             ],
//!         }],
//!     }],
//! )
//! if result:
//!     log.info(f"Rx AAR result: {result['result_code']}")
//!
//! # Rx: release QoS resources (P-CSCF)
//! diameter.rx_str("rx-sess-1")
//! ```

// The Rf charging builders (`build_ims_data`, `build_sms_data`, `rf_acr_*`)
// carry the full TS 32.299 IMS/SMS-Information envelope — 20-40+ optional
// protocol fields each — so `too_many_arguments` fires module-wide here even
// at the raised threshold. Allow it for the whole module rather than scatter
// per-function attributes; a params-struct refactor is the proper long-term
// fix but is out of scope for lint hygiene.
#![allow(clippy::too_many_arguments)]

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::warn;

use crate::diameter::codec::{
    encode_avp_address_ipv4, encode_avp_grouped, encode_avp_grouped_3gpp, encode_avp_octet,
    encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp, encode_avp_u64, encode_avp_utf8,
    encode_avp_utf8_3gpp, encode_diameter_message, encode_vendor_specific_app_id, FLAG_PROXIABLE,
    FLAG_REQUEST,
};
use crate::diameter::cx::{octet_string_as_utf8, required_str};
use crate::diameter::dictionary::{self, avp, AvpDef, AvpType};
use crate::diameter::rf::{
    self, AccountingAnswer, AccountingParams, AccountingRecordType,
};
use crate::diameter::ro::{ImsChargingData, NodeFunctionality, NodeRole, SmsChargingData};
use crate::diameter::rx::extract_result_code;
use crate::diameter::{DiameterClient, DiameterManager};

/// Extract Sh Data-Reference(s) from a Python object that may be ``int`` or ``list[int]``.
fn extract_references(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u32>> {
    if let Ok(single) = obj.extract::<u32>() {
        return Ok(vec![single]);
    }
    obj.extract::<Vec<u32>>()
}

fn media_type_from_str(s: &str) -> PyResult<crate::diameter::rx::MediaType> {
    use crate::diameter::rx::MediaType;
    Ok(match s.to_ascii_lowercase().as_str() {
        "audio" => MediaType::Audio,
        "video" => MediaType::Video,
        "data" => MediaType::Data,
        "application" => MediaType::Application,
        "control" => MediaType::Control,
        "text" => MediaType::Text,
        "message" => MediaType::Message,
        "other" => MediaType::Other,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown media_type {other:?} (expected audio|video|data|application|control|text|message|other)"
            )));
        }
    })
}

fn flow_status_from_str(s: &str) -> PyResult<crate::diameter::rx::FlowStatus> {
    use crate::diameter::rx::FlowStatus;
    Ok(match s.to_ascii_lowercase().as_str() {
        "enabled" => FlowStatus::Enabled,
        "disabled" => FlowStatus::Disabled,
        "removed" => FlowStatus::Removed,
        "enabled-up" | "enabled_uplink" | "enabled-uplink" => FlowStatus::EnabledUplink,
        "enabled-down" | "enabled_downlink" | "enabled-downlink" => FlowStatus::EnabledDownlink,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow_status {other:?} (expected enabled|disabled|removed|enabled-up|enabled-down)"
            )));
        }
    })
}

fn flow_usage_from_str(s: &str) -> PyResult<crate::diameter::rx::FlowUsage> {
    use crate::diameter::rx::FlowUsage;
    Ok(match s.to_ascii_lowercase().as_str() {
        "no_information" | "no-information" | "none" => FlowUsage::NoInformation,
        "rtcp" => FlowUsage::Rtcp,
        "af_signalling" | "af-signalling" | "signalling" => FlowUsage::AfSignalling,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow usage {other:?} (expected no_information|rtcp|af_signalling)"
            )));
        }
    })
}

/// Parse a Python list of dicts into a `Vec<MediaComponent>`.  Shape:
///
/// ```text
/// {
///   "number":              int       (required)
///   "media_type":          str       (required)
///   "max_bandwidth_ul":    int       (optional)
///   "max_bandwidth_dl":    int       (optional)
///   "flow_status":         str       (optional)
///   "codec_data":          bytes     (optional)
///   "flows":               [ ... ]   (optional, default [])
/// }
/// ```
fn parse_media_components(
    obj: &Bound<'_, PyAny>,
) -> PyResult<Vec<crate::diameter::rx::MediaComponent>> {
    use crate::diameter::rx::{MediaComponent, MediaFlow};
    use pyo3::types::{PyDict, PyList};

    let list = obj.cast::<PyList>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("media_components must be a list of dicts")
    })?;

    let mut out = Vec::with_capacity(list.len());
    for (idx, item) in list.iter().enumerate() {
        let component_dict = item.cast::<PyDict>().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(format!(
                "media_components[{idx}] must be a dict"
            ))
        })?;

        let number: u32 = component_dict
            .get_item("number")?
            .ok_or_else(|| {
                pyo3::exceptions::PyKeyError::new_err(format!(
                    "media_components[{idx}] missing 'number'"
                ))
            })?
            .extract()?;

        let media_type_str: String = component_dict
            .get_item("media_type")?
            .ok_or_else(|| {
                pyo3::exceptions::PyKeyError::new_err(format!(
                    "media_components[{idx}] missing 'media_type'"
                ))
            })?
            .extract()?;
        let media_type = media_type_from_str(&media_type_str)?;

        let max_bandwidth_ul: Option<u32> = component_dict
            .get_item("max_bandwidth_ul")?
            .map(|v| v.extract())
            .transpose()?;
        let max_bandwidth_dl: Option<u32> = component_dict
            .get_item("max_bandwidth_dl")?
            .map(|v| v.extract())
            .transpose()?;

        let flow_status = match component_dict.get_item("flow_status")? {
            Some(v) => {
                let s: String = v.extract()?;
                Some(flow_status_from_str(&s)?)
            }
            None => None,
        };

        let codec_data: Option<Vec<u8>> = component_dict
            .get_item("codec_data")?
            .map(|v| v.extract())
            .transpose()?;

        let mut flows: Vec<MediaFlow> = Vec::new();
        if let Some(flows_obj) = component_dict.get_item("flows")? {
            let flows_list = flows_obj.cast::<PyList>().map_err(|_| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "media_components[{idx}].flows must be a list"
                ))
            })?;
            for (fidx, flow_item) in flows_list.iter().enumerate() {
                let flow_dict = flow_item.cast::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "media_components[{idx}].flows[{fidx}] must be a dict"
                    ))
                })?;

                let flow_number: u32 = flow_dict
                    .get_item("number")?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyKeyError::new_err(format!(
                            "media_components[{idx}].flows[{fidx}] missing 'number'"
                        ))
                    })?
                    .extract()?;

                let descriptions: Vec<String> = match flow_dict.get_item("descriptions")? {
                    Some(v) => v.extract()?,
                    None => Vec::new(),
                };

                let status = match flow_dict.get_item("status")? {
                    Some(v) => {
                        let s: String = v.extract()?;
                        Some(flow_status_from_str(&s)?)
                    }
                    None => None,
                };

                let usage = match flow_dict.get_item("usage")? {
                    Some(v) => {
                        let s: String = v.extract()?;
                        Some(flow_usage_from_str(&s)?)
                    }
                    None => None,
                };

                flows.push(MediaFlow {
                    flow_number,
                    descriptions,
                    status,
                    usage,
                });
            }
        }

        out.push(MediaComponent {
            number,
            media_type,
            flows,
            max_bandwidth_ul,
            max_bandwidth_dl,
            flow_status,
            codec_data,
        });
    }

    Ok(out)
}

/// Accepts an IPv6 string ("2001:db8::1") or raw bytes (the
/// Framed-IPv6-Prefix AVP carries a length-prefixed octet string per
/// RFC 3162 §2.3; if the caller passes raw bytes, trust them verbatim).
fn extract_ipv6_prefix(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(raw) = obj.extract::<Vec<u8>>() {
        return Ok(raw);
    }
    let text: String = obj.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("framed_ipv6 must be str or bytes")
    })?;
    let addr: std::net::Ipv6Addr = text.parse().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "framed_ipv6 is not a valid IPv6 address: {text}"
        ))
    })?;
    // RFC 3162 §2.3 — Framed-IPv6-Prefix is reserved + prefix-length + bytes.
    // For a /128 host address, prefix_len = 128 and all 16 bytes follow.
    let mut bytes = Vec::with_capacity(18);
    bytes.push(0); // reserved
    bytes.push(128); // prefix length
    bytes.extend_from_slice(&addr.octets());
    Ok(bytes)
}

/// Accepts ``(data, type)`` where ``type`` is an int (RFC 4006 §8.47) or
/// a string alias.
fn extract_subscription_id(obj: &Bound<'_, PyAny>) -> PyResult<(String, u32)> {
    let tuple: (String, Bound<'_, PyAny>) = obj.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "subscription_id must be (data: str, type: int|str)",
        )
    })?;
    let (data, type_obj) = tuple;
    let type_num: u32 = if let Ok(int_value) = type_obj.extract::<u32>() {
        int_value
    } else {
        let alias: String = type_obj.extract().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "subscription_id[1] must be int or str alias",
            )
        })?;
        match alias.to_ascii_lowercase().as_str() {
            "e164" | "e.164" => 0,
            "imsi" => 1,
            "sip_uri" | "sip-uri" | "sip" => 2,
            "nai" => 3,
            "private" => 4,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown subscription_id type alias {other:?}"
                )));
            }
        }
    };
    Ok((data, type_num))
}

/// Shell-style glob matcher supporting `*` (any run) and `?` (one char).
/// Iterative with backtracking — no allocation, no regex dependency.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            // Backtrack: let the last `*` swallow one more char.
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Register a `@diameter.on_request` handler with an optional command filter
/// (stored as the registry's filter field, mirroring `@proxy.on_request`).
fn register_on_request(
    python: Python<'_>,
    func: &Bound<'_, PyAny>,
    filter: Option<&str>,
) -> PyResult<()> {
    let asyncio = python.import("asyncio")?;
    let is_async = asyncio
        .call_method1("iscoroutinefunction", (func,))?
        .is_truthy()?;
    let registry = python.import("_siphon_registry")?;
    let filter_obj: Bound<'_, PyAny> = match filter {
        Some(value) => value.into_pyobject(python)?.into_any(),
        None => python.None().into_bound(python),
    };
    registry.call_method1("register", ("diameter.on_request", filter_obj, func, is_async))?;
    Ok(())
}

/// Build a decorator closure that registers its argument as a
/// `@diameter.on_request` handler scoped by `filter`.
fn make_on_request_decorator(
    python: Python<'_>,
    filter: Option<String>,
) -> PyResult<Bound<'_, PyAny>> {
    let closure = pyo3::types::PyCFunction::new_closure(
        python,
        None,
        None,
        move |args: &Bound<'_, pyo3::types::PyTuple>,
              _kwargs: Option<&Bound<'_, PyDict>>|
              -> PyResult<Py<PyAny>> {
            let py = args.py();
            let func = args.get_item(0)?;
            register_on_request(py, &func, filter.as_deref())?;
            Ok(func.unbind())
        },
    )?;
    Ok(closure.into_any())
}

/// Validate a `@diameter.on_request` filter (`"App:CMD[|CMD…]"` or
/// `"CMD[|CMD…]"`) at decoration time — unknown app/command names raise, so a
/// typo fails loudly instead of registering a handler that never fires. Uses
/// the same vocabulary (`command_code_by_name` / `app_id_by_name`) the dispatch
/// resolves against.
fn validate_request_filter(filter: &str) -> PyResult<()> {
    let (app, commands) = match filter.split_once(':') {
        Some((app, commands)) => (Some(app.trim()), commands),
        None => (None, filter),
    };
    if let Some(app) = app {
        if dictionary::app_id_by_name(app).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter application in on_request filter: {app:?}"
            )));
        }
    }
    let mut saw_command = false;
    for command in commands.split('|') {
        let command = command.trim();
        if command.is_empty() {
            continue;
        }
        saw_command = true;
        if dictionary::command_code_by_name(command).is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter command in on_request filter: {command:?}"
            )));
        }
    }
    if !saw_command {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "empty on_request filter",
        ));
    }
    Ok(())
}

/// Python-visible event sink (`diameter.event_sink`). `emit(row: dict)`
/// serializes via `json.dumps` and forwards to the Rust batch writer.
#[pyclass(name = "DiameterEventSink", skip_from_py_object)]
#[derive(Clone, Default)]
pub struct PyEventSink {
    sink: Option<Arc<crate::diameter::event_sink::EventSink>>,
}

#[pymethods]
impl PyEventSink {
    /// Emit a JSON-serializable row. No-op when no sink is configured.
    fn emit(&self, python: Python<'_>, row: &Bound<'_, PyAny>) -> PyResult<()> {
        let Some(sink) = &self.sink else {
            return Ok(());
        };
        let json_module = python.import("json")?;
        let serialized: String = json_module.call_method1("dumps", (row,))?.extract()?;
        sink.emit(serialized);
        Ok(())
    }
}

/// Python-visible Diameter namespace.
#[pyclass(name = "DiameterNamespace", skip_from_py_object)]
pub struct PyDiameter {
    manager: Arc<DiameterManager>,
    /// JSON snapshot of `diameter.{tenants,listen}` for `diameter.config`
    /// (loaded once at startup — siphon has no YAML hot-reload).
    config_json: Option<Arc<String>>,
    event_sink: PyEventSink,
}

impl PyDiameter {
    pub fn new(manager: Arc<DiameterManager>) -> Self {
        Self {
            manager,
            config_json: None,
            event_sink: PyEventSink::default(),
        }
    }

    /// Attach server mode runtime: the config snapshot exposed as
    /// `diameter.config`, and the event sink behind `diameter.event_sink`.
    pub fn with_server_runtime(
        mut self,
        config_json: String,
        event_sink: Option<Arc<crate::diameter::event_sink::EventSink>>,
    ) -> Self {
        self.config_json = Some(Arc::new(config_json));
        self.event_sink = PyEventSink { sink: event_sink };
        self
    }

    /// Pick a Diameter peer for an Rf ACR.
    ///
    /// Resolution order matches the existing Cx/Sh/Rx pattern but allows
    /// callers to override:
    ///
    /// 1. Explicit `peer` argument from Python (e.g. ``peer="cdf1"``).
    /// 2. Otherwise the first registered client (`any_client`) — operators
    ///    typically connect a single CDF, and routing tables aren't yet
    ///    consulted by other applications either.
    pub(crate) fn pick_rf_peer(&self, peer: Option<&str>) -> Option<Arc<DiameterClient>> {
        if let Some(name) = peer {
            return self.manager.client(name);
        }
        self.manager.any_client()
    }
}

/// Build an `ImsChargingData` from the kwargs accepted by every `rf_acr_*`
/// binding.  Returns `Ok(None)` when no IMS-Information kwarg was passed —
/// the call site then skips the `Service-Information → IMS-Information`
/// emission entirely (callers that want a pure SMS-Information record
/// shouldn't also drop an empty IMS-Information envelope on the wire).
/// Returns a `PyValueError` on unrecognized role / functionality strings
/// so script errors fail loudly rather than silently dropping the AVP.
fn build_ims_data(
    calling_party: Option<&str>,
    called_party: Option<&str>,
    sip_method: Option<&str>,
    role_of_node: Option<&str>,
    node_functionality: Option<&str>,
    ims_charging_identifier: Option<&str>,
    user_session_id: Option<&str>,
    originating_ioi: Option<&str>,
    terminating_ioi: Option<&str>,
    application_server: Option<&str>,
    application_provided_called_party_address: Option<&str>,
    incoming_trunk_group_id: Option<&str>,
    outgoing_trunk_group_id: Option<&str>,
    visited_network_id: Option<&str>,
    cause_code: Option<i32>,
) -> PyResult<Option<ImsChargingData>> {
    let nothing_set = calling_party.is_none()
        && called_party.is_none()
        && sip_method.is_none()
        && role_of_node.is_none()
        && node_functionality.is_none()
        && ims_charging_identifier.is_none()
        && user_session_id.is_none()
        && originating_ioi.is_none()
        && terminating_ioi.is_none()
        && application_server.is_none()
        && application_provided_called_party_address.is_none()
        && incoming_trunk_group_id.is_none()
        && outgoing_trunk_group_id.is_none()
        && visited_network_id.is_none()
        && cause_code.is_none();
    if nothing_set {
        return Ok(None);
    }

    let role = match role_of_node {
        Some(value) => Some(NodeRole::from_str_ci(value).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown role_of_node {value:?}; expected one of \
                 'originating'/'terminating'/'proxy'/'b2bua'"
            ))
        })?),
        None => None,
    };
    let func = match node_functionality {
        Some(value) => Some(NodeFunctionality::from_str_ci(value).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown node_functionality {value:?}; expected one of \
                 'scscf'/'pcscf'/'icscf'/'mrfc'/'mgcf'/'bgcf'/'as'/'ibcf'/\
                 'ecscf'/'atcf'/'mmtel'/'tpf'/'atgw'"
            ))
        })?),
        None => None,
    };
    Ok(Some(ImsChargingData {
        calling_party: calling_party.map(str::to_owned),
        called_party: called_party.map(str::to_owned),
        sip_method: sip_method.map(str::to_owned),
        event: None,
        role_of_node: role,
        node_functionality: func,
        ims_charging_identifier: ims_charging_identifier.map(str::to_owned),
        cause_code,
        user_session_id: user_session_id.map(str::to_owned),
        request_timestamp: None,
        response_timestamp: None,
        originating_ioi: originating_ioi.map(str::to_owned),
        terminating_ioi: terminating_ioi.map(str::to_owned),
        application_server: application_server.map(str::to_owned),
        application_provided_called_party_address: application_provided_called_party_address
            .map(str::to_owned),
        incoming_trunk_group_id: incoming_trunk_group_id.map(str::to_owned),
        outgoing_trunk_group_id: outgoing_trunk_group_id.map(str::to_owned),
        visited_network_id: visited_network_id.map(str::to_owned),
    }))
}

/// Parse an IP address kwarg passed in to one of the SMS Address-typed
/// AVPs (SCCP / client / MTC-IWF).  Returns `Ok(None)` for `None` input.
fn parse_optional_ip(label: &str, value: Option<&str>) -> PyResult<Option<std::net::IpAddr>> {
    match value {
        None => Ok(None),
        Some(text) => text
            .parse::<std::net::IpAddr>()
            .map(Some)
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "{label} expects an IPv4/IPv6 literal, got {text:?}"
                ))
            }),
    }
}

/// Build a `SmsChargingData` from the SMS-specific kwargs accepted by
/// every `rf_acr_*` binding.  Returns `Ok(None)` when no SMS-Information
/// kwarg was passed — keeps the wire free of an empty SMS-Information
/// envelope on IMS-only call records.
///
/// `originating_ioi`, `terminating_ioi`, and `user_session_id` are
/// *shared* with [`build_ims_data`] — they flow into whichever envelope
/// is emitted but do not, on their own, trigger SMS-Information.  A
/// script that only passes IOIs gets IMS-Information (current behavior);
/// a script that passes any SMS-specific kwarg gets SMS-Information with
/// the shared fields propagated.
fn build_sms_data(
    originator_address: Option<&str>,
    recipient_address: Option<&str>,
    originator_sccp_address: Option<&str>,
    recipient_sccp_address: Option<&str>,
    sm_message_type: Option<u32>,
    reply_path_requested: Option<u32>,
    sm_user_data_header: Option<Vec<u8>>,
    sm_service_type: Option<u32>,
    sms_node: Option<u32>,
    sm_discharge_time: Option<f64>,
    number_of_messages_sent: Option<u32>,
    client_address: Option<&str>,
    data_coding_scheme: Option<i32>,
    sms_result: Option<u32>,
    sm_protocol_id: Option<Vec<u8>>,
    sm_status: Option<Vec<u8>>,
    application_port_identifier: Option<u32>,
    external_identifier: Option<&str>,
    sm_device_trigger_indicator: Option<u32>,
    mtc_iwf_address: Option<&str>,
    originating_ioi: Option<&str>,
    terminating_ioi: Option<&str>,
    user_session_id: Option<&str>,
) -> PyResult<Option<SmsChargingData>> {
    // Trigger condition: at least one SMS-specific kwarg.  Shared
    // kwargs (IOIs, user-session-id) do not count — they're propagated
    // into whichever envelope is emitted.
    let sms_specific_set = originator_address.is_some()
        || recipient_address.is_some()
        || originator_sccp_address.is_some()
        || recipient_sccp_address.is_some()
        || sm_message_type.is_some()
        || reply_path_requested.is_some()
        || sm_user_data_header.is_some()
        || sm_service_type.is_some()
        || sms_node.is_some()
        || sm_discharge_time.is_some()
        || number_of_messages_sent.is_some()
        || client_address.is_some()
        || data_coding_scheme.is_some()
        || sms_result.is_some()
        || sm_protocol_id.is_some()
        || sm_status.is_some()
        || application_port_identifier.is_some()
        || external_identifier.is_some()
        || sm_device_trigger_indicator.is_some()
        || mtc_iwf_address.is_some();
    if !sms_specific_set {
        return Ok(None);
    }

    let discharge_time = sm_discharge_time.map(|secs| {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(secs.max(0.0))
    });

    Ok(Some(SmsChargingData {
        originator_address: originator_address.map(str::to_owned),
        recipient_address: recipient_address.map(str::to_owned),
        originator_sccp_address: parse_optional_ip(
            "originator_sccp_address",
            originator_sccp_address,
        )?,
        recipient_sccp_address: parse_optional_ip(
            "recipient_sccp_address",
            recipient_sccp_address,
        )?,
        sm_message_type,
        reply_path_requested,
        sm_user_data_header,
        sm_service_type,
        sms_node,
        sm_discharge_time: discharge_time,
        number_of_messages_sent,
        client_address: parse_optional_ip("client_address", client_address)?,
        data_coding_scheme,
        sms_result,
        sm_protocol_id,
        sm_status,
        application_port_identifier,
        external_identifier: external_identifier.map(str::to_owned),
        sm_device_trigger_indicator,
        mtc_iwf_address: parse_optional_ip("mtc_iwf_address", mtc_iwf_address)?,
        originating_ioi: originating_ioi.map(str::to_owned),
        terminating_ioi: terminating_ioi.map(str::to_owned),
        user_session_id: user_session_id.map(str::to_owned),
    }))
}

/// Convert an `AccountingAnswer` to the dict shape every `rf_acr_*` binding
/// returns to Python.
fn accounting_answer_to_dict<'py>(
    python: Python<'py>,
    answer: AccountingAnswer,
    fallback_session_id: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item("result_code", answer.result_code)?;
    let session_id = answer
        .session_id
        .or_else(|| fallback_session_id.map(str::to_owned));
    dict.set_item("session_id", session_id)?;
    dict.set_item("record_number", answer.record_number)?;
    dict.set_item("interim_interval", answer.interim_interval)?;
    Ok(dict)
}

#[pymethods]
impl PyDiameter {
    /// Check if a peer is connected.
    ///
    /// Args:
    ///     peer_name: Name of the Diameter peer (e.g. "hss1").
    ///
    /// Returns:
    ///     ``True`` if the peer has a registered client connection.
    fn is_connected(&self, peer_name: &str) -> bool {
        self.manager.client(peer_name).is_some()
    }

    /// Get the number of connected peers.
    ///
    /// Returns:
    ///     The number of peers currently registered in the manager.
    fn peer_count(&self) -> usize {
        self.manager.peer_count()
    }

    /// Send a Cx User-Authorization-Request to the HSS.
    ///
    /// Used by the I-CSCF to discover which S-CSCF should handle a REGISTER.
    /// The HSS returns the assigned S-CSCF in the Server-Name AVP.
    ///
    /// Args:
    ///     public_identity: The user's public identity (e.g. ``"sip:alice@ims.example.com"``).
    ///     visited_network_id: Visited network identifier (defaults to ``""``).
    ///     user_auth_type: User-Authorization-Type AVP value (3GPP TS 29.229).
    ///         ``0`` = REGISTRATION, ``1`` = DE_REGISTRATION,
    ///         ``2`` = REGISTRATION_AND_CAPABILITIES.  Omit to not send the AVP.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``server_name`` (str or None),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, visited_network_id=None, user_auth_type=None))]
    fn cx_uar<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        visited_network_id: Option<&str>,
        user_auth_type: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_uar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let visited = visited_network_id.unwrap_or("");
        let answer = crate::script::detach_block_on(
            client.send_uar(public_identity, visited, user_auth_type),
        );

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let server_name = required_str(&message.avps, "Server-Name");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("server_name", server_name)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_uar failed");
                Ok(None)
            }
        }
    }

    /// Send a Cx Server-Assignment-Request to the HSS.
    ///
    /// Used by the S-CSCF after successful REGISTER authentication to confirm
    /// server assignment and download the user profile (iFC XML).
    ///
    /// Args:
    ///     public_identity: The user's public identity.
    ///     server_name: This S-CSCF's SIP URI (defaults to ``""``).
    ///     assignment_type: Server-Assignment-Type (default 1 = REGISTRATION).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``user_data`` (str or None, iFC XML),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, server_name=None, assignment_type=1))]
    fn cx_sar<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        server_name: Option<&str>,
        assignment_type: u32,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_sar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let name = server_name.unwrap_or("");
        let answer = crate::script::detach_block_on(
            client.send_sar(public_identity, name, assignment_type),
        );

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                // User-Data AVP (code 606, 3GPP) carries iFC XML as OctetString
                let user_data = octet_string_as_utf8(&message.avps, "User-Data");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("user_data", user_data)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_sar failed");
                Ok(None)
            }
        }
    }

    /// Send a Cx Location-Info-Request to the HSS.
    ///
    /// Used by the I-CSCF to find the serving S-CSCF for non-REGISTER requests
    /// (INVITE, SUBSCRIBE, etc.).
    ///
    /// Args:
    ///     public_identity: The target user's public identity.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``server_name`` (str or None),
    ///     or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity,))]
    fn cx_lir<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("cx_lir: no Diameter peer connected");
                return Ok(None);
            }
        };

        let answer = crate::script::detach_block_on(
            client.send_lir(public_identity),
        );

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let server_name = required_str(&message.avps, "Server-Name");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("server_name", server_name)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "cx_lir failed");
                Ok(None)
            }
        }
    }

    /// Send an S6a Authentication-Information-Request to the HSS (MME role).
    ///
    /// Args:
    ///     imsi: Subscriber IMSI (User-Name).
    ///     visited_plmn_id: 3-octet MCC/MNC (TS 23.003 §12.1), as ``bytes``.
    ///     num_vectors: Number of E-UTRAN vectors to request (default 1).
    ///     immediate_response_preferred: TS 29.272 §7.3.10 (default True).
    ///     resync_info: Optional RAND‖AUTS ``bytes`` for SQN resync.
    ///     peer: Optional peer name (defaults to the first connected peer).
    ///
    /// Returns:
    ///     Dict ``{"result_code": int, "vectors": [{"rand","xres","autn","kasme"}]}``
    ///     (vector fields are ``bytes``), or ``None`` if no peer is connected.
    #[pyo3(signature = (imsi, visited_plmn_id, num_vectors=1, immediate_response_preferred=true, resync_info=None, peer=None))]
    #[allow(clippy::too_many_arguments)]
    fn s6a_air<'py>(
        &self,
        python: Python<'py>,
        imsi: &str,
        visited_plmn_id: Vec<u8>,
        num_vectors: u32,
        immediate_response_preferred: bool,
        resync_info: Option<Vec<u8>>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("s6a_air: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_air(
                imsi,
                &visited_plmn_id,
                num_vectors,
                immediate_response_preferred,
                resync_info.as_deref(),
            ))
        });
        match answer {
            Ok(message) => {
                let parsed = match crate::diameter::s6a::parse_aia(&message) {
                    Some(parsed) => parsed,
                    None => return Ok(None),
                };
                let dict = PyDict::new(python);
                dict.set_item("result_code", parsed.result_code)?;
                let vectors = pyo3::types::PyList::empty(python);
                for vector in &parsed.vectors {
                    let item = PyDict::new(python);
                    item.set_item("rand", pyo3::types::PyBytes::new(python, &vector.rand))?;
                    item.set_item("xres", pyo3::types::PyBytes::new(python, &vector.xres))?;
                    item.set_item("autn", pyo3::types::PyBytes::new(python, &vector.autn))?;
                    item.set_item("kasme", pyo3::types::PyBytes::new(python, &vector.kasme))?;
                    vectors.append(item)?;
                }
                dict.set_item("vectors", vectors)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "s6a_air failed");
                Ok(None)
            }
        }
    }

    /// Send an S6a Update-Location-Request to the HSS (MME role).
    ///
    /// Args:
    ///     imsi: Subscriber IMSI.
    ///     rat_type: TS 29.272 §7.3.13 (default 1004 = EUTRAN).
    ///     ulr_flags: TS 29.272 §7.3.7 (default 0).
    ///     visited_plmn_id: 3-octet MCC/MNC, as ``bytes``.
    ///     peer: Optional peer name.
    ///
    /// Returns:
    ///     Dict ``{"result_code": int, "ula_flags": int|None,
    ///     "has_subscription_data": bool}`` or ``None``.
    #[pyo3(signature = (imsi, visited_plmn_id, rat_type=1004, ulr_flags=0, peer=None))]
    fn s6a_ulr<'py>(
        &self,
        python: Python<'py>,
        imsi: &str,
        visited_plmn_id: Vec<u8>,
        rat_type: u32,
        ulr_flags: u32,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("s6a_ulr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_ulr(
                imsi,
                rat_type,
                ulr_flags,
                &visited_plmn_id,
            ))
        });
        match answer {
            Ok(message) => {
                let parsed = match crate::diameter::s6a::parse_ula(&message) {
                    Some(parsed) => parsed,
                    None => return Ok(None),
                };
                let dict = PyDict::new(python);
                dict.set_item("result_code", parsed.result_code)?;
                dict.set_item("ula_flags", parsed.ula_flags)?;
                dict.set_item("has_subscription_data", parsed.has_subscription_data)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "s6a_ulr failed");
                Ok(None)
            }
        }
    }

    /// Send an S6a Purge-UE-Request to the HSS (MME role).
    ///
    /// Returns ``{"result_code": int}`` or ``None`` if no peer is connected.
    #[pyo3(signature = (imsi, pur_flags=None, peer=None))]
    fn s6a_purge_ue<'py>(
        &self,
        python: Python<'py>,
        imsi: &str,
        pur_flags: Option<u32>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("s6a_purge_ue: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.send_purge_ue(imsi, pur_flags))
        });
        match answer {
            Ok(message) => {
                let dict = PyDict::new(python);
                dict.set_item("result_code", extract_result_code(&message.avps))?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "s6a_purge_ue failed");
                Ok(None)
            }
        }
    }

    /// Send an Rx AA-Request to authorize an IMS media session.
    ///
    /// Used by the P-CSCF when SDP is negotiated during session setup
    /// (INVITE / 200 OK / UPDATE) to request dedicated bearer resources.
    ///
    /// Args:
    ///     session_id: Reuse an existing Rx session ID (modification AAR per
    ///         TS 29.214 §4.4.5).  ``None`` allocates a new session.
    ///     framed_ip: UE IPv4 address (Framed-IP-Address AVP).
    ///     framed_ipv6: UE IPv6 address (Framed-IPv6-Prefix AVP, raw bytes).
    ///     media_components: List of media-component dicts.  Each dict
    ///         mirrors :class:`MediaComponent` (TS 29.214 §5.3.7) — see
    ///         the project docs for the full shape.
    ///     af_application_id: AF-Application-Identifier (default
    ///         ``"IMS Services"``).
    ///     subscription_id: Optional ``(data, type)`` tuple. ``type`` is an
    ///         int per RFC 4006 §8.47 — 0=E.164, 1=IMSI, 2=SIP_URI, 3=NAI,
    ///         4=PRIVATE — or a string alias (``"sip_uri"`` / ``"e164"`` /
    ///         ``"imsi"`` / ``"nai"`` / ``"private"``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``session_id`` (str),
    ///     or ``None`` if no Rx peer is connected.
    #[pyo3(signature = (
        session_id=None,
        framed_ip=None,
        framed_ipv6=None,
        media_components=None,
        af_application_id="IMS Services",
        subscription_id=None,
    ))]
    fn rx_aar<'py>(
        &self,
        python: Python<'py>,
        session_id: Option<&str>,
        framed_ip: Option<&str>,
        framed_ipv6: Option<&Bound<'py, PyAny>>,
        media_components: Option<&Bound<'py, PyAny>>,
        af_application_id: &str,
        subscription_id: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        use crate::diameter::codec::{
            encode_avp_grouped, encode_avp_octet, encode_avp_octet_3gpp, encode_avp_u32,
            encode_avp_utf8, encode_diameter_message, FLAG_PROXIABLE, FLAG_REQUEST,
        };
        use crate::diameter::dictionary::{self, avp};
        use crate::diameter::rx::MediaComponent;

        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("rx_aar: no Diameter peer connected");
                return Ok(None);
            }
        };

        let components: Vec<MediaComponent> = match media_components {
            Some(obj) => parse_media_components(obj)?,
            None => Vec::new(),
        };

        let framed_ipv6_bytes: Option<Vec<u8>> = match framed_ipv6 {
            Some(obj) => Some(extract_ipv6_prefix(obj)?),
            None => None,
        };

        let subscription_parsed: Option<(String, u32)> = match subscription_id {
            Some(obj) => Some(extract_subscription_id(obj)?),
            None => None,
        };

        let peer = client.peer();
        let hbh = peer.next_hbh();
        let e2e = peer.next_e2e();
        let session = session_id
            .map(String::from)
            .unwrap_or_else(|| peer.new_session_id());
        let config = peer.config();

        let mut payload = Vec::with_capacity(512);
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session));
        payload.extend_from_slice(&encode_avp_u32(
            avp::AUTH_APPLICATION_ID,
            dictionary::RX_APP_ID,
        ));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        payload.extend_from_slice(&encode_avp_utf8(
            avp::DESTINATION_REALM,
            &config.destination_realm,
        ));

        // AF-Application-Identifier — TS 29.214 §5.3.4
        payload.extend_from_slice(&encode_avp_octet_3gpp(
            avp::AF_APPLICATION_IDENTIFIER,
            af_application_id.as_bytes(),
        ));

        // One Media-Component-Description per SDP m= section
        for component in &components {
            payload.extend_from_slice(&component.encode());
        }

        if let Some(ip) = framed_ip {
            match ip.parse::<std::net::Ipv4Addr>() {
                Ok(addr) => payload.extend_from_slice(&encode_avp_octet(
                    avp::FRAMED_IP_ADDRESS,
                    &addr.octets(),
                )),
                Err(_) => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "framed_ip is not a valid IPv4 address: {ip}"
                    )));
                }
            }
        }

        if let Some(bytes) = framed_ipv6_bytes.as_deref() {
            payload.extend_from_slice(&encode_avp_octet(avp::FRAMED_IPV6_PREFIX, bytes));
        }

        if let Some((data, type_num)) = subscription_parsed.as_ref() {
            let mut sub_inner = Vec::new();
            sub_inner.extend_from_slice(&encode_avp_u32(avp::SUBSCRIPTION_ID_TYPE, *type_num));
            sub_inner.extend_from_slice(&encode_avp_utf8(avp::SUBSCRIPTION_ID_DATA, data));
            payload.extend_from_slice(&encode_avp_grouped(avp::SUBSCRIPTION_ID, &sub_inner));
        }

        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_AA,
            dictionary::RX_APP_ID,
            hbh,
            e2e,
            &payload,
        );

        let answer = crate::script::detach_block_on(peer.send_request(wire));

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("session_id", &session)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "rx_aar failed");
                Ok(None)
            }
        }
    }


    /// Register the server mode CER identity callback.
    ///
    /// Called for an already-authenticated peer (both Rust auth gates have
    /// passed) to decide which identity to advertise in the CEA. Return
    /// ``(origin_host, origin_realm)`` to accept, or ``None`` to reject the CER.
    ///
    /// ```python,ignore
    /// @diameter.on_inbound_cer
    /// def cer_received(peer_addr, peer_name, asserted_origin_host):
    ///     identity = diameter.config["tenants"][_tenant(peer_addr)]["identity"]
    ///     return identity["origin_host"], identity["origin_realm"]
    /// ```
    #[staticmethod]
    fn on_inbound_cer(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            (
                "diameter.on_inbound_cer",
                python.None(),
                func.bind(python),
                is_async,
            ),
        )?;
        Ok(func)
    }

    /// Register the server mode inbound-request dispatcher.
    ///
    /// Called for inbound requests (R-bit set) from an authenticated peer.
    /// Return ``req.reject(code)``, ``await req.forward_to(peer, …)``,
    /// ``req.answer(code)``, or ``None`` (→ DIAMETER_UNABLE_TO_DELIVER, 3002).
    ///
    /// An optional filter scopes the handler to specific commands, mirroring
    /// ``@proxy.on_request("INVITE")``:
    ///   - bare ``@diameter.on_request`` — every command (the Diameter server relay catch-all)
    ///   - ``@diameter.on_request("ULR")`` — that command, any application
    ///   - ``@diameter.on_request("ULR|AIR")`` — several commands
    ///   - ``@diameter.on_request("S6a:ULR")`` — app-qualified. The most specific
    ///     matching handler wins (``App:CMD`` > ``CMD`` > catch-all).
    /// App/command names are validated at decoration time (typos raise).
    ///
    /// ```python,ignore
    /// @diameter.on_request("S6a:ULR")
    /// async def update_location(req):
    ///     return req.answer(2001)
    /// ```
    #[staticmethod]
    #[pyo3(signature = (arg=None))]
    fn on_request<'py>(
        python: Python<'py>,
        arg: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        match arg {
            // Bare decorator: @diameter.on_request  (arg is the handler).
            Some(value) if value.is_callable() => {
                register_on_request(python, &value, None)?;
                Ok(value)
            }
            // Filtered: @diameter.on_request("S6a:ULR") → returns a decorator.
            Some(value) => {
                let filter: String = value.extract().map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(
                        "diameter.on_request expects a handler function or a filter string",
                    )
                })?;
                validate_request_filter(&filter)?;
                make_on_request_decorator(python, Some(filter))
            }
            // @diameter.on_request() with empty parens → catch-all decorator.
            None => make_on_request_decorator(python, None),
        }
    }

    /// Register the server mode answer-rewrite hook.
    ///
    /// Called with ``fn(req, answer)`` on the answer an ``on_request`` handler
    /// produced — whether relayed via ``forward_to`` or built by
    /// ``answer``/``reject`` — just before it goes back upstream. A central
    /// place to rewrite answer AVPs for every reply (topology hiding,
    /// Origin-Host/Result-Code mapping) instead of repeating it in each
    /// ``on_request`` handler. Mutate ``answer`` in place; the return value is
    /// ignored. Both sync and async handlers are supported.
    ///
    /// ```python,ignore
    /// @diameter.on_reply
    /// def hide_topology(req, answer):
    ///     answer.set_avp("Origin-Host", b"diam.example.net")
    /// ```
    #[staticmethod]
    fn on_reply(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            (
                "diameter.on_reply",
                python.None(),
                func.bind(python),
                is_async,
            ),
        )?;
        Ok(func)
    }

    /// Register the server mode post-answer hook.
    ///
    /// Called after the answer has been sent upstream with
    /// ``fn(req, answer, latency_us)`` — typically to emit an event.
    #[staticmethod]
    fn on_request_completed(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            (
                "diameter.on_request_completed",
                python.None(),
                func.bind(python),
                is_async,
            ),
        )?;
        Ok(func)
    }

    /// Build a backend peer pool for `target` (a peer name or list of names)
    /// resolved through the connected peers (state-as-truth liveness).
    ///
    /// ```python,ignore
    /// pool = diameter.peer_pool(["hss-a", "hss-b"])
    /// peer = pool.pick_sticky(req.session_id, ttl_secs=300)
    /// ```
    ///
    /// `tenant` is an optional label used only to scope the pool; it defaults
    /// to `"default"` and can be left unset for single-domain servers.
    #[pyo3(signature = (target, tenant=None))]
    fn peer_pool(
        &self,
        target: &Bound<'_, PyAny>,
        tenant: Option<String>,
    ) -> PyResult<crate::script::api::diameter_server::PyPeerPool> {
        let names: Vec<String> = if let Ok(single) = target.extract::<String>() {
            vec![single]
        } else {
            target.extract::<Vec<String>>().map_err(|_| {
                pyo3::exceptions::PyTypeError::new_err(
                    "peer_pool target must be a peer name or list of names",
                )
            })?
        };
        let pool = std::sync::Arc::new(crate::diameter::pool::PeerPool::new(
            tenant.unwrap_or_else(|| "default".to_string()),
            std::sync::Arc::clone(&self.manager),
            names,
        ));
        Ok(crate::script::api::diameter_server::PyPeerPool::new(pool))
    }

    /// Whether `addr` falls within `cidr` (helper for routing scripts).
    #[staticmethod]
    fn ip_in_cidr(addr: &str, cidr: &str) -> PyResult<bool> {
        let ip: std::net::IpAddr = addr
            .parse()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err(format!("bad IP: {addr}")))?;
        let net = crate::diameter::auth::parse_cidr(cidr)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        Ok(net.contains(&ip))
    }

    /// Shell-style glob match (`*`, `?`) — for route-table matching in scripts.
    #[staticmethod]
    fn fnmatch(value: &str, pattern: &str) -> bool {
        glob_match(pattern.as_bytes(), value.as_bytes())
    }

    /// Monotonic-ish wall-clock microseconds since the Unix epoch.
    #[staticmethod]
    fn now_us() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    /// Read-only view of the parsed `diameter` config (`tenants`, `listen`),
    /// loaded once at startup. Returns an empty dict when no Diameter server config is set.
    ///
    /// Note: siphon has no YAML hot-reload — a route-table change needs a
    /// restart in v1.
    #[getter]
    fn config<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let json_module = python.import("json")?;
        match &self.config_json {
            Some(snapshot) => Ok(json_module.call_method1("loads", (snapshot.as_str(),))?),
            None => Ok(python.import("builtins")?.call_method0("dict")?),
        }
    }

    /// The generic event sink (`diameter.event_sink.emit(row)`).
    #[getter]
    fn event_sink(&self) -> PyEventSink {
        self.event_sink.clone()
    }

    /// Send a Sh User-Data-Request to the HSS (AS role).
    ///
    /// Used by an Application Server (e.g. MMTEL-AS) to fetch user profile
    /// data (simservs XML, iFC, public identities, etc.).
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: One of the TS 29.328 §7.6 Data-Reference values
    ///         (e.g. ``0`` = Repository-Data, ``11`` = IMS-User-State,
    ///         ``13`` = Initial-Filter-Criteria).  Accepts an ``int`` or a
    ///         ``list[int]`` for multiple references.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required when Data-Reference is Repository-Data.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``user_data`` (str or None,
    ///     the Sh-Data XML payload), or ``None`` if no Diameter peer is connected.
    #[pyo3(signature = (public_identity, data_reference, service_indication=None))]
    fn sh_udr<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: &Bound<'_, PyAny>,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_udr: no Diameter peer connected");
                return Ok(None);
            }
        };

        let references = extract_references(data_reference)?;

        let answer = crate::script::detach_block_on(client.send_udr(
            public_identity,
            &references,
            service_indication,
        ));

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let user_data = octet_string_as_utf8(&message.avps, "User-Data-Sh");

                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                dict.set_item("user_data", user_data)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_udr failed");
                Ok(None)
            }
        }
    }

    /// Send a Sh Profile-Update-Request to the HSS (AS role).
    ///
    /// Used by an Application Server to upload updated user profile data
    /// (e.g. simservs XML after XCAP PUT).
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: Data-Reference value (usually ``0`` for Repository-Data).
    ///     xml: UTF-8 XML payload for the User-Data-Sh AVP.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required by the HSS when Data-Reference is Repository-Data
    ///         (TS 29.328 §6.1.3 — Repository-Data is keyed on
    ///         ``(Public-Identity, Service-Indication)``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), or ``None`` if no peer is connected.
    #[pyo3(signature = (public_identity, data_reference, xml, service_indication=None))]
    fn sh_pur<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: u32,
        xml: &str,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_pur: no Diameter peer connected");
                return Ok(None);
            }
        };

        let answer = crate::script::detach_block_on(client.send_pur(
            public_identity,
            data_reference,
            xml,
            service_indication,
        ));

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_pur failed");
                Ok(None)
            }
        }
    }

    /// Send a Sh Subscribe-Notifications-Request to the HSS (AS role).
    ///
    /// Used by an Application Server to subscribe (or unsubscribe) for
    /// notifications about a user's profile changes. The HSS will later push
    /// updates via PNR — register a handler via ``@diameter.on_pnr``.
    ///
    /// Args:
    ///     public_identity: Target user's public identity.
    ///     data_reference: Data-Reference (int) or list of references to subscribe to.
    ///     subs_req_type: ``0`` = SUBSCRIBE, ``1`` = UNSUBSCRIBE.
    ///     service_indication: Service indication (e.g. ``"simservs"``),
    ///         required by the HSS when Data-Reference is Repository-Data
    ///         (TS 29.328 §6.1.4 — Repository-Data is keyed on
    ///         ``(Public-Identity, Service-Indication)``).
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), or ``None`` if no peer is connected.
    #[pyo3(signature = (public_identity, data_reference, subs_req_type, service_indication=None))]
    fn sh_snr<'py>(
        &self,
        python: Python<'py>,
        public_identity: &str,
        data_reference: &Bound<'_, PyAny>,
        subs_req_type: u32,
        service_indication: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sh_snr: no Diameter peer connected");
                return Ok(None);
            }
        };

        let references = extract_references(data_reference)?;

        let answer = crate::script::detach_block_on(client.send_snr(
            public_identity,
            &references,
            subs_req_type,
            service_indication,
        ));

        match answer {
            Ok(message) => {
                let result_code = extract_result_code(&message.avps);
                let dict = PyDict::new(python);
                dict.set_item("result_code", result_code)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sh_snr failed");
                Ok(None)
            }
        }
    }

    #[pyo3(signature = (session_id,))]
    fn rx_str(&self, session_id: &str) -> PyResult<Option<u32>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("rx_str: no Diameter peer connected");
                return Ok(None);
            }
        };

        let peer = client.peer();
        let answer = crate::script::detach_block_on(crate::diameter::rx::send_str(
            peer,
            session_id,
            crate::diameter::rx::TERMINATION_CAUSE_LOGOUT,
        ));

        match answer {
            Ok(result_code) => Ok(Some(result_code)),
            Err(error) => {
                warn!(error = %error, "rx_str failed");
                Ok(None)
            }
        }
    }

    /// Send an S6c Send-Routing-Info-for-SM request to the HSS.
    ///
    /// Used by the SMSC role (e.g. ip-sm-gw) to discover the served-node
    /// (MME or SGSN) for an MT-SMS delivery. The HSS answer carries the
    /// served-node identity which the SMSC then uses on SGd as the
    /// destination for the actual MT-Forward-Short-Message (TFR).
    ///
    /// Args:
    ///     msisdn: E.164 number of the called party (no leading ``+``).
    ///     sc_address: GT of the originating SMSC.
    ///     sm_rp_mti: SM-RP Message Type Indicator —
    ///         0 = SMS Deliver (typical MT delivery),
    ///         1 = SMS Status Report.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int), ``user_name`` (IMSI, optional),
    ///     ``sgsn_number`` (str, set when 2G/3G delivery), and
    ///     ``mme_number_for_mt_sms`` (str, set when LTE delivery).
    ///     ``None`` when no Diameter peer is connected.
    #[pyo3(signature = (msisdn, sc_address, sm_rp_mti=None))]
    fn s6c_srr<'py>(
        &self,
        python: Python<'py>,
        msisdn: &str,
        sc_address: &str,
        sm_rp_mti: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("s6c_srr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = crate::script::detach_block_on(
            client.send_srr(msisdn, sc_address, sm_rp_mti),
        );
        match answer {
            Ok(message) => match crate::diameter::s6c::parse_sra(&message) {
                Some(sra) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", sra.result_code)?;
                    dict.set_item("experimental_result_code", sra.experimental_result_code)?;
                    dict.set_item("user_name", sra.user_name)?;
                    dict.set_item("sgsn_number", sra.sgsn_number)?;
                    dict.set_item("mme_number_for_mt_sms", sra.mme_number_for_mt_sms)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("s6c_srr: HSS answer was not parseable as SRA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "s6c_srr failed");
                Ok(None)
            }
        }
    }

    /// Send an S6c Report-SM-Delivery-Status request to the HSS.
    ///
    /// Used after delivery to inform the HSS of the final outcome so it
    /// can release any held queueing state.
    ///
    /// Args:
    ///     user_name: IMSI of the served subscriber.
    ///     sc_address: GT of the originating SMSC.
    ///     delivery_outcome: TS 29.336 outcome enum —
    ///         0 = SUCCESSFUL_TRANSFER,
    ///         1 = ABSENT_USER,
    ///         2 = UE_MEMORY_CAPACITY_EXCEEDED,
    ///         3 = SUCCESSFUL_TRANSFER_NOT_LAST,
    ///         4 = TEMPORARY_ERROR.
    #[pyo3(signature = (user_name, sc_address, delivery_outcome))]
    fn s6c_rsr<'py>(
        &self,
        python: Python<'py>,
        user_name: &str,
        sc_address: &str,
        delivery_outcome: u32,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("s6c_rsr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = crate::script::detach_block_on(
            client.send_rsr(user_name, sc_address, delivery_outcome),
        );
        match answer {
            Ok(message) => match crate::diameter::s6c::parse_rsa(&message) {
                Some(rsa) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", rsa.result_code)?;
                    dict.set_item("experimental_result_code", rsa.experimental_result_code)?;
                    dict.set_item("user_name", rsa.user_name)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("s6c_rsr: HSS answer was not parseable as RSA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "s6c_rsr failed");
                Ok(None)
            }
        }
    }

    /// Send an SGd MT-Forward-Short-Message request to the served node
    /// (MME for LTE, SGSN for 2G/3G). Carries the SMS-DELIVER TPDU in
    /// the SM-RP-UI AVP.
    ///
    /// Args:
    ///     user_name: IMSI of the recipient UE.
    ///     sc_address: GT of the originating SMSC.
    ///     sm_rp_ui: SMS-DELIVER TPDU bytes (TS 23.040).
    ///     smsmi_correlation_id: Optional opaque correlation reference
    ///         the SMSC uses to bind the TFR to its own queueing state.
    ///     sm_rp_mti: SM-RP MTI — 0 = SMS Deliver, 1 = Status Report.
    ///
    /// Returns:
    ///     Dict with ``result_code`` (int) and ``absent_user_diagnostic``
    ///     (int or None — set when the UE was unreachable).
    #[pyo3(signature = (user_name, sc_address, sm_rp_ui, smsmi_correlation_id=None, sm_rp_mti=None))]
    fn sgd_tfr<'py>(
        &self,
        python: Python<'py>,
        user_name: &str,
        sc_address: &str,
        sm_rp_ui: &[u8],
        smsmi_correlation_id: Option<&str>,
        sm_rp_mti: Option<u32>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.manager.any_client() {
            Some(client) => client,
            None => {
                warn!("sgd_tfr: no Diameter peer connected");
                return Ok(None);
            }
        };
        let answer = crate::script::detach_block_on(client.send_tfr(
            user_name,
            sc_address,
            sm_rp_ui,
            smsmi_correlation_id,
            sm_rp_mti,
        ));
        match answer {
            Ok(message) => match crate::diameter::sgd::parse_tfa(&message) {
                Some(tfa) => {
                    let dict = PyDict::new(python);
                    dict.set_item("result_code", tfa.result_code)?;
                    dict.set_item("experimental_result_code", tfa.experimental_result_code)?;
                    dict.set_item("absent_user_diagnostic", tfa.absent_user_diagnostic)?;
                    Ok(Some(dict))
                }
                None => {
                    warn!("sgd_tfr: peer answer was not parseable as TFA");
                    Ok(None)
                }
            },
            Err(error) => {
                warn!(error = %error, "sgd_tfr failed");
                Ok(None)
            }
        }
    }


    /// Originate a Diameter request by spec name + application name +
    /// AVP kwargs. Generic counterpart of the typed helpers (`cx_uar`,
    /// `s6c_srr`, etc.) — useful for addons that need to drive
    /// applications whose full helper coverage isn't in siphon-core, or
    /// for scripts that prefer working in the spec's vocabulary.
    ///
    /// Args:
    ///     command: Diameter command name. Accepts the long form
    ///         (e.g. ``"Send-Routing-Info-for-SM-Request"``), the long
    ///         form without the ``-Request`` suffix, or the 3-letter
    ///         acronym (``"SRR"``). Case-insensitive.
    ///     application: Application short name (``"Cx"``, ``"S6c"``,
    ///         ``"SGd"``, …). Case-insensitive.
    ///     avps: Per-AVP keyword arguments. Keys are ``snake_case``
    ///         translations of the dictionary's Title-Kebab-Case names
    ///         (``msisdn`` → ``MSISDN``, ``sc_address`` → ``SC-Address``,
    ///         ``sm_rp_ui`` → ``SM-RP-UI``, …). Values are encoded by
    ///         the AVP's declared type:
    ///           UTF8String / DiameterIdentity → ``str``
    ///           OctetString                   → ``bytes`` or ``str``
    ///           Unsigned32 / Enumerated       → ``int``
    ///           Unsigned64                    → ``int``
    ///           Address (IPv4)                → ``str`` (dotted-quad)
    ///         Grouped AVPs are not supported via kwargs — use the
    ///         typed helper for those commands.
    ///     peer: Optional peer name override (defaults to any
    ///         connected peer for the application).
    ///     timeout_ms: Per-request timeout (default 10000ms — the same
    ///         default the underlying peer applies).
    ///
    /// Returns:
    ///     Dict with all answer AVPs (snake_case keys) plus
    ///     ``result_code``, or ``None`` when no peer is connected /
    ///     the peer rejected the message / the answer was malformed.
    ///
    /// Raises ``ValueError`` for unknown command/application names or
    /// unrecognised AVP kwargs.
    #[pyo3(signature = (
        command,
        application,
        peer=None,
        timeout_ms=10_000,
        **avps,
    ))]
    fn send_request<'py>(
        &self,
        python: Python<'py>,
        command: &str,
        application: &str,
        peer: Option<&str>,
        timeout_ms: u64,
        avps: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let _ = timeout_ms; // forwarded peer applies its own timeout today

        let command_code = dictionary::command_code_by_name(command).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter command name: {command}"
            ))
        })?;
        let (app_vendor, app_id) = dictionary::app_id_by_name(application).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown Diameter application name: {application}"
            ))
        })?;

        let client = match peer {
            Some(name) => self.manager.client(name),
            None => self.manager.any_client(),
        };
        let client = match client {
            Some(client) => client,
            None => {
                warn!(
                    command = command,
                    application = application,
                    "diameter.send_request: no peer connected"
                );
                return Ok(None);
            }
        };

        let session_id = client.peer().new_session_id();
        let hbh = client.peer().next_hbh();
        let e2e = client.peer().next_e2e();
        let config = client.peer().config().clone();

        let mut avp_bytes = Vec::with_capacity(256);
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
        avp_bytes.extend_from_slice(&encode_avp_utf8(
            avp::DESTINATION_REALM,
            &config.destination_realm,
        ));
        if let Some(dest_host) = &config.destination_host {
            avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
        }
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(app_vendor, app_id));

        if let Some(kwargs) = avps {
            for (key, value) in kwargs.iter() {
                let key_str: String = key.extract().map_err(|error| {
                    pyo3::exceptions::PyTypeError::new_err(format!(
                        "AVP kwarg name must be str: {error}"
                    ))
                })?;
                // Reserved kwargs siphon consumes itself — never travel
                // on the wire.
                if matches!(key_str.as_str(), "peer" | "timeout_ms" | "command" | "application")
                {
                    continue;
                }
                let avp_def = dictionary::lookup_avp_by_python_name(&key_str).ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown AVP kwarg: {key_str}"
                    ))
                })?;
                let encoded = encode_kwarg_avp(avp_def, &value)?;
                avp_bytes.extend_from_slice(&encoded);
            }
        }

        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            command_code,
            app_id,
            hbh,
            e2e,
            &avp_bytes,
        );

        let answer = crate::script::detach_block_on(client.peer().send_request(wire));
        let message = match answer {
            Ok(message) => message,
            Err(error) => {
                warn!(error = %error, command = command, "diameter.send_request failed");
                return Ok(None);
            }
        };

        let dict = decode_avps_to_pydict(python, &message.avps)?;
        Ok(Some(dict))
    }

    // ── Rf ACR/ACA — IMS offline charging (TS 32.299) ────────────────────

    /// Send an Rf ACR-START to the CDF.
    ///
    /// Begins an offline-charging accounting session.  Returns a dict with
    /// ``result_code`` (int, 2001 on success), ``session_id`` (str — use
    /// for subsequent ``rf_acr_interim`` / ``rf_acr_stop``),
    /// ``record_number`` (int — always 0 for START per RFC 6733 §9.8.3),
    /// and ``interim_interval`` (int or None — when set by the CDF in
    /// ACA-START, the CTF MUST honor this cadence per RFC 6733 §8.19).
    ///
    /// ``role_of_node`` accepts ``"originating"``, ``"terminating"``,
    /// ``"proxy"``, ``"b2bua"`` (TS 32.299 §7.2.149).
    ///
    /// ``node_functionality`` accepts ``"scscf"``, ``"pcscf"``, ``"icscf"``,
    /// ``"mrfc"``, ``"mgcf"``, ``"bgcf"``, ``"as"``, ``"ibcf"``, ``"ecscf"``,
    /// ``"atcf"``, ``"mmtel"``, ``"tpf"``, ``"atgw"`` (TS 32.299 §7.2.111).
    #[pyo3(signature = (
        *,
        calling_party=None, called_party=None, sip_method=None,
        role_of_node=None, node_functionality=None,
        ims_charging_identifier=None, user_session_id=None,
        originating_ioi=None, terminating_ioi=None,
        application_server=None, application_provided_called_party_address=None,
        incoming_trunk_group_id=None, outgoing_trunk_group_id=None,
        visited_network_id=None,
        originator_address=None, recipient_address=None,
        originator_sccp_address=None, recipient_sccp_address=None,
        sm_message_type=None, reply_path_requested=None,
        sm_user_data_header=None, sm_service_type=None,
        sms_node=None, sm_discharge_time=None,
        number_of_messages_sent=None, client_address=None,
        data_coding_scheme=None, sms_result=None,
        sm_protocol_id=None, sm_status=None,
        application_port_identifier=None, external_identifier=None,
        sm_device_trigger_indicator=None, mtc_iwf_address=None,
        user_name=None, cause_code=None,
        service_context_id=None, peer=None,
    ))]
    fn rf_acr_start<'py>(
        &self,
        python: Python<'py>,
        calling_party: Option<&str>,
        called_party: Option<&str>,
        sip_method: Option<&str>,
        role_of_node: Option<&str>,
        node_functionality: Option<&str>,
        ims_charging_identifier: Option<&str>,
        user_session_id: Option<&str>,
        originating_ioi: Option<&str>,
        terminating_ioi: Option<&str>,
        application_server: Option<&str>,
        application_provided_called_party_address: Option<&str>,
        incoming_trunk_group_id: Option<&str>,
        outgoing_trunk_group_id: Option<&str>,
        visited_network_id: Option<&str>,
        originator_address: Option<&str>,
        recipient_address: Option<&str>,
        originator_sccp_address: Option<&str>,
        recipient_sccp_address: Option<&str>,
        sm_message_type: Option<u32>,
        reply_path_requested: Option<u32>,
        sm_user_data_header: Option<Vec<u8>>,
        sm_service_type: Option<u32>,
        sms_node: Option<u32>,
        sm_discharge_time: Option<f64>,
        number_of_messages_sent: Option<u32>,
        client_address: Option<&str>,
        data_coding_scheme: Option<i32>,
        sms_result: Option<u32>,
        sm_protocol_id: Option<Vec<u8>>,
        sm_status: Option<Vec<u8>>,
        application_port_identifier: Option<u32>,
        external_identifier: Option<&str>,
        sm_device_trigger_indicator: Option<u32>,
        mtc_iwf_address: Option<&str>,
        user_name: Option<&str>,
        cause_code: Option<i32>,
        service_context_id: Option<&str>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("rf_acr_start: no Diameter peer connected");
                return Ok(None);
            }
        };
        let ims_data = build_ims_data(
            calling_party, called_party, sip_method,
            role_of_node, node_functionality, ims_charging_identifier,
            user_session_id, originating_ioi, terminating_ioi,
            application_server, application_provided_called_party_address,
            incoming_trunk_group_id, outgoing_trunk_group_id,
            visited_network_id, cause_code,
        )?;
        let sms_data = build_sms_data(
            originator_address, recipient_address,
            originator_sccp_address, recipient_sccp_address,
            sm_message_type, reply_path_requested,
            sm_user_data_header, sm_service_type,
            sms_node, sm_discharge_time,
            number_of_messages_sent, client_address,
            data_coding_scheme, sms_result,
            sm_protocol_id, sm_status,
            application_port_identifier, external_identifier,
            sm_device_trigger_indicator, mtc_iwf_address,
            originating_ioi, terminating_ioi, user_session_id,
        )?;

        let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
        params.user_name = user_name;
        params.ims_data = ims_data.as_ref();
        params.sms_data = sms_data.as_ref();
        params.service_context_id = service_context_id;

        let peer_handle = client.peer().clone();
        let answer = crate::script::detach_block_on(rf::send_acr(&peer_handle, &params));
        match answer {
            Ok(answer) => Ok(Some(accounting_answer_to_dict(python, answer, None)?)),
            Err(error) => {
                warn!(error = %error, "rf_acr_start failed");
                Ok(None)
            }
        }
    }

    /// Send an Rf ACR-INTERIM to the CDF.
    ///
    /// `record_number` MUST be a strictly increasing non-zero integer
    /// scoped to the same `session_id` per RFC 6733 §9.8.3.
    #[pyo3(signature = (
        session_id, record_number,
        *,
        calling_party=None, called_party=None, sip_method=None,
        role_of_node=None, node_functionality=None,
        ims_charging_identifier=None, user_session_id=None,
        originating_ioi=None, terminating_ioi=None,
        application_server=None, application_provided_called_party_address=None,
        incoming_trunk_group_id=None, outgoing_trunk_group_id=None,
        visited_network_id=None,
        originator_address=None, recipient_address=None,
        originator_sccp_address=None, recipient_sccp_address=None,
        sm_message_type=None, reply_path_requested=None,
        sm_user_data_header=None, sm_service_type=None,
        sms_node=None, sm_discharge_time=None,
        number_of_messages_sent=None, client_address=None,
        data_coding_scheme=None, sms_result=None,
        sm_protocol_id=None, sm_status=None,
        application_port_identifier=None, external_identifier=None,
        sm_device_trigger_indicator=None, mtc_iwf_address=None,
        user_name=None, cause_code=None,
        service_context_id=None, peer=None,
    ))]
    fn rf_acr_interim<'py>(
        &self,
        python: Python<'py>,
        session_id: &str,
        record_number: u32,
        calling_party: Option<&str>,
        called_party: Option<&str>,
        sip_method: Option<&str>,
        role_of_node: Option<&str>,
        node_functionality: Option<&str>,
        ims_charging_identifier: Option<&str>,
        user_session_id: Option<&str>,
        originating_ioi: Option<&str>,
        terminating_ioi: Option<&str>,
        application_server: Option<&str>,
        application_provided_called_party_address: Option<&str>,
        incoming_trunk_group_id: Option<&str>,
        outgoing_trunk_group_id: Option<&str>,
        visited_network_id: Option<&str>,
        originator_address: Option<&str>,
        recipient_address: Option<&str>,
        originator_sccp_address: Option<&str>,
        recipient_sccp_address: Option<&str>,
        sm_message_type: Option<u32>,
        reply_path_requested: Option<u32>,
        sm_user_data_header: Option<Vec<u8>>,
        sm_service_type: Option<u32>,
        sms_node: Option<u32>,
        sm_discharge_time: Option<f64>,
        number_of_messages_sent: Option<u32>,
        client_address: Option<&str>,
        data_coding_scheme: Option<i32>,
        sms_result: Option<u32>,
        sm_protocol_id: Option<Vec<u8>>,
        sm_status: Option<Vec<u8>>,
        application_port_identifier: Option<u32>,
        external_identifier: Option<&str>,
        sm_device_trigger_indicator: Option<u32>,
        mtc_iwf_address: Option<&str>,
        user_name: Option<&str>,
        cause_code: Option<i32>,
        service_context_id: Option<&str>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("rf_acr_interim: no Diameter peer connected");
                return Ok(None);
            }
        };
        let ims_data = build_ims_data(
            calling_party, called_party, sip_method,
            role_of_node, node_functionality, ims_charging_identifier,
            user_session_id, originating_ioi, terminating_ioi,
            application_server, application_provided_called_party_address,
            incoming_trunk_group_id, outgoing_trunk_group_id,
            visited_network_id, cause_code,
        )?;
        let sms_data = build_sms_data(
            originator_address, recipient_address,
            originator_sccp_address, recipient_sccp_address,
            sm_message_type, reply_path_requested,
            sm_user_data_header, sm_service_type,
            sms_node, sm_discharge_time,
            number_of_messages_sent, client_address,
            data_coding_scheme, sms_result,
            sm_protocol_id, sm_status,
            application_port_identifier, external_identifier,
            sm_device_trigger_indicator, mtc_iwf_address,
            originating_ioi, terminating_ioi, user_session_id,
        )?;

        let mut params = AccountingParams::new(AccountingRecordType::InterimRecord);
        params.record_number = record_number;
        params.session_id = Some(session_id);
        params.user_name = user_name;
        params.ims_data = ims_data.as_ref();
        params.sms_data = sms_data.as_ref();
        params.service_context_id = service_context_id;

        let peer_handle = client.peer().clone();
        let answer = crate::script::detach_block_on(rf::send_acr(&peer_handle, &params));
        match answer {
            Ok(answer) => Ok(Some(accounting_answer_to_dict(
                python,
                answer,
                Some(session_id),
            )?)),
            Err(error) => {
                warn!(error = %error, "rf_acr_interim failed");
                Ok(None)
            }
        }
    }

    /// Send an Rf ACR-STOP to the CDF.
    ///
    /// `termination_cause` should match the actual termination reason
    /// per RFC 6733 §8.15.  Defaults to 1 (DIAMETER_LOGOUT) for normal
    /// session teardown.  Use 8 (DIAMETER_SESSION_TIMEOUT) for
    /// session-timer expiry, 4 (DIAMETER_ADMINISTRATIVE) for forced
    /// teardown.
    #[pyo3(signature = (
        session_id, record_number,
        *,
        termination_cause=1,
        calling_party=None, called_party=None, sip_method=None,
        role_of_node=None, node_functionality=None,
        ims_charging_identifier=None, user_session_id=None,
        originating_ioi=None, terminating_ioi=None,
        application_server=None, application_provided_called_party_address=None,
        incoming_trunk_group_id=None, outgoing_trunk_group_id=None,
        visited_network_id=None,
        originator_address=None, recipient_address=None,
        originator_sccp_address=None, recipient_sccp_address=None,
        sm_message_type=None, reply_path_requested=None,
        sm_user_data_header=None, sm_service_type=None,
        sms_node=None, sm_discharge_time=None,
        number_of_messages_sent=None, client_address=None,
        data_coding_scheme=None, sms_result=None,
        sm_protocol_id=None, sm_status=None,
        application_port_identifier=None, external_identifier=None,
        sm_device_trigger_indicator=None, mtc_iwf_address=None,
        user_name=None, cause_code=None,
        service_context_id=None, peer=None,
    ))]
    fn rf_acr_stop<'py>(
        &self,
        python: Python<'py>,
        session_id: &str,
        record_number: u32,
        termination_cause: u32,
        calling_party: Option<&str>,
        called_party: Option<&str>,
        sip_method: Option<&str>,
        role_of_node: Option<&str>,
        node_functionality: Option<&str>,
        ims_charging_identifier: Option<&str>,
        user_session_id: Option<&str>,
        originating_ioi: Option<&str>,
        terminating_ioi: Option<&str>,
        application_server: Option<&str>,
        application_provided_called_party_address: Option<&str>,
        incoming_trunk_group_id: Option<&str>,
        outgoing_trunk_group_id: Option<&str>,
        visited_network_id: Option<&str>,
        originator_address: Option<&str>,
        recipient_address: Option<&str>,
        originator_sccp_address: Option<&str>,
        recipient_sccp_address: Option<&str>,
        sm_message_type: Option<u32>,
        reply_path_requested: Option<u32>,
        sm_user_data_header: Option<Vec<u8>>,
        sm_service_type: Option<u32>,
        sms_node: Option<u32>,
        sm_discharge_time: Option<f64>,
        number_of_messages_sent: Option<u32>,
        client_address: Option<&str>,
        data_coding_scheme: Option<i32>,
        sms_result: Option<u32>,
        sm_protocol_id: Option<Vec<u8>>,
        sm_status: Option<Vec<u8>>,
        application_port_identifier: Option<u32>,
        external_identifier: Option<&str>,
        sm_device_trigger_indicator: Option<u32>,
        mtc_iwf_address: Option<&str>,
        user_name: Option<&str>,
        cause_code: Option<i32>,
        service_context_id: Option<&str>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("rf_acr_stop: no Diameter peer connected");
                return Ok(None);
            }
        };
        let ims_data = build_ims_data(
            calling_party, called_party, sip_method,
            role_of_node, node_functionality, ims_charging_identifier,
            user_session_id, originating_ioi, terminating_ioi,
            application_server, application_provided_called_party_address,
            incoming_trunk_group_id, outgoing_trunk_group_id,
            visited_network_id, cause_code,
        )?;
        let sms_data = build_sms_data(
            originator_address, recipient_address,
            originator_sccp_address, recipient_sccp_address,
            sm_message_type, reply_path_requested,
            sm_user_data_header, sm_service_type,
            sms_node, sm_discharge_time,
            number_of_messages_sent, client_address,
            data_coding_scheme, sms_result,
            sm_protocol_id, sm_status,
            application_port_identifier, external_identifier,
            sm_device_trigger_indicator, mtc_iwf_address,
            originating_ioi, terminating_ioi, user_session_id,
        )?;

        let mut params = AccountingParams::new(AccountingRecordType::StopRecord);
        params.record_number = record_number;
        params.session_id = Some(session_id);
        params.user_name = user_name;
        params.ims_data = ims_data.as_ref();
        params.sms_data = sms_data.as_ref();
        params.service_context_id = service_context_id;
        params.termination_cause = Some(termination_cause);

        let peer_handle = client.peer().clone();
        let answer = crate::script::detach_block_on(rf::send_acr(&peer_handle, &params));
        match answer {
            Ok(answer) => Ok(Some(accounting_answer_to_dict(
                python,
                answer,
                Some(session_id),
            )?)),
            Err(error) => {
                warn!(error = %error, "rf_acr_stop failed");
                Ok(None)
            }
        }
    }

    /// Send an Rf ACR-EVENT to the CDF.
    ///
    /// Used for one-shot accounting (REGISTER, MESSAGE, SUBSCRIBE, …).
    /// Record-Number is fixed at 0 per RFC 6733 §9.8.3.
    #[pyo3(signature = (
        *,
        calling_party=None, called_party=None, sip_method=None,
        role_of_node=None, node_functionality=None,
        ims_charging_identifier=None, user_session_id=None,
        originating_ioi=None, terminating_ioi=None,
        application_server=None, application_provided_called_party_address=None,
        incoming_trunk_group_id=None, outgoing_trunk_group_id=None,
        visited_network_id=None,
        originator_address=None, recipient_address=None,
        originator_sccp_address=None, recipient_sccp_address=None,
        sm_message_type=None, reply_path_requested=None,
        sm_user_data_header=None, sm_service_type=None,
        sms_node=None, sm_discharge_time=None,
        number_of_messages_sent=None, client_address=None,
        data_coding_scheme=None, sms_result=None,
        sm_protocol_id=None, sm_status=None,
        application_port_identifier=None, external_identifier=None,
        sm_device_trigger_indicator=None, mtc_iwf_address=None,
        user_name=None, cause_code=None,
        service_context_id=None, peer=None,
    ))]
    fn rf_acr_event<'py>(
        &self,
        python: Python<'py>,
        calling_party: Option<&str>,
        called_party: Option<&str>,
        sip_method: Option<&str>,
        role_of_node: Option<&str>,
        node_functionality: Option<&str>,
        ims_charging_identifier: Option<&str>,
        user_session_id: Option<&str>,
        originating_ioi: Option<&str>,
        terminating_ioi: Option<&str>,
        application_server: Option<&str>,
        application_provided_called_party_address: Option<&str>,
        incoming_trunk_group_id: Option<&str>,
        outgoing_trunk_group_id: Option<&str>,
        visited_network_id: Option<&str>,
        originator_address: Option<&str>,
        recipient_address: Option<&str>,
        originator_sccp_address: Option<&str>,
        recipient_sccp_address: Option<&str>,
        sm_message_type: Option<u32>,
        reply_path_requested: Option<u32>,
        sm_user_data_header: Option<Vec<u8>>,
        sm_service_type: Option<u32>,
        sms_node: Option<u32>,
        sm_discharge_time: Option<f64>,
        number_of_messages_sent: Option<u32>,
        client_address: Option<&str>,
        data_coding_scheme: Option<i32>,
        sms_result: Option<u32>,
        sm_protocol_id: Option<Vec<u8>>,
        sm_status: Option<Vec<u8>>,
        application_port_identifier: Option<u32>,
        external_identifier: Option<&str>,
        sm_device_trigger_indicator: Option<u32>,
        mtc_iwf_address: Option<&str>,
        user_name: Option<&str>,
        cause_code: Option<i32>,
        service_context_id: Option<&str>,
        peer: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let client = match self.pick_rf_peer(peer) {
            Some(client) => client,
            None => {
                warn!("rf_acr_event: no Diameter peer connected");
                return Ok(None);
            }
        };
        let ims_data = build_ims_data(
            calling_party, called_party, sip_method,
            role_of_node, node_functionality, ims_charging_identifier,
            user_session_id, originating_ioi, terminating_ioi,
            application_server, application_provided_called_party_address,
            incoming_trunk_group_id, outgoing_trunk_group_id,
            visited_network_id, cause_code,
        )?;
        let sms_data = build_sms_data(
            originator_address, recipient_address,
            originator_sccp_address, recipient_sccp_address,
            sm_message_type, reply_path_requested,
            sm_user_data_header, sm_service_type,
            sms_node, sm_discharge_time,
            number_of_messages_sent, client_address,
            data_coding_scheme, sms_result,
            sm_protocol_id, sm_status,
            application_port_identifier, external_identifier,
            sm_device_trigger_indicator, mtc_iwf_address,
            originating_ioi, terminating_ioi, user_session_id,
        )?;

        let mut params = AccountingParams::new(AccountingRecordType::EventRecord);
        params.user_name = user_name;
        params.ims_data = ims_data.as_ref();
        params.sms_data = sms_data.as_ref();
        params.service_context_id = service_context_id;

        let peer_handle = client.peer().clone();
        let answer = crate::script::detach_block_on(rf::send_acr(&peer_handle, &params));
        match answer {
            Ok(answer) => Ok(Some(accounting_answer_to_dict(python, answer, None)?)),
            Err(error) => {
                warn!(error = %error, "rf_acr_event failed");
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Generic AVP encoding from Python kwargs
// ---------------------------------------------------------------------------

/// Encode a single AVP value (Python object → wire bytes) using the
/// AVP's declared type from the dictionary. Picks the 3GPP-flagged
/// encoder when the AVP is vendor-specific, the base encoder otherwise.
fn encode_kwarg_avp(def: &AvpDef, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let is_vendor = def.is_vendor_specific();
    match def.data_type {
        AvpType::UTF8String | AvpType::DiameterIdentity => {
            let s: String = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects str, got {error}",
                    def.name
                ))
            })?;
            Ok(if is_vendor {
                encode_avp_utf8_3gpp(def.code, &s)
            } else {
                encode_avp_utf8(def.code, &s)
            })
        }
        AvpType::OctetString => {
            // Accept bytes directly (raw payload, e.g. SM-RP-UI TPDU)
            // or str (encoded as UTF-8, e.g. MSISDN, SC-Address).
            let bytes: Vec<u8> = if let Ok(b) = value.extract::<Vec<u8>>() {
                b
            } else if let Ok(s) = value.extract::<String>() {
                s.into_bytes()
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects bytes or str",
                    def.name
                )));
            };
            Ok(if is_vendor {
                encode_avp_octet_3gpp(def.code, &bytes)
            } else {
                encode_avp_octet(def.code, &bytes)
            })
        }
        AvpType::Unsigned32 | AvpType::Enumerated => {
            let n: u32 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (u32 range), got {error}",
                    def.name
                ))
            })?;
            Ok(if is_vendor {
                encode_avp_u32_3gpp(def.code, n)
            } else {
                encode_avp_u32(def.code, n)
            })
        }
        AvpType::Unsigned64 => {
            let n: u64 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (u64 range), got {error}",
                    def.name
                ))
            })?;
            // No vendor variant in the codec for u64 — only one Unsigned64
            // 3GPP AVP exists in the dictionary today (CC-Sub-Session-Id).
            // Treat as plain u64 with vendor flag handled by encode_avp.
            Ok(encode_avp_u64(def.code, n))
        }
        AvpType::Integer32 => {
            let n: i32 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (i32 range), got {error}",
                    def.name
                ))
            })?;
            Ok(crate::diameter::codec::encode_avp_i32_3gpp(def.code, n))
        }
        AvpType::Address => {
            let s: String = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects str (IPv4 dotted-quad), got {error}",
                    def.name
                ))
            })?;
            let ip: std::net::Ipv4Addr = s.parse().map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "{} invalid IPv4 address {s:?}: {error}",
                    def.name
                ))
            })?;
            Ok(encode_avp_address_ipv4(def.code, ip))
        }
        AvpType::Time => Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "{} (Time AVPs) is not supported via kwargs — use a typed helper",
            def.name
        ))),
        AvpType::Grouped => {
            // Allow an empty grouped marker by passing None — useful for
            // a few AVPs that act as flags. Real grouped encoding (sub-AVPs
            // from a nested dict) is deferred until an actual use case
            // shows up; today scripts that need grouped AVPs use the
            // typed helpers.
            if value.is_none() {
                Ok(if is_vendor {
                    encode_avp_grouped_3gpp(def.code, &[])
                } else {
                    encode_avp_grouped(def.code, &[])
                })
            } else {
                Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} (Grouped AVP) requires a typed helper — \
                     scripted nested-AVP construction is not yet supported",
                    def.name
                )))
            }
        }
    }
}


fn decode_avps_to_pydict<'py>(
    python: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);
    if let Some(map) = value.as_object() {
        for (name, child) in map {
            let key = avp_name_to_snake(name);
            let py_value = json_to_py(python, child)?;
            dict.set_item(key, py_value)?;
        }
    }
    Ok(dict)
}

/// Translate a Title-Kebab AVP name to snake_case for Python.
fn avp_name_to_snake(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '-' => '_',
            ch => ch.to_ascii_lowercase(),
        })
        .collect()
}

fn json_to_py<'py>(
    python: Python<'py>,
    value: &serde_json::Value,
) -> PyResult<Py<PyAny>> {
    Ok(match value {
        serde_json::Value::Null => python.None(),
        serde_json::Value::Bool(b) => b
            .into_pyobject(python)
            .map(|v| v.to_owned().into_any().unbind())
            .unwrap_or_else(|_| python.None()),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else if let Some(i) = n.as_i64() {
                i.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(python)
                    .map(|v| v.into_any().unbind())
                    .unwrap_or_else(|_| python.None())
            } else {
                python.None()
            }
        }
        serde_json::Value::String(s) => s
            .as_str()
            .into_pyobject(python)
            .map(|v| v.into_any().unbind())
            .unwrap_or_else(|_| python.None()),
        serde_json::Value::Array(items) => {
            let list = pyo3::types::PyList::empty(python);
            for item in items {
                list.append(json_to_py(python, item)?)?;
            }
            list.into_any().unbind()
        }
        serde_json::Value::Object(_) => {
            decode_avps_to_pydict(python, value)?.into_any().unbind()
        }
    })
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::DiameterManager;

    #[test]
    fn empty_manager_no_peers() {
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        assert_eq!(py_diameter.peer_count(), 0);
        assert!(!py_diameter.is_connected("hss1"));
    }

    #[test]
    fn connected_after_register() {
        let manager = Arc::new(DiameterManager::new());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let config = crate::diameter::peer::PeerConfig {
                host: "hss1.example.com".to_string(),
                port: 3868,
                origin_host: "siphon.example.com".to_string(),
                origin_realm: "example.com".to_string(),
                destination_host: None,
                destination_realm: "example.com".to_string(),
                local_ip: "10.0.0.1".parse().unwrap(),
                application_ids: vec![],
                watchdog_interval: 30,
                reconnect_delay: 5,
                product_name: "SIPhon".to_string(),
                firmware_revision: 100,
            };

            let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
            let peer = Arc::new(crate::diameter::peer::DiameterPeer::new_for_test(config, write_tx));
            let client = Arc::new(crate::diameter::DiameterClient::new(peer));
            manager.register("hss1".to_string(), client);
        });

        let py_diameter = PyDiameter::new(manager);
        assert_eq!(py_diameter.peer_count(), 1);
        assert!(py_diameter.is_connected("hss1"));
        assert!(!py_diameter.is_connected("hss2"));
    }

    #[test]
    fn cx_uar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_uar(python, "sip:alice@example.com", None, None)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_uar_with_user_auth_type_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_uar(python, "sip:alice@example.com", None, Some(0))
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_sar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_sar(python, "sip:alice@example.com", None, 1)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn cx_lir_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .cx_lir(python, "sip:alice@example.com")
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn parse_media_components_full_shape() {
        use pyo3::types::{PyDict, PyList};

        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("number", 1u32).unwrap();
            component.set_item("media_type", "audio").unwrap();
            component.set_item("max_bandwidth_ul", 64000u32).unwrap();
            component.set_item("max_bandwidth_dl", 64000u32).unwrap();
            component.set_item("flow_status", "enabled").unwrap();
            component
                .set_item("codec_data", b"uplink\noffer\nm=audio 50000 RTP/AVP 0".to_vec())
                .unwrap();

            let flows = PyList::empty(python);

            let rtp = PyDict::new(python);
            rtp.set_item("number", 1u32).unwrap();
            rtp.set_item(
                "descriptions",
                vec![
                    "permit out 17 from 10.0.0.1 50000 to 10.0.0.2 30000",
                    "permit in 17 from 10.0.0.2 30000 to 10.0.0.1 50000",
                ],
            )
            .unwrap();
            flows.append(rtp).unwrap();

            let rtcp = PyDict::new(python);
            rtcp.set_item("number", 2u32).unwrap();
            rtcp.set_item("usage", "rtcp").unwrap();
            rtcp.set_item(
                "descriptions",
                vec![
                    "permit out 17 from 10.0.0.1 50001 to 10.0.0.2 30001",
                    "permit in 17 from 10.0.0.2 30001 to 10.0.0.1 50001",
                ],
            )
            .unwrap();
            flows.append(rtcp).unwrap();

            component.set_item("flows", flows).unwrap();

            let list = PyList::empty(python);
            list.append(component).unwrap();

            let parsed = parse_media_components(list.as_any()).unwrap();
            assert_eq!(parsed.len(), 1);
            let mc = &parsed[0];
            assert_eq!(mc.number, 1);
            assert_eq!(mc.max_bandwidth_ul, Some(64000));
            assert_eq!(mc.max_bandwidth_dl, Some(64000));
            assert_eq!(mc.flows.len(), 2);
            assert_eq!(mc.flows[0].flow_number, 1);
            assert_eq!(mc.flows[0].descriptions.len(), 2);
            assert_eq!(mc.flows[1].flow_number, 2);
            assert!(matches!(
                mc.flows[1].usage,
                Some(crate::diameter::rx::FlowUsage::Rtcp)
            ));

            // Encoded wire form must carry the Flow-Description bytes verbatim
            // plus a Flow-Usage AVP for the RTCP sub-component.  This is what
            // distinguishes the new structured form from the previous
            // wildcard placeholder.
            let encoded = mc.encode();
            let rule = b"permit out 17 from 10.0.0.1 50000 to 10.0.0.2 30000";
            assert!(
                encoded.windows(rule.len()).any(|w| w == rule),
                "encoded MCD must contain the full 5-tuple Flow-Description"
            );
            let flow_usage_code = crate::diameter::dictionary::avp::FLOW_USAGE.to_be_bytes();
            assert!(
                encoded.windows(4).any(|w| w == flow_usage_code),
                "RTCP sub-component must carry a Flow-Usage AVP"
            );
        });
    }

    #[test]
    fn parse_media_components_missing_number_errors() {
        use pyo3::types::{PyDict, PyList};

        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("media_type", "audio").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let error = parse_media_components(list.as_any()).unwrap_err();
            assert!(error.to_string().contains("number"));
        });
    }

    #[test]
    fn extract_subscription_id_string_alias() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let tuple = pyo3::types::PyTuple::new(
                python,
                [
                    "sip:alice@example.com".into_pyobject(python).unwrap().into_any(),
                    "sip_uri".into_pyobject(python).unwrap().into_any(),
                ],
            )
            .unwrap();
            let (data, type_num) = extract_subscription_id(tuple.as_any()).unwrap();
            assert_eq!(data, "sip:alice@example.com");
            assert_eq!(type_num, 2);
        });
    }

    #[test]
    fn rx_aar_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .rx_aar(python, None, None, None, None, "IMS Services", None)
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn rx_str_returns_none_without_peer() {
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        let result = py_diameter.rx_str("rx-session-1").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn sh_udr_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let data_reference = 0u32.into_pyobject(python).unwrap();
            let result = py_diameter
                .sh_udr(
                    python,
                    "sip:alice@ims.example.com",
                    data_reference.as_any(),
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn sh_pur_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .sh_pur(
                    python,
                    "sip:alice@ims.example.com",
                    0,
                    "<simservs/>",
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn sh_snr_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let data_reference = vec![0u32, 17u32].into_pyobject(python).unwrap();
            let result = py_diameter
                .sh_snr(
                    python,
                    "sip:alice@ims.example.com",
                    data_reference.as_any(),
                    0,
                    Some("simservs"),
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn extract_references_accepts_int_and_list() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let single = 17u32.into_pyobject(python).unwrap();
            assert_eq!(extract_references(single.as_any()).unwrap(), vec![17]);

            let list = vec![0u32, 11u32].into_pyobject(python).unwrap();
            assert_eq!(extract_references(list.as_any()).unwrap(), vec![0, 11]);
        });
    }

    // -----------------------------------------------------------------
    // Generic API surface — send_request / on_command
    // -----------------------------------------------------------------


    #[test]
    fn send_request_rejects_unknown_command() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter.send_request(
                python,
                "Bogus-Command-Request",
                "S6c",
                None,
                10_000,
                None,
            );
            let error = result.expect_err("unknown command must error");
            let msg = format!("{error}");
            assert!(msg.contains("unknown Diameter command"), "msg: {msg}");
        });
    }

    #[test]
    fn send_request_rejects_unknown_application() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter.send_request(
                python,
                "Send-Routing-Info-for-SM-Request",
                "BogusApp",
                None,
                10_000,
                None,
            );
            let error = result.expect_err("unknown app must error");
            let msg = format!("{error}");
            assert!(msg.contains("unknown Diameter application"), "msg: {msg}");
        });
    }

    #[test]
    fn send_request_returns_none_without_peer() {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        let py_diameter = PyDiameter::new(manager);
        pyo3::Python::attach(|python| {
            let result = py_diameter
                .send_request(
                    python,
                    "Send-Routing-Info-for-SM-Request",
                    "S6c",
                    None,
                    10_000,
                    None,
                )
                .unwrap();
            assert!(result.is_none());
        });
    }

    #[test]
    fn encode_kwarg_avp_encodes_string_octet() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name("sc_address")
            .expect("sc_address must resolve");
        pyo3::Python::attach(|python| {
            let value = "31611111111".into_pyobject(python).unwrap();
            let encoded = encode_kwarg_avp(avp_def, value.as_any()).unwrap();
            assert!(!encoded.is_empty(), "OctetString AVP must produce bytes");
        });
    }

    #[test]
    fn encode_kwarg_avp_encodes_bytes_octet() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name("sm_rp_ui")
            .expect("sm_rp_ui must resolve");
        pyo3::Python::attach(|python| {
            let value = pyo3::types::PyBytes::new(python, &[0xDE, 0xAD, 0xBE, 0xEF]);
            let encoded = encode_kwarg_avp(avp_def, value.as_any()).unwrap();
            assert!(!encoded.is_empty());
        });
    }

    #[test]
    fn encode_kwarg_avp_rejects_grouped_with_value() {
        pyo3::Python::initialize();
        let avp_def = crate::diameter::dictionary::lookup_avp_by_python_name(
            "smsmi_correlation_id",
        )
        .expect("smsmi_correlation_id must resolve");
        pyo3::Python::attach(|python| {
            let value = "anything".into_pyobject(python).unwrap();
            let result = encode_kwarg_avp(avp_def, value.as_any());
            let error = result.expect_err("grouped AVP must reject scalar value");
            let msg = format!("{error}");
            assert!(msg.contains("Grouped AVP"), "msg: {msg}");
        });
    }

    #[test]
    fn avp_name_to_snake_handles_acronyms() {
        assert_eq!(avp_name_to_snake("Session-Id"), "session_id");
        assert_eq!(avp_name_to_snake("MSISDN"), "msisdn");
        assert_eq!(avp_name_to_snake("SC-Address"), "sc_address");
        assert_eq!(avp_name_to_snake("SM-RP-UI"), "sm_rp_ui");
        assert_eq!(avp_name_to_snake("SMSMI-Correlation-ID"), "smsmi_correlation_id");
    }

}
