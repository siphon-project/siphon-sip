//! PyO3 `sbi` namespace — bridges Python `sbi.create_session()` to the
//! Rust [`NpcfClient`] for 5G N5/Npcf policy authorization.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyType};
use tracing::warn;

use indexmap::IndexMap;

use crate::sbi::nbsf::{BindingQuery, BsfClient, PcfBinding, Scheme};
use crate::sbi::npcf::{
    app_session_id_from_location, AppSessionContextReqData, MediaComponent, MediaSubComponent,
    NpcfClient,
};

pyo3::create_exception!(
    siphon,
    BsfError,
    pyo3::exceptions::PyRuntimeError,
    "Raised by sbi.discover_pcf_binding() when the BSF is unhealthy \
     (5xx / timeout / transport / malformed body). A 404 (no binding) is \
     NOT a BsfError — it returns None."
);

/// Python-visible SBI namespace.
#[pyclass(name = "SbiNamespace", skip_from_py_object)]
pub struct PySbi {
    client: Arc<NpcfClient>,
    bsf: Option<Arc<BsfClient>>,
    pcf_scheme: Scheme,
}

impl PySbi {
    pub fn new(
        client: Arc<NpcfClient>,
        bsf: Option<Arc<BsfClient>>,
        pcf_scheme: Scheme,
    ) -> Self {
        Self {
            client,
            bsf,
            pcf_scheme,
        }
    }
}

#[pymethods]
impl PySbi {
    /// The `sbi.BsfError` exception type (subclass of `RuntimeError`), raised
    /// by `discover_pcf_binding` when the BSF is unhealthy. Exposed as a class
    /// attribute so scripts can `except sbi.BsfError:`.
    #[classattr]
    #[allow(non_snake_case)]
    fn BsfError(python: Python<'_>) -> Bound<'_, PyType> {
        python.get_type::<BsfError>()
    }

    /// Nbsf_Management discovery — look up the PCF binding for a UE IP.
    ///
    /// The discriminator a P-CSCF uses to pick its policy interface per
    /// session (TS 29.521 §5.2.2.2.2):
    ///
    /// Returns:
    ///   * a dict (the PcfBinding, incl. a ready-to-use ``pcf_uri``) when the
    ///     BSF has a binding → caller treats as 5G;
    ///   * ``None`` when the BSF returns 404 (no binding) → caller treats as 4G;
    ///   * raises ``sbi.BsfError`` on 5xx / timeout / transport / malformed body.
    ///
    /// Raises ``RuntimeError`` (NOT ``BsfError``) when ``sbi.bsf_url`` is unset,
    /// so a misconfiguration is loud rather than a silent always-4G.
    ///
    /// Exactly one of ``ue_ipv4`` / ``ue_ipv6`` must be supplied. ``ue_ipv6``
    /// is treated as a prefix; a bare address gets ``/64`` appended.
    #[pyo3(signature = (ue_ipv4=None, ue_ipv6=None))]
    fn discover_pcf_binding<'py>(
        &self,
        python: Python<'py>,
        ue_ipv4: Option<&str>,
        ue_ipv6: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let query = match (ue_ipv4, ue_ipv6) {
            (Some(ipv4), None) => BindingQuery::Ipv4(ipv4.to_string()),
            (None, Some(ipv6)) => {
                // Treat a bare address as a /64 prefix (TS 29.521 wire form).
                let prefix = if ipv6.contains('/') {
                    ipv6.to_string()
                } else {
                    format!("{ipv6}/64")
                };
                BindingQuery::Ipv6Prefix(prefix)
            }
            (Some(_), Some(_)) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "discover_pcf_binding: supply exactly one of ue_ipv4 / ue_ipv6, not both",
                ));
            }
            (None, None) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "discover_pcf_binding: one of ue_ipv4 / ue_ipv6 is required",
                ));
            }
        };

        let bsf = match &self.bsf {
            Some(bsf) => Arc::clone(bsf),
            None => {
                // Deliberately a plain RuntimeError, not BsfError: a script's
                // `except sbi.BsfError` retry loop must NOT swallow a misconfig
                // into a silent default-access fallback.
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "discover_pcf_binding: BSF not configured (set sbi.bsf_url)",
                ));
            }
        };

        let result = crate::script::detach_block_on(async move { bsf.discover_binding(&query).await });

        match result {
            Ok(Some(binding)) => {
                Ok(Some(binding_to_pydict(python, &binding, self.pcf_scheme)?))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(BsfError::new_err(format!(
                "sbi.discover_pcf_binding failed: {error}"
            ))),
        }
    }

    /// Create an N5 app session for QoS policy authorization.
    ///
    /// Args:
    ///     af_app_id: AF-Application identifier (default ``"IMS Services"``).
    ///     sip_call_id: SIP Call-ID for correlation.
    ///     supi: Subscription Permanent Identifier.
    ///     ue_ipv4: UE IPv4 address.
    ///     ue_ipv6: UE IPv6 address.
    ///     dnn: Data Network Name.
    ///     notif_uri: PCF event callback URI.
    ///     media_components: list of media-component dicts (same shape as
    ///         :func:`diameter.rx_aar`'s ``media_components``).  Each dict
    ///         carries ``number``, ``media_type``, optional ``flow_status``,
    ///         ``codec_data``, and a ``flows`` list whose entries carry
    ///         ``number``, ``descriptions`` (IPFilterRules), and optional
    ///         ``status`` / ``usage``.
    ///     pcf_uri: per-call N5 target — the discovered PCF (e.g. a
    ///         BSF-returned ``pcf_uri``).  In ``direct`` communication mode it
    ///         is the POST base (instead of ``npcf_url``); in ``indirect`` mode
    ///         it becomes the ``3gpp-Sbi-Target-apiRoot`` header while the POST
    ///         goes to the SCP (``npcf_url``).  ``None`` ⇒ ``npcf_url``.
    ///
    /// Returns a dict with ``app_session_id``, ``authorized``, and
    /// ``app_session_uri`` (the absolute resource URI — persist it and pass it
    /// back to ``update_session`` / ``delete_session`` so teardown reaches the
    /// same PCF from any replica), or ``None`` on failure.
    #[pyo3(signature = (
        af_app_id="IMS Services",
        sip_call_id=None,
        supi=None,
        ue_ipv4=None,
        ue_ipv6=None,
        dnn=None,
        notif_uri=None,
        media_components=None,
        pcf_uri=None,
    ))]
    fn create_session<'py>(
        &self,
        python: Python<'py>,
        af_app_id: &str,
        sip_call_id: Option<&str>,
        supi: Option<&str>,
        ue_ipv4: Option<&str>,
        ue_ipv6: Option<&str>,
        dnn: Option<&str>,
        notif_uri: Option<&str>,
        media_components: Option<&Bound<'py, PyAny>>,
        pcf_uri: Option<&str>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let components = match media_components {
            Some(obj) => parse_sbi_media_components(obj)?,
            None => Vec::new(),
        };

        let request_data = AppSessionContextReqData {
            af_app_id: Some(af_app_id.to_string()),
            med_components: components_to_map(components),
            sip_call_id: sip_call_id.map(String::from),
            supi: supi.map(String::from),
            ue_ipv4: ue_ipv4.map(String::from),
            ue_ipv6: ue_ipv6.map(String::from),
            dnn: dnn.map(String::from),
            ev_subsc: None,
            notif_uri: notif_uri.map(String::from),
            supp_feat: None,
        };

        let client = Arc::clone(&self.client);
        let target = pcf_uri.map(String::from);
        let result = crate::script::detach_block_on(async move {
            client
                .create_app_session(target.as_deref(), &request_data)
                .await
        });

        match result {
            Ok(created) => {
                let dict = PyDict::new(python);
                dict.set_item("app_session_id", &created.app_session_id)?;
                dict.set_item("authorized", created.authorized)?;
                dict.set_item("app_session_uri", created.location)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sbi.create_session failed");
                Ok(None)
            }
        }
    }

    /// Delete an N5 app session.
    ///
    /// ``session_id`` is either the bare app-session id (resolved against
    /// ``npcf_url``) or the absolute ``app_session_uri`` returned by
    /// :func:`create_session` (sent verbatim — reaches the originating PCF from
    /// any replica). Returns True on success, False on failure.
    fn delete_session(&self, session_id: &str) -> PyResult<bool> {
        let client = Arc::clone(&self.client);
        let sid = session_id.to_string();
        let result = crate::script::detach_block_on(client.delete_app_session(&sid));

        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                warn!(error = %error, "sbi.delete_session failed");
                Ok(false)
            }
        }
    }

    /// Update an N5 app session — media renegotiation (re-INVITE / UPDATE).
    ///
    /// Same kwarg shape as :func:`create_session` minus the addressing
    /// fields the PCF already holds from the original create. ``session_id``
    /// accepts a bare id or the absolute ``app_session_uri`` from
    /// :func:`create_session` (same id-or-URI rule as :func:`delete_session`).
    #[pyo3(signature = (
        session_id,
        media_components=None,
    ))]
    fn update_session<'py>(
        &self,
        python: Python<'py>,
        session_id: &str,
        media_components: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let components = match media_components {
            Some(obj) => parse_sbi_media_components(obj)?,
            None => Vec::new(),
        };

        let request_data = AppSessionContextReqData {
            med_components: components_to_map(components),
            ..Default::default()
        };

        let client = Arc::clone(&self.client);
        let sid = session_id.to_string();
        let result = crate::script::detach_block_on(client.update_app_session(&sid, &request_data));

        match result {
            Ok(()) => {
                // The modify response (the updated AppSessionContext) carries no
                // flat id; echo the bare id from the ref the caller passed.
                let dict = PyDict::new(python);
                dict.set_item("app_session_id", app_session_id_from_location(session_id))?;
                dict.set_item("authorized", true)?;
                Ok(Some(dict))
            }
            Err(error) => {
                warn!(error = %error, "sbi.update_session failed");
                Ok(None)
            }
        }
    }
}

/// Convert a discovered [`PcfBinding`] into a Python dict with snake_case keys
/// (matching repo Python conventions), plus a ready-to-use ``pcf_uri`` derived
/// via [`PcfBinding::pcf_base_url`] so the script never has to know the
/// fqdn-vs-endpoint preference rules.
fn binding_to_pydict<'py>(
    python: Python<'py>,
    binding: &PcfBinding,
    scheme: Scheme,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);

    if let Some(ref supi) = binding.supi {
        dict.set_item("supi", supi)?;
    }
    if let Some(ref gpsi) = binding.gpsi {
        dict.set_item("gpsi", gpsi)?;
    }
    if let Some(ref ipv4_addr) = binding.ipv4_addr {
        dict.set_item("ipv4_addr", ipv4_addr)?;
    }
    if let Some(ref ipv6_prefix) = binding.ipv6_prefix {
        dict.set_item("ipv6_prefix", ipv6_prefix)?;
    }
    if let Some(ref dnn) = binding.dnn {
        dict.set_item("dnn", dnn)?;
    }
    if let Some(ref pcf_fqdn) = binding.pcf_fqdn {
        dict.set_item("pcf_fqdn", pcf_fqdn)?;
    }
    if let Some(ref endpoints) = binding.pcf_ip_end_points {
        let list = PyList::empty(python);
        for endpoint in endpoints {
            let endpoint_dict = PyDict::new(python);
            if let Some(ref ipv4) = endpoint.ipv4_address {
                endpoint_dict.set_item("ipv4_address", ipv4)?;
            }
            if let Some(ref ipv6) = endpoint.ipv6_address {
                endpoint_dict.set_item("ipv6_address", ipv6)?;
            }
            if let Some(ref transport) = endpoint.transport {
                endpoint_dict.set_item("transport", transport)?;
            }
            if let Some(port) = endpoint.port {
                endpoint_dict.set_item("port", port)?;
            }
            list.append(endpoint_dict)?;
        }
        dict.set_item("pcf_ip_end_points", list)?;
    }
    if let Some(ref pcf_diam_host) = binding.pcf_diam_host {
        dict.set_item("pcf_diam_host", pcf_diam_host)?;
    }
    if let Some(ref pcf_diam_realm) = binding.pcf_diam_realm {
        dict.set_item("pcf_diam_realm", pcf_diam_realm)?;
    }
    if let Some(ref snssai) = binding.snssai {
        let snssai_dict = PyDict::new(python);
        snssai_dict.set_item("sst", snssai.sst)?;
        if let Some(ref sd) = snssai.sd {
            snssai_dict.set_item("sd", sd)?;
        }
        dict.set_item("snssai", snssai_dict)?;
    }
    if let Some(ref pcf_id) = binding.pcf_id {
        dict.set_item("pcf_id", pcf_id)?;
    }
    if let Some(ref bind_level) = binding.bind_level {
        dict.set_item("bind_level", bind_level)?;
    }
    if let Some(ref supp_feat) = binding.supp_feat {
        dict.set_item("supp_feat", supp_feat)?;
    }

    // The convenience field the script feeds straight into
    // create_session(pcf_uri=...). None when the binding is degenerate.
    dict.set_item("pcf_uri", binding.pcf_base_url(scheme))?;

    Ok(dict)
}

/// Normalize a media-type alias into the upper-cased string the 5G SBI
/// schema expects (TS 29.514 §5.6.3.2).
fn media_type_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "audio" => "AUDIO",
        "video" => "VIDEO",
        "data" => "DATA",
        "application" => "APPLICATION",
        "control" => "CONTROL",
        "text" => "TEXT",
        "message" => "MESSAGE",
        "other" => "OTHER",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown media_type {other:?} (expected audio|video|data|application|control|text|message|other)"
            )));
        }
    }
    .to_string())
}

fn flow_status_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        // TS 29.514 FlowStatus enum: the directional variants use hyphens
        // ("ENABLED-UPLINK" / "ENABLED-DOWNLINK"), not underscores — an
        // underscore value fails the PCF's enum parse and drops the status.
        "enabled" => "ENABLED",
        "disabled" => "DISABLED",
        "removed" => "REMOVED",
        "enabled-up" | "enabled_uplink" | "enabled-uplink" => "ENABLED-UPLINK",
        "enabled-down" | "enabled_downlink" | "enabled-downlink" => "ENABLED-DOWNLINK",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow_status {other:?} (expected enabled|disabled|removed|enabled-up|enabled-down)"
            )));
        }
    }
    .to_string())
}

fn flow_usage_to_sbi(s: &str) -> PyResult<String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "no_information" | "no-information" | "none" => "NO_INFO",
        "rtcp" => "RTCP",
        "af_signalling" | "af-signalling" | "signalling" => "AF_SIGNALLING",
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flow usage {other:?} (expected no_information|rtcp|af_signalling)"
            )));
        }
    }
    .to_string())
}

/// Collect parsed media components into the `medComponents` map keyed by each
/// component's `medCompN` (TS 29.514 §5.6.2.3). Returns `None` for an empty
/// list so the field is omitted from the request body entirely.
fn components_to_map(
    components: Vec<MediaComponent>,
) -> Option<IndexMap<String, MediaComponent>> {
    if components.is_empty() {
        return None;
    }
    Some(
        components
            .into_iter()
            .map(|component| (component.med_comp_n.to_string(), component))
            .collect(),
    )
}

/// Parse a Python list of dicts into a `Vec<sbi::npcf::MediaComponent>`.
/// Mirrors the dict shape consumed by ``diameter.rx_aar`` but emits the
/// camelCase / UPPER_SNAKE strings the Npcf API requires.
fn parse_sbi_media_components(obj: &Bound<'_, PyAny>) -> PyResult<Vec<MediaComponent>> {
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
        let media_type = media_type_to_sbi(&media_type_str)?;

        let flow_status = match component_dict.get_item("flow_status")? {
            Some(value) => {
                let s: String = value.extract()?;
                flow_status_to_sbi(&s)?
            }
            None => "ENABLED".to_string(),
        };

        // TS 29.514 MediaComponent.codecs is an array (1–2 entries); the Python
        // API still takes a single `codec_data`, so wrap it.
        let codecs: Option<Vec<String>> = match component_dict.get_item("codec_data")? {
            Some(value) => {
                // The Rx side stores codec data as raw bytes per RFC 4566 SDP
                // octets; the SBI schema requires a string.  Decode lossily
                // so call sites can pass bytes uniformly.
                let codec = if let Ok(text) = value.extract::<String>() {
                    text
                } else {
                    let raw: Vec<u8> = value.extract()?;
                    String::from_utf8_lossy(&raw).into_owned()
                };
                Some(vec![codec])
            }
            None => None,
        };

        // medSubComps is a map keyed by the sub-component's fNum (TS 29.514
        // §5.6.2.7), not an array.
        let mut med_sub_comps: IndexMap<String, MediaSubComponent> = IndexMap::new();
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

                let descriptions = match flow_dict.get_item("descriptions")? {
                    Some(value) => {
                        let descs: Vec<String> = value.extract()?;
                        if descs.is_empty() {
                            None
                        } else {
                            Some(descs)
                        }
                    }
                    None => None,
                };

                let flow_status_inner = match flow_dict.get_item("status")? {
                    Some(value) => {
                        let s: String = value.extract()?;
                        Some(flow_status_to_sbi(&s)?)
                    }
                    None => None,
                };

                let flow_usage = match flow_dict.get_item("usage")? {
                    Some(value) => {
                        let s: String = value.extract()?;
                        Some(flow_usage_to_sbi(&s)?)
                    }
                    None => None,
                };

                med_sub_comps.insert(
                    flow_number.to_string(),
                    MediaSubComponent {
                        f_num: flow_number,
                        f_descs: descriptions,
                        f_status: flow_status_inner,
                        flow_usage,
                    },
                );
            }
        }

        out.push(MediaComponent {
            med_comp_n: number,
            med_type: media_type,
            f_status: flow_status,
            codecs,
            med_sub_comps: if med_sub_comps.is_empty() {
                None
            } else {
                Some(med_sub_comps)
            },
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn make_component_dict<'py>(python: Python<'py>) -> Bound<'py, PyDict> {
        let dict = PyDict::new(python);
        dict.set_item("number", 1u32).unwrap();
        dict.set_item("media_type", "audio").unwrap();

        let flows = PyList::empty(python);
        let flow = PyDict::new(python);
        flow.set_item("number", 1u32).unwrap();
        flow.set_item("usage", "rtcp").unwrap();
        flow.set_item(
            "descriptions",
            vec![
                "permit out 17 from 10.0.0.1 50001 to 10.0.0.2 30001",
                "permit in 17 from 10.0.0.2 30001 to 10.0.0.1 50001",
            ],
        )
        .unwrap();
        flows.append(flow).unwrap();
        dict.set_item("flows", flows).unwrap();
        dict
    }

    #[test]
    fn parse_sbi_media_components_basic() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let list = PyList::empty(python);
            list.append(make_component_dict(python)).unwrap();

            let parsed = parse_sbi_media_components(list.as_any()).unwrap();
            assert_eq!(parsed.len(), 1);
            let component = &parsed[0];
            assert_eq!(component.med_comp_n, 1);
            assert_eq!(component.med_type, "AUDIO");
            assert_eq!(component.f_status, "ENABLED");
            let subs = component.med_sub_comps.as_ref().unwrap();
            assert_eq!(subs.len(), 1);
            // Keyed by fNum.
            let sub = &subs["1"];
            assert_eq!(sub.f_num, 1);
            assert_eq!(sub.flow_usage.as_deref(), Some("RTCP"));
            let descs = sub.f_descs.as_ref().unwrap();
            assert_eq!(descs.len(), 2);
            assert!(descs[0].starts_with("permit out 17 from"));
        });
    }

    #[test]
    fn parse_sbi_rejects_missing_number() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("media_type", "audio").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let error = parse_sbi_media_components(list.as_any()).unwrap_err();
            assert!(error.to_string().contains("number"));
        });
    }

    #[test]
    fn parsed_component_serializes_to_med_sub_comps_json() {
        // End-to-end check: the parsed component MUST serialize into the
        // ``medSubComps`` envelope (TS 29.514 §5.6.2.4).  Pre-spec, the
        // Python binding hardcoded ``med_sub_comps: None`` so the
        // serialized JSON never contained ``medSubComps`` — defeating PCF
        // gating on any non-trivial UPF.
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let list = PyList::empty(python);
            list.append(make_component_dict(python)).unwrap();
            let parsed = parse_sbi_media_components(list.as_any()).unwrap();
            let json = serde_json::to_string(&parsed[0]).unwrap();
            assert!(
                json.contains("medSubComps"),
                "MediaComponent JSON must include medSubComps: {json}"
            );
            assert!(
                json.contains("fDescs"),
                "med_sub_comps[*].fDescs must reach the wire: {json}"
            );
            // medCompN / fNum are the keys the PCF parses — a camelCase of the
            // Rust field names would be ignored.
            assert!(json.contains("medCompN"), "medCompN must be present: {json}");
            assert!(json.contains("fNum"), "fNum must be present: {json}");
            assert!(json.contains("RTCP"), "Flow-Usage RTCP must survive: {json}");
            assert!(
                json.contains("permit out 17 from 10.0.0.1 50001"),
                "5-tuple Flow-Description must survive: {json}"
            );
        });
    }

    #[test]
    fn flow_status_directional_variants_use_hyphens() {
        // TS 29.514 FlowStatus enum uses hyphens for the directional variants.
        assert_eq!(flow_status_to_sbi("enabled-up").unwrap(), "ENABLED-UPLINK");
        assert_eq!(
            flow_status_to_sbi("enabled_downlink").unwrap(),
            "ENABLED-DOWNLINK"
        );
        assert_eq!(flow_status_to_sbi("enabled").unwrap(), "ENABLED");
        assert_eq!(flow_status_to_sbi("disabled").unwrap(), "DISABLED");
    }

    #[test]
    fn components_to_map_keys_by_med_comp_n_and_omits_empty() {
        assert!(components_to_map(vec![]).is_none());
        let map = components_to_map(vec![
            MediaComponent {
                med_comp_n: 1,
                med_type: "AUDIO".to_string(),
                f_status: "ENABLED".to_string(),
                codecs: None,
                med_sub_comps: None,
            },
            MediaComponent {
                med_comp_n: 2,
                med_type: "VIDEO".to_string(),
                f_status: "ENABLED".to_string(),
                codecs: None,
                med_sub_comps: None,
            },
        ])
        .unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["1"].med_type, "AUDIO");
        assert_eq!(map["2"].med_type, "VIDEO");
    }

    #[test]
    fn parse_wraps_codec_data_into_codecs_array() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("number", 1u32).unwrap();
            component.set_item("media_type", "audio").unwrap();
            component.set_item("codec_data", "PCMU").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let parsed = parse_sbi_media_components(list.as_any()).unwrap();
            assert_eq!(parsed[0].codecs.as_deref(), Some(&["PCMU".to_string()][..]));
            let json = serde_json::to_string(&parsed[0]).unwrap();
            assert!(json.contains("\"codecs\":[\"PCMU\"]"), "{json}");
        });
    }

    #[test]
    fn parse_sbi_rejects_unknown_media_type() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let component = PyDict::new(python);
            component.set_item("number", 1u32).unwrap();
            component.set_item("media_type", "hologram").unwrap();
            let list = PyList::empty(python);
            list.append(component).unwrap();
            let error = parse_sbi_media_components(list.as_any()).unwrap_err();
            assert!(error.to_string().contains("hologram"));
        });
    }

    #[test]
    fn binding_to_pydict_snake_case_keys_plus_pcf_uri() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let binding: PcfBinding = serde_json::from_str(
                r#"{
                    "supi": "imsi-001010000000001",
                    "ipv4Addr": "10.45.0.7",
                    "dnn": "ims",
                    "snssai": {"sst": 1, "sd": "000001"},
                    "pcfFqdn": "pcf01.5gc.example.org",
                    "pcfIpEndPoints": [{"ipv4Address": "10.10.0.20", "transport": "TCP", "port": 8080}]
                }"#,
            )
            .unwrap();

            let dict = binding_to_pydict(python, &binding, Scheme::Http).unwrap();

            let supi: String = dict.get_item("supi").unwrap().unwrap().extract().unwrap();
            assert_eq!(supi, "imsi-001010000000001");
            let dnn: String = dict.get_item("dnn").unwrap().unwrap().extract().unwrap();
            assert_eq!(dnn, "ims");

            // pcf_uri derived from pcfFqdn — the field the script hands straight
            // to create_session(pcf_uri=...).
            let pcf_uri: String = dict.get_item("pcf_uri").unwrap().unwrap().extract().unwrap();
            assert_eq!(pcf_uri, "http://pcf01.5gc.example.org");

            // Nested snssai dict.
            let snssai = dict.get_item("snssai").unwrap().unwrap();
            let sst: u8 = snssai.get_item("sst").unwrap().extract().unwrap();
            assert_eq!(sst, 1);

            // Endpoints list.
            let endpoints = dict.get_item("pcf_ip_end_points").unwrap().unwrap();
            assert_eq!(endpoints.len().unwrap(), 1);
        });
    }

    #[test]
    fn binding_to_pydict_pcf_uri_none_when_degenerate() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let binding: PcfBinding = serde_json::from_str(r#"{"supi": "imsi-1"}"#).unwrap();
            let dict = binding_to_pydict(python, &binding, Scheme::Http).unwrap();
            // pcf_uri key is present but None for a binding with no PCF address.
            let pcf_uri = dict.get_item("pcf_uri").unwrap().unwrap();
            assert!(pcf_uri.is_none());
        });
    }

    /// Façade-drift regression (the live blocker): the embedded `_SbiNamespace`
    /// stub in siphon_package.py must expose every method/attr the Rust `PySbi`
    /// does — pre-injection (`hasattr`) — and, once a singleton is injected as
    /// `_inner`, forward to it (so `sbi.discover_pcf_binding` / `sbi.BsfError`
    /// can never AttributeError again). Evaluated from source against an
    /// isolated globals dict, independent of the global SBI_SINGLETON OnceLock.
    #[test]
    fn sbi_facade_exposes_full_surface_and_forwards() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            // The package source does `import _siphon_registry` at top level.
            crate::script::api::ensure_registry(python).expect("ensure_registry");

            let source = include_str!("siphon_package.py");
            let module_globals = PyDict::new(python);
            python
                .run(
                    &std::ffi::CString::new(source).expect("CString"),
                    Some(&module_globals),
                    Some(&module_globals),
                )
                .expect("evaluate siphon_package.py");

            let script = r#"
# 1. Pre-injection surface parity with the Rust PySbi.
expected = ('create_session', 'delete_session', 'update_session',
            'discover_pcf_binding', 'on_event', 'BsfError')
for name in expected:
    assert hasattr(sbi, name), f"sbi facade missing {name!r}"
assert issubclass(sbi.BsfError, RuntimeError), "sbi.BsfError must be a RuntimeError"

# 2. Pre-injection, data methods raise the helpful NotImplementedError.
try:
    sbi.discover_pcf_binding(ue_ipv4="10.0.0.1")
except NotImplementedError as e:
    assert "bsf_url" in str(e), str(e)
else:
    raise AssertionError("discover_pcf_binding did not raise pre-injection")

# 3. Inject a fake _inner and assert every call forwards to it, and that
#    BsfError now forwards to the inner's exception type (so a script that
#    holds the stub catches the type the Rust impl actually raises).
class _FakeInner:
    class BsfError(RuntimeError):
        pass
    def discover_pcf_binding(self, **kw):
        return {"pcf_uri": "http://pcf01", "_seen": kw}
    def create_session(self, **kw):
        return {"app_session_id": "s1", "ok": True}
    def delete_session(self, ref):
        return ref
    def update_session(self, ref, **kw):
        return ref

fake = _FakeInner()
sbi._inner = fake
assert sbi.discover_pcf_binding(ue_ipv4="10.0.0.1")["pcf_uri"] == "http://pcf01"
assert sbi.create_session(supi="imsi-1")["app_session_id"] == "s1"
assert sbi.delete_session("http://pcf01/x") == "http://pcf01/x"
assert sbi.BsfError is _FakeInner.BsfError, "BsfError must forward to the inner type"
"#;
            python
                .run(
                    &std::ffi::CString::new(script).expect("CString"),
                    Some(&module_globals),
                    Some(&module_globals),
                )
                .expect("sbi facade surface + forwarding assertions");
        });
    }
}
