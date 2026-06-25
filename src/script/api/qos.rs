//! PyO3 `qos` namespace — turns SDP offer/answer pairs into the
//! ``media_components`` structure consumed by ``diameter.rx_aar`` and
//! ``sbi.create_session``.
//!
//! This is the bridge that lets a P-CSCF emit real (5-tuple) Flow-Description
//! rules instead of the wildcard placeholder that hides any gating bug in
//! the lab.  Building IPFilterRules in Python is fiddly and full of
//! corner-cases (rtcp-mux, hold, IPv6, multiple m= sections); the parsing
//! already lives in [`crate::media::sdp`] so we keep the logic on the Rust
//! side and expose a single helper.
//!
//! See 3GPP TS 29.214 §5.3.7 / §5.3.8 and RFC 6733 §4.3 for the AVP shape
//! we're targeting; the schema for 5G N5 is TS 29.514 §5.6.2.4.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::media::sdp::{MediaLine, SdpBody};

use super::rtpengine::{extract_message, extract_sdp_body};

/// Stateless QoS helper namespace.
///
/// Injected as ``siphon.qos`` at startup — always available.
#[pyclass(name = "QosNamespace")]
pub struct PyQosNamespace;

impl Default for PyQosNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl PyQosNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyQosNamespace {
    /// Translate an SDP offer/answer pair into a ``media_components`` list.
    ///
    /// Args:
    ///     offer: the original (offer) SDP.  Accepts a ``Request``,
    ///         ``Reply``, ``Call``, ``str``, or ``bytes``.
    ///     answer: the answer SDP (typically after ``rtpengine.answer()``
    ///         has rewritten the media endpoint).  Same accepted types.
    ///     direction: ``"orig"`` (UE is the offerer — UE addr comes from
    ///         ``offer``, remote addr from ``answer``) or ``"term"`` (UE
    ///         is the answerer — UE addr comes from ``answer``, remote
    ///         addr from ``offer``).
    ///
    /// Returns:
    ///     A list of dicts shaped for ``diameter.rx_aar(media_components=…)``
    ///     and ``sbi.create_session(media_components=…)``.  Each list entry
    ///     corresponds to one ``m=`` section in the SDPs (sections with port
    ///     ``0`` are skipped — RFC 4566 §5.14 "disabled stream").
    ///
    /// Raises:
    ///     ``ValueError`` if ``direction`` is not ``"orig"`` / ``"term"``,
    ///     if either SDP is missing a connection address for a media
    ///     section, or if the offer and answer disagree on the number of
    ///     ``m=`` sections.
    #[pyo3(signature = (*, offer, answer, direction="orig"))]
    fn media_flows_from_sdp<'py>(
        &self,
        python: Python<'py>,
        offer: &Bound<'py, PyAny>,
        answer: &Bound<'py, PyAny>,
        direction: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let direction = match direction {
            "orig" | "originating" => Direction::Originating,
            "term" | "terminating" => Direction::Terminating,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "direction must be 'orig' or 'term', got {other:?}"
                )));
            }
        };

        let offer_sdp = parse_to_sdp(offer)?;
        let answer_sdp = parse_to_sdp(answer)?;

        if offer_sdp.media_sections.len() != answer_sdp.media_sections.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offer/answer m= section count mismatch: offer={}, answer={}",
                offer_sdp.media_sections.len(),
                answer_sdp.media_sections.len(),
            )));
        }

        let offer_session_c = sdp_connection_ip(offer_sdp.connection());
        let answer_session_c = sdp_connection_ip(answer_sdp.connection());

        let components_list = PyList::empty(python);
        let mut component_number: u32 = 0;

        for (offer_media, answer_media) in offer_sdp
            .media_sections
            .iter()
            .zip(answer_sdp.media_sections.iter())
        {
            if offer_media.port == 0 || answer_media.port == 0 {
                continue; // RFC 4566 §5.14 — stream disabled.
            }

            let offer_ip = media_or_session_ip(offer_media, offer_session_c.as_deref())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "offer m={} {} has no connection address",
                        offer_media.media_type, offer_media.port
                    ))
                })?;
            let answer_ip = media_or_session_ip(answer_media, answer_session_c.as_deref())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "answer m={} {} has no connection address",
                        answer_media.media_type, answer_media.port
                    ))
                })?;

            let (ue_ip, ue_rtp_port, remote_ip, remote_rtp_port, ue_media, remote_media) =
                match direction {
                    Direction::Originating => (
                        offer_ip,
                        offer_media.port,
                        answer_ip,
                        answer_media.port,
                        offer_media,
                        answer_media,
                    ),
                    Direction::Terminating => (
                        answer_ip,
                        answer_media.port,
                        offer_ip,
                        offer_media.port,
                        answer_media,
                        offer_media,
                    ),
                };

            let proto_num = ip_proto_for_sdp_protocol(&offer_media.protocol);
            let media_type_alias = sdp_media_type_alias(&offer_media.media_type);

            component_number += 1;
            let component_dict = PyDict::new(python);
            component_dict.set_item("number", component_number)?;
            component_dict.set_item("media_type", media_type_alias)?;
            if let Some(status) = ue_media_flow_status(ue_media) {
                component_dict.set_item("flow_status", status)?;
            }

            let flows = PyList::empty(python);

            // RTP sub-component (Flow-Number = 1).
            let rtp_flow = PyDict::new(python);
            rtp_flow.set_item("number", 1u32)?;
            rtp_flow.set_item(
                "descriptions",
                vec![
                    ipfilter_rule("out", proto_num, &ue_ip, ue_rtp_port, &remote_ip, remote_rtp_port),
                    ipfilter_rule("in", proto_num, &remote_ip, remote_rtp_port, &ue_ip, ue_rtp_port),
                ],
            )?;
            flows.append(rtp_flow)?;

            // RTCP sub-component (Flow-Number = 2) — unless rtcp-mux on
            // BOTH sides (a=rtcp-mux in offer + answer means agreed; RFC
            // 5761 §5.1.3 — answerer MUST agree before mux is in effect).
            let mux_agreed = ue_media.has_attr("rtcp-mux") && remote_media.has_attr("rtcp-mux");
            if !mux_agreed {
                let ue_rtcp_port = explicit_rtcp_port(ue_media).unwrap_or(ue_rtp_port + 1);
                let remote_rtcp_port =
                    explicit_rtcp_port(remote_media).unwrap_or(remote_rtp_port + 1);

                let rtcp_flow = PyDict::new(python);
                rtcp_flow.set_item("number", 2u32)?;
                rtcp_flow.set_item("usage", "rtcp")?;
                rtcp_flow.set_item(
                    "descriptions",
                    vec![
                        ipfilter_rule(
                            "out",
                            proto_num,
                            &ue_ip,
                            ue_rtcp_port,
                            &remote_ip,
                            remote_rtcp_port,
                        ),
                        ipfilter_rule(
                            "in",
                            proto_num,
                            &remote_ip,
                            remote_rtcp_port,
                            &ue_ip,
                            ue_rtcp_port,
                        ),
                    ],
                )?;
                flows.append(rtcp_flow)?;
            }

            component_dict.set_item("flows", flows)?;
            components_list.append(component_dict)?;
        }

        Ok(components_list)
    }

    fn __repr__(&self) -> &'static str {
        "<QosNamespace>"
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Originating,
    Terminating,
}

/// Extract the IP portion of a `c=IN IP4 10.0.0.1` / `c=IN IP6 2001:db8::1` value.
fn sdp_connection_ip(value: Option<&str>) -> Option<String> {
    let raw = value?;
    // Format: "IN IP4 10.0.0.1" / "IN IP6 ::1" / sometimes a TTL/count suffix
    // for multicast that we strip.
    let mut parts = raw.split_whitespace();
    let _ = parts.next()?; // network type ("IN")
    let _ = parts.next()?; // address type ("IP4" / "IP6")
    let addr_field = parts.next()?;
    let addr = addr_field
        .split(['/', ' '])
        .next()
        .unwrap_or(addr_field)
        .trim();
    if addr.is_empty() {
        None
    } else {
        Some(addr.to_string())
    }
}

fn media_or_session_ip(media: &MediaLine, session_ip: Option<&str>) -> Option<String> {
    sdp_connection_ip(media.connection())
        .or_else(|| session_ip.map(|s| s.to_string()))
}

/// Pick a transport-layer protocol number for an IPFilterRule.  RFC 6733
/// §4.3: the protocol token in an IPFilterRule is the IANA Protocol Number
/// from the IP header — 17 = UDP, 6 = TCP, 132 = SCTP.
fn ip_proto_for_sdp_protocol(sdp_protocol: &str) -> u8 {
    let upper = sdp_protocol.to_ascii_uppercase();
    if upper.starts_with("TCP") || upper.contains("/TCP/") {
        6
    } else if upper.starts_with("SCTP") || upper.contains("/SCTP/") {
        132
    } else {
        17
    }
}

/// Lower-case SDP media type → the alias the ``rx_aar`` / ``create_session``
/// parser expects.
fn sdp_media_type_alias(sdp_media_type: &str) -> &'static str {
    match sdp_media_type.to_ascii_lowercase().as_str() {
        "audio" => "audio",
        "video" => "video",
        "application" => "application",
        "text" => "text",
        "message" => "message",
        "image" => "data",
        _ => "other",
    }
}

/// Derive UE-perspective `flow_status` from the media-section direction
/// attributes (RFC 3264 §6.1).  Returns `None` for sendrecv / unspecified —
/// the binding defaults to "enabled" downstream.
fn ue_media_flow_status(media: &MediaLine) -> Option<&'static str> {
    if media.has_attr("inactive") {
        Some("disabled")
    } else if media.has_attr("sendonly") {
        Some("enabled-up")
    } else if media.has_attr("recvonly") {
        Some("enabled-down")
    } else {
        None
    }
}

/// Parse `a=rtcp:PORT [...]` (RFC 3605) if present.
fn explicit_rtcp_port(media: &MediaLine) -> Option<u16> {
    let raw = media.get_attr("rtcp")?;
    let token = raw.split_whitespace().next()?;
    token.parse().ok()
}

fn ipfilter_rule(
    direction: &str,
    proto: u8,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> String {
    format!(
        "permit {direction} {proto} from {src_ip} {src_port} to {dst_ip} {dst_port}"
    )
}

/// Turn a `Bound<PyAny>` (str / bytes / Request / Reply / Call) into a parsed [`SdpBody`].
fn parse_to_sdp(obj: &Bound<'_, PyAny>) -> PyResult<SdpBody> {
    if let Ok(text) = obj.extract::<String>() {
        return Ok(SdpBody::parse(&text));
    }
    if let Ok(raw) = obj.extract::<Vec<u8>>() {
        let text = String::from_utf8(raw).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "SDP body is not valid UTF-8: {error}"
            ))
        })?;
        return Ok(SdpBody::parse(&text));
    }
    let message_arc = extract_message(obj).map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "expected a Request, Reply, Call, str, or bytes",
        )
    })?;
    let message = message_arc.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("message lock poisoned: {error}"))
    })?;
    let sdp_bytes = extract_sdp_body(&message)?;
    drop(message);
    let text = String::from_utf8(sdp_bytes).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "SDP body is not valid UTF-8: {error}"
        ))
    })?;
    Ok(SdpBody::parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 100.65.0.2\r\n",
        "s=-\r\n",
        "c=IN IP4 100.65.0.2\r\n",
        "t=0 0\r\n",
        "m=audio 50000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=sendrecv\r\n",
    );

    const ANSWER_REWRITTEN: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 100.64.0.10\r\n",
        "s=-\r\n",
        "c=IN IP4 100.64.0.10\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=sendrecv\r\n",
    );

    #[test]
    fn orig_emits_full_five_tuple_with_rtcp() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let offer = OFFER.into_pyobject(python).unwrap();
            let answer = ANSWER_REWRITTEN.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            assert_eq!(result.len(), 1);
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
            assert_eq!(
                component.get_item("media_type").unwrap().unwrap().extract::<String>().unwrap(),
                "audio"
            );
            let flows: Bound<'_, PyList> = component
                .get_item("flows")
                .unwrap()
                .unwrap()
                .cast_into()
                .unwrap();
            assert_eq!(flows.len(), 2);

            let rtp: Bound<'_, PyDict> = flows.get_item(0).unwrap().cast_into().unwrap();
            let rtp_descs: Vec<String> = rtp
                .get_item("descriptions")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(rtp_descs.len(), 2);
            assert_eq!(
                rtp_descs[0],
                "permit out 17 from 100.65.0.2 50000 to 100.64.0.10 30000"
            );
            assert_eq!(
                rtp_descs[1],
                "permit in 17 from 100.64.0.10 30000 to 100.65.0.2 50000"
            );

            let rtcp: Bound<'_, PyDict> = flows.get_item(1).unwrap().cast_into().unwrap();
            assert_eq!(
                rtcp.get_item("usage").unwrap().unwrap().extract::<String>().unwrap(),
                "rtcp"
            );
            let rtcp_descs: Vec<String> = rtcp
                .get_item("descriptions")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(
                rtcp_descs[0],
                "permit out 17 from 100.65.0.2 50001 to 100.64.0.10 30001"
            );
        });
    }

    #[test]
    fn term_flips_ue_and_remote() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let offer = OFFER.into_pyobject(python).unwrap();
            let answer = ANSWER_REWRITTEN.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "term")
                .unwrap();
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
            let flows: Bound<'_, PyList> = component
                .get_item("flows")
                .unwrap()
                .unwrap()
                .cast_into()
                .unwrap();
            let rtp: Bound<'_, PyDict> = flows.get_item(0).unwrap().cast_into().unwrap();
            let rtp_descs: Vec<String> = rtp
                .get_item("descriptions")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            // For term, the UE is the answerer (100.64.0.10:30000) and the
            // remote is the offerer (100.65.0.2:50000).
            assert_eq!(
                rtp_descs[0],
                "permit out 17 from 100.64.0.10 30000 to 100.65.0.2 50000"
            );
            assert_eq!(
                rtp_descs[1],
                "permit in 17 from 100.65.0.2 50000 to 100.64.0.10 30000"
            );
        });
    }

    #[test]
    fn rtcp_mux_skips_second_subcomponent() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let mux_offer = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.65.0.2\r\n",
                "s=-\r\n",
                "c=IN IP4 100.65.0.2\r\n",
                "t=0 0\r\n",
                "m=audio 50000 RTP/AVP 0\r\n",
                "a=rtcp-mux\r\n",
            );
            let mux_answer = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.64.0.10\r\n",
                "s=-\r\n",
                "c=IN IP4 100.64.0.10\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "a=rtcp-mux\r\n",
            );
            let offer = mux_offer.into_pyobject(python).unwrap();
            let answer = mux_answer.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            let component: Bound<'_, PyDict> =
                result.get_item(0).unwrap().cast_into().unwrap();
            let flows: Bound<'_, PyList> = component
                .get_item("flows")
                .unwrap()
                .unwrap()
                .cast_into()
                .unwrap();
            assert_eq!(flows.len(), 1, "rtcp-mux should collapse to one flow");
        });
    }

    #[test]
    fn rtcp_attr_overrides_default_port() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let custom_offer = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.65.0.2\r\n",
                "s=-\r\n",
                "c=IN IP4 100.65.0.2\r\n",
                "t=0 0\r\n",
                "m=audio 50000 RTP/AVP 0\r\n",
                "a=rtcp:59999\r\n",
            );
            let offer = custom_offer.into_pyobject(python).unwrap();
            let answer = ANSWER_REWRITTEN.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            let component: Bound<'_, PyDict> =
                result.get_item(0).unwrap().cast_into().unwrap();
            let flows: Bound<'_, PyList> = component
                .get_item("flows")
                .unwrap()
                .unwrap()
                .cast_into()
                .unwrap();
            let rtcp: Bound<'_, PyDict> = flows.get_item(1).unwrap().cast_into().unwrap();
            let rtcp_descs: Vec<String> = rtcp
                .get_item("descriptions")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert!(rtcp_descs[0].contains(" 100.65.0.2 59999 "));
        });
    }

    #[test]
    fn disabled_stream_is_skipped() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let disabled = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.65.0.2\r\n",
                "s=-\r\n",
                "c=IN IP4 100.65.0.2\r\n",
                "t=0 0\r\n",
                "m=video 0 RTP/AVP 96\r\n",
                "m=audio 50000 RTP/AVP 0\r\n",
            );
            let disabled_answer = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.64.0.10\r\n",
                "s=-\r\n",
                "c=IN IP4 100.64.0.10\r\n",
                "t=0 0\r\n",
                "m=video 0 RTP/AVP 96\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
            );
            let offer = disabled.into_pyobject(python).unwrap();
            let answer = disabled_answer.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            assert_eq!(result.len(), 1, "port=0 should not emit a component");
        });
    }

    #[test]
    fn sendonly_yields_uplink_status() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let hold = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.65.0.2\r\n",
                "s=-\r\n",
                "c=IN IP4 100.65.0.2\r\n",
                "t=0 0\r\n",
                "m=audio 50000 RTP/AVP 0\r\n",
                "a=sendonly\r\n",
            );
            let offer = hold.into_pyobject(python).unwrap();
            let answer = ANSWER_REWRITTEN.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            let component: Bound<'_, PyDict> =
                result.get_item(0).unwrap().cast_into().unwrap();
            let status: String = component
                .get_item("flow_status")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(status, "enabled-up");
        });
    }

    #[test]
    fn mismatched_m_counts_errors() {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let single = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.65.0.2\r\n",
                "s=-\r\n",
                "c=IN IP4 100.65.0.2\r\n",
                "t=0 0\r\n",
                "m=audio 50000 RTP/AVP 0\r\n",
            );
            let two = concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 100.64.0.10\r\n",
                "s=-\r\n",
                "c=IN IP4 100.64.0.10\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0\r\n",
                "m=video 30002 RTP/AVP 96\r\n",
            );
            let offer = single.into_pyobject(python).unwrap();
            let answer = two.into_pyobject(python).unwrap();
            let error = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap_err();
            assert!(error.to_string().contains("mismatch"));
        });
    }
}
