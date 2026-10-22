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
    ///     and ``sbi.create_session(media_components=…)``, one per ``m=``
    ///     line.  ``number`` is the ordinal of the ``m=`` line, so a line
    ///     keeps its number when an earlier one is disabled.
    ///     Every entry names ``flow_status``, derived per TS 29.213 table
    ///     6.2.1 from the offer and the answer (NOTE 5: the answer's port and
    ///     direction, but ``a=inactive`` in the offer wins; a media line
    ///     without a direction attribute takes the session-level one):
    ///     - ``"removed"``: port ``0`` in the offer or the answer.  The entry
    ///       has no flows.
    ///     - ``"enabled"``: TCP transport (``TCP``, ``TCP/MSRP``,
    ///       ``UDP/DTLS/SCTP``), ``a=rtcp-mux`` in offer and answer, or
    ///       ``a=sendrecv`` / no direction attribute.
    ///     - ``"disabled"``: ``a=inactive``.
    ///     - ``"enabled-up"`` / ``"enabled-down"``: ``a=sendonly`` /
    ///       ``a=recvonly``, read from the side of the SDP that carries it
    ///       (``sendonly`` in the UE's SDP is uplink, in the network's SDP
    ///       downlink; ``recvonly`` the other way round).
    ///     ``"enabled"`` is named, not left out: on an update an absent
    ///     Flow-Status means "unchanged" (TS 29.214 §5.3.16).
    ///     Each sub-component carries two descriptions, uplink first
    ///     (TS 29.214 clause 5.3.8: ``in`` is the uplink flow, ``out`` the
    ///     downlink flow; the UE is the source of ``in`` and the destination
    ///     of ``out``):
    ///
    /// ```text
    /// permit in  <proto> from <UE> <port> to <remote> <port>
    /// permit out <proto> from <remote> <port> to <UE> <port>
    /// ```
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

        // Media-Component-Number is the ordinal of the m= line (TS 29.213
        // table 6.2.1), so it stays the same for a line across renegotiations
        // whatever happens to the lines before it.
        for (component_number, (offer_media, answer_media)) in (1u32..).zip(
            offer_sdp
                .media_sections
                .iter()
                .zip(answer_sdp.media_sections.iter()),
        ) {
            let flow_status = table_flow_status(
                (&offer_sdp, offer_media),
                (&answer_sdp, answer_media),
                direction,
            );

            let component_dict = PyDict::new(python);
            component_dict.set_item("number", component_number)?;
            component_dict.set_item("media_type", sdp_media_type_alias(&offer_media.media_type))?;
            component_dict.set_item("flow_status", flow_status)?;

            if flow_status == "removed" {
                // A port-0 line has no IP flows to describe; the component is
                // still reported, so the PCRF releases what it had authorized.
                component_dict.set_item("flows", PyList::empty(python))?;
                components_list.append(component_dict)?;
                continue;
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

            let flows = PyList::empty(python);

            // RTP sub-component (Flow-Number = 1).
            let rtp_flow = PyDict::new(python);
            rtp_flow.set_item("number", 1u32)?;
            rtp_flow.set_item(
                "descriptions",
                flow_descriptions(
                    proto_num,
                    (&ue_ip, ue_rtp_port),
                    (&remote_ip, remote_rtp_port),
                ),
            )?;
            flows.append(rtp_flow)?;

            // RTCP sub-component (Flow-Number = 2) — unless rtcp-mux on
            // BOTH sides (a=rtcp-mux in offer + answer means agreed; RFC
            // 5761 §5.1.3 — answerer MUST agree before mux is in effect).
            if !rtcp_mux_negotiated(ue_media, remote_media) {
                let ue_rtcp_port = explicit_rtcp_port(ue_media).unwrap_or(ue_rtp_port + 1);
                let remote_rtcp_port =
                    explicit_rtcp_port(remote_media).unwrap_or(remote_rtp_port + 1);

                let rtcp_flow = PyDict::new(python);
                rtcp_flow.set_item("number", 2u32)?;
                rtcp_flow.set_item("usage", "rtcp")?;
                rtcp_flow.set_item(
                    "descriptions",
                    flow_descriptions(
                        proto_num,
                        (&ue_ip, ue_rtcp_port),
                        (&remote_ip, remote_rtcp_port),
                    ),
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
    sdp_connection_ip(media.connection()).or_else(|| session_ip.map(|s| s.to_string()))
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

/// An SDP direction attribute (RFC 4566 §6, RFC 3264 §5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SdpDirection {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

/// The direction attribute in force for one m= line: its own, else the
/// session-level one (RFC 4566 §6: a session-level attribute applies to every
/// media line that does not override it). `None` when neither has one.
fn media_direction(sdp: &SdpBody, media: &MediaLine) -> Option<SdpDirection> {
    direction_attribute(|name| media.has_attr(name))
        .or_else(|| direction_attribute(|name| sdp.session_has_attr(name)))
}

fn direction_attribute(has: impl Fn(&str) -> bool) -> Option<SdpDirection> {
    [
        ("sendrecv", SdpDirection::SendRecv),
        ("sendonly", SdpDirection::SendOnly),
        ("recvonly", SdpDirection::RecvOnly),
        ("inactive", SdpDirection::Inactive),
    ]
    .into_iter()
    .find(|(name, _)| has(name))
    .map(|(_, direction)| direction)
}

/// `a=rtcp-mux` is negotiated once both offer and answer carry it (RFC 5761
/// §5.1.1: the answerer includes it only when it agrees to multiplex).
fn rtcp_mux_negotiated(one: &MediaLine, other: &MediaLine) -> bool {
    one.has_attr("rtcp-mux") && other.has_attr("rtcp-mux")
}

/// "TCP", "TCP/MSRP" and "UDP/DTLS/SCTP" are the transports TS 29.213 table
/// 6.2.1 enables in both directions whatever the direction attributes say;
/// any other TCP-carried profile (TCP/TLS/MSRP, TCP/RTP/AVP) is TCP transport
/// too.
fn is_table_tcp_transport(sdp_protocol: &str) -> bool {
    let upper = sdp_protocol.to_ascii_uppercase();
    upper == "TCP" || upper.starts_with("TCP/") || upper == "UDP/DTLS/SCTP"
}

/// Flow-Status of one media component per TS 29.213 Rel-18 table 6.2.1.
///
/// NOTE 5 decides which SDP the direction comes from: the answer's port and
/// direction attribute, except that `a=inactive` in the offer wins (for
/// clients that ignore it). `<SDP direction>` (NOTE 8) is the direction of the
/// SDP the attribute was read from: on the originating leg the offer is the
/// UE's (uplink SDP) and the answer comes from the network, on the
/// terminating leg the other way round.
///
/// Always names a status. TS 29.214 §5.3.16 lets an update omit an AVP that
/// has not changed (table NOTE 7), so a PCRF reads an absent Flow-Status on an
/// update as "unchanged": leaving ENABLED implicit kept a held stream's gates
/// closed after it resumed.
fn table_flow_status(
    (offer_sdp, offer): (&SdpBody, &MediaLine),
    (answer_sdp, answer): (&SdpBody, &MediaLine),
    direction: Direction,
) -> &'static str {
    if offer.port == 0 || answer.port == 0 {
        return "removed";
    }
    if is_table_tcp_transport(&answer.protocol) || is_table_tcp_transport(&offer.protocol) {
        return "enabled";
    }
    // NOTE 12: multiplexed RTP/RTCP needs ENABLED so RTCP always passes.
    if rtcp_mux_negotiated(offer, answer) {
        return "enabled";
    }
    if media_direction(offer_sdp, offer) == Some(SdpDirection::Inactive) {
        return "disabled";
    }
    let answer_is_uplink_sdp = matches!(direction, Direction::Terminating);
    match media_direction(answer_sdp, answer) {
        Some(SdpDirection::RecvOnly) if answer_is_uplink_sdp => "enabled-down",
        Some(SdpDirection::RecvOnly) => "enabled-up",
        Some(SdpDirection::SendOnly) if answer_is_uplink_sdp => "enabled-up",
        Some(SdpDirection::SendOnly) => "enabled-down",
        Some(SdpDirection::Inactive) => "disabled",
        Some(SdpDirection::SendRecv) | None => "enabled",
    }
}

/// Parse `a=rtcp:PORT [...]` (RFC 3605) if present.
fn explicit_rtcp_port(media: &MediaLine) -> Option<u16> {
    let raw = media.get_attr("rtcp")?;
    let token = raw.split_whitespace().next()?;
    token.parse().ok()
}

/// The two Flow-Descriptions of one IP flow pair, uplink first.
///
/// TS 29.214 clause 5.3.8: the direction "in" refers to uplink IP flows and
/// "out" to downlink IP flows. RFC 6733 clause 4.3.1 defines "in" as from the
/// terminal and "out" as to the terminal, and TS 29.212 clause 5.4.2 spells
/// out the addresses: for "out" the source is the remote end and the
/// destination is the UE. TS 29.514 defines the N5 `FlowDescription` by the
/// same clause, so one form serves Rx and N5.
///
/// Neither specification orders the two descriptions; the Media-Sub-Component
/// grammar lists them as "UL and/or DL" and the uplink one goes first here.
fn flow_descriptions(proto: u8, ue: (&str, u16), remote: (&str, u16)) -> Vec<String> {
    vec![
        ipfilter_rule("in", proto, ue, remote),
        ipfilter_rule("out", proto, remote, ue),
    ]
}

fn ipfilter_rule(
    direction: &str,
    proto: u8,
    (src_ip, src_port): (&str, u16),
    (dst_ip, dst_port): (&str, u16),
) -> String {
    format!("permit {direction} {proto} from {src_ip} {src_port} to {dst_ip} {dst_port}")
}

/// Turn a `Bound<PyAny>` (str / bytes / Request / Reply / Call) into a parsed [`SdpBody`].
fn parse_to_sdp(obj: &Bound<'_, PyAny>) -> PyResult<SdpBody> {
    if let Ok(text) = obj.extract::<String>() {
        return Ok(SdpBody::parse(&text));
    }
    if let Ok(raw) = obj.extract::<Vec<u8>>() {
        let text = String::from_utf8(raw).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("SDP body is not valid UTF-8: {error}"))
        })?;
        return Ok(SdpBody::parse(&text));
    }
    let message_arc = extract_message(obj).map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("expected a Request, Reply, Call, str, or bytes")
    })?;
    let message = message_arc.lock().map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("message lock poisoned: {error}"))
    })?;
    let sdp_bytes = extract_sdp_body(&message)?;
    drop(message);
    let text = String::from_utf8(sdp_bytes).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("SDP body is not valid UTF-8: {error}"))
    })?;
    Ok(SdpBody::parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.2\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.2\r\n",
        "t=0 0\r\n",
        "m=audio 50000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=sendrecv\r\n",
    );

    const ANSWER_REWRITTEN: &str = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 198.51.100.10\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.10\r\n",
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
                component
                    .get_item("media_type")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
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
                "permit in 17 from 192.0.2.2 50000 to 198.51.100.10 30000"
            );
            assert_eq!(
                rtp_descs[1],
                "permit out 17 from 198.51.100.10 30000 to 192.0.2.2 50000"
            );

            let rtcp: Bound<'_, PyDict> = flows.get_item(1).unwrap().cast_into().unwrap();
            assert_eq!(
                rtcp.get_item("usage")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
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
                "permit in 17 from 192.0.2.2 50001 to 198.51.100.10 30001"
            );
            assert_eq!(
                rtcp_descs[1],
                "permit out 17 from 198.51.100.10 30001 to 192.0.2.2 50001"
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
            // For term, the UE is the answerer (198.51.100.10:30000) and the
            // remote is the offerer (192.0.2.2:50000).
            assert_eq!(
                rtp_descs[0],
                "permit in 17 from 198.51.100.10 30000 to 192.0.2.2 50000"
            );
            assert_eq!(
                rtp_descs[1],
                "permit out 17 from 192.0.2.2 50000 to 198.51.100.10 30000"
            );
        });
    }

    /// One parsed IPFilterRule: `permit <dir> <proto> from <ip> <port> to <ip> <port>`.
    struct Rule {
        direction: String,
        source: (String, String),
        destination: (String, String),
    }

    fn parse_rule(rule: &str) -> Rule {
        let tokens: Vec<&str> = rule.split_whitespace().collect();
        assert_eq!(tokens.len(), 9, "unexpected IPFilterRule shape: {rule}");
        assert_eq!(tokens[0], "permit", "{rule}");
        assert_eq!(tokens[3], "from", "{rule}");
        assert_eq!(tokens[6], "to", "{rule}");
        Rule {
            direction: tokens[1].to_string(),
            source: (tokens[4].to_string(), tokens[5].to_string()),
            destination: (tokens[7].to_string(), tokens[8].to_string()),
        }
    }

    /// The descriptions of every sub-component of the first media component.
    fn sub_component_descriptions(offer: &str, answer: &str, direction: &str) -> Vec<Vec<String>> {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let offer = offer.into_pyobject(python).unwrap();
            let answer = answer.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), direction)
                .unwrap();
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
            let flows: Bound<'_, PyList> = component
                .get_item("flows")
                .unwrap()
                .unwrap()
                .cast_into()
                .unwrap();
            flows
                .iter()
                .map(|flow| {
                    let flow: Bound<'_, PyDict> = flow.cast_into().unwrap();
                    flow.get_item("descriptions")
                        .unwrap()
                        .unwrap()
                        .extract()
                        .unwrap()
                })
                .collect()
        })
    }

    fn audio_sdp(address_type: &str, address: &str, port: u16) -> String {
        format!(
            "v=0\r\no=- 1 1 IN {address_type} {address}\r\ns=-\r\n\
             c=IN {address_type} {address}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n"
        )
    }

    /// TS 29.214 clause 5.3.8: "in" is the uplink flow and "out" the downlink
    /// flow. RFC 6733 clause 4.3.1 and TS 29.212 clause 5.4.2 fix the
    /// addresses that follow from it: the UE is the source of the "in" rule
    /// and the destination of the "out" rule. Holds for RTP and RTCP, on the
    /// originating and the terminating leg, for IPv4 and IPv6.
    #[test]
    fn ue_is_source_of_in_and_destination_of_out() {
        let cases = [
            ("IP4", "192.0.2.2", "198.51.100.10"),
            ("IP6", "2001:db8:1::2", "2001:db8:2::10"),
        ];
        for (address_type, offerer, answerer) in cases {
            let offer = audio_sdp(address_type, offerer, 50000);
            let answer = audio_sdp(address_type, answerer, 30000);
            // (direction, UE address, UE RTP port, remote address, remote RTP port)
            let legs = [
                ("orig", offerer, 50000u16, answerer, 30000u16),
                ("term", answerer, 30000, offerer, 50000),
            ];
            for (leg, ue_ip, ue_port, remote_ip, remote_port) in legs {
                let flows = sub_component_descriptions(&offer, &answer, leg);
                assert_eq!(flows.len(), 2, "RTP and RTCP sub-components ({leg})");
                // RTCP rides one port above RTP on both ends.
                for (port_offset, descriptions) in flows.iter().enumerate() {
                    let port_offset = port_offset as u16;
                    let ue = (ue_ip.to_string(), (ue_port + port_offset).to_string());
                    let remote = (
                        remote_ip.to_string(),
                        (remote_port + port_offset).to_string(),
                    );
                    assert_eq!(descriptions.len(), 2, "{leg}: {descriptions:?}");

                    let uplink = parse_rule(&descriptions[0]);
                    assert_eq!(uplink.direction, "in", "{leg}: {descriptions:?}");
                    assert_eq!(uplink.source, ue, "{leg}: {descriptions:?}");
                    assert_eq!(uplink.destination, remote, "{leg}: {descriptions:?}");

                    let downlink = parse_rule(&descriptions[1]);
                    assert_eq!(downlink.direction, "out", "{leg}: {descriptions:?}");
                    assert_eq!(downlink.source, remote, "{leg}: {descriptions:?}");
                    assert_eq!(downlink.destination, ue, "{leg}: {descriptions:?}");
                }
            }
        }
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
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
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
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
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

    /// `(number, media_type, flow_status, flow count)` of every component.
    fn components(offer: &str, answer: &str, direction: &str) -> Vec<(u32, String, String, usize)> {
        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let offer = offer.into_pyobject(python).unwrap();
            let answer = answer.into_pyobject(python).unwrap();
            ns.media_flows_from_sdp(python, offer.as_any(), answer.as_any(), direction)
                .unwrap()
                .iter()
                .map(|component| {
                    let component: Bound<'_, PyDict> = component.cast_into().unwrap();
                    let field = |key: &str| component.get_item(key).unwrap().unwrap();
                    (
                        field("number").extract().unwrap(),
                        field("media_type").extract().unwrap(),
                        field("flow_status").extract().unwrap(),
                        field("flows").cast_into::<PyList>().unwrap().len(),
                    )
                })
                .collect()
        })
    }

    /// An SDP with the given session-level attributes and m= sections, the
    /// lines of a section separated by `|`.
    fn sdp(address: &str, session_attrs: &[&str], media: &[&str]) -> String {
        let mut text =
            format!("v=0\r\no=- 1 1 IN IP4 {address}\r\ns=-\r\nc=IN IP4 {address}\r\nt=0 0\r\n");
        for attr in session_attrs {
            text.push_str(&format!("a={attr}\r\n"));
        }
        for section in media {
            for line in section.split('|') {
                text.push_str(line);
                text.push_str("\r\n");
            }
        }
        text
    }

    fn flow_status(offer_media: &str, answer_media: &str, direction: &str) -> String {
        let offer = sdp("192.0.2.2", &[], &[offer_media]);
        let answer = sdp("198.51.100.10", &[], &[answer_media]);
        components(&offer, &answer, direction).remove(0).2
    }

    const AUDIO_OFFER: &str = "m=audio 50000 RTP/AVP 0";
    const AUDIO_ANSWER: &str = "m=audio 30000 RTP/AVP 0";

    /// TS 29.213 table 6.2.1, Flow-Status, UDP / RTP/AVP branch without
    /// rtcp-mux. With the answer available its direction attribute decides
    /// (NOTE 5), read against the direction of the SDP that carries it
    /// (NOTE 8): on "orig" the answer is downlink SDP (UE terminated), on
    /// "term" it is uplink SDP (UE originated).
    #[test]
    fn table_6_2_1_direction_rows_from_offer_and_answer() {
        // (offer attribute, answer attribute, direction, Flow-Status)
        let rows = [
            // a=recvonly: ENABLED_DOWNLINK in uplink SDP, else ENABLED_UPLINK.
            ("sendonly", "recvonly", "orig", "enabled-up"),
            ("sendonly", "recvonly", "term", "enabled-down"),
            // a=sendonly: ENABLED_UPLINK in uplink SDP, else ENABLED_DOWNLINK.
            ("recvonly", "sendonly", "orig", "enabled-down"),
            ("recvonly", "sendonly", "term", "enabled-up"),
            // a=inactive in the answer: DISABLED.
            ("sendrecv", "inactive", "orig", "disabled"),
            ("sendrecv", "inactive", "term", "disabled"),
            ("sendonly", "inactive", "orig", "disabled"),
            ("recvonly", "inactive", "term", "disabled"),
            // a=sendrecv: ENABLED.
            ("sendrecv", "sendrecv", "orig", "enabled"),
            ("sendrecv", "sendrecv", "term", "enabled"),
            // NOTE 5: a=inactive in the offer wins over an answer that
            // ignored it.
            ("inactive", "sendrecv", "orig", "disabled"),
            ("inactive", "sendrecv", "term", "disabled"),
            ("inactive", "recvonly", "orig", "disabled"),
            ("inactive", "inactive", "term", "disabled"),
            // The answer's attribute decides, not the offer's: a sendonly
            // offer answered sendrecv is ENABLED.
            ("sendonly", "sendrecv", "orig", "enabled"),
            ("recvonly", "sendrecv", "term", "enabled"),
        ];
        for (offer_attr, answer_attr, direction, expected) in rows {
            let offer = format!("{AUDIO_OFFER}|a={offer_attr}");
            let answer = format!("{AUDIO_ANSWER}|a={answer_attr}");
            assert_eq!(
                flow_status(&offer, &answer, direction),
                expected,
                "offer a={offer_attr}, answer a={answer_attr}, {direction}"
            );
        }
    }

    /// "a=sendrecv or no direction attribute": ENABLED, named explicitly. On
    /// an update an absent Flow-Status reads as unchanged (TS 29.214
    /// §5.3.16), so a stream resumed from hold kept its gates held.
    #[test]
    fn table_6_2_1_no_direction_attribute_names_enabled() {
        for direction in ["orig", "term"] {
            assert_eq!(flow_status(AUDIO_OFFER, AUDIO_ANSWER, direction), "enabled");
        }
    }

    /// (offer session attrs, offer media, answer session attrs, answer media,
    /// direction, Flow-Status)
    type SessionRow = (
        &'static [&'static str],
        &'static str,
        &'static [&'static str],
        &'static str,
        &'static str,
        &'static str,
    );

    /// A session-level direction attribute applies to a media line without
    /// one (RFC 4566 §6); a media-level one overrides it.
    #[test]
    fn table_6_2_1_session_level_direction() {
        let rows: [SessionRow; 6] = [
            (
                &["sendonly"],
                AUDIO_OFFER,
                &["recvonly"],
                AUDIO_ANSWER,
                "orig",
                "enabled-up",
            ),
            (
                &["sendonly"],
                AUDIO_OFFER,
                &["recvonly"],
                AUDIO_ANSWER,
                "term",
                "enabled-down",
            ),
            (
                &[],
                AUDIO_OFFER,
                &["inactive"],
                AUDIO_ANSWER,
                "orig",
                "disabled",
            ),
            // NOTE 5 with the offer's inactive at session level.
            (
                &["inactive"],
                AUDIO_OFFER,
                &[],
                AUDIO_ANSWER,
                "term",
                "disabled",
            ),
            // The media line's own attribute wins over the session's.
            (
                &["inactive"],
                "m=audio 50000 RTP/AVP 0|a=sendrecv",
                &["inactive"],
                "m=audio 30000 RTP/AVP 0|a=sendrecv",
                "orig",
                "enabled",
            ),
            (
                &[],
                AUDIO_OFFER,
                &["sendonly"],
                "m=audio 30000 RTP/AVP 0|a=sendrecv",
                "term",
                "enabled",
            ),
        ];
        for (offer_session, offer_media, answer_session, answer_media, direction, expected) in rows
        {
            let offer = sdp("192.0.2.2", offer_session, &[offer_media]);
            let answer = sdp("198.51.100.10", answer_session, &[answer_media]);
            assert_eq!(
                components(&offer, &answer, direction)[0].2,
                expected,
                "offer {offer_session:?} {offer_media}, answer {answer_session:?} {answer_media}, {direction}"
            );
        }
    }

    /// "IF a=rtcp-mux is negotiated THEN Flow-Status := ENABLED" (NOTE 12),
    /// ahead of the direction attributes. Negotiated means offer and answer.
    #[test]
    fn table_6_2_1_rtcp_mux_forces_enabled() {
        for direction in ["orig", "term"] {
            for (offer_attr, answer_attr) in [
                ("sendonly", "recvonly"),
                ("recvonly", "sendonly"),
                ("sendrecv", "inactive"),
                ("inactive", "inactive"),
            ] {
                let offer = format!("{AUDIO_OFFER}|a=rtcp-mux|a={offer_attr}");
                let answer = format!("{AUDIO_ANSWER}|a=rtcp-mux|a={answer_attr}");
                assert_eq!(
                    flow_status(&offer, &answer, direction),
                    "enabled",
                    "rtcp-mux, offer a={offer_attr}, answer a={answer_attr}, {direction}"
                );
            }
        }
        // Offered but not accepted: not negotiated, the direction decides.
        let offer = format!("{AUDIO_OFFER}|a=rtcp-mux|a=sendonly");
        let answer = format!("{AUDIO_ANSWER}|a=recvonly");
        assert_eq!(flow_status(&offer, &answer, "orig"), "enabled-up");
    }

    /// "IF Transport in m-line is TCP or TCP/MSRP or UDP/DTLS/SCTP THEN
    /// Flow-Status := ENABLED", whatever the direction attributes.
    #[test]
    fn table_6_2_1_tcp_transport_is_enabled() {
        for protocol in ["TCP", "TCP/MSRP", "UDP/DTLS/SCTP", "TCP/TLS/MSRP"] {
            for direction in ["orig", "term"] {
                for (offer_attr, answer_attr) in
                    [("sendonly", "recvonly"), ("inactive", "inactive")]
                {
                    let offer = format!("m=message 50000 {protocol} *|a={offer_attr}");
                    let answer = format!("m=message 30000 {protocol} *|a={answer_attr}");
                    assert_eq!(
                        flow_status(&offer, &answer, direction),
                        "enabled",
                        "{protocol}, offer a={offer_attr}, answer a={answer_attr}, {direction}"
                    );
                }
            }
        }
    }

    /// "IF port in m-line = 0 THEN Flow-Status := REMOVED", and the
    /// Media-Component-Number is the ordinal of the m= line, so the lines
    /// after a disabled one keep their numbers.
    #[test]
    fn table_6_2_1_port_zero_is_removed_and_numbering_is_stable() {
        let offer = sdp(
            "192.0.2.2",
            &[],
            &[
                "m=video 0 RTP/AVP 96",
                "m=audio 50000 RTP/AVP 0",
                "m=video 50002 RTP/AVP 96",
            ],
        );
        // The answerer also rejects the second video stream.
        let answer = sdp(
            "198.51.100.10",
            &[],
            &[
                "m=video 0 RTP/AVP 96",
                "m=audio 30000 RTP/AVP 0",
                "m=video 0 RTP/AVP 96",
            ],
        );
        for direction in ["orig", "term"] {
            assert_eq!(
                components(&offer, &answer, direction),
                vec![
                    (1, "video".to_string(), "removed".to_string(), 0),
                    (2, "audio".to_string(), "enabled".to_string(), 2),
                    (3, "video".to_string(), "removed".to_string(), 0),
                ],
                "{direction}"
            );
        }
    }

    /// A rejected line needs no connection address (RFC 3264 §6: the answer
    /// may leave it out), and there are no flows to describe.
    #[test]
    fn removed_line_without_connection_address_is_reported() {
        let offer = sdp(
            "192.0.2.2",
            &[],
            &["m=audio 50000 RTP/AVP 0", "m=video 50002 RTP/AVP 96"],
        );
        let answer = concat!(
            "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nt=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\nc=IN IP4 198.51.100.10\r\n",
            "m=video 0 RTP/AVP 96\r\n",
        );
        assert_eq!(
            components(&offer, answer, "orig"),
            vec![
                (1, "audio".to_string(), "enabled".to_string(), 2),
                (2, "video".to_string(), "removed".to_string(), 0),
            ]
        );
    }

    /// Rx and N5 read the same list: each Flow-Status reaches the
    /// Media-Component-Description of the AAR and the `fStatus` of the
    /// Npcf_PolicyAuthorization body, under the same component number.
    #[test]
    fn rx_and_n5_carry_the_table_flow_status() {
        use crate::diameter::rx::FlowStatus;

        let offer = sdp(
            "192.0.2.2",
            &[],
            &[
                "m=audio 50000 RTP/AVP 0|a=sendonly",
                "m=video 0 RTP/AVP 96",
                "m=video 50002 RTP/AVP 96|a=inactive",
                "m=text 50004 RTP/AVP 98",
                "m=audio 50006 RTP/AVP 0|a=recvonly",
            ],
        );
        let answer = sdp(
            "198.51.100.10",
            &[],
            &[
                "m=audio 30000 RTP/AVP 0|a=recvonly",
                "m=video 0 RTP/AVP 96",
                "m=video 30002 RTP/AVP 96|a=inactive",
                "m=text 30004 RTP/AVP 98",
                "m=audio 30006 RTP/AVP 0|a=sendonly",
            ],
        );
        let expected = [
            (1, FlowStatus::EnabledUplink, "ENABLED-UPLINK"),
            (2, FlowStatus::Removed, "REMOVED"),
            (3, FlowStatus::Disabled, "DISABLED"),
            (4, FlowStatus::Enabled, "ENABLED"),
            (5, FlowStatus::EnabledDownlink, "ENABLED-DOWNLINK"),
        ];

        pyo3::Python::initialize();
        let ns = PyQosNamespace::new();
        pyo3::Python::attach(|python| {
            let offer = offer.into_pyobject(python).unwrap();
            let answer = answer.into_pyobject(python).unwrap();
            let list = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();

            let rx = super::super::diameter::parse_media_components(list.as_any()).unwrap();
            let n5 = super::super::sbi::parse_sbi_media_components(list.as_any()).unwrap();
            assert_eq!(rx.len(), expected.len());
            assert_eq!(n5.len(), expected.len());
            for ((number, rx_status, n5_status), (rx, n5)) in
                expected.into_iter().zip(rx.iter().zip(n5.iter()))
            {
                assert_eq!(rx.number, number);
                assert_eq!(rx.flow_status, Some(rx_status), "Rx component {number}");
                assert_eq!(n5.med_comp_n, number);
                assert_eq!(n5.f_status, n5_status, "N5 component {number}");
            }
            // A removed component carries no sub-components on either.
            assert!(rx[1].flows.is_empty());
            assert!(n5[1].med_sub_comps.is_none());
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
            // RFC 3264 §6.1: the answer to a sendonly stream is recvonly.
            let held = ANSWER_REWRITTEN.replace("a=sendrecv", "a=recvonly");
            let offer = hold.into_pyobject(python).unwrap();
            let answer = held.into_pyobject(python).unwrap();
            let result = ns
                .media_flows_from_sdp(python, offer.as_any(), answer.as_any(), "orig")
                .unwrap();
            let component: Bound<'_, PyDict> = result.get_item(0).unwrap().cast_into().unwrap();
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
