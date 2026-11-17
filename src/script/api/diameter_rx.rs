//! `diameter.rx_aar`'s arguments: the Python values checked and owned, and the
//! [`RxSessionRequest`] the shared AAR encoder takes built from them.

use pyo3::prelude::*;

use super::diameter::{extract_ipv6_prefix, extract_subscription_id, parse_media_components};
use crate::diameter::rx::{
    service_urn_value, MediaComponent, ReservationPriority, RxRequestType, RxSessionRequest,
    SpecificAction,
};

/// `rx_aar`'s Python arguments, parsed and owned so the borrowed
/// [`RxSessionRequest`] for the shared encoder can outlive them.
pub(super) struct RxAarRequest {
    session_id: Option<String>,
    af_application_id: String,
    media_components: Vec<MediaComponent>,
    specific_actions: Vec<SpecificAction>,
    framed_ip: Option<[u8; 4]>,
    framed_ipv6: Option<Vec<u8>>,
    subscription_id: Option<(String, u32)>,
    service_urn: Option<String>,
    mcptt_identifier: Option<String>,
    mcvideo_identifier: Option<String>,
    reservation_priority: Option<ReservationPriority>,
}

impl RxAarRequest {
    /// Validates in the order `rx_aar` always has, so a bad call raises what it did.
    pub(super) fn parse(
        session_id: Option<&str>,
        framed_ip: Option<&str>,
        framed_ipv6: Option<&Bound<'_, PyAny>>,
        media_components: Option<&Bound<'_, PyAny>>,
        af_application_id: &str,
        subscription_id: Option<&Bound<'_, PyAny>>,
        specific_actions: Option<&Bound<'_, PyAny>>,
        service_urn: Option<&str>,
    ) -> PyResult<Self> {
        let media_components = media_components.map(parse_media_components).transpose()?;
        let framed_ipv6 = framed_ipv6.map(extract_ipv6_prefix).transpose()?;
        let subscription_id = subscription_id.map(extract_subscription_id).transpose()?;
        let framed_ip = framed_ip
            .map(|ip| {
                ip.parse::<std::net::Ipv4Addr>()
                    .map(|addr| addr.octets())
                    .map_err(|_| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "framed_ip is not a valid IPv4 address: {ip}"
                        ))
                    })
            })
            .transpose()?;
        let specific_actions = specific_actions.map(parse_specific_actions).transpose()?;
        let service_urn = service_urn
            .map(|urn| {
                service_urn_value(urn).map(str::to_string).ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "service_urn names no service: {urn:?}"
                    ))
                })
            })
            .transpose()?;
        Ok(Self {
            session_id: session_id.map(String::from),
            af_application_id: af_application_id.to_string(),
            media_components: media_components.unwrap_or_default(),
            specific_actions: specific_actions.unwrap_or_default(),
            framed_ip,
            framed_ipv6,
            subscription_id,
            service_urn,
            mcptt_identifier: None,
            mcvideo_identifier: None,
            reservation_priority: None,
        })
    }

    /// The mission critical arguments: `mcptt_identifier`, `mcvideo_identifier`
    /// (an empty string is an absent one) and `reservation_priority`, checked
    /// by [`reservation_priority_argument`].
    pub(super) fn with_mission_critical(
        mut self,
        mcptt_identifier: Option<&str>,
        mcvideo_identifier: Option<&str>,
        reservation_priority: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let present = |identifier: Option<&str>| {
            identifier
                .filter(|value| !value.is_empty())
                .map(String::from)
        };
        self.mcptt_identifier = present(mcptt_identifier);
        self.mcvideo_identifier = present(mcvideo_identifier);
        self.reservation_priority = reservation_priority
            .map(|value| reservation_priority_argument("reservation_priority", value))
            .transpose()?;
        Ok(self)
    }

    pub(super) fn params(&self) -> RxSessionRequest<'_> {
        use RxRequestType::{InitialRequest, UpdateRequest};
        RxSessionRequest {
            session_id: self.session_id.as_deref(),
            af_application_id: self.af_application_id.as_bytes(),
            media_components: &self.media_components,
            specific_actions: &self.specific_actions,
            // A reused Session-Id modifies an existing Rx session.
            rx_request_type: self
                .session_id
                .as_ref()
                .map_or(InitialRequest, |_| UpdateRequest),
            framed_ip: self.framed_ip.as_ref().map(|octets| octets.as_slice()),
            framed_ipv6: self.framed_ipv6.as_deref(),
            subscription_id: self
                .subscription_id
                .as_ref()
                .map(|(data, kind)| (data.as_str(), *kind)),
            service_urn: self.service_urn.as_deref(),
            mcptt_identifier: self.mcptt_identifier.as_deref(),
            mcvideo_identifier: self.mcvideo_identifier.as_deref(),
            reservation_priority: self.reservation_priority,
        }
    }
}

/// A reservation priority argument named `name`: an int from 0 (DEFAULT, the
/// lowest) to 15 (PRIORITY-FIFTEEN, the highest), the values ETSI TS 183 017
/// clause 7.3.9 defines. `TypeError` for anything but an int (a bool is not
/// one here: `True` would otherwise be read as priority 1), `ValueError` for an
/// int outside the range, each naming the argument.
pub(super) fn reservation_priority_argument(
    name: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<ReservationPriority> {
    let not_an_int = || {
        pyo3::exceptions::PyTypeError::new_err(format!(
            "{name} must be an int from 0 to {}",
            ReservationPriority::MAX
        ))
    };
    if value.is_instance_of::<pyo3::types::PyBool>()
        || !value.is_instance_of::<pyo3::types::PyInt>()
    {
        return Err(not_an_int());
    }
    // An int too large for an i64 is out of range like any other.
    value
        .extract::<i64>()
        .ok()
        .and_then(|priority| u8::try_from(priority).ok())
        .and_then(ReservationPriority::new)
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "{name} must be from 0 to {}, got {value}",
                ReservationPriority::MAX
            ))
        })
}

/// `specific_actions` → Specific-Action values: `TypeError` unless a sequence of
/// int, `ValueError` naming the first value TS 29.214 §5.3.13 does not define.
fn parse_specific_actions(obj: &Bound<'_, PyAny>) -> PyResult<Vec<SpecificAction>> {
    let values: Vec<i64> = obj.extract()?;
    values
        .into_iter()
        .map(|value| {
            u32::try_from(value)
                .ok()
                .and_then(|value| SpecificAction::try_from(value).ok())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "specific_actions: {value} is not a Specific-Action value \
                         TS 29.214 §5.3.13 defines (1-4, 6-21)"
                    ))
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::dictionary::avp;
    use crate::diameter::rx::{encode_aar, raw_top_level_avps};
    use pyo3::IntoPyObject;

    fn bare_request(session_id: Option<&str>) -> RxAarRequest {
        RxAarRequest::parse(
            session_id,
            None,
            None,
            None,
            "IMS Services",
            None,
            None,
            None,
        )
        .unwrap()
    }

    fn peer_config() -> crate::diameter::peer::PeerConfig {
        crate::diameter::peer::PeerConfig {
            host: "pcrf.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            port: 3868,
            origin_host: "pcscf.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            origin_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            destination_host: None,
            destination_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            local_ip: "192.0.2.10".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            source_address: None,
            lifecycle: Default::default(),
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        }
    }

    fn avps_with_code(request: &RxAarRequest, wanted: u32) -> Vec<Vec<u8>> {
        let wire = encode_aar(&peer_config(), 1, 1, "pcscf;1;1", &request.params());
        raw_top_level_avps(&wire)
            .into_iter()
            .filter(|(code, _)| *code == wanted)
            .map(|(_, bytes)| bytes.to_vec())
            .collect()
    }

    /// The arguments reach the wire: MCPTT-Identifier (547) and
    /// MCVideo-Identifier (562) with V and no M under the 3GPP vendor,
    /// Reservation-Priority (458) under the ETSI one, each written out by hand
    /// (TS 29.214 table 5.3.0.1, ETSI TS 183 017 table 7.3.1).
    #[test]
    fn mission_critical_arguments_reach_the_aar() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let priority = 14i64.into_pyobject(python).unwrap();
            let request = bare_request(None)
                .with_mission_critical(Some("mcpttp"), Some("mcpttq"), Some(priority.as_any()))
                .unwrap();
            let identifier = |code_low: u8, value: &[u8; 6]| {
                let mut bytes = vec![
                    0x00, 0x00, 0x02, code_low, 0x80, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf,
                ];
                bytes.extend_from_slice(value);
                bytes.extend_from_slice(&[0, 0]);
                bytes
            };
            assert_eq!(
                avps_with_code(&request, avp::MCPTT_IDENTIFIER),
                [identifier(0x23, b"mcpttp")]
            );
            assert_eq!(
                avps_with_code(&request, avp::MCVIDEO_IDENTIFIER),
                [identifier(0x32, b"mcpttq")]
            );
            assert_eq!(
                avps_with_code(&request, avp::RESERVATION_PRIORITY),
                [vec![
                    0x00, 0x00, 0x01, 0xca, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x32, 0xdb, 0x00,
                    0x00, 0x00, 0x0e,
                ]]
            );
        });
    }

    /// A modification (`session_id` given) carries them too: that is how a
    /// priority change reaches the PCRF (TS 29.214 clause 4.4.2).
    #[test]
    fn mission_critical_arguments_reach_a_modification_aar() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let priority = 15i64.into_pyobject(python).unwrap();
            let request = bare_request(Some("pcscf;1;1"))
                .with_mission_critical(Some("mcpttp"), None, Some(priority.as_any()))
                .unwrap();
            assert_eq!(
                request.params().rx_request_type,
                RxRequestType::UpdateRequest
            );
            assert_eq!(avps_with_code(&request, avp::MCPTT_IDENTIFIER).len(), 1);
            assert_eq!(
                avps_with_code(&request, avp::RESERVATION_PRIORITY)[0][15],
                15
            );
        });
    }

    #[test]
    fn empty_identifiers_and_no_priority_send_nothing() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|_python| {
            for (mcptt, mcvideo) in [(None, None), (Some(""), Some(""))] {
                let request = bare_request(None)
                    .with_mission_critical(mcptt, mcvideo, None)
                    .unwrap();
                for code in [
                    avp::MCPTT_IDENTIFIER,
                    avp::MCVIDEO_IDENTIFIER,
                    avp::RESERVATION_PRIORITY,
                    avp::SUPPORTED_FEATURES,
                ] {
                    assert!(avps_with_code(&request, code).is_empty(), "AVP {code}");
                }
            }
        });
    }

    #[test]
    fn reservation_priority_argument_takes_0_to_15() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            for value in 0..=15i64 {
                let object = value.into_pyobject(python).unwrap();
                let priority =
                    reservation_priority_argument("reservation_priority", object.as_any()).unwrap();
                assert_eq!(i64::from(priority.value()), value);
            }
        });
    }

    #[test]
    fn reservation_priority_argument_refuses_out_of_range_and_non_int() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let huge = (1u128 << 70).into_pyobject(python).unwrap().into_any();
            let out_of_range = [-1i64, 16, 255, 256]
                .map(|value| value.into_pyobject(python).unwrap().into_any())
                .into_iter()
                .chain([huge]);
            for object in out_of_range {
                let error = reservation_priority_argument("reservation_priority", &object)
                    .expect_err("out of range");
                assert!(
                    error.is_instance_of::<pyo3::exceptions::PyValueError>(python),
                    "{error}"
                );
                assert!(
                    error.to_string().contains("reservation_priority"),
                    "{error}"
                );
            }

            let not_ints = [
                "7".into_pyobject(python).unwrap().into_any(),
                7.0f64.into_pyobject(python).unwrap().into_any(),
                pyo3::types::PyBool::new(python, true).to_owned().into_any(),
            ];
            for object in not_ints {
                let error =
                    reservation_priority_argument("res_prio", &object).expect_err("not an int");
                assert!(
                    error.is_instance_of::<pyo3::exceptions::PyTypeError>(python),
                    "{error}"
                );
                assert!(error.to_string().contains("res_prio"), "{error}");
            }

            // The same refusal through the argument of `rx_aar`.
            let bad = 16i64.into_pyobject(python).unwrap();
            let error = bare_request(None)
                .with_mission_critical(None, None, Some(bad.as_any()))
                .err()
                .expect("16 is past PRIORITY-FIFTEEN");
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }
}
