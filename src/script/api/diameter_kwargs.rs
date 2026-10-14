//! `diameter.send_request` keyword arguments: one Python value to the wire
//! octets of one AVP, by the type the dictionary gives the AVP.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::diameter::codec::{
    encode_avp, encode_avp_address_ipv4, encode_avp_grouped, encode_avp_grouped_3gpp,
    encode_avp_octet, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp, encode_avp_u64,
    encode_avp_utf8, encode_avp_utf8_3gpp, encode_avp_vendor, AVP_FLAG_MANDATORY,
    NTP_UNIX_EPOCH_OFFSET,
};
use crate::diameter::dictionary::{self, AvpDef, AvpType};

/// Encode a single AVP value (Python object → wire bytes) using the
/// AVP's declared type from the dictionary. Picks the 3GPP-flagged
/// encoder when the AVP is vendor-specific, the base encoder otherwise.
pub(crate) fn encode_kwarg_avp(def: &AvpDef, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
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
        AvpType::TbcdString => {
            // A str is an E.164 digit string, sent as the TBCD digits and
            // nothing else (see `AvpType::TbcdString`). Bytes are taken as
            // the octets to send.
            let bytes = if let Ok(digits) = value.extract::<String>() {
                crate::diameter::codec::encode_tbcd_digits(&digits)
            } else if let Ok(raw) = value.extract::<Vec<u8>>() {
                raw
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects str (E.164 digits) or bytes",
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
        AvpType::Time => {
            // Unix seconds, the form an answer hands a Time AVP back in. On
            // the wire it is seconds since 1900 (RFC 6733 clause 4.3.1).
            let unix_seconds: u64 = value.extract().map_err(|error| {
                pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} expects int (Unix seconds), got {error}",
                    def.name
                ))
            })?;
            let seconds = (unix_seconds.wrapping_add(NTP_UNIX_EPOCH_OFFSET) & 0xFFFF_FFFF) as u32;
            let flags = if dictionary::avp_is_mandatory(def.code, def.vendor_id) {
                AVP_FLAG_MANDATORY
            } else {
                0
            };
            Ok(if is_vendor {
                encode_avp_vendor(def.code, flags, def.vendor_id, &seconds.to_be_bytes())
            } else {
                encode_avp(def.code, flags, &seconds.to_be_bytes())
            })
        }
        AvpType::Grouped => {
            // `None` is the group with no member, which a few AVPs use as a
            // flag. A dict is the group with one member per item, in the
            // dict's order, each encoded by these same rules.
            let members = if value.is_none() {
                Vec::new()
            } else if let Ok(dict) = value.cast::<PyDict>() {
                encode_members(def, dict)?
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "{} (Grouped AVP) expects a dict of its member AVPs, or None",
                    def.name
                )));
            };
            Ok(if is_vendor {
                encode_avp_grouped_3gpp(def.code, &members)
            } else {
                encode_avp_grouped(def.code, &members)
            })
        }
    }
}

/// Every `**avps` keyword argument, in order, as AVP wire octets. Kwargs named
/// in `skip` are the caller's own and are not encoded. An AVP whose base
/// (vendor 0) code is in `fixed` is one the caller already sets, so supplying
/// it again is refused rather than sent twice.
pub(crate) fn encode_kwarg_avps(
    kwargs: Option<&Bound<'_, PyDict>>,
    skip: &[&str],
    fixed: &[u32],
) -> PyResult<Vec<u8>> {
    let mut encoded = Vec::new();
    let Some(kwargs) = kwargs else {
        return Ok(encoded);
    };
    for (key, value) in kwargs.iter() {
        let name: String = key.extract().map_err(|error| {
            pyo3::exceptions::PyTypeError::new_err(format!("AVP kwarg name must be str: {error}"))
        })?;
        if skip.contains(&name.as_str()) {
            continue;
        }
        let definition = dictionary::lookup_avp_by_python_name(&name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("unknown AVP kwarg: {name}"))
        })?;
        if definition.vendor_id == 0 && fixed.contains(&definition.code) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{} is set by the request itself and cannot be passed as a kwarg",
                definition.name
            )));
        }
        encoded.extend_from_slice(&encode_kwarg_avp(definition, &value)?);
    }
    Ok(encoded)
}

/// The members of a Grouped AVP given as a dict: each key is an AVP name the
/// way a kwarg spells it, each value what that AVP's type takes.
fn encode_members(group: &AvpDef, members: &Bound<'_, PyDict>) -> PyResult<Vec<u8>> {
    let mut encoded = Vec::new();
    for (key, value) in members.iter() {
        let name: String = key.extract().map_err(|error| {
            pyo3::exceptions::PyTypeError::new_err(format!(
                "{}: member names must be str: {error}",
                group.name
            ))
        })?;
        let member = dictionary::lookup_avp_by_python_name(&name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown AVP in {}: {name}",
                group.name
            ))
        })?;
        encoded.extend_from_slice(&encode_kwarg_avp(member, &value)?);
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{hex, AvpData, DiameterMsg};
    use crate::diameter::dictionary::lookup_avp_by_python_name;
    use crate::diameter::gba_test_vectors as vectors;
    use pyo3::types::PyBytes;

    fn definition(python_name: &str) -> &'static AvpDef {
        lookup_avp_by_python_name(python_name)
            .unwrap_or_else(|| panic!("{python_name} must resolve"))
    }

    /// The octets of one AVP as `[code, flags, length, vendor]` and its data.
    fn parse_one(encoded: &[u8]) -> crate::diameter::codec::Avp {
        // A message of one AVP, so the lossless decoder reads it.
        let wire = crate::diameter::codec::encode_diameter_message(0, 303, 0, 1, 1, encoded);
        let mut message = DiameterMsg::from_wire(&wire).expect("one AVP");
        assert_eq!(message.avps.len(), 1);
        message.avps.remove(0)
    }

    #[test]
    fn kwargs_encode_in_order_skipping_the_callers_own() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let kwargs = PyDict::new(python);
            kwargs.set_item("peer", "ignored").unwrap();
            kwargs.set_item("event_trigger", 2u32).unwrap();
            kwargs.set_item("user_name", "001010000000001").unwrap();
            let encoded = encode_kwarg_avps(Some(&kwargs), &["peer"], &[]).unwrap();
            let wire = crate::diameter::codec::encode_diameter_message(0, 258, 0, 1, 1, &encoded);
            let message = DiameterMsg::from_wire(&wire).unwrap();
            let codes: Vec<u32> = message.avps.iter().map(|avp| avp.code).collect();
            assert_eq!(codes, vec![1006, 1]);
            assert_eq!(encode_kwarg_avps(None, &[], &[]).unwrap(), Vec::<u8>::new());
        });
    }

    #[test]
    fn a_kwarg_for_a_fixed_avp_is_refused() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let kwargs = PyDict::new(python);
            kwargs
                .set_item("auth_application_id", 16_777_238u32)
                .unwrap();
            let error = encode_kwarg_avps(Some(&kwargs), &[], &[258]).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let kwargs = PyDict::new(python);
            kwargs.set_item("not_a_real_avp", 1u32).unwrap();
            let error = encode_kwarg_avps(Some(&kwargs), &[], &[]).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }

    #[test]
    fn a_dict_becomes_a_grouped_avp_with_its_members_in_order() {
        // SIP-Auth-Data-Item of a Zh MAR after a synchronisation failure: the
        // octets are the ones written out in the ZH_MAR_RESYNC vector.
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let mut authorization = vectors::RAND.to_vec();
            authorization.extend_from_slice(&vectors::AUTS);
            let item = PyDict::new(python);
            item.set_item("sip_authentication_scheme", "Digest-AKAv1-MD5")
                .unwrap();
            item.set_item("sip_authorization", PyBytes::new(python, &authorization))
                .unwrap();
            let encoded =
                encode_kwarg_avp(definition("sip_auth_data_item"), item.as_any()).unwrap();

            let expected = hex::encode(vectors::ZH_MAR_RESYNC);
            assert!(
                expected.contains(&hex::encode(&encoded)),
                "{} is not in the hand-written request",
                hex::encode(&encoded)
            );
            let avp = parse_one(&encoded);
            assert_eq!((avp.code, avp.vendor, avp.flags), (612, 10415, 0xc0));
            let AvpData::Grouped(members) = &avp.value else {
                panic!("SIP-Auth-Data-Item is grouped");
            };
            let codes: Vec<u32> = members.iter().map(|member| member.code).collect();
            assert_eq!(codes, vec![608, 610]);
        });
    }

    #[test]
    fn a_dict_nests_as_deep_as_the_avps_do() {
        // Experimental-Result holds two plain members; SM-Delivery-Outcome
        // holds a group that holds a value.
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let inner = PyDict::new(python);
            inner.set_item("sm_delivery_cause", 1).unwrap();
            let outer = PyDict::new(python);
            outer.set_item("mme_sm_delivery_outcome", inner).unwrap();
            let encoded =
                encode_kwarg_avp(definition("sm_delivery_outcome"), outer.as_any()).unwrap();
            let avp = parse_one(&encoded);
            let AvpData::Grouped(members) = &avp.value else {
                panic!("SM-Delivery-Outcome is grouped");
            };
            assert_eq!(members.len(), 1);
            let AvpData::Grouped(leaves) = &members[0].value else {
                panic!("MME-SM-Delivery-Outcome is grouped");
            };
            assert_eq!(leaves.len(), 1);
            assert_eq!(leaves[0].as_u32(), Some(1));
        });
    }

    #[test]
    fn a_member_the_dictionary_does_not_know_is_refused_by_name() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let item = PyDict::new(python);
            item.set_item("sip_authorisation", "typo").unwrap();
            let error = encode_kwarg_avp(definition("sip_auth_data_item"), item.as_any())
                .expect_err("an unknown member must not be dropped");
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let message = error.to_string();
            assert!(
                message.contains("SIP-Auth-Data-Item") && message.contains("sip_authorisation"),
                "{message}"
            );
        });
    }

    #[test]
    fn a_grouped_avp_still_refuses_a_value_that_is_not_a_dict() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let value = "anything".into_pyobject(python).unwrap();
            let error = encode_kwarg_avp(definition("sip_auth_data_item"), value.as_any())
                .expect_err("a str is not a group");
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(python));
            assert!(error.to_string().contains("Grouped AVP"), "{error}");
        });
    }

    #[test]
    fn a_time_avp_takes_unix_seconds_and_keeps_the_flags_of_its_specification() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            // GUSS-Timestamp: V set and M clear (TS 29.109 Table 6.1). The
            // octets are the ones written out in the ZH_MAR_RESYNC vector.
            let value = vectors::GUSS_TIMESTAMP_UNIX.into_pyobject(python).unwrap();
            let encoded = encode_kwarg_avp(definition("guss_timestamp"), value.as_any()).unwrap();
            assert_eq!(
                encoded,
                [
                    0x00, 0x00, 0x01, 0x99, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0xed,
                    0x00, 0x37, 0x80
                ]
            );
            // Key-ExpiryTime: V and M.
            let value = vectors::KEY_EXPIRY_UNIX.into_pyobject(python).unwrap();
            let encoded = encode_kwarg_avp(definition("key_expirytime"), value.as_any()).unwrap();
            assert_eq!(
                encoded,
                [
                    0x00, 0x00, 0x01, 0x94, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0xed,
                    0x00, 0x45, 0x90
                ]
            );
            // Event-Timestamp (RFC 6733 clause 8.21): no vendor, M.
            let encoded = encode_kwarg_avp(definition("event_timestamp"), value.as_any()).unwrap();
            assert_eq!(
                encoded,
                [0x00, 0x00, 0x00, 0x37, 0x40, 0x00, 0x00, 0x0c, 0xed, 0x00, 0x45, 0x90]
            );
        });
    }
}
