//! `diameter.originate`: the arguments of a request this node starts, turned
//! into [`crate::diameter::originate`] and its answer into a `DiameterAnswer`.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyList;

use super::diameter_server::{build_child_spec, PyDiameterAnswer};
use crate::diameter::codec::{Avp, DiameterMsg};
use crate::diameter::originate::{self, Failure, Refusal, Request};
use crate::diameter::{dictionary, DiameterManager};

/// Where a request goes: `peer` (None for any), `tenant`, Destination-Host
/// (None to route on the realm alone) and Destination-Realm.
pub(crate) struct Destination<'a> {
    pub peer: Option<&'a str>,
    pub tenant: &'a str,
    pub host: Option<&'a str>,
    pub realm: &'a str,
}

/// A command given by name (as `send_request` takes it) or by code.
fn command_code(command: &Bound<'_, PyAny>) -> PyResult<u32> {
    if let Ok(code) = command.extract::<u32>() {
        return Ok(code);
    }
    let name: String = command.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("command must be a str name or an int code")
    })?;
    dictionary::command_code_by_name(&name).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("unknown Diameter command name: {name}"))
    })
}

/// The caller's AVPs, each a `(code_or_name, value[, vendor[, mandatory]])`
/// tuple as a grouped AVP's members are given to `set_avp`.
fn caller_avps(avps: &Bound<'_, PyAny>) -> PyResult<Vec<Avp>> {
    let list = avps.cast::<PyList>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "avps must be a list of (code_or_name, value) tuples",
        )
    })?;
    list.iter().map(|item| build_child_spec(&item)).collect()
}

/// Build the request and send it; the coroutine resolves to the answer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn originate<'py>(
    python: Python<'py>,
    manager: &DiameterManager,
    command: &Bound<'py, PyAny>,
    application: &str,
    avps: &Bound<'py, PyAny>,
    destination: Destination<'_>,
    session_id: Option<&str>,
    proxiable: bool,
    timeout: std::time::Duration,
) -> PyResult<Bound<'py, PyAny>> {
    let command_code = command_code(command)?;
    let (_, application_id) = dictionary::app_id_by_name(application).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown Diameter application name: {application}"
        ))
    })?;
    let avps = caller_avps(avps)?;
    let connection = originate::connection(
        manager,
        destination.tenant,
        destination.peer,
        destination.host,
        destination.realm,
    )
    .ok_or_else(|| {
        pyo3::exceptions::PyLookupError::new_err(format!(
            "no open Diameter connection towards {}",
            destination.host.unwrap_or(destination.realm)
        ))
    })?;
    let request = Request {
        command_code,
        application_id,
        proxiable,
        session_id,
        destination_host: destination.host,
        destination_realm: destination.realm,
        avps,
    };
    let wire = originate::wire(&connection, request).map_err(|refusal| match refusal {
        Refusal::EmptyIdentity => {
            pyo3::exceptions::PyValueError::new_err("nonempty destination and session required")
        }
        Refusal::EnvelopeAvp(code) => pyo3::exceptions::PyValueError::new_err(format!(
            "AVP {code} is set by the request itself and cannot be passed in avps"
        )),
    })?;
    let connection = Arc::clone(&connection);
    crate::script::awaitable(python, async move {
        let answer = connection
            .send_request_timeout(wire, timeout)
            .await
            .map_err(|reason| match originate::failure(&reason) {
                Failure::Timeout => pyo3::exceptions::PyTimeoutError::new_err(reason),
                Failure::Connection => pyo3::exceptions::PyConnectionError::new_err(reason),
            })?;
        let message = DiameterMsg::from_wire(&answer.raw).map_err(|error| {
            pyo3::exceptions::PyConnectionError::new_err(format!("malformed answer: {error}"))
        })?;
        Ok(PyDiameterAnswer::from_msg(message))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyTuple;

    #[test]
    fn avps_take_names_codes_vendors_and_groups() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let avps = PyList::empty(python);
            avps.append(("User-Name", "001010000000001")).unwrap();
            // Cancellation-Type 1420 by code and vendor; its M bit is the
            // dictionary's.
            avps.append((1420u32, 2u32, 10415u32)).unwrap();
            // CLR-Flags 1638 with the M bit cleared (TS 29.272 table 7.3.1/1).
            avps.append((
                1638u32,
                pyo3::types::PyBytes::new(python, &[0, 0, 0, 2]),
                10415u32,
                false,
            ))
            .unwrap();
            let group = PyList::empty(python);
            group.append(("Vendor-Id", 10415u32)).unwrap();
            group.append(("Auth-Application-Id", 16777251u32)).unwrap();
            avps.append(("Vendor-Specific-Application-Id", group))
                .unwrap();
            let built = caller_avps(avps.as_any()).unwrap();
            let shape: Vec<(u32, u32, u8)> = built
                .iter()
                .map(|avp| (avp.code, avp.vendor, avp.flags))
                .collect();
            assert_eq!(
                shape,
                vec![
                    (1, 0, 0x40),
                    (1420, 10415, 0xC0),
                    (1638, 10415, 0x80),
                    (260, 0, 0x40)
                ]
            );
            assert!(matches!(
                &built[3].value,
                crate::diameter::codec::AvpData::Grouped(members) if members.len() == 2
            ));
        });
    }

    #[test]
    fn a_bad_shape_or_name_is_refused() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let not_a_list = PyTuple::new(python, [1u32]).unwrap();
            assert!(caller_avps(not_a_list.as_any())
                .unwrap_err()
                .is_instance_of::<pyo3::exceptions::PyTypeError>(python));
            let avps = PyList::empty(python);
            avps.append(("Not-An-Avp", 1u32)).unwrap();
            assert!(caller_avps(avps.as_any())
                .unwrap_err()
                .is_instance_of::<pyo3::exceptions::PyValueError>(python));
            assert_eq!(
                command_code(&"CLR".into_pyobject(python).unwrap().into_any()).unwrap(),
                317
            );
            assert_eq!(
                command_code(&322u32.into_pyobject(python).unwrap().into_any()).unwrap(),
                322
            );
            assert!(
                command_code(&"Not-A-Command".into_pyobject(python).unwrap().into_any()).is_err()
            );
        });
    }

    #[test]
    fn without_a_connection_nothing_is_sent_and_lookup_error_is_raised() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let manager = DiameterManager::new();
            let avps = PyList::empty(python);
            let error = originate(
                python,
                &manager,
                &"CLR".into_pyobject(python).unwrap().into_any(),
                "S6a",
                avps.as_any(),
                Destination {
                    peer: None,
                    tenant: "t-no-connection",
                    host: Some("mme1.epc.example"),
                    realm: "epc.example",
                },
                None,
                true,
                std::time::Duration::from_millis(100),
            )
            .unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyLookupError>(python));
        });
    }
}
