//! `RegisterExchange`: the REGISTER behind a registration change and the 200 OK
//! that answered it, as `@registrar.on_change` handlers see them.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::registrar::RegisterExchange;

/// One REGISTER as received and the 200 OK siphon sent for it (3GPP TS 24.229
/// clause 5.4.1.7).
///
/// Passed as ``exchange=`` to an ``@registrar.on_change`` handler that names
/// that parameter. One REGISTER is one device, so with several devices
/// registered to one AoR each device's change carries its own request, not the
/// AoR's whole registration. It is ``None`` where no REGISTER of this node's
/// own is behind the change: an expiry, a network or admin removal, a
/// ``"snapshot"``, a ``registrar.save_proxy()`` binding, and a REGISTER the
/// script saved from a handler that did not receive it.
///
/// An S-CSCF builds the third-party REGISTER body from it:
///
/// ```python
/// from siphon import proxy, registrar
///
/// @registrar.on_change
/// async def on_change(aor, event, contacts, exchange):
///     if exchange is None or event not in ("registered", "refreshed", "deregistered"):
///         return
///     # message/sip: the REGISTER as received (what the AS needs when the
///     # filter criteria ask for the request only).
///     body = exchange.request
///     content_type = "message/sip"
///     # multipart/mixed: the REGISTER, the 200 OK and the service info
///     # (TS 24.229 clause 5.4.1.7).
///     if exchange.response is not None:
///         boundary = "ims-boundary"
///         service_info = b'<?xml version="1.0"?><ims-3gpp version="1"><service-info>info</service-info></ims-3gpp>'
///         parts = [
///             (b"message/sip", exchange.request),
///             (b"message/sip", exchange.response),
///             (b"application/3gpp-ims+xml", service_info),
///         ]
///         body = b"".join(
///             b"--" + boundary.encode() + b"\r\nContent-Type: " + kind + b"\r\n\r\n" + data + b"\r\n"
///             for kind, data in parts
///         ) + b"--" + boundary.encode() + b"--\r\n"
///         content_type = f"multipart/mixed;boundary={boundary}"
///     await proxy.send_request(
///         "REGISTER", "sip:as.ims.example.com", body=body,
///         headers={"Content-Type": content_type, "Expires": "600000"},
///     )
/// ```
#[pyclass(name = "RegisterExchange", frozen, skip_from_py_object)]
pub struct PyRegisterExchange {
    inner: Arc<RegisterExchange>,
}

impl PyRegisterExchange {
    pub fn new(inner: Arc<RegisterExchange>) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyRegisterExchange {
    /// The REGISTER byte for byte as it was received (``bytes``): compact
    /// forms, header order, folding and body as the device sent them.
    #[getter]
    fn request<'py>(&self, python: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(python, self.inner.request())
    }

    /// The 200 OK as siphon sent it, To-tag included (``bytes``); ``None`` when
    /// siphon did not answer this REGISTER itself (it relayed it) or the
    /// handler runs for a REGISTER that was answered with something else.
    #[getter]
    fn response<'py>(&self, python: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .response()
            .map(|response| PyBytes::new(python, response))
    }

    fn __repr__(&self) -> String {
        format!(
            "RegisterExchange(request={} bytes, response={})",
            self.inner.request().len(),
            match self.inner.response() {
                Some(response) => format!("{} bytes", response.len()),
                None => "None".to_string(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_getters_return_the_bytes_and_none_before_a_response() {
        Python::initialize();
        Python::attach(|python| {
            let exchange = Arc::new(RegisterExchange::new(b"REGISTER wire"));
            let object = Py::new(python, PyRegisterExchange::new(Arc::clone(&exchange)))
                .expect("the pyclass builds");
            let request: Vec<u8> = object
                .getattr(python, "request")
                .and_then(|value| value.extract(python))
                .expect("request is bytes");
            assert_eq!(request, b"REGISTER wire");
            assert!(object
                .getattr(python, "response")
                .expect("response")
                .is_none(python));
            assert_eq!(
                object
                    .call_method0(python, "__repr__")
                    .and_then(|value| value.extract::<String>(python))
                    .expect("repr"),
                "RegisterExchange(request=13 bytes, response=None)"
            );

            exchange.set_response(bytes::Bytes::from_static(b"SIP/2.0 200 OK"));
            let response: Vec<u8> = object
                .getattr(python, "response")
                .and_then(|value| value.extract(python))
                .expect("response is bytes");
            assert_eq!(response, b"SIP/2.0 200 OK");
        });
    }
}
