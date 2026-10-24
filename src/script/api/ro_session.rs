//! `diameter.ro_session()` — a Ro credit-control session held in Rust
//! (RFC 8506, TS 32.299), as many per call as the script needs, or none bound
//! to a call at all.
//!
//! ```python
//! from siphon import diameter
//!
//! # A forwarded leg, charged to the forwarding user, ended with the call.
//! leg = await diameter.ro_session(
//!     "sip:+15550100002@ims.example.net", call_id=call.call_id,
//!     role_of_node="forwarding", node_functionality="as",
//!     calling_party=caller, called_party=target, ims_charging_identifier=icid)
//! if not leg.authorized:
//!     call.reject(402, "Payment Required")
//!
//! # A CAMEL call charged from an SCP: the gsmSSF counts the time.
//! camel = await diameter.ro_session(
//!     msisdn, subscription_id_type="e164", key=dialogue_id,
//!     metering="external", service_context_id="32276@3gpp.org",
//!     on_event=on_charging_event)
//! grant = await camel.report(used_total=apply_charging_report_seconds)
//! await camel.terminate(used_total=final_seconds)
//! ```
//!
//! The session — Session-Id, CC-Request-Number, grant, Validity-Time,
//! failure handling, failover peer, reported usage — is Rust state
//! ([`crate::diameter::ro_service`]); the Python object is a handle to it.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::error;

use crate::diameter::ro_service::{
    CcCreditSession, ChargeDecision, Metering, RoChargingService, RoSessionEvent,
};
use std::sync::Arc;

fn charger() -> Option<Arc<RoChargingService>> {
    crate::dispatcher::RO_CONTROL
        .get()
        .map(|control| Arc::clone(&control.charger))
}

/// A Ro credit-control session.
///
/// `authorized` says whether the call may go ahead: a grant (`open` is then
/// true and the session is live), or an uncharged go-ahead (Ro not enabled,
/// CREDIT_CONTROL_NOT_APPLICABLE, fail-open) with no session. A refusal is
/// `authorized == False` with the OCS `result_code`.
#[pyclass(name = "RoSession", skip_from_py_object)]
pub struct PyRoSession {
    session: Option<CcCreditSession>,
    authorized: bool,
    result_code: Option<u32>,
}

impl PyRoSession {
    pub(crate) fn from_session(session: CcCreditSession) -> Self {
        let result_code = session.last_result_code();
        Self {
            session: Some(session),
            authorized: true,
            result_code,
        }
    }

    fn live(&self) -> Option<(CcCreditSession, Arc<RoChargingService>)> {
        let session = self.session.clone()?;
        let charger = charger()?;
        Some((session, charger))
    }
}

fn answer_dict(
    python: Python<'_>,
    session: &CcCreditSession,
    result_code: Option<u32>,
) -> PyResult<Py<PyAny>> {
    let grant = session.grant();
    let dict = PyDict::new(python);
    dict.set_item("result_code", result_code)?;
    dict.set_item("open", session.is_open())?;
    dict.set_item("granted_time", grant.granted_time)?;
    dict.set_item("validity_time", grant.validity_time)?;
    dict.set_item("time_quota_threshold", grant.time_quota_threshold)?;
    dict.set_item("final_unit_action", grant.final_unit_action)?;
    dict.set_item("tariff_time_change", grant.tariff_time_change)?;
    dict.set_item(
        "free_format_data",
        grant
            .free_format_data
            .as_deref()
            .map(|data| pyo3::types::PyBytes::new(python, data)),
    )?;
    Ok(dict.into_any().unbind())
}

#[pymethods]
impl PyRoSession {
    #[getter]
    fn authorized(&self) -> bool {
        self.authorized
    }

    /// Result-Code of the last answer in the session, or of the refusal.
    #[getter]
    fn result_code(&self) -> Option<u32> {
        match &self.session {
            Some(session) => session.last_result_code().or(self.result_code),
            None => self.result_code,
        }
    }

    /// Whether the credit-control session is live.
    #[getter]
    fn open(&self) -> bool {
        self.session.as_ref().is_some_and(CcCreditSession::is_open)
    }

    #[getter]
    fn session_id(&self) -> Option<String> {
        self.session.as_ref().map(|s| s.session_id().to_string())
    }

    #[getter]
    fn subscription_id(&self) -> Option<String> {
        self.session.as_ref().map(|s| s.subscriber().data.clone())
    }

    #[getter]
    fn service_context_id(&self) -> Option<String> {
        self.session
            .as_ref()
            .map(|s| s.service_context_id().to_string())
    }

    #[getter]
    fn key(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|s| s.key().map(String::from))
    }

    /// SIP Call-ID of the call the session is bound to.
    #[getter]
    fn call_id(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(CcCreditSession::teardown_call)
    }

    /// CC-Time of the grant in force (seconds).
    #[getter]
    fn granted_time(&self) -> Option<u32> {
        self.session.as_ref().and_then(|s| s.grant().granted_time)
    }

    #[getter]
    fn validity_time(&self) -> Option<u32> {
        self.session.as_ref().and_then(|s| s.grant().validity_time)
    }

    #[getter]
    fn time_quota_threshold(&self) -> Option<u32> {
        self.session
            .as_ref()
            .and_then(|s| s.grant().time_quota_threshold)
    }

    /// Final-Unit-Action of the grant in force: 0 TERMINATE, 1 REDIRECT,
    /// 2 RESTRICT_ACCESS; `None` when it is not the last.
    #[getter]
    fn final_unit_action(&self) -> Option<u32> {
        self.session
            .as_ref()
            .and_then(|s| s.grant().final_unit_action)
    }

    /// Tariff-Time-Change of the grant in force, Unix seconds.
    #[getter]
    fn tariff_time_change(&self) -> Option<u64> {
        self.session
            .as_ref()
            .and_then(|s| s.grant().tariff_time_change)
    }

    /// PS-Free-Format-Data the OCS returned in VCS-Information (TS 32.276),
    /// for a Proxy Function to pass to the MSC; None when it sent none.
    #[getter]
    fn free_format_data<'py>(
        &self,
        python: Python<'py>,
    ) -> Option<Bound<'py, pyo3::types::PyBytes>> {
        let data = self.session.as_ref()?.grant().free_format_data?;
        Some(pyo3::types::PyBytes::new(python, &data))
    }

    /// Bind the session to the live B2BUA call with this SIP Call-ID: it ends
    /// with that call, and credit exhaustion disconnects it. Returns False
    /// when no such call is live or the session has ended.
    fn bind(&self, call_id: &str) -> bool {
        match &self.session {
            Some(session) => crate::dispatcher::ro_bind_call(session, call_id),
            None => false,
        }
    }

    /// The call was answered: start the chargeable clock (local metering) and
    /// report it with a CCR-UPDATE. A bound session is told by siphon itself
    /// on a B2BUA answer; this is for a leg whose answer siphon does not see
    /// as one. Idempotent.
    fn answered<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let live = self.live();
        crate::script::awaitable(python, async move {
            if let Some((session, charger)) = live {
                charger.report_answer(&session).await;
            }
            Ok(())
        })
    }

    /// External metering: report the cumulative usage in seconds and ask for
    /// more (CCR-UPDATE). Returns ``{result_code, open, granted_time,
    /// validity_time, time_quota_threshold, final_unit_action,
    /// tariff_time_change, free_format_data}``; ``result_code`` is None when
    /// no server answered. A refusal ends the session. ``vcs_information``
    /// (the members of ``diameter.ro_session``'s) is laid over the session's
    /// for this and later requests: Start-of-Charging once the call is
    /// answered, say.
    #[pyo3(signature = (used_total, vcs_information=None))]
    fn report<'py>(
        &self,
        python: Python<'py>,
        used_total: u32,
        vcs_information: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let Some((session, charger)) = self.live() else {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "RoSession.report: no credit-control session",
            ));
        };
        if let Some(update) = vcs_information.map(vcs_from_dict).transpose()? {
            session.update_vcs(update);
        }
        crate::script::awaitable(python, async move {
            let result_code = match charger.report_usage(&session, used_total).await {
                Ok(answer) => Some(answer.result_code),
                Err(_) => None,
            };
            Ok(crate::script::Deferred::build(move |py| {
                answer_dict(py, &session, result_code)
            }))
        })
    }

    /// End the session (CCR-TERMINATION). ``cause_code`` is the
    /// IMS-Information Cause-Code (0 a normal end, the negated SIP status
    /// otherwise; None omits it). ``used_total`` is the final cumulative usage
    /// of an externally metered session. ``vcs_information`` adds what is
    /// known only at the release to the CCR-TERMINATION: ``isup_cause_value``,
    /// ``isup_cause_location``, ``isup_cause_diagnostics``, ``stop_time``
    /// (TS 32.276). Idempotent.
    #[pyo3(signature = (cause_code=Some(0), used_total=None, vcs_information=None))]
    fn terminate<'py>(
        &self,
        python: Python<'py>,
        cause_code: Option<i32>,
        used_total: Option<u32>,
        vcs_information: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vcs = vcs_information.map(vcs_from_dict).transpose()?;
        let live = self.live();
        crate::script::awaitable(python, async move {
            if let Some((session, charger)) = live {
                let used_total = match session.metering() {
                    Metering::External => used_total,
                    Metering::Local => None,
                };
                charger
                    .terminate_with(&session, used_total, cause_code, vcs)
                    .await;
            }
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        match &self.session {
            Some(session) => format!(
                "RoSession(session_id={:?}, subscription_id={:?}, open={})",
                session.session_id(),
                session.subscriber().data,
                session.is_open()
            ),
            None => format!(
                "RoSession(authorized={}, result_code={:?})",
                self.authorized, self.result_code
            ),
        }
    }
}

/// Wrap a script callable as the session's event hook. Called as
/// `handler(session, event)` with `event` a dict `{event, reason, result_code,
/// final_unit_action, redirect_server_address}`; an `async def` is awaited.
pub(crate) fn event_hook(
    handler: Py<PyAny>,
    is_async: bool,
) -> crate::diameter::ro_service::RoEventHook {
    let handler = Arc::new(handler);
    Arc::new(move |session: &CcCreditSession, event: &RoSessionEvent| {
        let handler = Arc::clone(&handler);
        let session = session.clone();
        let event = event.clone();
        tokio::spawn(async move {
            let _ = crate::script::py_executor::try_run(move || {
                Python::attach(|python| {
                    let result = (|| -> PyResult<()> {
                        let dict = PyDict::new(python);
                        dict.set_item("event", event.kind.label())?;
                        dict.set_item("reason", &event.reason)?;
                        dict.set_item("result_code", event.result_code)?;
                        dict.set_item("final_unit_action", event.final_unit_action)?;
                        dict.set_item("redirect_server_address", &event.redirect_server_address)?;
                        let handle = Py::new(python, PyRoSession::from_session(session))?;
                        let returned = handler.bind(python).call1((handle, dict))?;
                        if is_async {
                            crate::script::engine::run_coroutine(python, &returned)?;
                        }
                        Ok(())
                    })();
                    if let Err(failure) = result {
                        error!(error = %failure, event = event.kind.label(), "ro: on_event handler failed");
                    }
                })
            })
            .await;
        });
    })
}

/// Everything `diameter.ro_session()` takes, owned, for the awaitable.
pub(crate) struct OpenRequest {
    pub subscriber: crate::diameter::ro::SubscriberId,
    pub additional_subscribers: Vec<crate::diameter::ro::SubscriberId>,
    pub vcs_data: Option<crate::diameter::ro::VcsInformation>,
    pub ims_data: Option<crate::diameter::ro::ImsChargingData>,
    pub service_context_id: Option<String>,
    pub requested_seconds: Option<u32>,
    pub rating_group: Option<u32>,
    pub service_identifier: Option<u32>,
    pub metering: Metering,
    pub charge_from: Option<crate::diameter::ro_service::ChargeFrom>,
    pub key: Option<String>,
    pub call_id: Option<String>,
    pub event_hook: Option<crate::diameter::ro_service::RoEventHook>,
}

/// Open the session (CCR-INITIAL) and, with `call_id`, bind it.
pub(crate) async fn open(request: OpenRequest) -> PyResult<PyRoSession> {
    let Some(charger) = charger() else {
        // Ro not configured: the same no-op go-ahead `call.ro_authorize()`
        // gives, uncharged.
        return Ok(PyRoSession {
            session: None,
            authorized: true,
            result_code: None,
        });
    };
    let mut spec = charger.session_spec(request.subscriber, request.ims_data);
    spec.additional_subscribers = request.additional_subscribers;
    spec.vcs_data = request.vcs_data;
    if let Some(context) = request.service_context_id {
        spec.service_context_id = context;
    }
    if let Some(seconds) = request.requested_seconds {
        spec.requested_seconds = seconds;
    }
    if request.rating_group.is_some() {
        spec.rating_group = request.rating_group;
    }
    if request.service_identifier.is_some() {
        spec.service_identifier = request.service_identifier;
    }
    if let Some(charge_from) = request.charge_from {
        spec.charge_from = charge_from;
    }
    spec.metering = request.metering;
    spec.key = request.key;
    spec.event_hook = request.event_hook;
    match charger.open_session(spec).await {
        ChargeDecision::Granted(Some(session)) => {
            if let Some(call_id) = request.call_id.as_deref() {
                if !crate::dispatcher::ro_bind_call(&session, call_id) {
                    charger.terminate_call(&session, None).await;
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "diameter.ro_session: no live B2BUA call with Call-ID {call_id}; \
                         the session was opened and terminated"
                    )));
                }
            }
            Ok(PyRoSession::from_session(session))
        }
        ChargeDecision::Granted(None) | ChargeDecision::AllowUncharged => Ok(PyRoSession {
            session: None,
            authorized: true,
            result_code: None,
        }),
        ChargeDecision::Denied(code) => Ok(PyRoSession {
            session: None,
            authorized: false,
            result_code: Some(code),
        }),
    }
}

/// `diameter.ro_find(key)`.
pub(crate) fn find(key: &str) -> Option<PyRoSession> {
    charger()?
        .session_by_key(key)
        .map(PyRoSession::from_session)
}

/// Octets from a script value: `bytes`, or a hex string.
fn octets(value: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<u8>> {
    if let Ok(text) = value.extract::<String>() {
        return crate::diameter::codec::hex::decode(text.trim()).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "vcs_information[{name:?}]: not a hex string"
            ))
        });
    }
    value.extract::<Vec<u8>>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(format!(
            "vcs_information[{name:?}]: bytes or a hex string"
        ))
    })
}

fn unix_time(value: &Bound<'_, PyAny>, name: &str) -> PyResult<std::time::SystemTime> {
    let seconds: f64 = value.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(format!("vcs_information[{name:?}]: Unix seconds"))
    })?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "vcs_information[{name:?}]: Unix seconds, not {seconds}"
        )));
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(seconds))
}

/// Build `VCS-Information` from the `vcs_information=` dict. An unknown key
/// is an error, so a misspelt member is not silently left off the record.
pub(crate) fn vcs_from_dict(
    dict: &Bound<'_, PyDict>,
) -> PyResult<crate::diameter::ro::VcsInformation> {
    use crate::diameter::ro::{BasicServiceCode, IsupCause, VcsInformation};
    let mut vcs = VcsInformation::default();
    let mut service = BasicServiceCode::default();
    let mut cause = IsupCause::default();
    for (key, value) in dict.iter() {
        let name: String = key.extract()?;
        if value.is_none() {
            continue;
        }
        match name.as_str() {
            "bearer_capability" => vcs.bearer_capability = Some(octets(&value, &name)?),
            "network_call_reference_number" => {
                vcs.network_call_reference_number = Some(octets(&value, &name)?)
            }
            "msc_address" => vcs.msc_address = Some(octets(&value, &name)?),
            "bearer_service" => service.bearer_service = Some(octets(&value, &name)?),
            "teleservice" => service.teleservice = Some(octets(&value, &name)?),
            "isup_location_number" => vcs.isup_location_number = Some(octets(&value, &name)?),
            "vlr_number" => vcs.vlr_number = Some(octets(&value, &name)?),
            "forwarding_pending" => vcs.forwarding_pending = Some(value.extract()?),
            "isup_cause_location" => cause.location = Some(value.extract()?),
            "isup_cause_value" => cause.value = Some(value.extract()?),
            "isup_cause_diagnostics" => cause.diagnostics = Some(octets(&value, &name)?),
            "start_time" => vcs.start_time = Some(unix_time(&value, &name)?),
            "start_of_charging" => vcs.start_of_charging = Some(unix_time(&value, &name)?),
            "stop_time" => vcs.stop_time = Some(unix_time(&value, &name)?),
            "ps_free_format_data" => vcs.ps_free_format_data = Some(octets(&value, &name)?),
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "vcs_information: unknown member {other:?}"
                )))
            }
        }
    }
    if service != BasicServiceCode::default() {
        vcs.basic_service_code = Some(service);
    }
    if cause != IsupCause::default() {
        vcs.isup_cause = Some(cause);
    }
    Ok(vcs)
}
