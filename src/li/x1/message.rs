//! The X1 message set (ETSI TS 103 221-1 clause 6).
//!
//! X1 is not a REST resource collection. It is a single endpoint that accepts
//! an `X1Request` *container* holding one or more `x1RequestMessage` elements,
//! each discriminated by its `xsi:type` attribute, and answers with an
//! `X1Response` container holding one response message per request message,
//! correlated by `x1TransactionId`.
//!
//! Every message in both directions carries the same five envelope fields
//! ([`Envelope`]). `ErrorResponse` extends the same envelope, so an error is a
//! well-formed X1 response — not an HTTP status with an ad-hoc body.

use super::error::{ErrorCode, X1Error};
use super::types::{
    DId, DeliveryAddress, DeliveryType, DestinationDeliveryStatus, Liid, MediationDeliveryType,
    NeStatus, OkValue, ProvisioningStatus, ServiceType, TargetIdentifier, TaskReportType,
    Timestamp, Token, TypeOfNeIssueMessage, Version, XId, X1TransactionId,
};

/// The five fields every X1 message carries (clause 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Identifies the ADMF. Bound to the presented client certificate.
    pub admf_identifier: Token,
    /// Identifies the network element (this siphon instance).
    pub ne_identifier: Token,
    /// Microsecond-precision, explicitly zoned.
    pub message_timestamp: Timestamp,
    /// The schema version this message is written to.
    pub version: Version,
    /// Correlates request with response.
    pub x1_transaction_id: X1TransactionId,
}

/// The `RequestMessageType` enumeration (clause 6.7).
///
/// Used for dispatch, and echoed in `ErrorResponse/requestMessageType` so the
/// ADMF knows which of its messages failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// `ActivateTask`
    ActivateTask,
    /// `ModifyTask`
    ModifyTask,
    /// `DeactivateTask`
    DeactivateTask,
    /// `DeactivateAllTasks`
    DeactivateAllTasks,
    /// `GetTaskDetails`
    GetTaskDetails,
    /// `CreateDestination`
    CreateDestination,
    /// `ModifyDestination`
    ModifyDestination,
    /// `RemoveDestination`
    RemoveDestination,
    /// `RemoveAllDestinations`
    RemoveAllDestinations,
    /// `GetDestinationDetails`
    GetDestinationDetails,
    /// `GetNEStatus`
    GetNEStatus,
    /// `GetAllDetails`
    GetAllDetails,
    /// `GetAllTaskDetails`
    GetAllTaskDetails,
    /// `GetAllDestinationDetails`
    GetAllDestinationDetails,
    /// `ListAllDetails`
    ListAllDetails,
    /// `ReportTaskIssue`
    ReportTaskIssue,
    /// `ReportDestinationIssue`
    ReportDestinationIssue,
    /// `ReportNEIssue`
    ReportNEIssue,
    /// `Ping`
    Ping,
    /// `Keepalive`
    Keepalive,
}

impl MessageKind {
    /// The value as it appears in `requestMessageType`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActivateTask => "ActivateTask",
            Self::ModifyTask => "ModifyTask",
            Self::DeactivateTask => "DeactivateTask",
            Self::DeactivateAllTasks => "DeactivateAllTasks",
            Self::GetTaskDetails => "GetTaskDetails",
            Self::CreateDestination => "CreateDestination",
            Self::ModifyDestination => "ModifyDestination",
            Self::RemoveDestination => "RemoveDestination",
            Self::RemoveAllDestinations => "RemoveAllDestinations",
            Self::GetDestinationDetails => "GetDestinationDetails",
            Self::GetNEStatus => "GetNEStatus",
            Self::GetAllDetails => "GetAllDetails",
            Self::GetAllTaskDetails => "GetAllTaskDetails",
            Self::GetAllDestinationDetails => "GetAllDestinationDetails",
            Self::ListAllDetails => "ListAllDetails",
            Self::ReportTaskIssue => "ReportTaskIssue",
            Self::ReportDestinationIssue => "ReportDestinationIssue",
            Self::ReportNEIssue => "ReportNEIssue",
            Self::Ping => "Ping",
            Self::Keepalive => "Keepalive",
        }
    }

    /// The `xsi:type` of the request form of this message.
    pub fn request_type_name(self) -> String {
        format!("{}Request", self.as_str())
    }

    /// The `xsi:type` of the response form of this message.
    pub fn response_type_name(self) -> String {
        format!("{}Response", self.as_str())
    }

    /// Resolve a request `xsi:type` to its message kind.
    ///
    /// `None` covers both a type outside this profile (the generic-object
    /// messages) and one outside the schema entirely; the caller answers
    /// [`ErrorCode::UnsupportedRequest`] either way, which is what an NE that
    /// does not implement a message is required to do.
    pub fn from_request_type_name(name: &str) -> Option<Self> {
        let base = name.strip_suffix("Request")?;
        let all = [
            Self::ActivateTask,
            Self::ModifyTask,
            Self::DeactivateTask,
            Self::DeactivateAllTasks,
            Self::GetTaskDetails,
            Self::CreateDestination,
            Self::ModifyDestination,
            Self::RemoveDestination,
            Self::RemoveAllDestinations,
            Self::GetDestinationDetails,
            Self::GetNEStatus,
            Self::GetAllDetails,
            Self::GetAllTaskDetails,
            Self::GetAllDestinationDetails,
            Self::ListAllDetails,
            Self::ReportTaskIssue,
            Self::ReportDestinationIssue,
            Self::ReportNEIssue,
            Self::Ping,
            Self::Keepalive,
        ];
        all.into_iter().find(|kind| kind.as_str() == base)
    }
}

/// `MediationDetails` (clause 6.2.1.2) — where the LIID actually lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediationDetails {
    /// The handover identifier the mediation function keys on.
    pub liid: Liid,
    /// Which handover interfaces this mediation entry covers.
    pub delivery_type: MediationDeliveryType,
    /// Optional start of the authorised window.
    pub start_time: Option<Timestamp>,
    /// Optional end of the authorised window.
    pub end_time: Option<Timestamp>,
    /// Optional destination narrowing for this mediation entry.
    pub list_of_dids: Vec<DId>,
}

/// `TaskDetails` (clause 6.2.1.2) — a provisioned intercept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDetails {
    /// The task's identity, and the XID of every PDU delivered for it.
    pub x_id: XId,
    /// One or more identifiers to intercept on. At least one is required.
    pub target_identifiers: Vec<TargetIdentifier>,
    /// What this task delivers.
    pub delivery_type: DeliveryType,
    /// The destinations this task delivers to, and only these.
    pub list_of_dids: Vec<DId>,
    /// Destination-*set* references (`listOfDIDs/dSId`).
    ///
    /// A destination set is a generic object, which is out of this profile.
    /// The references are kept rather than dropped so a task naming one can be
    /// refused: silently ignoring a destination reference would provision a
    /// task that delivers somewhere the ADMF did not ask for, or nowhere.
    pub list_of_dsids: Vec<String>,
    /// Optional mediation entries (this is where LIIDs come from).
    pub list_of_mediation_details: Vec<MediationDetails>,
    /// Correlation value provisioned by the ADMF, if it supplies one.
    ///
    /// When absent the network element mints one per session. Honoured rather
    /// than assumed, because we do not always own that number.
    pub correlation_id: Option<u64>,
    /// Whether the NE may deactivate this task on its own.
    pub implicit_deactivation_allowed: Option<bool>,
    /// Optional product grouping identifier.
    pub product_id: Option<XId>,
    /// Optional service scoping.
    pub list_of_service_types: Vec<ServiceType>,
}

impl TaskDetails {
    /// The first LIID across the task's mediation entries, if any.
    ///
    /// X2 delivery needs a LIID; when the ADMF provisions none, the delivery
    /// path falls back to the XID's text form.
    pub fn primary_liid(&self) -> Option<&Liid> {
        self.list_of_mediation_details.first().map(|m| &m.liid)
    }

    /// Every target identifier the network element cannot intercept on.
    pub fn unsupported_identifiers(&self) -> Vec<&str> {
        self.target_identifiers
            .iter()
            .filter(|identifier| !identifier.is_supported())
            .map(|identifier| identifier.element_name())
            .collect()
    }
}

/// `DestinationDetails` (clause 6.3.1.2) — a provisioned delivery sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationDetails {
    /// The destination's identity, referenced from a task's `listOfDIDs`.
    pub d_id: DId,
    /// Optional operator-facing label.
    pub friendly_name: Option<String>,
    /// What this destination accepts.
    pub delivery_type: DeliveryType,
    /// Where product is sent.
    pub delivery_address: DeliveryAddress,
}

/// `TaskStatus` (clause 6.4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskStatus {
    /// Whether provisioning completed.
    pub provisioning_status: ProvisioningStatus,
    /// Faults still outstanding against this task.
    pub list_of_faults: Vec<X1Error>,
    /// When product last flowed for this task.
    pub time_of_last_intercept: Option<Timestamp>,
    /// When the task was last modified.
    pub time_of_last_modification: Option<Timestamp>,
    /// How many times the task has been modified.
    pub number_of_modifications: Option<i64>,
}

/// `TaskResponseDetails` — a task plus its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResponseDetails {
    /// The provisioned task.
    pub task_details: TaskDetails,
    /// Its current status.
    pub task_status: TaskStatus,
}

/// `DestinationStatus` (clause 6.4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationStatus {
    /// Whether delivery to this destination is working.
    pub destination_delivery_status: DestinationDeliveryStatus,
    /// Faults still outstanding against this destination.
    pub list_of_faults: Vec<X1Error>,
}

/// `DestinationResponseDetails` — a destination plus its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationResponseDetails {
    /// The provisioned destination.
    pub destination_details: DestinationDetails,
    /// Its current delivery status.
    pub destination_status: DestinationStatus,
}

/// `NeStatusDetails` (clause 6.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeStatusDetails {
    /// Overall health.
    pub ne_status: NeStatus,
    /// Faults still outstanding against the node.
    pub list_of_faults: Vec<X1Error>,
}

/// The payload of an `x1RequestMessage`, after its `xsi:type` is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBody {
    /// `ActivateTaskRequest`
    ActivateTask(Box<TaskDetails>),
    /// `ModifyTaskRequest`
    ModifyTask(Box<TaskDetails>),
    /// `DeactivateTaskRequest`
    DeactivateTask(XId),
    /// `DeactivateAllTasksRequest`
    DeactivateAllTasks,
    /// `GetTaskDetailsRequest`
    GetTaskDetails(XId),
    /// `CreateDestinationRequest`
    CreateDestination(Box<DestinationDetails>),
    /// `ModifyDestinationRequest`
    ModifyDestination(Box<DestinationDetails>),
    /// `RemoveDestinationRequest`
    RemoveDestination(DId),
    /// `RemoveAllDestinationsRequest`
    RemoveAllDestinations,
    /// `GetDestinationDetailsRequest`
    GetDestinationDetails(DId),
    /// `GetNEStatusRequest`
    GetNEStatus,
    /// `GetAllDetailsRequest`
    GetAllDetails,
    /// `GetAllTaskDetailsRequest`
    GetAllTaskDetails,
    /// `GetAllDestinationDetailsRequest`
    GetAllDestinationDetails,
    /// `ListAllDetailsRequest`
    ListAllDetails,
    /// `PingRequest`
    Ping,
    /// `KeepaliveRequest`
    Keepalive,
    /// `ReportTaskIssueRequest` — the NE-to-ADMF direction.
    ReportTaskIssue {
        /// Which task the report concerns.
        x_id: XId,
        /// Why the report is being sent.
        report_type: TaskReportType,
        /// Optional clause 6.7 code.
        error_code: Option<i64>,
        /// Optional free text.
        details: Option<String>,
    },
    /// `ReportDestinationIssueRequest` — the NE-to-ADMF direction.
    ReportDestinationIssue {
        /// Which destination the report concerns.
        d_id: DId,
        /// Why the report is being sent.
        report_type: TaskReportType,
        /// Optional clause 6.7 code.
        error_code: Option<i64>,
        /// Optional free text.
        details: Option<String>,
    },
    /// `ReportNEIssueRequest` — the NE-to-ADMF direction.
    ReportNEIssue {
        /// The severity of the report.
        issue_type: TypeOfNeIssueMessage,
        /// Required description.
        description: String,
        /// Optional clause 6.7 code.
        issue_code: Option<i64>,
    },
}

impl RequestBody {
    /// The message kind this body belongs to.
    pub fn kind(&self) -> MessageKind {
        match self {
            Self::ActivateTask(_) => MessageKind::ActivateTask,
            Self::ModifyTask(_) => MessageKind::ModifyTask,
            Self::DeactivateTask(_) => MessageKind::DeactivateTask,
            Self::DeactivateAllTasks => MessageKind::DeactivateAllTasks,
            Self::GetTaskDetails(_) => MessageKind::GetTaskDetails,
            Self::CreateDestination(_) => MessageKind::CreateDestination,
            Self::ModifyDestination(_) => MessageKind::ModifyDestination,
            Self::RemoveDestination(_) => MessageKind::RemoveDestination,
            Self::RemoveAllDestinations => MessageKind::RemoveAllDestinations,
            Self::GetDestinationDetails(_) => MessageKind::GetDestinationDetails,
            Self::GetNEStatus => MessageKind::GetNEStatus,
            Self::GetAllDetails => MessageKind::GetAllDetails,
            Self::GetAllTaskDetails => MessageKind::GetAllTaskDetails,
            Self::GetAllDestinationDetails => MessageKind::GetAllDestinationDetails,
            Self::ListAllDetails => MessageKind::ListAllDetails,
            Self::Ping => MessageKind::Ping,
            Self::Keepalive => MessageKind::Keepalive,
            Self::ReportTaskIssue { .. } => MessageKind::ReportTaskIssue,
            Self::ReportDestinationIssue { .. } => MessageKind::ReportDestinationIssue,
            Self::ReportNEIssue { .. } => MessageKind::ReportNEIssue,
        }
    }
}

/// One `x1RequestMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMessage {
    /// The five common fields.
    pub envelope: Envelope,
    /// The message-specific payload.
    pub body: RequestBody,
}

/// The payload of an `x1ResponseMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseBody {
    /// A simple acknowledgement, used by every command and liveness message.
    Ok(OkValue),
    /// `GetTaskDetailsResponse`
    TaskDetails(Box<TaskResponseDetails>),
    /// `GetDestinationDetailsResponse`
    DestinationDetails(Box<DestinationResponseDetails>),
    /// `GetNEStatusResponse`
    NeStatus(NeStatusDetails),
    /// `GetAllDetailsResponse`
    AllDetails {
        /// Node health.
        ne_status: NeStatusDetails,
        /// Every provisioned task.
        tasks: Vec<TaskResponseDetails>,
        /// Every provisioned destination.
        destinations: Vec<DestinationResponseDetails>,
    },
    /// `GetAllTaskDetailsResponse`
    AllTaskDetails(Vec<TaskResponseDetails>),
    /// `GetAllDestinationDetailsResponse`
    AllDestinationDetails(Vec<DestinationResponseDetails>),
    /// `ListAllDetailsResponse`
    ListAllDetails {
        /// Every provisioned task identifier.
        x_ids: Vec<XId>,
        /// Every provisioned destination identifier.
        d_ids: Vec<DId>,
    },
    /// `ErrorResponse` — a per-message failure, still a valid X1 response.
    Error {
        /// Which request message failed.
        request_message_type: MessageKind,
        /// The failure.
        error: X1Error,
    },
}

/// One `x1ResponseMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseMessage {
    /// The five common fields, echoing the request's transaction id.
    pub envelope: Envelope,
    /// Which message this answers — determines the response's `xsi:type`.
    pub kind: MessageKind,
    /// The message-specific payload.
    pub body: ResponseBody,
}

impl ResponseMessage {
    /// The `xsi:type` this response serialises with.
    ///
    /// An error answer is always `ErrorResponse`, whatever it answers.
    pub fn type_name(&self) -> String {
        match self.body {
            ResponseBody::Error { .. } => "ErrorResponse".to_string(),
            _ => self.kind.response_type_name(),
        }
    }

    /// Build an acknowledgement for `kind`.
    pub fn ok(envelope: Envelope, kind: MessageKind) -> Self {
        Self {
            envelope,
            kind,
            body: ResponseBody::Ok(OkValue::AcknowledgedAndCompleted),
        }
    }

    /// Build an `ErrorResponse` for `kind`.
    pub fn error(envelope: Envelope, kind: MessageKind, error: X1Error) -> Self {
        Self {
            envelope,
            kind,
            body: ResponseBody::Error {
                request_message_type: kind,
                error,
            },
        }
    }
}

/// A parsed `X1Request` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContainer {
    /// One or more request messages, in document order.
    pub messages: Vec<RequestMessage>,
}

/// An `X1Response` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseContainer {
    /// One response per request message, in the same order.
    pub messages: Vec<ResponseMessage>,
}

/// An `X1TopLevelErrorResponse`.
///
/// Reserved for a container that could not be parsed far enough to answer
/// per-message — it carries no `x1TransactionId`, because none was readable.
/// A bad message *inside* a good container gets a per-message
/// [`ResponseBody::Error`] instead, so its siblings are still answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopLevelErrorResponse {
    /// Identifies the ADMF.
    pub admf_identifier: Token,
    /// Identifies this network element.
    pub ne_identifier: Token,
    /// When the failure was detected.
    pub message_timestamp: Timestamp,
    /// The schema version this node speaks.
    pub version: Version,
}

/// One message in a decoded container: either a usable message, or a failure
/// that must still be answered in that message's slot.
///
/// Decoding never discards a message. If the envelope parsed but the payload
/// did not, the envelope comes back alongside the error so the response can
/// echo the right `x1TransactionId`; if the envelope itself was unreadable,
/// there is nothing to correlate on and the whole container is rejected with a
/// [`TopLevelErrorResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedMessage {
    /// A message that parsed cleanly.
    Message(Box<RequestMessage>),
    /// A message whose envelope parsed but whose payload did not.
    Failed {
        /// The envelope, so the error response can be correlated.
        envelope: Box<Envelope>,
        /// What the request claimed to be, if it named a known type.
        kind: Option<MessageKind>,
        /// Why it failed.
        error: X1Error,
    },
}

impl DecodedMessage {
    /// The envelope, whichever variant this is.
    pub fn envelope(&self) -> &Envelope {
        match self {
            Self::Message(message) => &message.envelope,
            Self::Failed { envelope, .. } => envelope,
        }
    }
}

/// Build the `ErrorResponse` for a decoded message that failed.
///
/// A failed message with no resolvable kind is reported against
/// [`MessageKind::Ping`]'s slot only if the caller supplies one; otherwise the
/// caller must pick. This helper exists so the "unknown type" path still
/// produces a schema-valid `requestMessageType`.
pub fn error_response_for(
    envelope: Envelope,
    kind: Option<MessageKind>,
    error: X1Error,
) -> ResponseMessage {
    // `requestMessageType` is a closed enumeration, so a request whose
    // xsi:type we could not resolve has no honest value to put there. The
    // schema's own escape hatch for that is the generic error code, reported
    // against the message we can name: we fall back to GetNEStatus, the one
    // request that carries no payload and cannot be confused with a
    // provisioning action.
    let reported = kind.unwrap_or(MessageKind::GetNEStatus);
    ResponseMessage {
        envelope,
        kind: reported,
        body: ResponseBody::Error {
            request_message_type: reported,
            error,
        },
    }
}

/// Convenience for building an [`X1Error`] naming an unsupported message type.
pub fn unsupported_message(type_name: &str) -> X1Error {
    X1Error::new(
        ErrorCode::UnsupportedRequest,
        format!("message type {type_name:?} is not supported by this network element"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::x1::types::DEFAULT_VERSION;

    fn envelope() -> Envelope {
        Envelope {
            admf_identifier: Token::parse("admf-id", "admfIdentifier").unwrap(),
            ne_identifier: Token::parse("siphon-ne", "neIdentifier").unwrap(),
            message_timestamp: Timestamp::now(),
            version: Version::parse(DEFAULT_VERSION).unwrap(),
            x1_transaction_id: X1TransactionId::generate(),
        }
    }

    #[test]
    fn request_type_names_round_trip() {
        let all = [
            MessageKind::ActivateTask,
            MessageKind::ModifyTask,
            MessageKind::DeactivateTask,
            MessageKind::DeactivateAllTasks,
            MessageKind::GetTaskDetails,
            MessageKind::CreateDestination,
            MessageKind::ModifyDestination,
            MessageKind::RemoveDestination,
            MessageKind::RemoveAllDestinations,
            MessageKind::GetDestinationDetails,
            MessageKind::GetNEStatus,
            MessageKind::GetAllDetails,
            MessageKind::GetAllTaskDetails,
            MessageKind::GetAllDestinationDetails,
            MessageKind::ListAllDetails,
            MessageKind::ReportTaskIssue,
            MessageKind::ReportDestinationIssue,
            MessageKind::ReportNEIssue,
            MessageKind::Ping,
            MessageKind::Keepalive,
        ];
        for kind in all {
            let name = kind.request_type_name();
            assert_eq!(
                MessageKind::from_request_type_name(&name),
                Some(kind),
                "{name} did not resolve back to its kind"
            );
        }
    }

    #[test]
    fn out_of_profile_types_do_not_resolve() {
        // The generic-object messages are in the schema but out of this
        // profile — they must land on the UnsupportedRequest path, not be
        // mistaken for something we handle.
        for name in [
            "CreateObjectRequest",
            "ModifyObjectRequest",
            "GetObjectRequest",
            "DeleteObjectRequest",
            "ListObjectsOfTypeRequest",
            "DeleteAllObjectsRequest",
            "GetAllGenericObjectDetailsRequest",
        ] {
            assert_eq!(MessageKind::from_request_type_name(name), None, "{name}");
        }
    }

    #[test]
    fn unknown_and_malformed_type_names_do_not_resolve() {
        assert_eq!(MessageKind::from_request_type_name("NotARealMessage"), None);
        assert_eq!(MessageKind::from_request_type_name("ActivateTask"), None); // no suffix
        assert_eq!(MessageKind::from_request_type_name("ActivateTaskResponse"), None);
        assert_eq!(MessageKind::from_request_type_name(""), None);
    }

    #[test]
    fn response_type_name_is_derived_from_the_kind() {
        assert_eq!(
            MessageKind::ActivateTask.response_type_name(),
            "ActivateTaskResponse"
        );
        assert_eq!(MessageKind::Ping.response_type_name(), "PingResponse");
    }

    #[test]
    fn an_error_answer_always_serialises_as_error_response() {
        let response = ResponseMessage::error(
            envelope(),
            MessageKind::ActivateTask,
            X1Error::syntax("nope"),
        );
        assert_eq!(response.type_name(), "ErrorResponse");
    }

    #[test]
    fn a_success_answer_serialises_as_its_own_response_type() {
        let response = ResponseMessage::ok(envelope(), MessageKind::CreateDestination);
        assert_eq!(response.type_name(), "CreateDestinationResponse");
    }

    #[test]
    fn body_reports_its_own_kind() {
        assert_eq!(RequestBody::Ping.kind(), MessageKind::Ping);
        assert_eq!(
            RequestBody::DeactivateTask(XId::generate()).kind(),
            MessageKind::DeactivateTask
        );
        assert_eq!(
            RequestBody::GetAllDetails.kind(),
            MessageKind::GetAllDetails
        );
    }

    #[test]
    fn task_details_surfaces_unsupported_identifiers() {
        let task = TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![
                TargetIdentifier::SipUri("sip:alice@example.com".into()),
                TargetIdentifier::Unsupported("gtpuTunnelId".into()),
                TargetIdentifier::Unsupported("vrf".into()),
            ],
            delivery_type: DeliveryType::X2Only,
            list_of_dids: vec![DId::generate()],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        };
        assert_eq!(task.unsupported_identifiers(), vec!["gtpuTunnelId", "vrf"]);
        assert!(task.primary_liid().is_none());
    }

    #[test]
    fn primary_liid_comes_from_mediation_details() {
        let task = TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri("sip:a@b.com".into())],
            delivery_type: DeliveryType::X2Only,
            list_of_dids: vec![DId::generate()],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: vec![MediationDetails {
                liid: Liid::parse("LI-2026-0001").unwrap(),
                delivery_type: MediationDeliveryType::Hi2Only,
                start_time: None,
                end_time: None,
                list_of_dids: Vec::new(),
            }],
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        };
        assert_eq!(task.primary_liid().map(|l| l.as_str()), Some("LI-2026-0001"));
    }

    #[test]
    fn decoded_message_exposes_the_envelope_either_way() {
        let good = DecodedMessage::Message(Box::new(RequestMessage {
            envelope: envelope(),
            body: RequestBody::Ping,
        }));
        let bad = DecodedMessage::Failed {
            envelope: Box::new(envelope()),
            kind: Some(MessageKind::ActivateTask),
            error: X1Error::syntax("bad"),
        };
        // Both must be correlatable, which is the whole point of keeping the
        // envelope on the failure path.
        let _ = good.envelope().x1_transaction_id;
        let _ = bad.envelope().x1_transaction_id;
    }

    #[test]
    fn unresolved_kind_still_produces_a_schema_valid_request_message_type() {
        let response = error_response_for(envelope(), None, unsupported_message("CreateObject"));
        match response.body {
            ResponseBody::Error {
                request_message_type,
                error,
            } => {
                // Must be a member of the closed enumeration, not invented text.
                assert!(!request_message_type.as_str().is_empty());
                assert_eq!(error.code, ErrorCode::UnsupportedRequest);
            }
            other => panic!("expected an error body, got {other:?}"),
        }
    }
}
