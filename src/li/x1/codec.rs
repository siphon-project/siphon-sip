//! XML encoding and decoding for the X1 message set.
//!
//! Decoding walks the same DOM the schema validator parsed, so there is one
//! parser and one document rather than two readers that can disagree.
//! Encoding goes through `quick-xml`'s writer, which escapes text correctly.
//!
//! # Dispatch is by `xsi:type`, not by route
//!
//! `x1RequestMessage` is a single element whose concrete type is named by the
//! `xsi:type` attribute. [`decode_request_container`] resolves that attribute
//! to a [`MessageKind`] and decodes the matching payload. A type outside this
//! profile is not a decode failure: it comes back as a [`DecodedMessage::Failed`]
//! carrying its envelope, so it can be answered with a per-message
//! `ErrorResponse` while its siblings are answered normally.

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use uppsala::{Document, NodeId};

use super::error::{ErrorCode, X1Error};
use super::message::{
    unsupported_message, DecodedMessage, DestinationDetails, DestinationResponseDetails,
    DestinationStatus, Envelope, MediationDetails, MessageKind, NeStatusDetails, RequestBody,
    RequestContainer, RequestMessage, ResponseBody, ResponseContainer, ResponseMessage,
    TaskDetails, TaskResponseDetails, TaskStatus, TopLevelErrorResponse,
};
use super::types::{
    parse_expanded_ipv6, parse_ipv4, DId, DeliveryAddress, DeliveryType, IpAddressPort, Liid,
    MediationDeliveryType, Port, ServiceType, TargetIdentifier, TaskReportType, Timestamp, Token,
    TypeOfNeIssueMessage, Version, XId, X1TransactionId, NS_COMMON, NS_X1, NS_XSI,
};

/// Prefix used for the TS 103 280 dictionary namespace on the wire.
const COMMON_PREFIX: &str = "c";

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

/// The element children of `node`, as `(local name, id)` in document order.
fn child_elements(document: &Document<'_>, node: NodeId) -> Vec<(String, NodeId)> {
    document
        .children(node)
        .into_iter()
        .filter_map(|id| {
            document
                .element(id)
                .map(|element| (element.name.local_name.to_string(), id))
        })
        .collect()
}

/// The first element child of `node` with the given local name.
fn child(document: &Document<'_>, node: NodeId, name: &str) -> Option<NodeId> {
    child_elements(document, node)
        .into_iter()
        .find(|(local, _)| local == name)
        .map(|(_, id)| id)
}

/// Trimmed text of an element child, if present.
fn child_text(document: &Document<'_>, node: NodeId, name: &str) -> Option<String> {
    let id = child(document, node, name)?;
    Some(document.text_content_deep(id).trim().to_string())
}

/// Trimmed text of a mandatory element child.
fn require_text(document: &Document<'_>, node: NodeId, name: &str) -> Result<String, X1Error> {
    child_text(document, node, name)
        .ok_or_else(|| X1Error::syntax(format!("missing mandatory element <{name}>")))
}

/// A mandatory element child, as a node.
fn require_child(document: &Document<'_>, node: NodeId, name: &str) -> Result<NodeId, X1Error> {
    child(document, node, name)
        .ok_or_else(|| X1Error::syntax(format!("missing mandatory element <{name}>")))
}

/// Parse an optional integer child.
fn optional_integer(
    document: &Document<'_>,
    node: NodeId,
    name: &str,
) -> Result<Option<i64>, X1Error> {
    match child_text(document, node, name) {
        None => Ok(None),
        Some(text) => text
            .parse::<i64>()
            .map(Some)
            .map_err(|error| X1Error::syntax(format!("<{name}> {text:?} is not an integer: {error}"))),
    }
}

/// Parse an optional boolean child, accepting the XSD lexical forms.
fn optional_boolean(
    document: &Document<'_>,
    node: NodeId,
    name: &str,
) -> Result<Option<bool>, X1Error> {
    match child_text(document, node, name).as_deref() {
        None => Ok(None),
        Some("true") | Some("1") => Ok(Some(true)),
        Some("false") | Some("0") => Ok(Some(false)),
        Some(other) => Err(X1Error::syntax(format!(
            "<{name}> {other:?} is not a boolean"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// The `x1RequestMessage` nodes of an `X1Request` container, in order.
///
/// Errors when the container itself is not readable — a wrong root element or
/// no messages at all. Those are answered with an `X1TopLevelErrorResponse`,
/// because there is no `x1TransactionId` to correlate a per-message error on.
pub fn request_message_nodes(document: &Document<'_>) -> Result<Vec<NodeId>, X1Error> {
    let root = document.root();
    let container = child_elements(document, root)
        .into_iter()
        .find(|(local, _)| local == "X1Request")
        .map(|(_, id)| id)
        .ok_or_else(|| X1Error::syntax("document root is not <X1Request>"))?;

    let messages: Vec<NodeId> = child_elements(document, container)
        .into_iter()
        .filter(|(local, _)| local == "x1RequestMessage")
        .map(|(_, id)| id)
        .collect();

    if messages.is_empty() {
        return Err(X1Error::syntax(
            "<X1Request> contains no <x1RequestMessage> elements",
        ));
    }
    Ok(messages)
}

/// Wrap one `x1RequestMessage` in a container of its own, so it can be
/// schema-validated in isolation.
///
/// This is what lets a structurally invalid message fail *alone*: validating
/// the whole container would reject its siblings too, and the specification
/// requires each message to be answered in its own right.
///
/// The namespace declarations are copied from the source document rather than
/// assumed. `node_to_xml` serialises prefixed names but does **not** re-emit
/// the `xmlns:` declarations that bound them, so a wrapper carrying a fixed
/// prefix list produces a document whose prefixes no longer resolve. That is
/// invisible against a peer that happens to pick the same prefixes and breaks
/// immediately against one that does not — JAXB, for instance, generates
/// `ns2` for the TS 103 280 dictionary.
pub fn single_message_document(document: &Document<'_>, node: NodeId) -> String {
    let mut declarations: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Walk root → message so an inner declaration shadows an outer one, which
    // is what XML scoping does.
    let mut chain = vec![node];
    let mut current = node;
    while let Some(parent) = document.parent(current) {
        chain.push(parent);
        current = parent;
    }
    for id in chain.into_iter().rev() {
        let Some(element) = document.element(id) else {
            continue;
        };
        for (prefix, uri) in &element.namespace_declarations {
            let prefix = prefix.to_string();
            if seen.insert(prefix.clone()) {
                declarations.push((prefix, uri.to_string()));
            } else if let Some(entry) =
                declarations.iter_mut().find(|(name, _)| *name == prefix)
            {
                entry.1 = uri.to_string();
            }
        }
    }

    // The three this profile always needs, in case the source left any implicit.
    for (prefix, uri) in [
        (String::new(), NS_X1),
        (COMMON_PREFIX.to_string(), NS_COMMON),
        ("xsi".to_string(), NS_XSI),
    ] {
        if seen.insert(prefix.clone()) {
            declarations.push((prefix, uri.to_string()));
        }
    }

    let rendered: String = declarations
        .iter()
        .map(|(prefix, uri)| {
            if prefix.is_empty() {
                format!(" xmlns=\"{uri}\"")
            } else {
                format!(" xmlns:{prefix}=\"{uri}\"")
            }
        })
        .collect();

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<X1Request{rendered}>{}</X1Request>",
        document.node_to_xml(node)
    )
}

/// Decode an `X1Request` container.
///
/// Individual messages that fail to decode are returned as
/// [`DecodedMessage::Failed`] so their siblings still get answered.
pub fn decode_request_container(
    document: &Document<'_>,
) -> Result<Vec<DecodedMessage>, X1Error> {
    Ok(request_message_nodes(document)?
        .into_iter()
        .map(|id| decode_request_message(document, id))
        .collect())
}


/// Decode one `x1RequestMessage`.
///
/// Never fails outright: a message whose envelope parsed but whose payload did
/// not comes back as [`DecodedMessage::Failed`] carrying that envelope, so the
/// response can still be correlated on its `x1TransactionId`.
pub fn decode_request_message(document: &Document<'_>, node: NodeId) -> DecodedMessage {
    // The message type is read from the attribute, independently of whether the
    // envelope parses, so a message with a bad envelope is still reported
    // against the right `requestMessageType` rather than a guess.
    let type_name = document
        .element(node)
        .and_then(|element| element.get_attribute_ns(NS_XSI, "type"))
        // A prefixed attribute value carries the prefix, which is not part of
        // the type's name.
        .map(|value| value.rsplit(':').next().unwrap_or(value).to_string());
    let kind = type_name
        .as_deref()
        .and_then(MessageKind::from_request_type_name);

    let envelope = match decode_envelope(document, node) {
        Ok(envelope) => envelope,
        Err(error) => {
            // The envelope did not fully parse, but an error response the ADMF
            // cannot correlate is nearly useless to it — so whatever *did*
            // parse is kept, in particular the transaction id. Only the fields
            // that were themselves unreadable are substituted.
            return DecodedMessage::Failed {
                envelope: Box::new(salvage_envelope(document, node)),
                kind,
                error,
            };
        }
    };

    let Some(type_name) = type_name else {
        return DecodedMessage::Failed {
            envelope: Box::new(envelope),
            kind: None,
            error: X1Error::syntax("<x1RequestMessage> carries no xsi:type attribute"),
        };
    };

    let Some(kind) = kind else {
        return DecodedMessage::Failed {
            envelope: Box::new(envelope),
            kind: None,
            error: unsupported_message(&type_name),
        };
    };

    match decode_request_body(document, node, kind) {
        Ok(body) => DecodedMessage::Message(Box::new(RequestMessage { envelope, body })),
        Err(error) => DecodedMessage::Failed {
            envelope: Box::new(envelope),
            kind: Some(kind),
            error,
        },
    }
}

/// Build the best envelope available from a message whose own envelope did not
/// fully parse.
///
/// Each field is taken when it is readable and substituted when it is not, so
/// one bad field does not cost the ADMF the correlation. The transaction id
/// matters most: without it the error response cannot be tied to the request
/// that caused it, which turns a precise complaint into a mystery.
///
/// A substituted transaction id is freshly generated rather than zeroed,
/// because the field is a UUID on the wire and an all-zero one would read as a
/// real (if wrong) identifier.
fn salvage_envelope(document: &Document<'_>, node: NodeId) -> Envelope {
    let field = |name: &str| child_text(document, node, name);
    Envelope {
        admf_identifier: field("admfIdentifier")
            .and_then(|value| Token::parse(&value, "admfIdentifier").ok())
            .unwrap_or_else(Token::unknown),
        ne_identifier: field("neIdentifier")
            .and_then(|value| Token::parse(&value, "neIdentifier").ok())
            .unwrap_or_else(Token::unknown),
        // Our own clock is the honest answer for a timestamp we could not read.
        message_timestamp: field("messageTimestamp")
            .and_then(|value| Timestamp::parse(&value).ok())
            .unwrap_or_else(Timestamp::now),
        version: field("version")
            .and_then(|value| Version::parse(&value).ok())
            .unwrap_or_default(),
        x1_transaction_id: field("x1TransactionId")
            .and_then(|value| X1TransactionId::parse(&value).ok())
            .unwrap_or_else(X1TransactionId::generate),
    }
}

/// Decode the five envelope fields.
fn decode_envelope(document: &Document<'_>, node: NodeId) -> Result<Envelope, X1Error> {
    Ok(Envelope {
        admf_identifier: Token::parse(
            &require_text(document, node, "admfIdentifier")?,
            "admfIdentifier",
        )?,
        ne_identifier: Token::parse(
            &require_text(document, node, "neIdentifier")?,
            "neIdentifier",
        )?,
        message_timestamp: Timestamp::parse(&require_text(document, node, "messageTimestamp")?)?,
        version: Version::parse(&require_text(document, node, "version")?)?,
        x1_transaction_id: X1TransactionId::parse(&require_text(
            document,
            node,
            "x1TransactionId",
        )?)?,
    })
}

/// Decode the payload for a resolved message kind.
fn decode_request_body(
    document: &Document<'_>,
    node: NodeId,
    kind: MessageKind,
) -> Result<RequestBody, X1Error> {
    match kind {
        MessageKind::ActivateTask => Ok(RequestBody::ActivateTask(Box::new(decode_task_details(
            document,
            require_child(document, node, "taskDetails")?,
        )?))),
        MessageKind::ModifyTask => Ok(RequestBody::ModifyTask(Box::new(decode_task_details(
            document,
            require_child(document, node, "taskDetails")?,
        )?))),
        MessageKind::DeactivateTask => Ok(RequestBody::DeactivateTask(XId::parse(&require_text(
            document, node, "xId",
        )?)?)),
        MessageKind::DeactivateAllTasks => Ok(RequestBody::DeactivateAllTasks),
        MessageKind::GetTaskDetails => Ok(RequestBody::GetTaskDetails(XId::parse(&require_text(
            document, node, "xId",
        )?)?)),
        MessageKind::CreateDestination => Ok(RequestBody::CreateDestination(Box::new(
            decode_destination_details(document, require_child(document, node, "destinationDetails")?)?,
        ))),
        MessageKind::ModifyDestination => Ok(RequestBody::ModifyDestination(Box::new(
            decode_destination_details(document, require_child(document, node, "destinationDetails")?)?,
        ))),
        MessageKind::RemoveDestination => Ok(RequestBody::RemoveDestination(DId::parse(
            &require_text(document, node, "dId")?,
        )?)),
        MessageKind::RemoveAllDestinations => Ok(RequestBody::RemoveAllDestinations),
        MessageKind::GetDestinationDetails => Ok(RequestBody::GetDestinationDetails(DId::parse(
            &require_text(document, node, "dId")?,
        )?)),
        MessageKind::GetNEStatus => Ok(RequestBody::GetNEStatus),
        MessageKind::GetAllDetails => Ok(RequestBody::GetAllDetails),
        MessageKind::GetAllTaskDetails => Ok(RequestBody::GetAllTaskDetails),
        MessageKind::GetAllDestinationDetails => Ok(RequestBody::GetAllDestinationDetails),
        MessageKind::ListAllDetails => Ok(RequestBody::ListAllDetails),
        MessageKind::Ping => Ok(RequestBody::Ping),
        MessageKind::Keepalive => Ok(RequestBody::Keepalive),
        MessageKind::ReportTaskIssue => Ok(RequestBody::ReportTaskIssue {
            x_id: XId::parse(&require_text(document, node, "xId")?)?,
            report_type: TaskReportType::parse(&require_text(document, node, "taskReportType")?)?,
            error_code: optional_integer(document, node, "taskIssueErrorCode")?,
            details: child_text(document, node, "taskIssueDetails"),
        }),
        MessageKind::ReportDestinationIssue => Ok(RequestBody::ReportDestinationIssue {
            d_id: DId::parse(&require_text(document, node, "dId")?)?,
            report_type: TaskReportType::parse(&require_text(
                document,
                node,
                "destinationReportType",
            )?)?,
            error_code: optional_integer(document, node, "destinationIssueErrorCode")?,
            details: child_text(document, node, "destinationIssueDetails"),
        }),
        MessageKind::ReportNEIssue => Ok(RequestBody::ReportNEIssue {
            issue_type: TypeOfNeIssueMessage::parse(&require_text(
                document,
                node,
                "typeOfNeIssueMessage",
            )?)?,
            description: require_text(document, node, "description")?,
            issue_code: optional_integer(document, node, "issueCode")?,
        }),
    }
}

/// Decode a `TaskDetails`.
pub fn decode_task_details(
    document: &Document<'_>,
    node: NodeId,
) -> Result<TaskDetails, X1Error> {
    let identifiers_node = require_child(document, node, "targetIdentifiers")?;
    let mut target_identifiers = Vec::new();
    for (local, id) in child_elements(document, identifiers_node) {
        if local != "targetIdentifier" {
            continue;
        }
        // TargetIdentifier is an xs:choice, so exactly one child names the
        // identifier kind.
        let Some((choice_name, choice_id)) = child_elements(document, id).into_iter().next() else {
            return Err(X1Error::syntax(
                "<targetIdentifier> contains no identifier element",
            ));
        };
        let value = document.text_content_deep(choice_id).trim().to_string();
        target_identifiers.push(TargetIdentifier::from_element(&choice_name, &value)?);
    }
    if target_identifiers.is_empty() {
        return Err(X1Error::syntax(
            "<targetIdentifiers> must contain at least one <targetIdentifier>",
        ));
    }

    let dids_node = require_child(document, node, "listOfDIDs")?;
    let mut list_of_dids = Vec::new();
    let mut list_of_dsids = Vec::new();
    for (local, id) in child_elements(document, dids_node) {
        let text = document.text_content_deep(id).trim().to_string();
        match local.as_str() {
            "dId" => list_of_dids.push(DId::parse(&text)?),
            "dSId" => list_of_dsids.push(text),
            _ => {}
        }
    }

    let mut list_of_mediation_details = Vec::new();
    if let Some(mediation_node) = child(document, node, "listOfMediationDetails") {
        for (local, id) in child_elements(document, mediation_node) {
            if local == "mediationDetails" {
                list_of_mediation_details.push(decode_mediation_details(document, id)?);
            }
        }
    }

    let mut list_of_service_types = Vec::new();
    if let Some(types_node) = child(document, node, "listOfServiceTypes") {
        for (local, id) in child_elements(document, types_node) {
            if local == "serviceType" {
                let text = document.text_content_deep(id).trim().to_string();
                list_of_service_types.push(ServiceType::parse(&text)?);
            }
        }
    }

    let correlation_id = match child_text(document, node, "correlationID") {
        None => None,
        Some(text) => Some(text.parse::<u64>().map_err(|error| {
            X1Error::syntax(format!(
                "<correlationID> {text:?} is not a non-negative integer: {error}"
            ))
        })?),
    };

    Ok(TaskDetails {
        x_id: XId::parse(&require_text(document, node, "xId")?)?,
        target_identifiers,
        delivery_type: DeliveryType::parse(&require_text(document, node, "deliveryType")?)?,
        list_of_dids,
        list_of_dsids,
        list_of_mediation_details,
        correlation_id,
        implicit_deactivation_allowed: optional_boolean(
            document,
            node,
            "implicitDeactivationAllowed",
        )?,
        product_id: match child_text(document, node, "productID") {
            None => None,
            Some(text) => Some(XId::parse(&text)?),
        },
        list_of_service_types,
    })
}

/// Decode a `MediationDetails`.
fn decode_mediation_details(
    document: &Document<'_>,
    node: NodeId,
) -> Result<MediationDetails, X1Error> {
    let mut list_of_dids = Vec::new();
    if let Some(dids_node) = child(document, node, "listOfDIDs") {
        for (local, id) in child_elements(document, dids_node) {
            if local == "dId" {
                let text = document.text_content_deep(id).trim().to_string();
                list_of_dids.push(DId::parse(&text)?);
            }
        }
    }
    Ok(MediationDetails {
        liid: Liid::parse(&require_text(document, node, "LIID")?)?,
        delivery_type: MediationDeliveryType::parse(&require_text(
            document,
            node,
            "deliveryType",
        )?)?,
        start_time: match child_text(document, node, "StartTime") {
            None => None,
            Some(text) => Some(Timestamp::parse(&text)?),
        },
        end_time: match child_text(document, node, "EndTime") {
            None => None,
            Some(text) => Some(Timestamp::parse(&text)?),
        },
        list_of_dids,
    })
}

/// Decode a `DestinationDetails`.
pub fn decode_destination_details(
    document: &Document<'_>,
    node: NodeId,
) -> Result<DestinationDetails, X1Error> {
    let address_node = require_child(document, node, "deliveryAddress")?;
    let Some((choice_name, choice_id)) = child_elements(document, address_node).into_iter().next()
    else {
        return Err(X1Error::syntax(
            "<deliveryAddress> contains no address element",
        ));
    };

    let delivery_address = match choice_name.as_str() {
        "ipAddressAndPort" => {
            DeliveryAddress::IpAddressAndPort(decode_ip_address_port(document, choice_id)?)
        }
        "e164Number" => DeliveryAddress::E164Number(
            document.text_content_deep(choice_id).trim().to_string(),
        ),
        "uri" => DeliveryAddress::Uri(document.text_content_deep(choice_id).trim().to_string()),
        "emailAddress" => DeliveryAddress::EmailAddress(
            document.text_content_deep(choice_id).trim().to_string(),
        ),
        other => {
            return Err(X1Error::new(
                ErrorCode::UnsupportedDeliveryAddressType,
                format!("delivery address form {other:?} is not recognised"),
            ))
        }
    };

    Ok(DestinationDetails {
        d_id: DId::parse(&require_text(document, node, "dId")?)?,
        friendly_name: child_text(document, node, "friendlyName"),
        delivery_type: DeliveryType::parse(&require_text(document, node, "deliveryType")?)?,
        delivery_address,
    })
}

/// Decode a TS 103 280 `IPAddressPort`.
fn decode_ip_address_port(
    document: &Document<'_>,
    node: NodeId,
) -> Result<IpAddressPort, X1Error> {
    let address_node = require_child(document, node, "address")?;
    let Some((kind, value_id)) = child_elements(document, address_node).into_iter().next() else {
        return Err(X1Error::syntax("<address> contains no address element"));
    };
    let text = document.text_content_deep(value_id).trim().to_string();
    let address = match kind.as_str() {
        "IPv4Address" => std::net::IpAddr::V4(parse_ipv4(&text)?),
        // Enforced expanded — see `parse_expanded_ipv6`.
        "IPv6Address" => std::net::IpAddr::V6(parse_expanded_ipv6(&text)?),
        other => {
            return Err(X1Error::syntax(format!(
                "<address> child {other:?} is neither IPv4Address nor IPv6Address"
            )))
        }
    };

    let port_node = require_child(document, node, "port")?;
    let Some((port_kind, port_id)) = child_elements(document, port_node).into_iter().next() else {
        return Err(X1Error::syntax("<port> contains no port element"));
    };
    let port_text = document.text_content_deep(port_id).trim().to_string();
    let number: u16 = port_text
        .parse()
        .map_err(|error| X1Error::syntax(format!("port {port_text:?} is not valid: {error}")))?;
    let port = match port_kind.as_str() {
        "TCPPort" => Port::Tcp(number),
        "UDPPort" => Port::Udp(number),
        other => {
            return Err(X1Error::syntax(format!(
                "<port> child {other:?} is neither TCPPort nor UDPPort"
            )))
        }
    };

    Ok(IpAddressPort { address, port })
}

/// Decode an `X1Response` container — used by the NE-to-ADMF client direction
/// to read the ADMF's answers.
pub fn decode_response_container(
    document: &Document<'_>,
) -> Result<ResponseContainer, X1Error> {
    let root = document.root();
    let container = child_elements(document, root)
        .into_iter()
        .find(|(local, _)| local == "X1Response")
        .map(|(_, id)| id)
        .ok_or_else(|| X1Error::syntax("document root is not <X1Response>"))?;

    let mut messages = Vec::new();
    for (local, node) in child_elements(document, container) {
        if local != "x1ResponseMessage" {
            continue;
        }
        let envelope = decode_envelope(document, node)?;
        let type_name = document
            .element(node)
            .and_then(|element| element.get_attribute_ns(NS_XSI, "type"))
            .map(|value| value.rsplit(':').next().unwrap_or(value).to_string())
            .ok_or_else(|| {
                X1Error::syntax("<x1ResponseMessage> carries no xsi:type attribute")
            })?;

        if type_name == "ErrorResponse" {
            let error_node = require_child(document, node, "errorInformation")?;
            let code = require_text(document, error_node, "errorCode")?;
            let description = require_text(document, error_node, "errorDescription")?;
            let reported = require_text(document, node, "requestMessageType")?;
            let kind = MessageKind::from_request_type_name(&format!("{reported}Request"))
                .unwrap_or(MessageKind::GetNEStatus);
            messages.push(ResponseMessage {
                envelope,
                kind,
                body: ResponseBody::Error {
                    request_message_type: kind,
                    // The ADMF's code is echoed as text: it may legitimately
                    // use a code outside the subset this NE emits.
                    error: X1Error::new(
                        ErrorCode::Generic,
                        format!("ADMF reported error {code}: {description}"),
                    ),
                },
            });
            continue;
        }

        let base = type_name.strip_suffix("Response").unwrap_or(&type_name);
        let kind = MessageKind::from_request_type_name(&format!("{base}Request"))
            .ok_or_else(|| unsupported_message(&type_name))?;

        let body = match kind {
            // The reconciliation answer: what the ADMF believes is provisioned
            // on this network element.
            MessageKind::GetAllDetails => ResponseBody::AllDetails {
                ne_status: decode_ne_status(document, node)?,
                tasks: decode_task_response_list(document, node)?,
                destinations: decode_destination_response_list(document, node)?,
            },
            MessageKind::GetAllTaskDetails => {
                ResponseBody::AllTaskDetails(decode_task_response_list(document, node)?)
            }
            MessageKind::GetAllDestinationDetails => ResponseBody::AllDestinationDetails(
                decode_destination_response_list(document, node)?,
            ),
            // Every other message this element sends is answered with a bare
            // acknowledgement.
            _ => {
                let ok = child_text(document, node, "oK")
                    .ok_or_else(|| X1Error::syntax("response carries no <oK> element"))?;
                ResponseBody::Ok(super::types::OkValue::parse(&ok)?)
            }
        };
        messages.push(ResponseMessage {
            envelope,
            kind,
            body,
        });
    }

    Ok(ResponseContainer { messages })
}


/// Decode a `NeStatusDetails` from a response message.
fn decode_ne_status(document: &Document<'_>, node: NodeId) -> Result<NeStatusDetails, X1Error> {
    let status_node = require_child(document, node, "neStatusDetails")?;
    Ok(NeStatusDetails {
        ne_status: super::types::NeStatus::parse(&require_text(
            document,
            status_node,
            "neStatus",
        )?)?,
        list_of_faults: decode_faults(document, status_node),
    })
}

/// Decode a `listOfFaults`, which is mandatory but may be empty.
fn decode_faults(document: &Document<'_>, node: NodeId) -> Vec<X1Error> {
    let Some(faults_node) = child(document, node, "listOfFaults") else {
        return Vec::new();
    };
    child_elements(document, faults_node)
        .into_iter()
        .filter(|(local, _)| local == "unresolvedFault")
        .map(|(_, id)| {
            let code = child_text(document, id, "errorCode").unwrap_or_default();
            let description = child_text(document, id, "errorDescription").unwrap_or_default();
            // The peer's code is preserved as text: it may legitimately use a
            // code outside the subset this element emits.
            X1Error::new(ErrorCode::Generic, format!("{code}: {description}"))
        })
        .collect()
}

/// Decode a `listOfTaskResponseDetails`.
fn decode_task_response_list(
    document: &Document<'_>,
    node: NodeId,
) -> Result<Vec<TaskResponseDetails>, X1Error> {
    let Some(list_node) = child(document, node, "listOfTaskResponseDetails") else {
        return Ok(Vec::new());
    };
    let mut tasks = Vec::new();
    for (local, id) in child_elements(document, list_node) {
        if local != "taskResponseDetails" {
            continue;
        }
        let details_node = require_child(document, id, "taskDetails")?;
        let status_node = require_child(document, id, "taskStatus")?;
        tasks.push(TaskResponseDetails {
            task_details: decode_task_details(document, details_node)?,
            task_status: TaskStatus {
                provisioning_status: super::types::ProvisioningStatus::parse(&require_text(
                    document,
                    status_node,
                    "provisioningStatus",
                )?)?,
                list_of_faults: decode_faults(document, status_node),
                time_of_last_intercept: match child_text(
                    document,
                    status_node,
                    "timeOfLastIntercept",
                ) {
                    None => None,
                    Some(text) => Some(Timestamp::parse(&text)?),
                },
                time_of_last_modification: match child_text(
                    document,
                    status_node,
                    "timeOfLastModification",
                ) {
                    None => None,
                    Some(text) => Some(Timestamp::parse(&text)?),
                },
                number_of_modifications: optional_integer(
                    document,
                    status_node,
                    "numberOfModifications",
                )?,
            },
        });
    }
    Ok(tasks)
}

/// Decode a `listOfDestinationResponseDetails`.
fn decode_destination_response_list(
    document: &Document<'_>,
    node: NodeId,
) -> Result<Vec<DestinationResponseDetails>, X1Error> {
    let Some(list_node) = child(document, node, "listOfDestinationResponseDetails") else {
        return Ok(Vec::new());
    };
    let mut destinations = Vec::new();
    for (local, id) in child_elements(document, list_node) {
        if local != "destinationResponseDetails" {
            continue;
        }
        let details_node = require_child(document, id, "destinationDetails")?;
        let status_node = require_child(document, id, "destinationStatus")?;
        destinations.push(DestinationResponseDetails {
            destination_details: decode_destination_details(document, details_node)?,
            destination_status: DestinationStatus {
                destination_delivery_status: super::types::DestinationDeliveryStatus::parse(
                    &require_text(document, status_node, "destinationDeliveryStatus")?,
                )?,
                list_of_faults: decode_faults(document, status_node),
            },
        });
    }
    Ok(destinations)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// A thin wrapper over `quick_xml::Writer` for building X1 documents.
struct XmlBuilder {
    writer: Writer<Vec<u8>>,
}

impl XmlBuilder {
    fn new() -> Self {
        Self {
            writer: Writer::new(Vec::new()),
        }
    }

    fn declaration(&mut self) -> Result<(), X1Error> {
        self.writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .map_err(write_error)
    }

    /// Open an element with attributes.
    fn open_with(&mut self, name: &str, attributes: &[(&str, &str)]) -> Result<(), X1Error> {
        let mut start = BytesStart::new(name);
        for (key, value) in attributes {
            start.push_attribute((*key, *value));
        }
        self.writer
            .write_event(Event::Start(start))
            .map_err(write_error)
    }

    fn open(&mut self, name: &str) -> Result<(), X1Error> {
        self.open_with(name, &[])
    }

    fn close(&mut self, name: &str) -> Result<(), X1Error> {
        self.writer
            .write_event(Event::End(BytesEnd::new(name)))
            .map_err(write_error)
    }

    /// Write `<name>text</name>`, escaping the text.
    fn text_element(&mut self, name: &str, text: &str) -> Result<(), X1Error> {
        self.open(name)?;
        self.writer
            .write_event(Event::Text(BytesText::new(text)))
            .map_err(write_error)?;
        self.close(name)
    }

    fn finish(self) -> Result<String, X1Error> {
        String::from_utf8(self.writer.into_inner())
            .map_err(|error| X1Error::syntax(format!("X1 output is not valid UTF-8: {error}")))
    }
}

/// Writing into a `Vec<u8>` cannot fail in practice, but `write_event` is
/// generic over `io::Write` and so is fallible in the type system. Mapping it
/// keeps the encoder free of `unwrap`.
fn write_error(error: std::io::Error) -> X1Error {
    X1Error::syntax(format!("could not write X1 XML: {error}"))
}

/// Encode an `X1Response` container.
pub fn encode_response_container(container: &ResponseContainer) -> Result<String, X1Error> {
    let mut builder = XmlBuilder::new();
    builder.declaration()?;
    builder.open_with(
        "X1Response",
        &[
            ("xmlns", NS_X1),
            (&format!("xmlns:{COMMON_PREFIX}"), NS_COMMON),
            ("xmlns:xsi", NS_XSI),
        ],
    )?;
    for message in &container.messages {
        encode_response_message(&mut builder, message)?;
    }
    builder.close("X1Response")?;
    builder.finish()
}

/// Encode one `x1ResponseMessage`.
fn encode_response_message(
    builder: &mut XmlBuilder,
    message: &ResponseMessage,
) -> Result<(), X1Error> {
    builder.open_with(
        "x1ResponseMessage",
        &[("xsi:type", message.type_name().as_str())],
    )?;
    encode_envelope(builder, &message.envelope)?;

    match &message.body {
        ResponseBody::Ok(value) => builder.text_element("oK", value.as_str())?,
        ResponseBody::TaskDetails(details) => {
            builder.open("taskResponseDetails")?;
            encode_task_response_details(builder, details)?;
            builder.close("taskResponseDetails")?;
        }
        ResponseBody::DestinationDetails(details) => {
            builder.open("destinationResponseDetails")?;
            encode_destination_response_details(builder, details)?;
            builder.close("destinationResponseDetails")?;
        }
        ResponseBody::NeStatus(status) => {
            builder.open("neStatusDetails")?;
            encode_ne_status_details(builder, status)?;
            builder.close("neStatusDetails")?;
        }
        ResponseBody::AllDetails {
            ne_status,
            tasks,
            destinations,
        } => {
            builder.open("neStatusDetails")?;
            encode_ne_status_details(builder, ne_status)?;
            builder.close("neStatusDetails")?;
            builder.open("listOfTaskResponseDetails")?;
            for task in tasks {
                builder.open("taskResponseDetails")?;
                encode_task_response_details(builder, task)?;
                builder.close("taskResponseDetails")?;
            }
            builder.close("listOfTaskResponseDetails")?;
            builder.open("listOfDestinationResponseDetails")?;
            for destination in destinations {
                builder.open("destinationResponseDetails")?;
                encode_destination_response_details(builder, destination)?;
                builder.close("destinationResponseDetails")?;
            }
            builder.close("listOfDestinationResponseDetails")?;
        }
        ResponseBody::AllTaskDetails(tasks) => {
            builder.open("listOfTaskResponseDetails")?;
            for task in tasks {
                builder.open("taskResponseDetails")?;
                encode_task_response_details(builder, task)?;
                builder.close("taskResponseDetails")?;
            }
            builder.close("listOfTaskResponseDetails")?;
        }
        ResponseBody::AllDestinationDetails(destinations) => {
            builder.open("listOfDestinationResponseDetails")?;
            for destination in destinations {
                builder.open("destinationResponseDetails")?;
                encode_destination_response_details(builder, destination)?;
                builder.close("destinationResponseDetails")?;
            }
            builder.close("listOfDestinationResponseDetails")?;
        }
        ResponseBody::ListAllDetails { x_ids, d_ids } => {
            // Note the schema's capitalisation here differs from the request
            // side: ListAllDetailsResponse uses ListOfXIDs / ListOfDIDs.
            builder.open("ListOfXIDs")?;
            for x_id in x_ids {
                builder.text_element("xId", &x_id.to_string())?;
            }
            builder.close("ListOfXIDs")?;
            builder.open("ListOfDIDs")?;
            for d_id in d_ids {
                builder.text_element("dId", &d_id.to_string())?;
            }
            builder.close("ListOfDIDs")?;
        }
        ResponseBody::Error {
            request_message_type,
            error,
        } => {
            builder.text_element("requestMessageType", request_message_type.as_str())?;
            builder.open("errorInformation")?;
            builder.text_element("errorCode", &error.code.number().to_string())?;
            builder.text_element("errorDescription", &error.description)?;
            builder.close("errorInformation")?;
        }
    }

    builder.close("x1ResponseMessage")
}

/// Encode the five envelope fields, in schema order.
fn encode_envelope(builder: &mut XmlBuilder, envelope: &Envelope) -> Result<(), X1Error> {
    builder.text_element("admfIdentifier", envelope.admf_identifier.as_str())?;
    builder.text_element("neIdentifier", envelope.ne_identifier.as_str())?;
    builder.text_element("messageTimestamp", envelope.message_timestamp.as_str())?;
    builder.text_element("version", envelope.version.as_str())?;
    builder.text_element("x1TransactionId", &envelope.x1_transaction_id.to_string())
}

/// Encode a `TaskDetails` in schema element order.
fn encode_task_details(builder: &mut XmlBuilder, task: &TaskDetails) -> Result<(), X1Error> {
    builder.open("taskDetails")?;
    builder.text_element("xId", &task.x_id.to_string())?;

    builder.open("targetIdentifiers")?;
    for identifier in &task.target_identifiers {
        builder.open("targetIdentifier")?;
        builder.text_element(identifier.element_name(), &identifier.value_text())?;
        builder.close("targetIdentifier")?;
    }
    builder.close("targetIdentifiers")?;

    builder.text_element("deliveryType", task.delivery_type.as_str())?;

    builder.open("listOfDIDs")?;
    for d_id in &task.list_of_dids {
        builder.text_element("dId", &d_id.to_string())?;
    }
    for d_set_id in &task.list_of_dsids {
        builder.text_element("dSId", d_set_id)?;
    }
    builder.close("listOfDIDs")?;

    if !task.list_of_mediation_details.is_empty() {
        builder.open("listOfMediationDetails")?;
        for mediation in &task.list_of_mediation_details {
            builder.open("mediationDetails")?;
            builder.text_element("LIID", mediation.liid.as_str())?;
            builder.text_element("deliveryType", mediation.delivery_type.as_str())?;
            if let Some(start) = &mediation.start_time {
                builder.text_element("StartTime", start.as_str())?;
            }
            if let Some(end) = &mediation.end_time {
                builder.text_element("EndTime", end.as_str())?;
            }
            if !mediation.list_of_dids.is_empty() {
                builder.open("listOfDIDs")?;
                for d_id in &mediation.list_of_dids {
                    builder.text_element("dId", &d_id.to_string())?;
                }
                builder.close("listOfDIDs")?;
            }
            builder.close("mediationDetails")?;
        }
        builder.close("listOfMediationDetails")?;
    }

    if let Some(correlation) = task.correlation_id {
        builder.text_element("correlationID", &correlation.to_string())?;
    }
    if let Some(allowed) = task.implicit_deactivation_allowed {
        builder.text_element("implicitDeactivationAllowed", if allowed { "true" } else { "false" })?;
    }
    if let Some(product) = &task.product_id {
        builder.text_element("productID", &product.to_string())?;
    }
    if !task.list_of_service_types.is_empty() {
        builder.open("listOfServiceTypes")?;
        for service in &task.list_of_service_types {
            builder.text_element("serviceType", service.as_str())?;
        }
        builder.close("listOfServiceTypes")?;
    }

    builder.close("taskDetails")
}

/// Encode a `DestinationDetails` in schema element order.
fn encode_destination_details(
    builder: &mut XmlBuilder,
    destination: &DestinationDetails,
) -> Result<(), X1Error> {
    builder.open("destinationDetails")?;
    builder.text_element("dId", &destination.d_id.to_string())?;
    if let Some(name) = &destination.friendly_name {
        builder.text_element("friendlyName", name)?;
    }
    builder.text_element("deliveryType", destination.delivery_type.as_str())?;
    builder.open("deliveryAddress")?;
    match &destination.delivery_address {
        DeliveryAddress::IpAddressAndPort(endpoint) => {
            builder.open("ipAddressAndPort")?;
            // `address` and `port` are defined in the TS 103 280 schema, whose
            // elementFormDefault is qualified — so they carry the dictionary
            // namespace, not X1's.
            builder.open(&format!("{COMMON_PREFIX}:address"))?;
            builder.text_element(
                &format!("{COMMON_PREFIX}:{}", endpoint.address_element_name()),
                // Renders IPv6 fully expanded, per the dictionary's pattern.
                &endpoint.address_text(),
            )?;
            builder.close(&format!("{COMMON_PREFIX}:address"))?;
            builder.open(&format!("{COMMON_PREFIX}:port"))?;
            builder.text_element(
                &format!("{COMMON_PREFIX}:{}", endpoint.port.element_name()),
                &endpoint.port.number().to_string(),
            )?;
            builder.close(&format!("{COMMON_PREFIX}:port"))?;
            builder.close("ipAddressAndPort")?;
        }
        DeliveryAddress::E164Number(value) => builder.text_element("e164Number", value)?,
        DeliveryAddress::Uri(value) => builder.text_element("uri", value)?,
        DeliveryAddress::EmailAddress(value) => builder.text_element("emailAddress", value)?,
    }
    builder.close("deliveryAddress")?;
    builder.close("destinationDetails")
}

/// Encode `listOfFaults`, which is mandatory even when empty.
fn encode_faults(builder: &mut XmlBuilder, faults: &[X1Error]) -> Result<(), X1Error> {
    builder.open("listOfFaults")?;
    for fault in faults {
        builder.open("unresolvedFault")?;
        builder.text_element("errorCode", &fault.code.number().to_string())?;
        builder.text_element("errorDescription", &fault.description)?;
        builder.close("unresolvedFault")?;
    }
    builder.close("listOfFaults")
}

fn encode_task_response_details(
    builder: &mut XmlBuilder,
    details: &TaskResponseDetails,
) -> Result<(), X1Error> {
    encode_task_details(builder, &details.task_details)?;
    encode_task_status(builder, &details.task_status)
}

fn encode_task_status(builder: &mut XmlBuilder, status: &TaskStatus) -> Result<(), X1Error> {
    builder.open("taskStatus")?;
    builder.text_element("provisioningStatus", status.provisioning_status.as_str())?;
    encode_faults(builder, &status.list_of_faults)?;
    if let Some(stamp) = &status.time_of_last_intercept {
        builder.text_element("timeOfLastIntercept", stamp.as_str())?;
    }
    if let Some(stamp) = &status.time_of_last_modification {
        builder.text_element("timeOfLastModification", stamp.as_str())?;
    }
    if let Some(count) = status.number_of_modifications {
        builder.text_element("numberOfModifications", &count.to_string())?;
    }
    builder.close("taskStatus")
}

fn encode_destination_response_details(
    builder: &mut XmlBuilder,
    details: &DestinationResponseDetails,
) -> Result<(), X1Error> {
    encode_destination_details(builder, &details.destination_details)?;
    builder.open("destinationStatus")?;
    builder.text_element(
        "destinationDeliveryStatus",
        details.destination_status.destination_delivery_status.as_str(),
    )?;
    encode_faults(builder, &details.destination_status.list_of_faults)?;
    builder.close("destinationStatus")
}

fn encode_ne_status_details(
    builder: &mut XmlBuilder,
    status: &NeStatusDetails,
) -> Result<(), X1Error> {
    builder.text_element("neStatus", status.ne_status.as_str())?;
    encode_faults(builder, &status.list_of_faults)
}

/// Encode an `X1TopLevelErrorResponse`.
///
/// Used only when the container could not be parsed far enough to answer
/// per-message: it carries no `x1TransactionId`, because none was readable.
pub fn encode_top_level_error(response: &TopLevelErrorResponse) -> Result<String, X1Error> {
    let mut builder = XmlBuilder::new();
    builder.declaration()?;
    builder.open_with(
        "X1TopLevelErrorResponse",
        &[("xmlns", NS_X1), ("xmlns:xsi", NS_XSI)],
    )?;
    builder.text_element("admfIdentifier", response.admf_identifier.as_str())?;
    builder.text_element("neIdentifier", response.ne_identifier.as_str())?;
    builder.text_element("messageTimestamp", response.message_timestamp.as_str())?;
    builder.text_element("version", response.version.as_str())?;
    builder.close("X1TopLevelErrorResponse")?;
    builder.finish()
}

/// Encode an `X1Request` container — the NE-to-ADMF direction.
pub fn encode_request_container(container: &RequestContainer) -> Result<String, X1Error> {
    let mut builder = XmlBuilder::new();
    builder.declaration()?;
    builder.open_with(
        "X1Request",
        &[
            ("xmlns", NS_X1),
            (&format!("xmlns:{COMMON_PREFIX}"), NS_COMMON),
            ("xmlns:xsi", NS_XSI),
        ],
    )?;
    for message in &container.messages {
        encode_request_message(&mut builder, message)?;
    }
    builder.close("X1Request")?;
    builder.finish()
}

/// Encode one `x1RequestMessage`.
fn encode_request_message(
    builder: &mut XmlBuilder,
    message: &RequestMessage,
) -> Result<(), X1Error> {
    let type_name = message.body.kind().request_type_name();
    builder.open_with("x1RequestMessage", &[("xsi:type", type_name.as_str())])?;
    encode_envelope(builder, &message.envelope)?;

    match &message.body {
        RequestBody::ActivateTask(task) | RequestBody::ModifyTask(task) => {
            encode_task_details(builder, task)?;
        }
        RequestBody::DeactivateTask(x_id) | RequestBody::GetTaskDetails(x_id) => {
            builder.text_element("xId", &x_id.to_string())?;
        }
        RequestBody::CreateDestination(destination)
        | RequestBody::ModifyDestination(destination) => {
            encode_destination_details(builder, destination)?;
        }
        RequestBody::RemoveDestination(d_id) | RequestBody::GetDestinationDetails(d_id) => {
            builder.text_element("dId", &d_id.to_string())?;
        }
        RequestBody::DeactivateAllTasks
        | RequestBody::RemoveAllDestinations
        | RequestBody::GetNEStatus
        | RequestBody::GetAllDetails
        | RequestBody::GetAllTaskDetails
        | RequestBody::GetAllDestinationDetails
        | RequestBody::ListAllDetails
        | RequestBody::Ping
        | RequestBody::Keepalive => {}
        RequestBody::ReportTaskIssue {
            x_id,
            report_type,
            error_code,
            details,
        } => {
            builder.text_element("xId", &x_id.to_string())?;
            builder.text_element("taskReportType", report_type.as_str())?;
            if let Some(code) = error_code {
                builder.text_element("taskIssueErrorCode", &code.to_string())?;
            }
            if let Some(text) = details {
                builder.text_element("taskIssueDetails", text)?;
            }
        }
        RequestBody::ReportDestinationIssue {
            d_id,
            report_type,
            error_code,
            details,
        } => {
            builder.text_element("dId", &d_id.to_string())?;
            builder.text_element("destinationReportType", report_type.as_str())?;
            if let Some(code) = error_code {
                builder.text_element("destinationIssueErrorCode", &code.to_string())?;
            }
            if let Some(text) = details {
                builder.text_element("destinationIssueDetails", text)?;
            }
        }
        RequestBody::ReportNEIssue {
            issue_type,
            description,
            issue_code,
        } => {
            builder.text_element("typeOfNeIssueMessage", issue_type.as_str())?;
            builder.text_element("description", description)?;
            if let Some(code) = issue_code {
                builder.text_element("issueCode", &code.to_string())?;
            }
        }
    }

    builder.close("x1RequestMessage")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::x1::message::{
        DestinationStatus, RequestContainer, TaskStatus, TopLevelErrorResponse,
    };
    use crate::li::x1::schema::X1Schema;
    use crate::li::x1::types::{
        DestinationDeliveryStatus, NeStatus, OkValue, ProvisioningStatus, DEFAULT_VERSION,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::OnceLock;

    /// Shared compiled schema — every emitted document is checked against it.
    fn schema() -> &'static X1Schema {
        static SCHEMA: OnceLock<X1Schema> = OnceLock::new();
        SCHEMA.get_or_init(|| X1Schema::compile().expect("embedded X1 schemas must compile"))
    }

    /// Assert a document we produced is accepted by the published schema.
    ///
    /// This is the gate that matters: a response that fails here would fail at
    /// the ADMF instead, during an interop session rather than in CI.
    fn assert_schema_valid(xml: &str) {
        if let Err(error) = schema().validate(xml) {
            panic!("emitted document is not schema-valid: {error}\n---\n{xml}\n---");
        }
    }

    fn envelope() -> Envelope {
        Envelope {
            admf_identifier: Token::parse("admf-id", "admfIdentifier").unwrap(),
            ne_identifier: Token::parse("siphon-ne", "neIdentifier").unwrap(),
            message_timestamp: Timestamp::parse("2026-08-31T09:00:00.000000Z").unwrap(),
            version: Version::parse(DEFAULT_VERSION).unwrap(),
            x1_transaction_id: X1TransactionId::parse("0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f60")
                .unwrap(),
        }
    }

    fn ip_destination(address: IpAddr) -> DestinationDetails {
        DestinationDetails {
            d_id: DId::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            friendly_name: Some("primary mdf".to_string()),
            delivery_type: DeliveryType::X2AndX3,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address,
                port: Port::Tcp(42069),
            }),
        }
    }

    fn full_task() -> TaskDetails {
        TaskDetails {
            x_id: XId::parse("11111111-2222-3333-4444-555555555555").unwrap(),
            target_identifiers: vec![
                TargetIdentifier::SipUri("sip:alice@example.com".into()),
                TargetIdentifier::E164Number("15551234567".into()),
            ],
            delivery_type: DeliveryType::X2AndX3,
            list_of_dids: vec![DId::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap()],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: vec![MediationDetails {
                liid: Liid::parse("LI-2026-0001").unwrap(),
                delivery_type: MediationDeliveryType::Hi2AndHi3,
                start_time: Some(Timestamp::parse("2026-08-01T00:00:00.000000Z").unwrap()),
                end_time: Some(Timestamp::parse("2026-09-01T00:00:00.000000Z").unwrap()),
                list_of_dids: Vec::new(),
            }],
            correlation_id: Some(4242),
            implicit_deactivation_allowed: Some(true),
            product_id: None,
            list_of_service_types: vec![ServiceType::Voice],
        }
    }

    fn decode_one(xml: &str) -> DecodedMessage {
        let document = uppsala::parse(xml).expect("test fixture must parse");
        let mut messages =
            decode_request_container(&document).expect("test fixture must decode as a container");
        assert_eq!(messages.len(), 1, "fixture should hold exactly one message");
        messages.remove(0)
    }

    fn request_xml(body: RequestBody) -> String {
        let container = RequestContainer {
            messages: vec![RequestMessage {
                envelope: envelope(),
                body,
            }],
        };
        encode_request_container(&container).expect("encoding must succeed")
    }

    #[test]
    fn every_request_we_emit_is_schema_valid() {
        let bodies = vec![
            RequestBody::ActivateTask(Box::new(full_task())),
            RequestBody::ModifyTask(Box::new(full_task())),
            RequestBody::DeactivateTask(XId::generate()),
            RequestBody::DeactivateAllTasks,
            RequestBody::GetTaskDetails(XId::generate()),
            RequestBody::CreateDestination(Box::new(ip_destination(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 50,
            ))))),
            RequestBody::ModifyDestination(Box::new(ip_destination(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 50,
            ))))),
            RequestBody::RemoveDestination(DId::generate()),
            RequestBody::RemoveAllDestinations,
            RequestBody::GetDestinationDetails(DId::generate()),
            RequestBody::GetNEStatus,
            RequestBody::GetAllDetails,
            RequestBody::GetAllTaskDetails,
            RequestBody::GetAllDestinationDetails,
            RequestBody::ListAllDetails,
            RequestBody::Ping,
            RequestBody::Keepalive,
            RequestBody::ReportTaskIssue {
                x_id: XId::generate(),
                report_type: TaskReportType::FullyActionedAndSuccessful,
                error_code: Some(9040),
                details: Some("activated".into()),
            },
            RequestBody::ReportDestinationIssue {
                d_id: DId::generate(),
                report_type: TaskReportType::TerminatingFault,
                error_code: Some(9030),
                details: Some("delivery connection lost".into()),
            },
            RequestBody::ReportNEIssue {
                issue_type: TypeOfNeIssueMessage::FaultReport,
                description: "media backend unavailable".into(),
                issue_code: Some(9020),
            },
        ];
        for body in bodies {
            let kind = body.kind();
            let xml = request_xml(body);
            if let Err(error) = schema().validate(&xml) {
                panic!(
                    "{} is not schema-valid: {error}\n---\n{xml}\n---",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn every_response_we_emit_is_schema_valid() {
        let task_details = TaskResponseDetails {
            task_details: full_task(),
            task_status: TaskStatus {
                provisioning_status: ProvisioningStatus::Complete,
                list_of_faults: Vec::new(),
                time_of_last_intercept: Some(
                    Timestamp::parse("2026-08-31T09:00:00.000000Z").unwrap(),
                ),
                time_of_last_modification: None,
                number_of_modifications: Some(0),
            },
        };
        let destination_details = DestinationResponseDetails {
            destination_details: ip_destination(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))),
            destination_status: DestinationStatus {
                destination_delivery_status: DestinationDeliveryStatus::ActiveAndWorking,
                list_of_faults: Vec::new(),
            },
        };
        let ne_status = NeStatusDetails {
            ne_status: NeStatus::Ok,
            list_of_faults: Vec::new(),
        };

        let cases: Vec<(MessageKind, ResponseBody)> = vec![
            (
                MessageKind::ActivateTask,
                ResponseBody::Ok(OkValue::AcknowledgedAndCompleted),
            ),
            (MessageKind::Ping, ResponseBody::Ok(OkValue::Acknowledged)),
            (
                MessageKind::GetTaskDetails,
                ResponseBody::TaskDetails(Box::new(task_details.clone())),
            ),
            (
                MessageKind::GetDestinationDetails,
                ResponseBody::DestinationDetails(Box::new(destination_details.clone())),
            ),
            (
                MessageKind::GetNEStatus,
                ResponseBody::NeStatus(ne_status.clone()),
            ),
            (
                MessageKind::GetAllDetails,
                ResponseBody::AllDetails {
                    ne_status: ne_status.clone(),
                    tasks: vec![task_details.clone()],
                    destinations: vec![destination_details.clone()],
                },
            ),
            (
                MessageKind::GetAllTaskDetails,
                ResponseBody::AllTaskDetails(vec![task_details]),
            ),
            (
                MessageKind::GetAllDestinationDetails,
                ResponseBody::AllDestinationDetails(vec![destination_details]),
            ),
            (
                MessageKind::ListAllDetails,
                ResponseBody::ListAllDetails {
                    x_ids: vec![XId::generate()],
                    d_ids: vec![DId::generate()],
                },
            ),
            (
                MessageKind::ActivateTask,
                ResponseBody::Error {
                    request_message_type: MessageKind::ActivateTask,
                    error: X1Error::new(ErrorCode::XidAlreadyExists, "already provisioned"),
                },
            ),
        ];

        for (kind, body) in cases {
            let container = ResponseContainer {
                messages: vec![ResponseMessage {
                    envelope: envelope(),
                    kind,
                    body,
                }],
            };
            let xml = encode_response_container(&container).expect("encoding must succeed");
            if let Err(error) = schema().validate(&xml) {
                panic!(
                    "{} response is not schema-valid: {error}\n---\n{xml}\n---",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn an_empty_details_response_is_still_schema_valid() {
        let container = ResponseContainer {
            messages: vec![ResponseMessage {
                envelope: envelope(),
                kind: MessageKind::GetAllDetails,
                body: ResponseBody::AllDetails {
                    ne_status: NeStatusDetails {
                        ne_status: NeStatus::Ok,
                        list_of_faults: Vec::new(),
                    },
                    tasks: Vec::new(),
                    destinations: Vec::new(),
                },
            }],
        };
        let xml = encode_response_container(&container).unwrap();
        assert_schema_valid(&xml);
    }

    #[test]
    fn a_top_level_error_response_is_schema_valid() {
        let xml = encode_top_level_error(&TopLevelErrorResponse {
            admf_identifier: Token::parse("admf-id", "admfIdentifier").unwrap(),
            ne_identifier: Token::parse("siphon-ne", "neIdentifier").unwrap(),
            message_timestamp: Timestamp::parse("2026-08-31T09:00:00.000000Z").unwrap(),
            version: Version::parse(DEFAULT_VERSION).unwrap(),
        })
        .unwrap();
        assert_schema_valid(&xml);
        assert!(xml.contains("X1TopLevelErrorResponse"));
    }

    #[test]
    fn an_emitted_ipv6_destination_is_expanded_and_schema_valid() {
        let compressed: IpAddr = "2001:db8:1c18:6b8c::1".parse().unwrap();
        let xml = request_xml(RequestBody::CreateDestination(Box::new(ip_destination(
            compressed,
        ))));
        assert!(
            xml.contains("2001:0db8:1c18:6b8c:0000:0000:0000:0001"),
            "the emitted address must be fully expanded, got:\n{xml}"
        );
        assert!(
            !xml.contains("2001:db8:1c18:6b8c::1"),
            "the compressed form must not appear on the wire"
        );
        assert_schema_valid(&xml);
    }

    #[test]
    fn a_compressed_ipv6_never_survives_a_round_trip() {
        let compressed: IpAddr = "2001:db8::1".parse().unwrap();
        let xml = request_xml(RequestBody::CreateDestination(Box::new(ip_destination(
            compressed,
        ))));
        match decode_one(&xml) {
            DecodedMessage::Message(message) => match message.body {
                RequestBody::CreateDestination(destination) => {
                    match destination.delivery_address {
                        DeliveryAddress::IpAddressAndPort(endpoint) => {
                            assert_eq!(endpoint.address, compressed);
                            assert_eq!(
                                endpoint.address_text(),
                                "2001:0db8:0000:0000:0000:0000:0000:0001"
                            );
                        }
                        other => panic!("expected ipAddressAndPort, got {other:?}"),
                    }
                }
                other => panic!("expected CreateDestination, got {other:?}"),
            },
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn a_full_task_round_trips_unchanged() {
        let original = full_task();
        let xml = request_xml(RequestBody::ActivateTask(Box::new(original.clone())));
        assert_schema_valid(&xml);
        match decode_one(&xml) {
            DecodedMessage::Message(message) => match message.body {
                RequestBody::ActivateTask(decoded) => assert_eq!(*decoded, original),
                other => panic!("expected ActivateTask, got {other:?}"),
            },
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn a_destination_round_trips_unchanged() {
        let original = ip_destination(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        let xml = request_xml(RequestBody::CreateDestination(Box::new(original.clone())));
        assert_schema_valid(&xml);
        match decode_one(&xml) {
            DecodedMessage::Message(message) => match message.body {
                RequestBody::CreateDestination(decoded) => assert_eq!(*decoded, original),
                other => panic!("expected CreateDestination, got {other:?}"),
            },
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn the_envelope_round_trips_unchanged() {
        let xml = request_xml(RequestBody::Ping);
        match decode_one(&xml) {
            DecodedMessage::Message(message) => assert_eq!(message.envelope, envelope()),
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn dispatch_is_by_xsi_type() {
        for body in [
            RequestBody::Ping,
            RequestBody::Keepalive,
            RequestBody::GetNEStatus,
            RequestBody::DeactivateAllTasks,
            RequestBody::RemoveAllDestinations,
            RequestBody::ListAllDetails,
        ] {
            let expected = body.kind();
            let xml = request_xml(body);
            match decode_one(&xml) {
                DecodedMessage::Message(message) => assert_eq!(message.body.kind(), expected),
                DecodedMessage::Failed { error, .. } => {
                    panic!("{} did not dispatch: {error}", expected.as_str())
                }
            }
        }
    }

    #[test]
    fn an_out_of_profile_message_type_fails_that_message_only() {
        let xml = request_xml(RequestBody::Ping).replace("PingRequest", "DeleteAllObjectsRequest");
        match decode_one(&xml) {
            DecodedMessage::Failed {
                envelope: decoded,
                kind,
                error,
            } => {
                assert_eq!(error.code, ErrorCode::UnsupportedRequest);
                assert!(kind.is_none());
                assert_eq!(decoded.x1_transaction_id, envelope().x1_transaction_id);
            }
            DecodedMessage::Message(message) => panic!(
                "an out-of-profile type must not decode, got {:?}",
                message.body
            ),
        }
    }

    #[test]
    fn a_missing_xsi_type_is_a_per_message_failure() {
        let xml = request_xml(RequestBody::Ping).replace(" xsi:type=\"PingRequest\"", "");
        match decode_one(&xml) {
            DecodedMessage::Failed { error, .. } => {
                assert_eq!(error.code, ErrorCode::SyntaxSchemaError)
            }
            DecodedMessage::Message(_) => panic!("a message without xsi:type must not decode"),
        }
    }

    #[test]
    fn a_prefixed_xsi_type_value_resolves() {
        let xml = request_xml(RequestBody::Ping).replace(
            "xsi:type=\"PingRequest\"",
            "xmlns:x1=\"http://uri.etsi.org/03221/X1/2017/10\" xsi:type=\"x1:PingRequest\"",
        );
        match decode_one(&xml) {
            DecodedMessage::Message(message) => assert_eq!(message.body.kind(), MessageKind::Ping),
            DecodedMessage::Failed { error, .. } => {
                panic!("prefixed xsi:type must resolve: {error}")
            }
        }
    }

    /// A peer's own namespace prefixes must survive per-message isolation.
    ///
    /// The regression this pins: `single_message_document` used to wrap the
    /// extracted message in a container carrying a *fixed* prefix list, while
    /// `node_to_xml` serialises prefixed names without re-emitting the
    /// declarations that bound them. Against a peer using the same prefixes as
    /// siphon that is invisible; against JAXB, which generates `ns2` for the
    /// TS 103 280 dictionary, every message carrying a delivery address failed
    /// to parse — so no destination could ever be created.
    #[test]
    fn a_peer_chosen_namespace_prefix_survives_isolation() {
        let source = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<X1Request xmlns=\"http://uri.etsi.org/03221/X1/2017/10\" ",
            "xmlns:ns2=\"http://uri.etsi.org/03280/common/2017/07\" ",
            "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">",
            "<x1RequestMessage xsi:type=\"CreateDestinationRequest\">",
            "<admfIdentifier>simulator</admfIdentifier>",
            "<neIdentifier>network-element</neIdentifier>",
            "<messageTimestamp>2026-08-31T17:16:08.832000Z</messageTimestamp>",
            "<version>v1.6.1</version>",
            "<x1TransactionId>a8d730e4-e71a-4ce8-978d-124c0ab6ed1b</x1TransactionId>",
            "<destinationDetails>",
            "<dId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</dId>",
            "<deliveryType>X2Only</deliveryType>",
            "<deliveryAddress><ipAddressAndPort>",
            "<ns2:address><ns2:IPv4Address>192.0.2.62</ns2:IPv4Address></ns2:address>",
            "<ns2:port><ns2:TCPPort>42069</ns2:TCPPort></ns2:port>",
            "</ipAddressAndPort></deliveryAddress>",
            "</destinationDetails>",
            "</x1RequestMessage></X1Request>",
        );

        let document = uppsala::parse(source).expect("the peer's document must parse");
        let nodes = request_message_nodes(&document).expect("one message");
        assert_eq!(nodes.len(), 1);

        // The isolated document must parse *and* validate — the prefix has to
        // resolve, or the message is refused before anything reads it.
        let isolated = single_message_document(&document, nodes[0]);
        assert!(
            isolated.contains("ns2"),
            "the peer's prefix should be carried into the wrapper:\n{isolated}"
        );
        uppsala::parse(&isolated)
            .unwrap_or_else(|error| panic!("isolated document does not parse: {error:?}\n{isolated}"));
        assert_schema_valid(&isolated);

        // And it decodes to the destination the peer described.
        match decode_request_message(&document, nodes[0]) {
            DecodedMessage::Message(message) => match message.body {
                RequestBody::CreateDestination(destination) => {
                    match destination.delivery_address {
                        DeliveryAddress::IpAddressAndPort(endpoint) => {
                            assert_eq!(endpoint.address_text(), "192.0.2.62");
                            assert_eq!(endpoint.port.number(), 42069);
                        }
                        other => panic!("expected ipAddressAndPort, got {other:?}"),
                    }
                }
                other => panic!("expected CreateDestination, got {other:?}"),
            },
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn a_multi_message_container_decodes_in_order() {
        let container = RequestContainer {
            messages: vec![
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::Ping,
                },
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::Keepalive,
                },
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::GetNEStatus,
                },
            ],
        };
        let xml = encode_request_container(&container).unwrap();
        assert_schema_valid(&xml);

        let document = uppsala::parse(&xml).unwrap();
        let decoded = decode_request_container(&document).unwrap();
        assert_eq!(decoded.len(), 3);
        let kinds: Vec<MessageKind> = decoded
            .iter()
            .map(|message| match message {
                DecodedMessage::Message(message) => message.body.kind(),
                DecodedMessage::Failed { .. } => panic!("all three must decode"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                MessageKind::Ping,
                MessageKind::Keepalive,
                MessageKind::GetNEStatus
            ]
        );
    }

    #[test]
    fn a_bad_message_does_not_fail_its_siblings() {
        let container = RequestContainer {
            messages: vec![
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::Ping,
                },
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::DeactivateTask(XId::generate()),
                },
                RequestMessage {
                    envelope: envelope(),
                    body: RequestBody::Keepalive,
                },
            ],
        };
        let xml = encode_request_container(&container)
            .unwrap()
            .replace("<xId>", "<xId>zzz");

        let document = uppsala::parse(&xml).unwrap();
        let decoded = decode_request_container(&document).unwrap();
        assert_eq!(decoded.len(), 3, "every message keeps its slot");
        assert!(matches!(decoded[0], DecodedMessage::Message(_)));
        assert!(matches!(decoded[1], DecodedMessage::Failed { .. }));
        assert!(matches!(decoded[2], DecodedMessage::Message(_)));
    }

    #[test]
    fn a_container_with_no_messages_is_a_container_level_failure() {
        let xml = "<?xml version=\"1.0\"?>\n<X1Request xmlns=\"http://uri.etsi.org/03221/X1/2017/10\"/>";
        let document = uppsala::parse(xml).unwrap();
        assert!(decode_request_container(&document).is_err());
    }

    #[test]
    fn a_wrong_root_element_is_a_container_level_failure() {
        let xml =
            "<?xml version=\"1.0\"?>\n<NotAnX1Request xmlns=\"http://uri.etsi.org/03221/X1/2017/10\"/>";
        let document = uppsala::parse(xml).unwrap();
        assert!(decode_request_container(&document).is_err());
    }

    #[test]
    fn a_bad_transaction_id_is_a_per_message_failure() {
        let xml = request_xml(RequestBody::Ping)
            .replace("0f3b7a1c-2d4e-4f60-8a91-1b2c3d4e5f60", "not-a-uuid");
        match decode_one(&xml) {
            DecodedMessage::Failed { error, .. } => {
                assert_eq!(error.code, ErrorCode::SyntaxSchemaError);
                assert!(error.description.contains("x1TransactionId"));
            }
            DecodedMessage::Message(_) => {
                panic!("a malformed x1TransactionId must not be accepted")
            }
        }
    }

    #[test]
    fn a_missing_envelope_field_is_a_per_message_failure() {
        let xml =
            request_xml(RequestBody::Ping).replace("<neIdentifier>siphon-ne</neIdentifier>", "");
        match decode_one(&xml) {
            DecodedMessage::Failed { error, .. } => {
                assert!(error.description.contains("neIdentifier"))
            }
            DecodedMessage::Message(_) => panic!("a missing envelope field must not be accepted"),
        }
    }

    #[test]
    fn text_is_escaped_on_the_way_out() {
        let mut destination = ip_destination(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)));
        destination.friendly_name = Some("mdf <one> & \"two\"".to_string());
        let xml = request_xml(RequestBody::CreateDestination(Box::new(destination.clone())));
        assert_schema_valid(&xml);
        assert!(!xml.contains("<one>"), "raw markup leaked into the document");
        match decode_one(&xml) {
            DecodedMessage::Message(message) => match message.body {
                RequestBody::CreateDestination(decoded) => {
                    assert_eq!(decoded.friendly_name, destination.friendly_name)
                }
                other => panic!("expected CreateDestination, got {other:?}"),
            },
            DecodedMessage::Failed { error, .. } => panic!("decode failed: {error}"),
        }
    }

    #[test]
    fn an_error_description_is_escaped() {
        let container = ResponseContainer {
            messages: vec![ResponseMessage {
                envelope: envelope(),
                kind: MessageKind::ActivateTask,
                body: ResponseBody::Error {
                    request_message_type: MessageKind::ActivateTask,
                    error: X1Error::syntax("bad value <script>&"),
                },
            }],
        };
        let xml = encode_response_container(&container).unwrap();
        assert_schema_valid(&xml);
        assert!(!xml.contains("<script>"));
    }

    #[test]
    fn an_admf_acknowledgement_decodes() {
        let container = ResponseContainer {
            messages: vec![ResponseMessage {
                envelope: envelope(),
                kind: MessageKind::ReportNEIssue,
                body: ResponseBody::Ok(OkValue::AcknowledgedAndCompleted),
            }],
        };
        let xml = encode_response_container(&container).unwrap();
        assert_schema_valid(&xml);

        let document = uppsala::parse(&xml).unwrap();
        let decoded = decode_response_container(&document).unwrap();
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].kind, MessageKind::ReportNEIssue);
        assert!(matches!(decoded.messages[0].body, ResponseBody::Ok(_)));
    }

    #[test]
    fn an_admf_error_response_decodes_with_its_code() {
        let container = ResponseContainer {
            messages: vec![ResponseMessage {
                envelope: envelope(),
                kind: MessageKind::ReportTaskIssue,
                body: ResponseBody::Error {
                    request_message_type: MessageKind::ReportTaskIssue,
                    error: X1Error::new(ErrorCode::XidDoesNotExist, "unknown task"),
                },
            }],
        };
        let xml = encode_response_container(&container).unwrap();
        let document = uppsala::parse(&xml).unwrap();
        let decoded = decode_response_container(&document).unwrap();
        match &decoded.messages[0].body {
            ResponseBody::Error { error, .. } => {
                assert!(
                    error.description.contains("2020"),
                    "got {}",
                    error.description
                );
                assert!(error.description.contains("unknown task"));
            }
            other => panic!("expected an error body, got {other:?}"),
        }
    }
}
