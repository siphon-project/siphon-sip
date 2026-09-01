//! X1 error codes and the error type carried in an `ErrorResponse`.
//!
//! Every failure on the X1 interface is answered with a well-formed
//! `ErrorResponse` message carrying one of the codes below — never with a bare
//! HTTP status and an ad-hoc body. `ErrorResponse` extends `X1ResponseMessage`,
//! so it echoes the envelope (including `x1TransactionId`) exactly like a
//! success response does; the ADMF correlates it the same way.
//!
//! The codes are ETSI TS 103 221-1 clause 6.7. They are cross-checked against
//! an independent MIT-licensed implementation of the same specification
//! (`sipgate/li-lib-x1x2x3`), because transcribing a numeric table from prose
//! is exactly the kind of thing that is wrong in a way no round-trip test can
//! see.

use std::fmt;

/// An ETSI TS 103 221-1 clause 6.7 error code.
///
/// Kept as a named enum rather than bare integers so a handler cannot invent a
/// code that is not in the table, and so the mapping to a description lives in
/// one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // -- 1000 series: generic / protocol ---------------------------------
    /// Something went wrong that no more specific code describes.
    Generic,
    /// The request did not parse, or failed schema validation.
    SyntaxSchemaError,
    /// The `version` element names a version this NE does not support.
    UnsupportedVersion,
    /// The `admfIdentifier` does not match the client certificate presented.
    AdmfIdentifierDoesNotMatchCertificate,
    /// The `admfIdentifier` is well-formed but is not the ADMF we expect.
    UnexpectedAdmfIdentifier,
    /// The `neIdentifier` does not match this NE's certificate.
    NeIdentifierDoesNotMatchCertificate,
    /// The `neIdentifier` names some other network element.
    UnexpectedNeIdentifier,
    /// Keepalive is not supported by this NE.
    KeepaliveNotSupported,
    /// The message type is not supported by this NE.
    UnsupportedRequest,

    // -- 2000 series: identifier lifecycle -------------------------------
    /// A task with this XID is already provisioned.
    XidAlreadyExists,
    /// No task with this XID is provisioned.
    XidDoesNotExist,
    /// A destination with this DID is already provisioned.
    DidAlreadyExists,
    /// No destination with this DID is provisioned.
    DidDoesNotExist,

    // -- 3000 series: ActivateTask / ModifyTask --------------------------
    /// `ActivateTask` failed for a reason with no more specific code.
    GenericActivateTaskFailure,
    /// `ModifyTask` failed for a reason with no more specific code.
    GenericModifyTaskFailure,
    /// The task names a target identifier type this NE cannot intercept.
    UnsupportedTargetIdentifierType,
    /// The combination of target identifiers is not supported.
    UnsupportedCombinationOfTargetIdentifiers,
    /// The task names more destinations than this NE supports.
    MultipleDestinationsNotSupported,
    /// The `deliveryType` and the named destinations cannot be combined.
    ///
    /// This is the code for a task asking for content delivery that this node
    /// cannot perform — see [`crate::li::x1::store::TaskStore`].
    InvalidCombinationOfDeliveryTypeAndDestinations,
    /// The task names a service type this NE does not serve.
    UnsupportedServiceType,

    // -- 4000/5000 series: deactivation ----------------------------------
    /// `DeactivateTask` failed for a reason with no more specific code.
    GenericDeactivateTaskFailure,
    /// `DeactivateAllTasks` failed for a reason with no more specific code.
    GenericDeactivateAllTasksFailure,
    /// `DeactivateAllTasks` is not enabled on this NE.
    DeactivateAllTasksNotEnabled,

    // -- 6000/7000/8000 series: destinations -----------------------------
    /// `CreateDestination` failed for a reason with no more specific code.
    GenericCreateDestinationFailure,
    /// `ModifyDestination` failed for a reason with no more specific code.
    GenericModifyDestinationFailure,
    /// The delivery address is of a kind this NE cannot deliver to.
    UnsupportedDeliveryAddressType,
    /// `RemoveDestination` failed for a reason with no more specific code.
    GenericRemoveDestinationFailure,
    /// The destination is still referenced by at least one task.
    DestinationInUse,
    /// `RemoveAllDestinations` failed for a reason with no more specific code.
    GenericRemoveAllDestinationsFailure,
    /// One or more destinations are still referenced by tasks.
    DestinationsInUse,
    /// `RemoveAllDestinations` is not enabled on this NE.
    RemoveAllDestinationsNotEnabled,

    // -- 9000 series: NE-to-ADMF report reasons --------------------------
    /// A previously reported fault has cleared.
    ErrorCleared,
    /// A non-fatal condition the ADMF should know about.
    GenericWarning,
    /// A fault that does not stop the task delivering.
    GenericNonTerminatingFault,
    /// A fault that has stopped the task delivering.
    TerminatingFault,
    /// The request was actioned successfully.
    RequestActioned,
    /// Keepalives were expected from the ADMF and did not arrive.
    KeepalivesNotReceived,
    /// The NE's provisioning database was cleared.
    DatabaseCleared,
}

impl ErrorCode {
    /// The numeric code that goes on the wire in `errorInformation/errorCode`.
    pub fn number(self) -> i64 {
        match self {
            Self::Generic => 1000,
            Self::SyntaxSchemaError => 1010,
            Self::UnsupportedVersion => 1020,
            Self::AdmfIdentifierDoesNotMatchCertificate => 1030,
            Self::UnexpectedAdmfIdentifier => 1040,
            Self::NeIdentifierDoesNotMatchCertificate => 1050,
            Self::UnexpectedNeIdentifier => 1060,
            Self::KeepaliveNotSupported => 1070,
            Self::UnsupportedRequest => 1080,
            Self::XidAlreadyExists => 2010,
            Self::XidDoesNotExist => 2020,
            Self::DidAlreadyExists => 2030,
            Self::DidDoesNotExist => 2040,
            Self::GenericActivateTaskFailure => 3000,
            Self::GenericModifyTaskFailure => 3001,
            Self::UnsupportedTargetIdentifierType => 3010,
            Self::UnsupportedCombinationOfTargetIdentifiers => 3020,
            Self::MultipleDestinationsNotSupported => 3030,
            Self::InvalidCombinationOfDeliveryTypeAndDestinations => 3040,
            Self::UnsupportedServiceType => 3050,
            Self::GenericDeactivateTaskFailure => 4000,
            Self::GenericDeactivateAllTasksFailure => 5000,
            Self::DeactivateAllTasksNotEnabled => 5010,
            Self::GenericCreateDestinationFailure => 6000,
            Self::GenericModifyDestinationFailure => 6001,
            Self::UnsupportedDeliveryAddressType => 6020,
            Self::GenericRemoveDestinationFailure => 7000,
            Self::DestinationInUse => 7010,
            Self::GenericRemoveAllDestinationsFailure => 8000,
            Self::DestinationsInUse => 8010,
            Self::RemoveAllDestinationsNotEnabled => 8020,
            Self::ErrorCleared => 9000,
            Self::GenericWarning => 9010,
            Self::GenericNonTerminatingFault => 9020,
            Self::TerminatingFault => 9030,
            Self::RequestActioned => 9040,
            Self::KeepalivesNotReceived => 9050,
            Self::DatabaseCleared => 10000,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.number())
    }
}

/// A failure to be rendered as an X1 `ErrorResponse`.
///
/// `description` is operator-facing text placed in `errorDescription`. It must
/// not carry anything confidential: it crosses the X1 interface to the ADMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X1Error {
    /// The clause 6.7 code.
    pub code: ErrorCode,
    /// Human-readable detail for `errorInformation/errorDescription`.
    pub description: String,
}

impl X1Error {
    /// Build an error with the given code and description.
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    /// A request that did not parse or failed schema validation.
    pub fn syntax(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::SyntaxSchemaError, description)
    }

    /// A message type this profile does not implement.
    ///
    /// Used for the generic-object messages (`CreateObject`, `ModifyObject`,
    /// `DeleteObject`, `ListObjectsOfType`, `GetAllGenericObjectDetails`,
    /// `DeleteAllObjects`), which are in the schema but out of this profile.
    /// They get a clean per-message `ErrorResponse` rather than failing the
    /// whole container, so their siblings are still answered.
    pub fn unsupported_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedRequest, description)
    }
}

impl fmt::Display for X1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "X1 error {}: {}", self.code, self.description)
    }
}

impl std::error::Error for X1Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_published_table() {
        // Spot-check the codes this implementation actually depends on
        // behaving correctly, against TS 103 221-1 clause 6.7.
        assert_eq!(ErrorCode::Generic.number(), 1000);
        assert_eq!(ErrorCode::SyntaxSchemaError.number(), 1010);
        assert_eq!(ErrorCode::UnsupportedVersion.number(), 1020);
        assert_eq!(
            ErrorCode::AdmfIdentifierDoesNotMatchCertificate.number(),
            1030
        );
        assert_eq!(ErrorCode::UnsupportedRequest.number(), 1080);
        assert_eq!(ErrorCode::XidAlreadyExists.number(), 2010);
        assert_eq!(ErrorCode::XidDoesNotExist.number(), 2020);
        assert_eq!(ErrorCode::DidAlreadyExists.number(), 2030);
        assert_eq!(ErrorCode::DidDoesNotExist.number(), 2040);
        assert_eq!(
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations.number(),
            3040
        );
        assert_eq!(ErrorCode::DestinationInUse.number(), 7010);
        assert_eq!(ErrorCode::DatabaseCleared.number(), 10000);
    }

    #[test]
    fn every_code_is_distinct() {
        // A duplicated number would silently make two distinct failures
        // indistinguishable to the ADMF.
        let all = [
            ErrorCode::Generic,
            ErrorCode::SyntaxSchemaError,
            ErrorCode::UnsupportedVersion,
            ErrorCode::AdmfIdentifierDoesNotMatchCertificate,
            ErrorCode::UnexpectedAdmfIdentifier,
            ErrorCode::NeIdentifierDoesNotMatchCertificate,
            ErrorCode::UnexpectedNeIdentifier,
            ErrorCode::KeepaliveNotSupported,
            ErrorCode::UnsupportedRequest,
            ErrorCode::XidAlreadyExists,
            ErrorCode::XidDoesNotExist,
            ErrorCode::DidAlreadyExists,
            ErrorCode::DidDoesNotExist,
            ErrorCode::GenericActivateTaskFailure,
            ErrorCode::GenericModifyTaskFailure,
            ErrorCode::UnsupportedTargetIdentifierType,
            ErrorCode::UnsupportedCombinationOfTargetIdentifiers,
            ErrorCode::MultipleDestinationsNotSupported,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations,
            ErrorCode::UnsupportedServiceType,
            ErrorCode::GenericDeactivateTaskFailure,
            ErrorCode::GenericDeactivateAllTasksFailure,
            ErrorCode::DeactivateAllTasksNotEnabled,
            ErrorCode::GenericCreateDestinationFailure,
            ErrorCode::GenericModifyDestinationFailure,
            ErrorCode::UnsupportedDeliveryAddressType,
            ErrorCode::GenericRemoveDestinationFailure,
            ErrorCode::DestinationInUse,
            ErrorCode::GenericRemoveAllDestinationsFailure,
            ErrorCode::DestinationsInUse,
            ErrorCode::RemoveAllDestinationsNotEnabled,
            ErrorCode::ErrorCleared,
            ErrorCode::GenericWarning,
            ErrorCode::GenericNonTerminatingFault,
            ErrorCode::TerminatingFault,
            ErrorCode::RequestActioned,
            ErrorCode::KeepalivesNotReceived,
            ErrorCode::DatabaseCleared,
        ];
        let mut numbers: Vec<i64> = all.iter().map(|c| c.number()).collect();
        numbers.sort_unstable();
        let count = numbers.len();
        numbers.dedup();
        assert_eq!(numbers.len(), count, "duplicate error code number");
    }

    #[test]
    fn display_carries_code_and_description() {
        let error = X1Error::syntax("bad timestamp");
        assert_eq!(error.code, ErrorCode::SyntaxSchemaError);
        assert_eq!(error.to_string(), "X1 error 1010: bad timestamp");
    }

    #[test]
    fn unsupported_request_uses_1080() {
        let error = X1Error::unsupported_request("CreateObject");
        assert_eq!(error.code.number(), 1080);
    }
}
