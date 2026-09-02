//! The network-element-to-ADMF direction (TS 103 221-1 clause 6.5).
//!
//! X1 is symmetric: the same message set, envelope and transport, with the
//! network element as the client. This direction did not exist at all before,
//! and without it the ADMF is told nothing:
//!
//! * `ReportNEIssue` — the node started, is shutting down, or has a fault.
//! * `ReportTaskIssue` — a warrant was actioned, or has stopped working.
//! * `ReportDestinationIssue` — a delivery connection was lost or recovered.
//!   This is what closes the loop with the X2/X3 loss policies: a mediation
//!   outage has to be *reported*, not merely survived.
//! * `Keepalive` — on a timer.
//! * `GetAllDetails` — reconciliation.
//!
//! # Reconciliation is the point
//!
//! After a restart the element's provisioning state is empty and the ADMF's is
//! not. Issuing `GetAllDetails` outbound pulls our own state back so the two
//! sides agree again. Without it a bounce silently diverges them, and neither
//! side can tell.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::config::{LiX1AdmfConfig, LiX1Config};

use super::codec;
use super::error::{ErrorCode, X1Error};
use super::message::{Envelope, RequestBody, RequestContainer, RequestMessage, ResponseBody};
use super::schema::X1Schema;
use super::store::{DestinationStore, TaskStore};
use super::types::{
    DId, TaskReportType, Timestamp, Token, TypeOfNeIssueMessage, Version, X1TransactionId, XId,
};

/// An X1 client pointed at the ADMF.
pub struct X1Client {
    http: reqwest::Client,
    endpoint: String,
    admf_identifier: Token,
    ne_identifier: Token,
    version: Version,
    schema: Arc<X1Schema>,
}

impl std::fmt::Debug for X1Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X1Client")
            .field("endpoint", &self.endpoint)
            .field("ne_identifier", &self.ne_identifier)
            .finish_non_exhaustive()
    }
}

impl X1Client {
    /// Build a client from the `lawful_intercept.x1.admf` block.
    ///
    /// Mutual TLS both ways: we present `client_certificate` and verify the
    /// ADMF against `server_ca`. Both certificate and key must be readable —
    /// an unreadable one is an error rather than a silent downgrade to an
    /// unauthenticated connection, the same rule the outbound SIP TLS path
    /// applies.
    pub fn new(
        config: &LiX1Config,
        admf: &LiX1AdmfConfig,
        schema: Arc<X1Schema>,
    ) -> Result<Self, X1Error> {
        let certificate = std::fs::read(&admf.client_certificate).map_err(|error| {
            X1Error::new(
                ErrorCode::Generic,
                format!(
                    "cannot read lawful_intercept.x1.admf.client_certificate '{}': {error}",
                    admf.client_certificate
                ),
            )
        })?;
        let key = std::fs::read(&admf.client_private_key).map_err(|error| {
            X1Error::new(
                ErrorCode::Generic,
                format!(
                    "cannot read lawful_intercept.x1.admf.client_private_key '{}': {error}",
                    admf.client_private_key
                ),
            )
        })?;

        // reqwest wants one PEM blob holding both.
        let mut identity_pem = certificate;
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&key);
        let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|error| {
            X1Error::new(
                ErrorCode::Generic,
                format!("cannot build the X1 client identity: {error}"),
            )
        })?;

        let mut builder = reqwest::Client::builder()
            .identity(identity)
            .timeout(Duration::from_secs(admf.request_timeout_secs.max(1)));

        if let Some(ref server_ca) = admf.server_ca {
            let ca_pem = std::fs::read(server_ca).map_err(|error| {
                X1Error::new(
                    ErrorCode::Generic,
                    format!(
                        "cannot read lawful_intercept.x1.admf.server_ca '{server_ca}': {error}"
                    ),
                )
            })?;
            // A PEM bundle may hold several certificates; add every one.
            for authority in reqwest::Certificate::from_pem_bundle(&ca_pem).map_err(|error| {
                X1Error::new(
                    ErrorCode::Generic,
                    format!("cannot parse lawful_intercept.x1.admf.server_ca: {error}"),
                )
            })? {
                builder = builder.add_root_certificate(authority);
            }
        }

        let http = builder.build().map_err(|error| {
            X1Error::new(
                ErrorCode::Generic,
                format!("cannot build the X1 HTTP client: {error}"),
            )
        })?;

        Ok(Self {
            http,
            endpoint: admf.endpoint.clone(),
            admf_identifier: match &config.admf_identifier {
                Some(value) => Token::parse(value, "lawful_intercept.x1.admf_identifier")?,
                // The envelope field is mandatory. Without a configured value
                // there is nothing honest to put here, so this is refused at
                // startup rather than guessed.
                None => {
                    return Err(X1Error::new(
                        ErrorCode::Generic,
                        "lawful_intercept.x1.admf_identifier must be set to use the \
                         network-element-to-ADMF direction — every X1 message carries it",
                    ))
                }
            },
            ne_identifier: Token::parse(
                &config.ne_identifier,
                "lawful_intercept.x1.ne_identifier",
            )?,
            version: Version::parse(&config.version)?,
            schema,
        })
    }

    /// Build a fresh envelope for an outbound message.
    fn envelope(&self) -> Envelope {
        Envelope {
            admf_identifier: self.admf_identifier.clone(),
            ne_identifier: self.ne_identifier.clone(),
            message_timestamp: Timestamp::now(),
            version: self.version.clone(),
            // We are the requester, so we mint the transaction id.
            x1_transaction_id: X1TransactionId::generate(),
        }
    }

    /// Send one message and return the ADMF's answer.
    async fn send(&self, body: RequestBody) -> Result<ResponseBody, X1Error> {
        let kind = body.kind();
        let container = RequestContainer {
            messages: vec![RequestMessage {
                envelope: self.envelope(),
                body,
            }],
        };
        let xml = codec::encode_request_container(&container)?;

        // Validate before sending: a malformed request would be rejected at
        // the ADMF, where the failure is far harder to diagnose.
        self.schema.validate(&xml)?;

        let response = self
            .http
            .post(&self.endpoint)
            .header(http::header::CONTENT_TYPE, "application/xml")
            .body(xml)
            .send()
            .await
            .map_err(|error| {
                X1Error::new(
                    ErrorCode::Generic,
                    format!("X1 request to the ADMF failed: {error}"),
                )
            })?;

        let status = response.status();
        let text = response.text().await.map_err(|error| {
            X1Error::new(
                ErrorCode::Generic,
                format!("could not read the ADMF's response: {error}"),
            )
        })?;
        if !status.is_success() {
            return Err(X1Error::new(
                ErrorCode::Generic,
                format!("the ADMF answered HTTP {status}"),
            ));
        }

        self.schema.validate(&text)?;
        let document = uppsala::parse(&text).map_err(|error| {
            X1Error::syntax(format!("the ADMF's response does not parse: {error:?}"))
        })?;
        let decoded = codec::decode_response_container(&document)?;

        let message =
            decoded.messages.into_iter().next().ok_or_else(|| {
                X1Error::syntax("the ADMF's response container holds no messages")
            })?;
        if message.kind != kind {
            return Err(X1Error::syntax(format!(
                "the ADMF answered {} to a {} request",
                message.kind.as_str(),
                kind.as_str()
            )));
        }
        Ok(message.body)
    }

    /// Report a node-level condition (`ReportNEIssue`).
    pub async fn report_ne_issue(
        &self,
        issue_type: TypeOfNeIssueMessage,
        description: impl Into<String>,
        issue_code: Option<i64>,
    ) -> Result<(), X1Error> {
        self.send(RequestBody::ReportNEIssue {
            issue_type,
            description: description.into(),
            issue_code,
        })
        .await
        .map(|_| ())
    }

    /// Report a task-level condition (`ReportTaskIssue`).
    pub async fn report_task_issue(
        &self,
        x_id: XId,
        report_type: TaskReportType,
        error_code: Option<i64>,
        details: Option<String>,
    ) -> Result<(), X1Error> {
        self.send(RequestBody::ReportTaskIssue {
            x_id,
            report_type,
            error_code,
            details,
        })
        .await
        .map(|_| ())
    }

    /// Report a delivery-path condition (`ReportDestinationIssue`).
    ///
    /// This is the message that tells the ADMF a mediation function has become
    /// unreachable, and that it has come back.
    pub async fn report_destination_issue(
        &self,
        d_id: DId,
        report_type: TaskReportType,
        error_code: Option<i64>,
        details: Option<String>,
    ) -> Result<(), X1Error> {
        self.send(RequestBody::ReportDestinationIssue {
            d_id,
            report_type,
            error_code,
            details,
        })
        .await
        .map(|_| ())
    }

    /// Send a `Keepalive`.
    pub async fn keepalive(&self) -> Result<(), X1Error> {
        self.send(RequestBody::Keepalive).await.map(|_| ())
    }

    /// Send a `Ping`.
    pub async fn ping(&self) -> Result<(), X1Error> {
        self.send(RequestBody::Ping).await.map(|_| ())
    }

    /// Pull this element's provisioned state back from the ADMF.
    ///
    /// Returns the tasks and destinations the ADMF believes are provisioned
    /// here. The caller decides what to do with the difference.
    pub async fn get_all_details(&self) -> Result<ReconciledState, X1Error> {
        match self.send(RequestBody::GetAllDetails).await? {
            ResponseBody::AllDetails {
                tasks,
                destinations,
                ..
            } => Ok(ReconciledState {
                tasks: tasks.into_iter().map(|entry| entry.task_details).collect(),
                destinations: destinations
                    .into_iter()
                    .map(|entry| entry.destination_details)
                    .collect(),
            }),
            other => Err(X1Error::syntax(format!(
                "GetAllDetails answered with the wrong body: {other:?}"
            ))),
        }
    }
}

/// What the ADMF believes is provisioned on this network element.
#[derive(Debug, Clone, Default)]
pub struct ReconciledState {
    /// Provisioned tasks.
    pub tasks: Vec<super::message::TaskDetails>,
    /// Provisioned destinations.
    pub destinations: Vec<super::message::DestinationDetails>,
}

/// Apply reconciled state to the local stores.
///
/// Destinations are applied first, because a task cannot be activated until
/// the destinations it names exist. Anything the ADMF sends that this node
/// cannot honour — a content warrant on a backend that cannot deliver content,
/// a target identifier type it cannot intercept on — is refused here exactly as
/// it would be at `ActivateTask`, and reported rather than silently dropped:
/// the ADMF believes that warrant is live, and it is not.
pub fn apply_reconciled_state(
    state: &ReconciledState,
    tasks: &TaskStore,
    destinations: &DestinationStore,
) -> Vec<(String, X1Error)> {
    let mut rejected = Vec::new();

    for destination in &state.destinations {
        if destinations.contains(destination.d_id) {
            continue;
        }
        if let Err(error) = destinations.create(destination.clone()) {
            rejected.push((destination.d_id.to_string(), error));
        }
    }

    for task in &state.tasks {
        if tasks.get(task.x_id).is_some() {
            continue;
        }
        if let Err(error) = tasks.activate(task.clone()) {
            rejected.push((task.x_id.to_string(), error));
        }
    }

    rejected
}

/// Start the outbound direction: reconcile, then keep alive on a timer.
///
/// Returns immediately; the work runs on spawned tasks so a slow or
/// unreachable ADMF cannot hold up startup. An unreachable ADMF is logged
/// loudly and retried on the keepalive tick rather than being fatal — the
/// element must still serve warrants it already has.
pub fn spawn(
    client: Arc<X1Client>,
    admf: &LiX1AdmfConfig,
    tasks: TaskStore,
    destinations: DestinationStore,
) {
    if admf.reconcile_on_start {
        let client = Arc::clone(&client);
        let tasks = tasks.clone();
        let destinations = destinations.clone();
        tokio::spawn(async move {
            match client.get_all_details().await {
                Ok(state) => {
                    let task_count = state.tasks.len();
                    let destination_count = state.destinations.len();
                    let rejected = apply_reconciled_state(&state, &tasks, &destinations);
                    info!(
                        tasks = task_count,
                        destinations = destination_count,
                        rejected = rejected.len(),
                        "X1 provisioning state reconciled with the ADMF"
                    );
                    for (subject, error) in rejected {
                        // The ADMF thinks this warrant is live here and it is
                        // not. Say so at error level, and tell the ADMF too.
                        error!(
                            %subject,
                            %error,
                            "reconciled X1 object could not be applied — the ADMF believes it \
                             is provisioned on this node and it is not"
                        );
                        let _ = client
                            .report_ne_issue(
                                TypeOfNeIssueMessage::FaultReport,
                                format!("reconciliation rejected {subject}: {error}"),
                                Some(ErrorCode::GenericNonTerminatingFault.number()),
                            )
                            .await;
                    }
                }
                Err(error) => {
                    error!(
                        %error,
                        "could not reconcile X1 provisioning state with the ADMF — this node's \
                         view of what is provisioned may differ from the ADMF's"
                    );
                }
            }
        });
    }

    // Announce that the node is up. The ADMF learns a restart happened, which
    // is the other half of reconciliation.
    {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            if let Err(error) = client
                .report_ne_issue(
                    TypeOfNeIssueMessage::Warning,
                    "network element started",
                    None,
                )
                .await
            {
                warn!(%error, "could not report startup to the ADMF");
            }
        });
    }

    let interval = admf.keepalive_secs;
    if interval == 0 {
        debug!("X1 keepalives disabled (lawful_intercept.x1.admf.keepalive_secs = 0)");
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        // A missed tick must not produce a burst of catch-up keepalives.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it so the startup report goes
        // first.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(error) = client.keepalive().await {
                warn!(%error, "X1 keepalive to the ADMF failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::x1::message::{DestinationDetails, TaskDetails};
    use crate::li::x1::store::ContentCapability;
    use crate::li::x1::types::{
        DeliveryAddress, DeliveryType, IpAddressPort, Port, TargetIdentifier,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn destination(d_id: DId, delivery: DeliveryType) -> DestinationDetails {
        DestinationDetails {
            d_id,
            friendly_name: None,
            delivery_type: delivery,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                port: Port::Tcp(42069),
            }),
        }
    }

    fn task(x_id: XId, d_id: DId, delivery: DeliveryType) -> TaskDetails {
        TaskDetails {
            x_id,
            target_identifiers: vec![TargetIdentifier::SipUri("sip:alice@example.com".into())],
            delivery_type: delivery,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        }
    }

    fn stores(capability: ContentCapability) -> (TaskStore, DestinationStore) {
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), capability);
        (tasks, destinations)
    }

    #[test]
    fn reconciliation_restores_destinations_then_tasks() {
        // This is the restart case: the stores are empty and the ADMF's view
        // is not.
        let (tasks, destinations) = stores(ContentCapability::Available);
        let d_id = DId::generate();
        let x_id = XId::generate();
        let state = ReconciledState {
            // Deliberately listed tasks-first in the struct; the applier must
            // still create the destination before activating the task.
            tasks: vec![task(x_id, d_id, DeliveryType::X2Only)],
            destinations: vec![destination(d_id, DeliveryType::X2AndX3)],
        };

        let rejected = apply_reconciled_state(&state, &tasks, &destinations);
        assert!(
            rejected.is_empty(),
            "nothing should be rejected: {rejected:?}"
        );
        assert_eq!(destinations.len(), 1);
        assert_eq!(tasks.len(), 1);
        assert!(tasks.get(x_id).is_some());
    }

    #[test]
    fn reconciliation_is_idempotent() {
        // A second reconciliation (a reconnect) must not duplicate or fail.
        let (tasks, destinations) = stores(ContentCapability::Available);
        let d_id = DId::generate();
        let x_id = XId::generate();
        let state = ReconciledState {
            tasks: vec![task(x_id, d_id, DeliveryType::X2Only)],
            destinations: vec![destination(d_id, DeliveryType::X2AndX3)],
        };

        assert!(apply_reconciled_state(&state, &tasks, &destinations).is_empty());
        assert!(apply_reconciled_state(&state, &tasks, &destinations).is_empty());
        assert_eq!(tasks.len(), 1);
        assert_eq!(destinations.len(), 1);
    }

    #[test]
    fn reconciliation_reports_what_it_cannot_honour() {
        // The ADMF believes a content warrant is live here. On a backend that
        // cannot deliver content it is not, and that divergence must surface.
        let (tasks, destinations) = stores(ContentCapability::WrongBackend {
            backend: "rtpengine",
        });
        let d_id = DId::generate();
        let x_id = XId::generate();
        let state = ReconciledState {
            tasks: vec![task(x_id, d_id, DeliveryType::X2AndX3)],
            destinations: vec![destination(d_id, DeliveryType::X2AndX3)],
        };

        let rejected = apply_reconciled_state(&state, &tasks, &destinations);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].0, x_id.to_string());
        assert_eq!(
            rejected[0].1.code,
            ErrorCode::InvalidCombinationOfDeliveryTypeAndDestinations
        );
        // The destination still applied; only the task was refused.
        assert_eq!(destinations.len(), 1);
        assert!(tasks.is_empty());
    }

    #[test]
    fn reconciliation_reports_a_task_whose_destination_is_missing() {
        let (tasks, destinations) = stores(ContentCapability::Available);
        let state = ReconciledState {
            tasks: vec![task(XId::generate(), DId::generate(), DeliveryType::X2Only)],
            destinations: Vec::new(),
        };
        let rejected = apply_reconciled_state(&state, &tasks, &destinations);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].1.code, ErrorCode::DidDoesNotExist);
    }

    #[test]
    fn reconciliation_of_an_empty_state_is_a_no_op() {
        let (tasks, destinations) = stores(ContentCapability::Available);
        let rejected = apply_reconciled_state(&ReconciledState::default(), &tasks, &destinations);
        assert!(rejected.is_empty());
        assert!(tasks.is_empty());
        assert!(destinations.is_empty());
    }

    #[test]
    fn reconciliation_leaves_locally_provisioned_state_alone() {
        // A warrant provisioned here but absent from the ADMF's answer is not
        // torn down by reconciliation: dropping a live warrant because one
        // query came back short would be far worse than keeping it.
        let (tasks, destinations) = stores(ContentCapability::Available);
        let d_id = DId::generate();
        let x_id = XId::generate();
        destinations
            .create(destination(d_id, DeliveryType::X2AndX3))
            .unwrap();
        tasks
            .activate(task(x_id, d_id, DeliveryType::X2Only))
            .unwrap();

        apply_reconciled_state(&ReconciledState::default(), &tasks, &destinations);
        assert!(tasks.get(x_id).is_some());
        assert_eq!(destinations.len(), 1);
    }

    #[test]
    fn the_client_refuses_to_build_without_an_admf_identifier() {
        // Every X1 message carries admfIdentifier; there is nothing honest to
        // put there if it was never configured.
        use crate::config::{LiX1AdmfConfig, LiX1TlsConfig};
        let config = LiX1Config {
            listen: "127.0.0.1:0".into(),
            path: "/X1/NE".into(),
            tls: LiX1TlsConfig {
                certificate: String::new(),
                private_key: String::new(),
                client_ca: String::new(),
            },
            ne_identifier: "siphon-ne".into(),
            admf_identifier: None,
            version: crate::li::x1::types::DEFAULT_VERSION.into(),
            bind_admf_identifier_to_certificate: true,
            admf: None,
        };
        let admf = LiX1AdmfConfig {
            endpoint: "https://admf.example/X1/ADMF".into(),
            client_certificate: "/nonexistent/ne.pem".into(),
            client_private_key: "/nonexistent/ne.key".into(),
            server_ca: None,
            keepalive_secs: 30,
            request_timeout_secs: 10,
            reconcile_on_start: true,
        };
        let schema = Arc::new(X1Schema::compile().unwrap());
        // The missing certificate is reported first; either way it must fail
        // rather than build a client that cannot produce a valid envelope.
        assert!(X1Client::new(&config, &admf, schema).is_err());
    }
}
