//! The X1 network-element server: one HTTPS endpoint behind mutual TLS.
//!
//! The module is split so the part that can be wrong is the part that is easy
//! to test:
//!
//! * [`X1Server::handle_container`] is the whole protocol — parse, validate,
//!   dispatch, answer — as a pure function from request body and peer identity
//!   to response body. Every protocol test drives this directly.
//! * [`serve`] is the transport: a rustls acceptor, a TCP accept loop, and one
//!   hyper service per connection. It contains no protocol logic.
//!
//! # Why this is not on the admin axum server
//!
//! The handler must see the peer's client certificate to bind `admfIdentifier`
//! to it, and that means owning the TLS acceptor. The existing admin listener
//! is plain HTTP and surfaces no peer certificate.
//!
//! # Fail closed
//!
//! A configured X1 listener that cannot be bound — no certificate, an
//! unreadable client CA, a taken port — is a startup error. Parsing config
//! that drives nothing is how the previous module came to be non-compliant.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::LiX1Config;

use super::codec;
use super::error::{ErrorCode, X1Error};
use super::message::{
    error_response_for, DecodedMessage, Envelope, MessageKind, NeStatusDetails, RequestBody,
    ResponseBody, ResponseContainer, ResponseMessage, TopLevelErrorResponse,
};
use super::schema::X1Schema;
use super::store::{DestinationStore, TaskStore};
use super::types::{NeStatus, OkValue, Timestamp, Token, Version};

/// The compliance audit hook: called for every provisioning change.
///
/// Named rather than repeated, because the same signature appears on the
/// struct, the constructor and every call site that builds a server.
pub type AuditHook = Arc<dyn Fn(&str, Option<&str>, String) + Send + Sync>;

/// What the server learned about the peer from the TLS handshake.
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity {
    /// Subject Common Name of the presented client certificate, if any.
    pub common_name: Option<String>,
}

impl PeerIdentity {
    /// Extract the subject Common Name from a DER client certificate.
    ///
    /// Returns `None` when the certificate does not parse or carries no CN —
    /// both of which leave the `admfIdentifier` binding unsatisfied, which the
    /// caller treats as a refusal when the binding is enabled.
    pub fn from_certificate(certificate: &CertificateDer<'_>) -> Self {
        use x509_cert::der::Decode;

        let Ok(parsed) = x509_cert::Certificate::from_der(certificate.as_ref()) else {
            return Self::default();
        };
        let common_name = parsed
            .tbs_certificate()
            .subject()
            .common_name()
            .ok()
            .flatten()
            .map(|name| name.value().into_owned());
        Self { common_name }
    }
}

/// Everything the X1 endpoint needs to answer a message.
pub struct X1Server {
    schema: X1Schema,
    tasks: TaskStore,
    destinations: DestinationStore,
    ne_identifier: Token,
    expected_admf: Option<Token>,
    version: Version,
    bind_admf_to_certificate: bool,
    /// Called for every provisioning change, for the compliance audit trail.
    audit: AuditHook,
}

impl std::fmt::Debug for X1Server {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("X1Server")
            .field("ne_identifier", &self.ne_identifier)
            .field("tasks", &self.tasks.len())
            .field("destinations", &self.destinations.len())
            .finish_non_exhaustive()
    }
}

impl X1Server {
    /// Build a server over the given stores.
    ///
    /// Fails when the configured identifiers or version are not schema-valid —
    /// at startup, rather than on the first message.
    pub fn new(
        config: &LiX1Config,
        tasks: TaskStore,
        destinations: DestinationStore,
        audit: AuditHook,
    ) -> Result<Self, X1Error> {
        let expected_admf = match &config.admf_identifier {
            Some(value) => Some(Token::parse(value, "lawful_intercept.x1.admf_identifier")?),
            None => None,
        };
        Ok(Self {
            schema: X1Schema::compile()?,
            tasks,
            destinations,
            ne_identifier: Token::parse(
                &config.ne_identifier,
                "lawful_intercept.x1.ne_identifier",
            )?,
            expected_admf,
            version: Version::parse(&config.version)?,
            bind_admf_to_certificate: config.bind_admf_identifier_to_certificate,
            audit,
        })
    }

    /// The task store this server provisions into.
    pub fn tasks(&self) -> &TaskStore {
        &self.tasks
    }

    /// The destination store this server provisions into.
    pub fn destinations(&self) -> &DestinationStore {
        &self.destinations
    }

    /// Handle one `X1Request` container and produce the response body.
    ///
    /// This is the whole protocol. It never fails: a container that cannot be
    /// read produces an `X1TopLevelErrorResponse`, and a message that cannot be
    /// handled produces a per-message `ErrorResponse` alongside its siblings'
    /// real answers.
    pub fn handle_container(&self, body: &str, peer: &PeerIdentity) -> String {
        match self.try_handle_container(body, peer) {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "X1 request rejected at container level");
                self.top_level_error()
            }
        }
    }

    fn try_handle_container(&self, body: &str, peer: &PeerIdentity) -> Result<String, X1Error> {
        // Widen any non-conformant fractional second before anything looks at
        // the document, so a peer that renders milliseconds can still provision
        // a warrant. See `compat` for why this is worth doing at all.
        let (body, _rewritten) = super::compat::normalise_inbound_timestamps(body);
        let body = body.as_str();

        let document = uppsala::parse(body)
            .map_err(|error| X1Error::syntax(format!("XML does not parse: {error:?}")))?;

        // The container's own shape has to be readable. If it is not there is
        // no x1TransactionId to correlate anything on, so the answer is an
        // X1TopLevelErrorResponse.
        let nodes = codec::request_message_nodes(&document)?;

        // Schema-validate each message *in isolation*.
        //
        // Validating the whole container would let one structurally invalid
        // message reject its siblings, and the specification requires every
        // message to be answered in its own right. The fast path is the common
        // one: a container whose messages are all valid is validated
        // message-by-message at tens of microseconds each, which is immaterial
        // on a provisioning interface.
        let mut messages = Vec::with_capacity(nodes.len());
        for node in nodes {
            let decoded = codec::decode_request_message(&document, node);

            // A message the decoder already rejected does not need the
            // schema's opinion as well — its own error is more specific.
            if matches!(decoded, DecodedMessage::Failed { .. }) {
                messages.push(self.handle_message(decoded, peer));
                continue;
            }

            let isolated = codec::single_message_document(&document, node);
            if let Err(error) = self.schema.validate(&isolated) {
                let envelope = self.response_envelope(decoded.envelope());
                let kind = match &decoded {
                    DecodedMessage::Message(message) => Some(message.body.kind()),
                    DecodedMessage::Failed { kind, .. } => *kind,
                };
                debug!(%error, "X1 message failed schema validation");
                messages.push(error_response_for(envelope, kind, error));
                continue;
            }

            messages.push(self.handle_message(decoded, peer));
        }

        let response = ResponseContainer { messages };
        let encoded = codec::encode_response_container(&response)?;

        // Validate what we are about to send. A malformed response would fail
        // at the ADMF, where the failure is far more expensive to diagnose.
        if let Err(error) = self.schema.validate(&encoded) {
            error!(
                %error,
                "X1 response failed schema validation before sending — this is a defect in siphon"
            );
            return Err(error);
        }
        Ok(encoded)
    }

    /// Answer one decoded message.
    fn handle_message(&self, decoded: DecodedMessage, peer: &PeerIdentity) -> ResponseMessage {
        let (message, kind_hint, decode_error) = match decoded {
            DecodedMessage::Message(message) => (Some(*message), None, None),
            DecodedMessage::Failed {
                envelope,
                kind,
                error,
            } => (
                None,
                Some((*envelope, kind)),
                Some(error),
            ),
        };

        if let (Some((envelope, kind)), Some(error)) = (kind_hint, decode_error) {
            let response_envelope = self.response_envelope(&envelope);
            return error_response_for(response_envelope, kind, error);
        }

        let Some(message) = message else {
            // Unreachable: one of the two arms above always matched.
            return error_response_for(
                self.fresh_envelope(Token::unknown()),
                None,
                X1Error::new(ErrorCode::Generic, "internal dispatch error"),
            );
        };

        let kind = message.body.kind();
        let response_envelope = self.response_envelope(&message.envelope);

        // -- authenticate the message before acting on it ---------------
        if let Err(error) = self.check_identity(&message.envelope, peer) {
            warn!(
                code = %error.code,
                admf = %message.envelope.admf_identifier,
                "X1 message refused on identity"
            );
            return ResponseMessage::error(response_envelope, kind, error);
        }

        match self.dispatch(kind, message.body) {
            Ok(body) => ResponseMessage {
                envelope: response_envelope,
                kind,
                body,
            },
            Err(error) => {
                debug!(code = %error.code, message = kind.as_str(), "X1 message refused");
                ResponseMessage::error(response_envelope, kind, error)
            }
        }
    }

    /// Enforce the identity rules of clause 6.1.
    fn check_identity(&self, envelope: &Envelope, peer: &PeerIdentity) -> Result<(), X1Error> {
        if let Some(expected) = &self.expected_admf {
            if envelope.admf_identifier.as_str() != expected.as_str() {
                return Err(X1Error::new(
                    ErrorCode::UnexpectedAdmfIdentifier,
                    format!(
                        "admfIdentifier {} is not the ADMF this network element serves",
                        envelope.admf_identifier
                    ),
                ));
            }
        }

        if envelope.ne_identifier.as_str() != self.ne_identifier.as_str() {
            return Err(X1Error::new(
                ErrorCode::UnexpectedNeIdentifier,
                format!(
                    "neIdentifier {} does not name this network element",
                    envelope.ne_identifier
                ),
            ));
        }

        if self.bind_admf_to_certificate {
            // The reason X1 is served on its own listener: the message's claim
            // about who it is from is checked against who the TLS layer proved
            // it is from.
            match &peer.common_name {
                Some(common_name) if common_name == envelope.admf_identifier.as_str() => {}
                Some(common_name) => {
                    return Err(X1Error::new(
                        ErrorCode::AdmfIdentifierDoesNotMatchCertificate,
                        format!(
                            "admfIdentifier {} does not match the client certificate subject \
                             CN {common_name:?}",
                            envelope.admf_identifier
                        ),
                    ))
                }
                None => {
                    return Err(X1Error::new(
                        ErrorCode::AdmfIdentifierDoesNotMatchCertificate,
                        "the client certificate carries no subject Common Name to bind \
                         admfIdentifier against",
                    ))
                }
            }
        }

        Ok(())
    }

    /// Act on one message.
    fn dispatch(&self, kind: MessageKind, body: RequestBody) -> Result<ResponseBody, X1Error> {
        match body {
            RequestBody::ActivateTask(task) => {
                let x_id = task.x_id;
                let summary = format!(
                    "xid={x_id} delivery={} targets={} destinations={}",
                    task.delivery_type,
                    task.target_identifiers.len(),
                    task.list_of_dids.len()
                );
                self.tasks.activate(*task)?;
                self.audit("TaskActivated", Some(&x_id.to_string()), summary);
                Ok(self.acknowledged())
            }
            RequestBody::ModifyTask(task) => {
                let x_id = task.x_id;
                let summary = format!("xid={x_id} delivery={}", task.delivery_type);
                self.tasks.modify(*task)?;
                self.audit("TaskModified", Some(&x_id.to_string()), summary);
                Ok(self.acknowledged())
            }
            RequestBody::DeactivateTask(x_id) => {
                self.tasks.deactivate(x_id)?;
                self.audit(
                    "TaskDeactivated",
                    Some(&x_id.to_string()),
                    format!("xid={x_id}"),
                );
                Ok(self.acknowledged())
            }
            RequestBody::DeactivateAllTasks => {
                let count = self.tasks.deactivate_all();
                self.audit("AllTasksDeactivated", None, format!("removed={count}"));
                Ok(self.acknowledged())
            }
            RequestBody::GetTaskDetails(x_id) => {
                let task = self.tasks.get(x_id).ok_or_else(|| {
                    X1Error::new(
                        ErrorCode::XidDoesNotExist,
                        format!("task {x_id} is not provisioned"),
                    )
                })?;
                Ok(ResponseBody::TaskDetails(Box::new(
                    task.to_response_details(),
                )))
            }
            RequestBody::CreateDestination(destination) => {
                let d_id = destination.d_id;
                let summary = format!("did={d_id} delivery={}", destination.delivery_type);
                self.destinations.create(*destination)?;
                self.audit("DestinationCreated", Some(&d_id.to_string()), summary);
                Ok(self.acknowledged())
            }
            RequestBody::ModifyDestination(destination) => {
                let d_id = destination.d_id;
                let summary = format!("did={d_id} delivery={}", destination.delivery_type);
                self.destinations.modify(*destination)?;
                self.audit("DestinationModified", Some(&d_id.to_string()), summary);
                Ok(self.acknowledged())
            }
            RequestBody::RemoveDestination(d_id) => {
                // Removing a destination a task still delivers to would leave
                // that warrant provisioned and delivering nowhere.
                let referencing = self.tasks.tasks_referencing(d_id);
                if !referencing.is_empty() {
                    return Err(X1Error::new(
                        ErrorCode::DestinationInUse,
                        format!(
                            "destination {d_id} is still referenced by task(s) {}",
                            referencing
                                .iter()
                                .map(|x_id| x_id.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
                self.destinations.remove(d_id)?;
                self.audit(
                    "DestinationRemoved",
                    Some(&d_id.to_string()),
                    format!("did={d_id}"),
                );
                Ok(self.acknowledged())
            }
            RequestBody::RemoveAllDestinations => {
                // Same rule, applied to the whole set.
                let in_use: Vec<String> = self
                    .destinations
                    .ids()
                    .into_iter()
                    .filter(|d_id| !self.tasks.tasks_referencing(*d_id).is_empty())
                    .map(|d_id| d_id.to_string())
                    .collect();
                if !in_use.is_empty() {
                    return Err(X1Error::new(
                        ErrorCode::DestinationsInUse,
                        format!(
                            "destination(s) {} are still referenced by provisioned tasks",
                            in_use.join(", ")
                        ),
                    ));
                }
                let count = self.destinations.len();
                self.destinations.remove_all();
                self.audit("AllDestinationsRemoved", None, format!("removed={count}"));
                Ok(self.acknowledged())
            }
            RequestBody::GetDestinationDetails(d_id) => {
                let destination = self.destinations.get(d_id).ok_or_else(|| {
                    X1Error::new(
                        ErrorCode::DidDoesNotExist,
                        format!("destination {d_id} is not provisioned"),
                    )
                })?;
                Ok(ResponseBody::DestinationDetails(Box::new(
                    destination.to_response_details(),
                )))
            }
            RequestBody::GetNEStatus => Ok(ResponseBody::NeStatus(self.ne_status())),
            RequestBody::GetAllDetails => Ok(ResponseBody::AllDetails {
                ne_status: self.ne_status(),
                tasks: self
                    .tasks
                    .list()
                    .iter()
                    .map(|task| task.to_response_details())
                    .collect(),
                destinations: self
                    .destinations
                    .list()
                    .iter()
                    .map(|destination| destination.to_response_details())
                    .collect(),
            }),
            RequestBody::GetAllTaskDetails => Ok(ResponseBody::AllTaskDetails(
                self.tasks
                    .list()
                    .iter()
                    .map(|task| task.to_response_details())
                    .collect(),
            )),
            RequestBody::GetAllDestinationDetails => Ok(ResponseBody::AllDestinationDetails(
                self.destinations
                    .list()
                    .iter()
                    .map(|destination| destination.to_response_details())
                    .collect(),
            )),
            RequestBody::ListAllDetails => Ok(ResponseBody::ListAllDetails {
                x_ids: self.tasks.ids(),
                d_ids: self.destinations.ids(),
            }),
            RequestBody::Ping | RequestBody::Keepalive => Ok(self.acknowledged()),
            // The report messages travel network-element-to-ADMF. An ADMF has
            // no business sending them to us, so they are refused rather than
            // silently acknowledged.
            RequestBody::ReportTaskIssue { .. }
            | RequestBody::ReportDestinationIssue { .. }
            | RequestBody::ReportNEIssue { .. } => Err(X1Error::new(
                ErrorCode::UnsupportedRequest,
                format!(
                    "{} is a network-element-to-ADMF message and is not accepted inbound",
                    kind.as_str()
                ),
            )),
        }
    }

    fn acknowledged(&self) -> ResponseBody {
        // siphon provisions synchronously: by the time the answer is built the
        // change has already been applied, so it is complete, not merely
        // acknowledged.
        ResponseBody::Ok(OkValue::AcknowledgedAndCompleted)
    }

    fn ne_status(&self) -> NeStatusDetails {
        NeStatusDetails {
            ne_status: NeStatus::Ok,
            list_of_faults: Vec::new(),
        }
    }

    /// Build the response envelope: the request's identifiers and transaction
    /// id, with our own timestamp and declared version.
    fn response_envelope(&self, request: &Envelope) -> Envelope {
        Envelope {
            admf_identifier: request.admf_identifier.clone(),
            ne_identifier: self.ne_identifier.clone(),
            message_timestamp: Timestamp::now(),
            version: self.version.clone(),
            x1_transaction_id: request.x1_transaction_id,
        }
    }

    /// An envelope with no request to echo — only for the internal error path.
    fn fresh_envelope(&self, admf: Token) -> Envelope {
        Envelope {
            admf_identifier: admf,
            ne_identifier: self.ne_identifier.clone(),
            message_timestamp: Timestamp::now(),
            version: self.version.clone(),
            x1_transaction_id: super::types::X1TransactionId::generate(),
        }
    }

    /// The container-level failure answer.
    fn top_level_error(&self) -> String {
        let response = TopLevelErrorResponse {
            admf_identifier: self
                .expected_admf
                .clone()
                .unwrap_or_else(Token::unknown),
            ne_identifier: self.ne_identifier.clone(),
            message_timestamp: Timestamp::now(),
            version: self.version.clone(),
        };
        codec::encode_top_level_error(&response).unwrap_or_else(|error| {
            // Encoding a four-field document cannot realistically fail, but a
            // lawful-intercept interface must answer rather than hang up.
            error!(%error, "could not encode X1TopLevelErrorResponse");
            String::new()
        })
    }

    fn audit(&self, operation: &str, subject: Option<&str>, detail: String) {
        (self.audit)(operation, subject, detail);
    }
}

/// Build the rustls server config for the X1 listener.
///
/// Mutual TLS is mandatory: `client_ca` gates who may provision warrants. An
/// unreadable or empty CA bundle is an error, never a downgrade to accepting
/// any client — the same fail-closed rule `transport::tls` applies.
fn build_tls_config(
    config: &crate::config::LiX1TlsConfig,
) -> io::Result<tokio_rustls::rustls::ServerConfig> {
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    let certificate_file = File::open(&config.certificate).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "failed to open lawful_intercept.x1.tls.certificate '{}': {error}",
                config.certificate
            ),
        )
    })?;
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut BufReader::new(certificate_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse X1 certificate PEM: {error}"),
                )
            })?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lawful_intercept.x1.tls.certificate contains no certificates",
        ));
    }

    let key = PrivateKeyDer::from_pem_file(&config.private_key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to read lawful_intercept.x1.tls.private_key '{}': {error}",
                config.private_key
            ),
        )
    })?;

    let ca_file = File::open(&config.client_ca).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "failed to open lawful_intercept.x1.tls.client_ca '{}': {error}",
                config.client_ca
            ),
        )
    })?;
    let ca_certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse X1 client CA PEM: {error}"),
                )
            })?;
    if ca_certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lawful_intercept.x1.tls.client_ca contains no certificates — X1 would \
             accept any client",
        ));
    }

    let mut roots = rustls::RootCertStore::empty();
    for authority in ca_certificates {
        roots.add(authority).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to add X1 client CA: {error}"),
            )
        })?;
    }

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build X1 client certificate verifier: {error}"),
            )
        })?;

    // TLS 1.2 is the floor named by the specification; 1.3 is preferred and
    // negotiated when the ADMF offers it.
    rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_client_cert_verifier(verifier)
    .with_single_cert(certificates, key)
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to build X1 TLS config: {error}"),
        )
    })
}

/// Bind and serve the X1 endpoint.
///
/// Returns once the listener is bound; the accept loop runs on a spawned task.
/// A bind failure is returned to the caller so startup can fail rather than
/// continue with an interface that silently is not listening.
pub async fn serve(
    config: Arc<LiX1Config>,
    server: Arc<X1Server>,
) -> io::Result<SocketAddr> {
    let tls_config = build_tls_config(&config.tls)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(&config.listen).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to bind the X1 listener on {}: {error}",
                config.listen
            ),
        )
    })?;
    let local_addr = listener.local_addr()?;

    info!(
        address = %local_addr,
        path = %config.path,
        ne_identifier = %config.ne_identifier,
        "ETSI X1 listener started (mutual TLS)"
    );

    tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    error!(%error, "X1 accept failed");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let server = Arc::clone(&server);
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Err(error) = serve_connection(acceptor, stream, server, config).await {
                    debug!(%peer_addr, %error, "X1 connection ended");
                }
            });
        }
    });

    Ok(local_addr)
}

/// Complete the TLS handshake and serve HTTP/1.1 on one connection.
async fn serve_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    server: Arc<X1Server>,
    config: Arc<LiX1Config>,
) -> io::Result<()> {
    let tls_stream = acceptor.accept(stream).await?;

    // The client certificate is available only after the handshake, and only
    // from the connection we own — this is why X1 has its own listener.
    let peer = {
        let (_, connection) = tls_stream.get_ref();
        connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(PeerIdentity::from_certificate)
            .unwrap_or_default()
    };

    let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let server = Arc::clone(&server);
        let config = Arc::clone(&config);
        let peer = peer.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_http(request, server, config, peer).await) }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), service)
        .await
        .map_err(|error| io::Error::other(format!("X1 HTTP connection error: {error}")))
}

/// The HTTP shell around [`X1Server::handle_container`].
///
/// X1 is one endpoint taking one method. Everything else gets a plain HTTP
/// status, because a request that is not an X1 message has no X1 answer.
async fn handle_http(
    request: hyper::Request<hyper::body::Incoming>,
    server: Arc<X1Server>,
    config: Arc<LiX1Config>,
    peer: PeerIdentity,
) -> hyper::Response<String> {
    use http::{header, Method, StatusCode};
    use http_body_util::BodyExt;

    let build = |status: StatusCode, body: String| {
        hyper::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(body)
            .unwrap_or_else(|_| hyper::Response::new(String::new()))
    };

    if request.uri().path() != config.path {
        return build(StatusCode::NOT_FOUND, String::new());
    }
    if request.method() != Method::POST {
        return build(StatusCode::METHOD_NOT_ALLOWED, String::new());
    }

    let body = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            warn!(%error, "could not read the X1 request body");
            return build(StatusCode::BAD_REQUEST, String::new());
        }
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        return build(StatusCode::BAD_REQUEST, server.top_level_error());
    };

    let response = server.handle_container(text, &peer);
    build(StatusCode::OK, response)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LiX1AdmfConfig, LiX1TlsConfig};
    use crate::li::x1::store::ContentCapability;
    use crate::li::x1::types::{DId, DeliveryType, XId, DEFAULT_VERSION};
    use std::sync::Mutex;

    const ADMF: &str = "admf-id";
    const NE: &str = "siphon-ne";

    /// Records what the server audited, so tests can prove a provisioning
    /// change was written to the compliance trail.
    #[derive(Default)]
    struct AuditLog {
        entries: Mutex<Vec<(String, Option<String>, String)>>,
    }

    impl AuditLog {
        fn hook(self: &Arc<Self>) -> AuditHook {
            let log = Arc::clone(self);
            Arc::new(move |operation, subject, detail| {
                if let Ok(mut entries) = log.entries.lock() {
                    entries.push((
                        operation.to_string(),
                        subject.map(str::to_string),
                        detail,
                    ));
                }
            })
        }

        fn operations(&self) -> Vec<String> {
            self.entries
                .lock()
                .map(|entries| entries.iter().map(|(op, _, _)| op.clone()).collect())
                .unwrap_or_default()
        }
    }

    fn config() -> LiX1Config {
        LiX1Config {
            listen: "127.0.0.1:0".to_string(),
            path: "/X1/NE".to_string(),
            tls: LiX1TlsConfig {
                certificate: String::new(),
                private_key: String::new(),
                client_ca: String::new(),
            },
            ne_identifier: NE.to_string(),
            admf_identifier: Some(ADMF.to_string()),
            version: DEFAULT_VERSION.to_string(),
            bind_admf_identifier_to_certificate: false,
            admf: None,
        }
    }

    fn server_with(capability: ContentCapability) -> (Arc<X1Server>, Arc<AuditLog>) {
        let audit = Arc::new(AuditLog::default());
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), capability);
        let server = X1Server::new(&config(), tasks, destinations, audit.hook())
            .expect("server must build from a valid config");
        (Arc::new(server), audit)
    }

    fn server() -> (Arc<X1Server>, Arc<AuditLog>) {
        server_with(ContentCapability::Available)
    }

    fn peer() -> PeerIdentity {
        PeerIdentity {
            common_name: Some(ADMF.to_string()),
        }
    }

    /// Build a request container around one or more message bodies.
    fn request(bodies: &[(&str, String)]) -> String {
        let mut messages = String::new();
        for (type_name, payload) in bodies {
            messages.push_str(&format!(
                r#"<x1RequestMessage xsi:type="{type_name}">
    <admfIdentifier>{ADMF}</admfIdentifier>
    <neIdentifier>{NE}</neIdentifier>
    <messageTimestamp>2026-08-31T09:00:00.000000Z</messageTimestamp>
    <version>{DEFAULT_VERSION}</version>
    <x1TransactionId>{}</x1TransactionId>
    {payload}
  </x1RequestMessage>
"#,
                XId::generate()
            ));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"
           xmlns:c="http://uri.etsi.org/03280/common/2017/07"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
{messages}</X1Request>"#
        )
    }

    fn create_destination_payload(d_id: DId, delivery: DeliveryType) -> String {
        format!(
            r#"<destinationDetails>
      <dId>{d_id}</dId>
      <friendlyName>test mdf</friendlyName>
      <deliveryType>{delivery}</deliveryType>
      <deliveryAddress>
        <ipAddressAndPort>
          <c:address><c:IPv4Address>192.0.2.50</c:IPv4Address></c:address>
          <c:port><c:TCPPort>42069</c:TCPPort></c:port>
        </ipAddressAndPort>
      </deliveryAddress>
    </destinationDetails>"#
        )
    }

    fn activate_task_payload(x_id: XId, d_id: DId, delivery: DeliveryType) -> String {
        format!(
            r#"<taskDetails>
      <xId>{x_id}</xId>
      <targetIdentifiers>
        <targetIdentifier><sipUri>sip:alice@example.com</sipUri></targetIdentifier>
      </targetIdentifiers>
      <deliveryType>{delivery}</deliveryType>
      <listOfDIDs><dId>{d_id}</dId></listOfDIDs>
    </taskDetails>"#
        )
    }

    /// Provision a destination and return its DID.
    fn provision_destination(server: &X1Server, delivery: DeliveryType) -> DId {
        let d_id = DId::generate();
        let response = server.handle_container(
            &request(&[(
                "CreateDestinationRequest",
                create_destination_payload(d_id, delivery),
            )]),
            &peer(),
        );
        assert!(
            response.contains("CreateDestinationResponse"),
            "destination setup failed: {response}"
        );
        d_id
    }

    #[test]
    fn activate_get_modify_deactivate() {
        let (server, audit) = server();
        let d_id = provision_destination(&server, DeliveryType::X2AndX3);
        let x_id = XId::generate();

        let activate = server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );
        assert!(activate.contains("ActivateTaskResponse"), "{activate}");
        assert!(activate.contains("AcknowledgedAndCompleted"));
        assert_eq!(server.tasks().len(), 1);

        let get = server.handle_container(
            &request(&[("GetTaskDetailsRequest", format!("<xId>{x_id}</xId>"))]),
            &peer(),
        );
        assert!(get.contains("GetTaskDetailsResponse"), "{get}");
        assert!(get.contains(&x_id.to_string()));
        assert!(get.contains("sip:alice@example.com"));

        let modify = server.handle_container(
            &request(&[(
                "ModifyTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2AndX3),
            )]),
            &peer(),
        );
        assert!(modify.contains("ModifyTaskResponse"), "{modify}");
        assert_eq!(
            server.tasks().get(x_id).unwrap().details.delivery_type,
            DeliveryType::X2AndX3
        );

        let deactivate = server.handle_container(
            &request(&[("DeactivateTaskRequest", format!("<xId>{x_id}</xId>"))]),
            &peer(),
        );
        assert!(deactivate.contains("DeactivateTaskResponse"), "{deactivate}");
        assert!(server.tasks().is_empty());

        let operations = audit.operations();
        assert!(operations.contains(&"DestinationCreated".to_string()));
        assert!(operations.contains(&"TaskActivated".to_string()));
        assert!(operations.contains(&"TaskModified".to_string()));
        assert!(operations.contains(&"TaskDeactivated".to_string()));
    }

    #[test]
    fn a_deactivated_task_stops_matching() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let x_id = XId::generate();

        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );
        assert!(server.tasks().get(x_id).is_some());

        server.handle_container(
            &request(&[("DeactivateTaskRequest", format!("<xId>{x_id}</xId>"))]),
            &peer(),
        );
        assert!(server.tasks().get(x_id).is_none());
        assert!(server.tasks().destinations_for(x_id).is_empty());
    }

    #[test]
    fn activating_a_duplicate_xid_returns_2010() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let x_id = XId::generate();
        let body = request(&[(
            "ActivateTaskRequest",
            activate_task_payload(x_id, d_id, DeliveryType::X2Only),
        )]);

        server.handle_container(&body, &peer());
        let second = server.handle_container(&body, &peer());
        assert!(second.contains("ErrorResponse"), "{second}");
        assert!(second.contains("<errorCode>2010</errorCode>"), "{second}");
    }

    #[test]
    fn getting_an_unknown_task_returns_2020() {
        let (server, _) = server();
        let response = server.handle_container(
            &request(&[(
                "GetTaskDetailsRequest",
                format!("<xId>{}</xId>", XId::generate()),
            )]),
            &peer(),
        );
        assert!(response.contains("<errorCode>2020</errorCode>"), "{response}");
    }

    #[test]
    fn deactivate_all_tasks_clears_the_store() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        for _ in 0..3 {
            server.handle_container(
                &request(&[(
                    "ActivateTaskRequest",
                    activate_task_payload(XId::generate(), d_id, DeliveryType::X2Only),
                )]),
                &peer(),
            );
        }
        assert_eq!(server.tasks().len(), 3);

        let response =
            server.handle_container(&request(&[("DeactivateAllTasksRequest", String::new())]), &peer());
        assert!(response.contains("DeactivateAllTasksResponse"), "{response}");
        assert!(server.tasks().is_empty());
    }

    #[test]
    fn create_get_modify_remove_a_destination() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2AndX3);

        let get = server.handle_container(
            &request(&[("GetDestinationDetailsRequest", format!("<dId>{d_id}</dId>"))]),
            &peer(),
        );
        assert!(get.contains("GetDestinationDetailsResponse"), "{get}");
        assert!(get.contains("192.0.2.50"));
        assert!(get.contains("activeAndWorking"));

        let remove = server.handle_container(
            &request(&[("RemoveDestinationRequest", format!("<dId>{d_id}</dId>"))]),
            &peer(),
        );
        assert!(remove.contains("RemoveDestinationResponse"), "{remove}");
        assert!(server.destinations().is_empty());
    }

    #[test]
    fn removing_a_referenced_destination_returns_7010() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let x_id = XId::generate();
        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );

        let response = server.handle_container(
            &request(&[("RemoveDestinationRequest", format!("<dId>{d_id}</dId>"))]),
            &peer(),
        );
        assert!(response.contains("<errorCode>7010</errorCode>"), "{response}");
        assert!(
            response.contains(&x_id.to_string()),
            "the refusal should name the referencing task: {response}"
        );
        assert!(
            server.destinations().contains(d_id),
            "the destination must survive a refused removal"
        );
    }

    #[test]
    fn remove_all_destinations_is_refused_while_any_is_referenced() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(XId::generate(), d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );

        let response = server
            .handle_container(&request(&[("RemoveAllDestinationsRequest", String::new())]), &peer());
        assert!(response.contains("<errorCode>8010</errorCode>"), "{response}");
        assert_eq!(server.destinations().len(), 1);
    }

    #[test]
    fn remove_all_destinations_succeeds_when_nothing_references_them() {
        let (server, _) = server();
        provision_destination(&server, DeliveryType::X2Only);
        provision_destination(&server, DeliveryType::X2Only);

        let response = server
            .handle_container(&request(&[("RemoveAllDestinationsRequest", String::new())]), &peer());
        assert!(response.contains("RemoveAllDestinationsResponse"), "{response}");
        assert!(server.destinations().is_empty());
    }

    #[test]
    fn a_task_naming_an_unknown_destination_returns_2040() {
        let (server, _) = server();
        let response = server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(XId::generate(), DId::generate(), DeliveryType::X2Only),
            )]),
            &peer(),
        );
        assert!(response.contains("<errorCode>2040</errorCode>"), "{response}");
        assert!(server.tasks().is_empty());
    }

    #[test]
    fn a_task_delivers_only_to_the_dids_it_names() {
        let (server, _) = server();
        let named = provision_destination(&server, DeliveryType::X2AndX3);
        let unnamed = provision_destination(&server, DeliveryType::X2AndX3);
        let x_id = XId::generate();
        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, named, DeliveryType::X2AndX3),
            )]),
            &peer(),
        );

        let resolved = server.tasks().destinations_for(x_id);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].details.d_id, named);
        assert_ne!(resolved[0].details.d_id, unnamed);
    }

    #[test]
    fn get_all_details_reports_tasks_and_destinations() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let x_id = XId::generate();
        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );

        let response =
            server.handle_container(&request(&[("GetAllDetailsRequest", String::new())]), &peer());
        assert!(response.contains("GetAllDetailsResponse"), "{response}");
        assert!(response.contains(&x_id.to_string()));
        assert!(response.contains(&d_id.to_string()));
        assert!(response.contains("<neStatus>OK</neStatus>"));
    }

    #[test]
    fn list_all_details_reports_bare_identifiers() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let x_id = XId::generate();
        server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(x_id, d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );

        let response =
            server.handle_container(&request(&[("ListAllDetailsRequest", String::new())]), &peer());
        assert!(response.contains("ListAllDetailsResponse"), "{response}");
        assert!(response.contains(&x_id.to_string()));
        assert!(response.contains(&d_id.to_string()));
    }

    #[test]
    fn get_ne_status_answers_ok_on_a_healthy_node() {
        let (server, _) = server();
        let response =
            server.handle_container(&request(&[("GetNEStatusRequest", String::new())]), &peer());
        assert!(response.contains("GetNEStatusResponse"), "{response}");
        assert!(response.contains("<neStatus>OK</neStatus>"));
    }

    #[test]
    fn ping_and_keepalive_are_acknowledged() {
        let (server, _) = server();
        for type_name in ["PingRequest", "KeepaliveRequest"] {
            let response = server.handle_container(&request(&[(type_name, String::new())]), &peer());
            assert!(
                response.contains(&type_name.replace("Request", "Response")),
                "{type_name}: {response}"
            );
            assert!(response.contains("AcknowledgedAndCompleted"));
        }
    }

    #[test]
    fn a_multi_message_container_yields_a_multi_message_response_in_order() {
        let (server, _) = server();
        let body = request(&[
            ("PingRequest", String::new()),
            ("GetNEStatusRequest", String::new()),
            ("KeepaliveRequest", String::new()),
        ]);
        let response = server.handle_container(&body, &peer());

        let ping = response.find("PingResponse").expect("ping answered");
        let status = response.find("GetNEStatusResponse").expect("status answered");
        let keepalive = response.find("KeepaliveResponse").expect("keepalive answered");
        assert!(ping < status && status < keepalive, "responses out of order:\n{response}");
        assert_eq!(response.matches("x1ResponseMessage").count(), 6); // 3 open + 3 close
    }

    #[test]
    fn every_response_echoes_its_request_transaction_id() {
        let (server, _) = server();
        let body = request(&[
            ("PingRequest", String::new()),
            ("KeepaliveRequest", String::new()),
        ]);
        let request_ids: Vec<&str> = body
            .match_indices("<x1TransactionId>")
            .map(|(index, _)| {
                let start = index + "<x1TransactionId>".len();
                let end = body[start..].find('<').unwrap() + start;
                &body[start..end]
            })
            .collect();
        assert_eq!(request_ids.len(), 2);

        let response = server.handle_container(&body, &peer());
        let response_ids: Vec<&str> = response
            .match_indices("<x1TransactionId>")
            .map(|(index, _)| {
                let start = index + "<x1TransactionId>".len();
                let end = response[start..].find('<').unwrap() + start;
                &response[start..end]
            })
            .collect();
        assert_eq!(
            response_ids, request_ids,
            "responses must be correlatable, in order"
        );
    }

    #[test]
    fn a_bad_message_gets_its_own_error_and_its_siblings_are_answered() {
        let (server, _) = server();
        let body = request(&[
            ("PingRequest", String::new()),
            ("GetTaskDetailsRequest", "<xId>not-a-uuid</xId>".to_string()),
            ("KeepaliveRequest", String::new()),
        ]);
        let response = server.handle_container(&body, &peer());

        assert!(response.contains("PingResponse"), "{response}");
        assert!(response.contains("KeepaliveResponse"), "{response}");
        assert!(response.contains("ErrorResponse"), "{response}");
        assert_eq!(response.matches("x1ResponseMessage").count(), 6);
    }

    #[test]
    fn an_unparseable_container_yields_a_top_level_error_response() {
        let (server, _) = server();
        for body in [
            "not xml at all",
            "<X1Request><unclosed>",
            "<?xml version=\"1.0\"?><SomethingElse/>",
        ] {
            let response = server.handle_container(body, &peer());
            assert!(
                response.contains("X1TopLevelErrorResponse"),
                "{body:?} should yield a top-level error, got: {response}"
            );
        }
    }

    #[test]
    fn an_out_of_profile_message_type_returns_1080_not_a_container_failure() {
        let (server, _) = server();
        let body = request(&[
            ("PingRequest", String::new()),
            ("DeleteAllObjectsRequest", String::new()),
        ]);
        let response = server.handle_container(&body, &peer());
        assert!(response.contains("PingResponse"), "{response}");
        assert!(response.contains("<errorCode>1080</errorCode>"), "{response}");
        assert!(!response.contains("X1TopLevelErrorResponse"));
    }

    #[test]
    fn a_network_element_to_admf_report_is_refused_inbound() {
        let (server, _) = server();
        let response = server.handle_container(
            &request(&[(
                "ReportNEIssueRequest",
                "<typeOfNeIssueMessage>Warning</typeOfNeIssueMessage>\
                 <description>test</description>"
                    .to_string(),
            )]),
            &peer(),
        );
        assert!(response.contains("<errorCode>1080</errorCode>"), "{response}");
    }

    #[test]
    fn an_unexpected_admf_identifier_returns_1040() {
        let (server, _) = server();
        let body = request(&[("PingRequest", String::new())])
            .replace(&format!("<admfIdentifier>{ADMF}</admfIdentifier>"), "<admfIdentifier>other-admf</admfIdentifier>");
        let response = server.handle_container(&body, &peer());
        assert!(response.contains("<errorCode>1040</errorCode>"), "{response}");
    }

    #[test]
    fn an_unexpected_ne_identifier_returns_1060() {
        let (server, _) = server();
        let body = request(&[("PingRequest", String::new())])
            .replace(&format!("<neIdentifier>{NE}</neIdentifier>"), "<neIdentifier>some-other-ne</neIdentifier>");
        let response = server.handle_container(&body, &peer());
        assert!(response.contains("<errorCode>1060</errorCode>"), "{response}");
    }

    #[test]
    fn a_certificate_that_does_not_match_the_admf_identifier_returns_1030() {
        let audit = Arc::new(AuditLog::default());
        let mut settings = config();
        settings.bind_admf_identifier_to_certificate = true;
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
        let server = X1Server::new(&settings, tasks, destinations, audit.hook()).unwrap();

        let wrong_peer = PeerIdentity {
            common_name: Some("someone-else".to_string()),
        };
        let response =
            server.handle_container(&request(&[("PingRequest", String::new())]), &wrong_peer);
        assert!(response.contains("<errorCode>1030</errorCode>"), "{response}");
    }

    #[test]
    fn a_certificate_with_no_common_name_returns_1030_when_binding_is_on() {
        let audit = Arc::new(AuditLog::default());
        let mut settings = config();
        settings.bind_admf_identifier_to_certificate = true;
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
        let server = X1Server::new(&settings, tasks, destinations, audit.hook()).unwrap();

        let response = server.handle_container(
            &request(&[("PingRequest", String::new())]),
            &PeerIdentity::default(),
        );
        assert!(response.contains("<errorCode>1030</errorCode>"), "{response}");
    }

    #[test]
    fn a_matching_certificate_is_accepted_when_binding_is_on() {
        let audit = Arc::new(AuditLog::default());
        let mut settings = config();
        settings.bind_admf_identifier_to_certificate = true;
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
        let server = X1Server::new(&settings, tasks, destinations, audit.hook()).unwrap();

        let response = server.handle_container(&request(&[("PingRequest", String::new())]), &peer());
        assert!(response.contains("PingResponse"), "{response}");
    }

    #[test]
    fn a_content_warrant_is_refused_when_the_backend_cannot_deliver_it() {
        for delivery in [DeliveryType::X3Only, DeliveryType::X2AndX3] {
            let (server, _) = server_with(ContentCapability::WrongBackend {
                backend: "rtpengine",
            });
            let d_id = provision_destination(&server, DeliveryType::X2AndX3);
            let response = server.handle_container(
                &request(&[(
                    "ActivateTaskRequest",
                    activate_task_payload(XId::generate(), d_id, delivery),
                )]),
                &peer(),
            );
            assert!(
                response.contains("<errorCode>3040</errorCode>"),
                "{delivery} should be refused with 3040, got: {response}"
            );
            assert!(
                response.contains("rtpengine"),
                "the refusal must name the backend: {response}"
            );
            assert!(
                server.tasks().is_empty(),
                "a refused warrant must not be provisioned"
            );
        }
    }

    #[test]
    fn an_iri_warrant_is_accepted_on_any_backend() {
        let (server, _) = server_with(ContentCapability::WrongBackend {
            backend: "rtpproxy",
        });
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let response = server.handle_container(
            &request(&[(
                "ActivateTaskRequest",
                activate_task_payload(XId::generate(), d_id, DeliveryType::X2Only),
            )]),
            &peer(),
        );
        assert!(response.contains("ActivateTaskResponse"), "{response}");
        assert_eq!(server.tasks().len(), 1);
    }

    #[test]
    fn an_unsupported_target_identifier_returns_3010() {
        let (server, _) = server();
        let d_id = provision_destination(&server, DeliveryType::X2Only);
        let payload = format!(
            r#"<taskDetails>
      <xId>{}</xId>
      <targetIdentifiers>
        <targetIdentifier><gtpuTunnelId>42</gtpuTunnelId></targetIdentifier>
      </targetIdentifiers>
      <deliveryType>X2Only</deliveryType>
      <listOfDIDs><dId>{d_id}</dId></listOfDIDs>
    </taskDetails>"#,
            XId::generate()
        );
        let response =
            server.handle_container(&request(&[("ActivateTaskRequest", payload)]), &peer());
        assert!(response.contains("<errorCode>3010</errorCode>"), "{response}");
        assert!(response.contains("gtpuTunnelId"), "{response}");
    }

    #[test]
    fn a_compressed_ipv6_destination_is_refused() {
        let (server, _) = server();
        let payload = format!(
            r#"<destinationDetails>
      <dId>{}</dId>
      <deliveryType>X2Only</deliveryType>
      <deliveryAddress>
        <ipAddressAndPort>
          <c:address><c:IPv6Address>2001:db8::1</c:IPv6Address></c:address>
          <c:port><c:TCPPort>42069</c:TCPPort></c:port>
        </ipAddressAndPort>
      </deliveryAddress>
    </destinationDetails>"#,
            DId::generate()
        );
        let response =
            server.handle_container(&request(&[("CreateDestinationRequest", payload)]), &peer());
        // Refused per-message, not at container level: a malformed message
        // must not cost its siblings their answers.
        assert!(
            response.contains("ErrorResponse"),
            "a compressed IPv6 address must be refused: {response}"
        );
        assert!(
            !response.contains("X1TopLevelErrorResponse"),
            "the container itself was readable, so this is a per-message failure: {response}"
        );
        assert!(response.contains("<errorCode>1010</errorCode>"), "{response}");
        assert!(server.destinations().is_empty());
    }

    #[test]
    fn a_structurally_invalid_message_fails_alone() {
        // Schema validation runs per message, so one message missing a
        // mandatory element must not cost its siblings their answers.
        let (server, _) = server();
        let broken = format!(
            r#"<taskDetails>
      <xId>{}</xId>
      <targetIdentifiers>
        <targetIdentifier><sipUri>sip:alice@example.com</sipUri></targetIdentifier>
      </targetIdentifiers>
      <listOfDIDs><dId>{}</dId></listOfDIDs>
    </taskDetails>"#,
            XId::generate(),
            DId::generate()
        );
        let body = request(&[
            ("PingRequest", String::new()),
            ("ActivateTaskRequest", broken),
            ("KeepaliveRequest", String::new()),
        ]);
        let response = server.handle_container(&body, &peer());

        assert!(response.contains("PingResponse"), "{response}");
        assert!(response.contains("KeepaliveResponse"), "{response}");
        assert!(response.contains("ErrorResponse"), "{response}");
        assert!(
            !response.contains("X1TopLevelErrorResponse"),
            "the container was readable, so this must be per-message: {response}"
        );
        assert_eq!(response.matches("x1ResponseMessage").count(), 6);
    }

    #[test]
    fn an_expanded_ipv6_destination_round_trips_expanded() {
        let (server, _) = server();
        let d_id = DId::generate();
        let payload = format!(
            r#"<destinationDetails>
      <dId>{d_id}</dId>
      <deliveryType>X2Only</deliveryType>
      <deliveryAddress>
        <ipAddressAndPort>
          <c:address><c:IPv6Address>2001:0db8:1c18:6b8c:0000:0000:0000:0001</c:IPv6Address></c:address>
          <c:port><c:TCPPort>42069</c:TCPPort></c:port>
        </ipAddressAndPort>
      </deliveryAddress>
    </destinationDetails>"#
        );
        let created =
            server.handle_container(&request(&[("CreateDestinationRequest", payload)]), &peer());
        assert!(created.contains("CreateDestinationResponse"), "{created}");

        let fetched = server.handle_container(
            &request(&[("GetDestinationDetailsRequest", format!("<dId>{d_id}</dId>"))]),
            &peer(),
        );
        assert!(
            fetched.contains("2001:0db8:1c18:6b8c:0000:0000:0000:0001"),
            "the address must come back expanded: {fetched}"
        );
        assert!(!fetched.contains("2001:db8:1c18:6b8c::1"));
    }

    #[test]
    fn a_bad_ne_identifier_fails_at_construction() {
        let audit = Arc::new(AuditLog::default());
        let mut settings = config();
        settings.ne_identifier = "has\ttab".to_string();
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
        assert!(X1Server::new(&settings, tasks, destinations, audit.hook()).is_err());
    }

    #[test]
    fn a_bad_version_fails_at_construction() {
        let audit = Arc::new(AuditLog::default());
        let mut settings = config();
        settings.version = "1.23.1".to_string();
        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
        assert!(X1Server::new(&settings, tasks, destinations, audit.hook()).is_err());
    }

    #[test]
    fn the_admf_block_is_optional() {
        let settings = config();
        assert!(settings.admf.is_none());
        let with_admf = LiX1AdmfConfig {
            endpoint: "https://admf.example/X1/ADMF".to_string(),
            client_certificate: "/etc/siphon/li/ne.pem".to_string(),
            client_private_key: "/etc/siphon/li/ne.key".to_string(),
            server_ca: None,
            keepalive_secs: 30,
            request_timeout_secs: 10,
            reconcile_on_start: true,
        };
        assert_eq!(with_admf.keepalive_secs, 30);
    }
}
