//! The network-element-to-ADMF direction, proven on the wire.
//!
//! These tests stand up a mock ADMF that captures what siphon actually sends
//! and answers it, so the whole path is exercised: build the envelope, encode,
//! validate, POST, read the answer, decode, act on it.
//!
//! That last step is the point. Without it, `spawn()` could reconcile against
//! nothing and no test would notice — the provisioning state would silently
//! stay empty after a restart while the ADMF believed warrants were live.
//!
//! The mock speaks plain HTTP. Mutual TLS on this interface is proven by the
//! listener tests in `li_tests.rs`; repeating the handshake here would only
//! re-test rustls. What is under test is the message layer and the effect.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siphon::config::{LiX1AdmfConfig, LiX1Config, LiX1TlsConfig};
use siphon::li::x1::client::X1Client;
use siphon::li::x1::codec::encode_response_container;
use siphon::li::x1::message::{
    DestinationDetails, DestinationResponseDetails, DestinationStatus, Envelope, MessageKind,
    NeStatusDetails, ResponseBody, ResponseContainer, ResponseMessage, TaskDetails,
    TaskResponseDetails, TaskStatus,
};
use siphon::li::x1::store::{ContentCapability, DestinationStore, TaskStore};
use siphon::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, DestinationDeliveryStatus, IpAddressPort, NeStatus,
    OkValue, Port, ProvisioningStatus, TargetIdentifier, TaskReportType, Timestamp, Token,
    TypeOfNeIssueMessage, Version, XId, X1TransactionId, DEFAULT_VERSION,
};
use siphon::li::x1::X1Schema;

const ADMF: &str = "admf-id";
const NE: &str = "siphon-ne";

// ---------------------------------------------------------------------------
// A mock ADMF
// ---------------------------------------------------------------------------

/// What the ADMF answers with, and what it saw.
#[derive(Clone, Default)]
struct AdmfState {
    /// Every request body siphon sent, in order.
    received: Arc<Mutex<Vec<String>>>,
    /// The canned response body. When `None` the ADMF answers 500.
    response: Arc<Mutex<Option<String>>>,
}

impl AdmfState {
    fn requests(&self) -> Vec<String> {
        self.received
            .lock()
            .map(|received| received.clone())
            .unwrap_or_default()
    }

    fn set_response(&self, body: String) {
        if let Ok(mut response) = self.response.lock() {
            *response = Some(body);
        }
    }
}

/// Start a mock ADMF on an ephemeral port. Returns its address and state.
async fn start_mock_admf() -> (SocketAddr, AdmfState) {
    use http_body_util::BodyExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock ADMF must bind");
    let address = listener.local_addr().expect("local addr");
    let state = AdmfState::default();

    let served = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = served.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    async move {
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes())
                            .unwrap_or_default();
                        let text = String::from_utf8_lossy(&body).into_owned();
                        if let Ok(mut received) = state.received.lock() {
                            received.push(text);
                        }

                        let canned = state.response.lock().ok().and_then(|body| body.clone());
                        let response = match canned {
                            Some(body) => hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/xml")
                                .body(body),
                            None => hyper::Response::builder().status(500).body(String::new()),
                        };
                        Ok::<_, std::convert::Infallible>(
                            response.unwrap_or_else(|_| hyper::Response::new(String::new())),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    (address, state)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A client certificate and key on disk, so `X1Client::new` can load them.
fn write_client_identity(directory: &tempfile::TempDir) -> (String, String) {
    use rcgen::{CertificateParams, DnType, KeyPair};
    use std::io::Write;

    let key = KeyPair::generate().expect("keygen");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, NE);
    let certificate = params.self_signed(&key).expect("self-sign");

    let write = |name: &str, contents: String| {
        let path = directory.path().join(name);
        let mut file = std::fs::File::create(&path).expect("write pem");
        file.write_all(contents.as_bytes()).expect("write pem");
        path.to_string_lossy().into_owned()
    };
    (
        write("ne.pem", certificate.pem()),
        write("ne.key", key.serialize_pem()),
    )
}

fn x1_config() -> LiX1Config {
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
        bind_admf_identifier_to_certificate: true,
        admf: None,
    }
}

fn admf_config(address: SocketAddr, directory: &tempfile::TempDir) -> LiX1AdmfConfig {
    let (certificate, key) = write_client_identity(directory);
    LiX1AdmfConfig {
        endpoint: format!("http://{address}/X1/ADMF"),
        client_certificate: certificate,
        client_private_key: key,
        server_ca: None,
        keepalive_secs: 0,
        request_timeout_secs: 5,
        reconcile_on_start: true,
    }
}

fn build_client(address: SocketAddr, directory: &tempfile::TempDir) -> Arc<X1Client> {
    let schema = Arc::new(X1Schema::compile().expect("schemas must compile"));
    Arc::new(
        X1Client::new(&x1_config(), &admf_config(address, directory), schema)
            .expect("client must build"),
    )
}

/// The envelope the mock ADMF answers with.
fn admf_envelope() -> Envelope {
    Envelope {
        admf_identifier: Token::parse(ADMF, "admfIdentifier").unwrap(),
        ne_identifier: Token::parse(NE, "neIdentifier").unwrap(),
        message_timestamp: Timestamp::now(),
        version: Version::parse(DEFAULT_VERSION).unwrap(),
        x1_transaction_id: X1TransactionId::generate(),
    }
}

fn ok_response(kind: MessageKind) -> String {
    encode_response_container(&ResponseContainer {
        messages: vec![ResponseMessage {
            envelope: admf_envelope(),
            kind,
            body: ResponseBody::Ok(OkValue::AcknowledgedAndCompleted),
        }],
    })
    .expect("encode")
}

fn destination(d_id: DId) -> DestinationDetails {
    DestinationDetails {
        d_id,
        friendly_name: Some("mdf".to_string()),
        delivery_type: DeliveryType::X2AndX3,
        delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 50)),
            port: Port::Tcp(42069),
        }),
    }
}

fn task(x_id: XId, d_id: DId) -> TaskDetails {
    TaskDetails {
        x_id,
        target_identifiers: vec![TargetIdentifier::SipUri("sip:alice@example.com".into())],
        delivery_type: DeliveryType::X2Only,
        list_of_dids: vec![d_id],
        list_of_dsids: Vec::new(),
        list_of_mediation_details: Vec::new(),
        correlation_id: None,
        implicit_deactivation_allowed: None,
        product_id: None,
        list_of_service_types: Vec::new(),
    }
}

/// A `GetAllDetailsResponse` describing one task and one destination.
fn all_details_response(x_id: XId, d_id: DId) -> String {
    encode_response_container(&ResponseContainer {
        messages: vec![ResponseMessage {
            envelope: admf_envelope(),
            kind: MessageKind::GetAllDetails,
            body: ResponseBody::AllDetails {
                ne_status: NeStatusDetails {
                    ne_status: NeStatus::Ok,
                    list_of_faults: Vec::new(),
                },
                tasks: vec![TaskResponseDetails {
                    task_details: task(x_id, d_id),
                    task_status: TaskStatus {
                        provisioning_status: ProvisioningStatus::Complete,
                        list_of_faults: Vec::new(),
                        time_of_last_intercept: None,
                        time_of_last_modification: None,
                        number_of_modifications: Some(0),
                    },
                }],
                destinations: vec![DestinationResponseDetails {
                    destination_details: destination(d_id),
                    destination_status: DestinationStatus {
                        destination_delivery_status: DestinationDeliveryStatus::ActiveAndWorking,
                        list_of_faults: Vec::new(),
                    },
                }],
            },
        }],
    })
    .expect("encode")
}

fn stores() -> (TaskStore, DestinationStore) {
    let destinations = DestinationStore::new();
    let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
    (tasks, destinations)
}

/// Poll until `condition` holds or the deadline passes.
async fn wait_for(label: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {label}");
}

// ---------------------------------------------------------------------------
// What siphon actually puts on the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_keepalive_reaches_the_admf_with_the_right_envelope() {
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::Keepalive));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);

    client.keepalive().await.expect("keepalive must succeed");

    let requests = admf.requests();
    assert_eq!(requests.len(), 1, "exactly one request should have been sent");
    let sent = &requests[0];
    assert!(sent.contains(r#"xsi:type="KeepaliveRequest""#), "{sent}");
    assert!(sent.contains(&format!("<admfIdentifier>{ADMF}</admfIdentifier>")), "{sent}");
    assert!(sent.contains(&format!("<neIdentifier>{NE}</neIdentifier>")), "{sent}");
    assert!(sent.contains(&format!("<version>{DEFAULT_VERSION}</version>")), "{sent}");
    assert!(sent.contains("<x1TransactionId>"), "{sent}");
}

#[tokio::test]
async fn a_ne_issue_report_carries_its_type_and_description() {
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::ReportNEIssue));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);

    client
        .report_ne_issue(
            TypeOfNeIssueMessage::FaultReport,
            "media backend unavailable",
            Some(9020),
        )
        .await
        .expect("report must succeed");

    let sent = &admf.requests()[0];
    assert!(sent.contains(r#"xsi:type="ReportNEIssueRequest""#), "{sent}");
    assert!(sent.contains("<typeOfNeIssueMessage>FaultReport</typeOfNeIssueMessage>"), "{sent}");
    assert!(sent.contains("<description>media backend unavailable</description>"), "{sent}");
    assert!(sent.contains("<issueCode>9020</issueCode>"), "{sent}");
}

#[tokio::test]
async fn a_task_issue_report_names_the_task() {
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::ReportTaskIssue));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);
    let x_id = XId::generate();

    client
        .report_task_issue(
            x_id,
            TaskReportType::FullyActionedAndSuccessful,
            Some(9040),
            Some("task activated".to_string()),
        )
        .await
        .expect("report must succeed");

    let sent = &admf.requests()[0];
    assert!(sent.contains(r#"xsi:type="ReportTaskIssueRequest""#), "{sent}");
    assert!(sent.contains(&format!("<xId>{x_id}</xId>")), "{sent}");
    assert!(
        sent.contains("<taskReportType>FullyActionedAndSuccessful</taskReportType>"),
        "{sent}"
    );
}

#[tokio::test]
async fn a_destination_issue_report_names_the_destination() {
    // The message that tells the ADMF a mediation function went away. Without
    // it a delivery outage is survived silently and never reported.
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::ReportDestinationIssue));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);
    let d_id = DId::generate();

    client
        .report_destination_issue(
            d_id,
            TaskReportType::TerminatingFault,
            Some(9030),
            Some("delivery connection lost".to_string()),
        )
        .await
        .expect("report must succeed");

    let sent = &admf.requests()[0];
    assert!(sent.contains(r#"xsi:type="ReportDestinationIssueRequest""#), "{sent}");
    assert!(sent.contains(&format!("<dId>{d_id}</dId>")), "{sent}");
    assert!(
        sent.contains("<destinationReportType>TerminatingFault</destinationReportType>"),
        "{sent}"
    );
    assert!(
        sent.contains("<destinationIssueDetails>delivery connection lost</destinationIssueDetails>"),
        "{sent}"
    );
}

#[tokio::test]
async fn get_all_details_sends_the_query_and_parses_the_answer() {
    let (address, admf) = start_mock_admf().await;
    let x_id = XId::generate();
    let d_id = DId::generate();
    admf.set_response(all_details_response(x_id, d_id));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);

    let state = client
        .get_all_details()
        .await
        .expect("reconciliation query must succeed");

    let sent = &admf.requests()[0];
    assert!(sent.contains(r#"xsi:type="GetAllDetailsRequest""#), "{sent}");
    assert_eq!(state.tasks.len(), 1);
    assert_eq!(state.tasks[0].x_id, x_id);
    assert_eq!(state.destinations.len(), 1);
    assert_eq!(state.destinations[0].d_id, d_id);
}

#[tokio::test]
async fn an_admf_that_answers_an_http_error_is_reported_not_swallowed() {
    let (address, admf) = start_mock_admf().await;
    // No canned response: the mock answers 500.
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);

    let error = client
        .keepalive()
        .await
        .expect_err("an HTTP error must surface");
    assert!(error.description.contains("500"), "{}", error.description);
    assert_eq!(admf.requests().len(), 1, "the request was still sent");
}

#[tokio::test]
async fn an_answer_to_the_wrong_message_is_refused() {
    // A response whose type does not match the request cannot be trusted to
    // be the answer to it.
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::ActivateTask));
    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);

    let error = client
        .keepalive()
        .await
        .expect_err("a mismatched answer must be refused");
    assert!(
        error.description.contains("ActivateTask"),
        "{}",
        error.description
    );
}

// ---------------------------------------------------------------------------
// The effect actually firing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn spawn_reconciles_provisioned_state_from_the_admf() {
    // The restart case, end to end: empty stores, `spawn()` runs, siphon
    // issues GetAllDetails on its own, and the answer lands in the stores.
    //
    // This is the test that proves the reconciliation is wired rather than
    // merely written — `apply_reconciled_state` being correct means nothing if
    // nothing ever calls it.
    let (address, admf) = start_mock_admf().await;
    let x_id = XId::generate();
    let d_id = DId::generate();
    admf.set_response(all_details_response(x_id, d_id));

    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);
    let config = admf_config(address, &directory);
    let (tasks, destinations) = stores();
    assert!(tasks.is_empty(), "the stores start empty, as after a restart");

    siphon::li::x1::client::spawn(client, &config, tasks.clone(), destinations.clone());

    wait_for("the reconciled task to land", || tasks.len() == 1).await;
    assert_eq!(tasks.get(x_id).map(|task| task.details.x_id), Some(x_id));
    assert_eq!(destinations.len(), 1);
    assert!(destinations.contains(d_id));

    // And the restored warrant matches, so interception resumes after the
    // restart rather than quietly not.
    assert_eq!(
        tasks
            .match_message(None, Some("sip:alice@example.com"), None, None)
            .len(),
        1
    );

    // The ADMF also heard that the node came up.
    wait_for("the startup report", || {
        admf.requests()
            .iter()
            .any(|body| body.contains("ReportNEIssueRequest"))
    })
    .await;
}

#[tokio::test]
async fn spawn_announces_startup_even_with_reconciliation_disabled() {
    let (address, admf) = start_mock_admf().await;
    admf.set_response(ok_response(MessageKind::ReportNEIssue));

    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);
    let mut config = admf_config(address, &directory);
    config.reconcile_on_start = false;
    let (tasks, destinations) = stores();

    siphon::li::x1::client::spawn(client, &config, tasks.clone(), destinations);

    wait_for("the startup report", || {
        admf.requests()
            .iter()
            .any(|body| body.contains("ReportNEIssueRequest"))
    })
    .await;
    assert!(
        !admf
            .requests()
            .iter()
            .any(|body| body.contains("GetAllDetailsRequest")),
        "reconciliation was disabled, so no query should have been sent"
    );
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn an_unreachable_admf_does_not_stop_the_node() {
    // A node must keep serving the warrants it already has even when the ADMF
    // is down; the divergence is logged and retried, not fatal.
    let directory = tempfile::tempdir().expect("tempdir");
    // Bind and immediately drop, so the port is almost certainly closed.
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        listener.local_addr().expect("addr")
    };
    let client = build_client(dead, &directory);
    let config = admf_config(dead, &directory);
    let (tasks, destinations) = stores();

    siphon::li::x1::client::spawn(client, &config, tasks.clone(), destinations);

    // Give the spawned work a moment to fail.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn reconciliation_reports_a_warrant_it_cannot_honour() {
    // The ADMF believes a content warrant is live here. On a node that cannot
    // deliver content it is not, and the ADMF has to be told — otherwise the
    // two sides disagree and only one of them knows.
    let (address, admf) = start_mock_admf().await;
    let x_id = XId::generate();
    let d_id = DId::generate();

    let mut content_task = task(x_id, d_id);
    content_task.delivery_type = DeliveryType::X2AndX3;
    let response = encode_response_container(&ResponseContainer {
        messages: vec![ResponseMessage {
            envelope: admf_envelope(),
            kind: MessageKind::GetAllDetails,
            body: ResponseBody::AllDetails {
                ne_status: NeStatusDetails {
                    ne_status: NeStatus::Ok,
                    list_of_faults: Vec::new(),
                },
                tasks: vec![TaskResponseDetails {
                    task_details: content_task,
                    task_status: TaskStatus {
                        provisioning_status: ProvisioningStatus::Complete,
                        list_of_faults: Vec::new(),
                        time_of_last_intercept: None,
                        time_of_last_modification: None,
                        number_of_modifications: Some(0),
                    },
                }],
                destinations: vec![DestinationResponseDetails {
                    destination_details: destination(d_id),
                    destination_status: DestinationStatus {
                        destination_delivery_status: DestinationDeliveryStatus::ActiveAndWorking,
                        list_of_faults: Vec::new(),
                    },
                }],
            },
        }],
    })
    .expect("encode");
    admf.set_response(response);

    let directory = tempfile::tempdir().expect("tempdir");
    let client = build_client(address, &directory);
    let config = admf_config(address, &directory);

    let destinations = DestinationStore::new();
    let tasks = TaskStore::new(
        destinations.clone(),
        ContentCapability::WrongBackend {
            backend: "rtpengine",
        },
    );

    siphon::li::x1::client::spawn(client, &config, tasks.clone(), destinations.clone());

    // The destination applies; the warrant does not, and a fault report goes
    // back naming it.
    wait_for("the destination to land", || destinations.len() == 1).await;
    wait_for("the rejection report", || {
        admf.requests().iter().any(|body| {
            body.contains("ReportNEIssueRequest") && body.contains(&x_id.to_string())
        })
    })
    .await;
    assert!(
        tasks.is_empty(),
        "a warrant this node cannot honour must not read as provisioned"
    );
}
