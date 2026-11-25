//! The credential lookup by AoR, and what the source tells the manager about
//! a pass: the contract a controller's endpoint implements.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::registrant::test_support;

const AOR: &str = "sip:trunk@carrier.example";

/// One canned HTTP answer, and the requests it saw.
struct Stub {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn stub(status: &str, body: &str) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if let Ok(mut seen) = seen.lock() {
                seen.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            }
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    Stub { base, requests }
}

fn source(base: &str, lookup: bool) -> RegistrantSource {
    RegistrantSource::Http(
        HttpSource::new(crate::config::RegistrantHttpConfig {
            url: format!("{base}/trunks"),
            refresh_secs: 30,
            timeout_ms: 1000,
            auth_header: Some("Bearer sentinel-token".to_string()),
            lookup_url: lookup.then(|| format!("{base}/trunks/lookup?aor={{aor}}")),
        })
        .expect("the HTTP client builds"),
    )
}

const ROW: &str = r#"{"aor":"sip:trunk@carrier.example","registrar":"sip:198.51.100.10:5060","username":"looked-up","ha1":"0123456789abcdef0123456789abcdef","ha1_algorithm":"md5","realm":"carrier.example","enabled":false}"#;

#[test]
fn an_aor_is_encoded_as_a_query_component() {
    assert_eq!(
        encode_query_component("sip:trunk@carrier.example"),
        "sip%3Atrunk%40carrier.example"
    );
    assert_eq!(
        encode_query_component("sip:a b&c=d/e?f#g+h@x.example;t=1"),
        "sip%3Aa%20b%26c%3Dd%2Fe%3Ff%23g%2Bh%40x.example%3Bt%3D1"
    );
    assert_eq!(
        encode_query_component("unreserved-._~09AZaz"),
        "unreserved-._~09AZaz"
    );
}

#[tokio::test]
async fn the_lookup_asks_for_the_aor_with_the_lists_authorization_and_reads_one_row() {
    let stub = stub("200 OK", ROW).await;
    let source = source(&stub.base, true);
    assert!(source.lookup_configured());

    let row = source
        .lookup_row(AOR)
        .await
        .expect("answered")
        .expect("a row");

    assert_eq!(row.username, "looked-up");
    assert!(!row.enabled, "a disabled row is still returned");
    let requests = stub.requests.lock().expect("lock");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /trunks/lookup?aor=sip%3Atrunk%40carrier.example HTTP/1.1"),
        "{}",
        requests[0]
    );
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer sentinel-token"),
        "{}",
        requests[0]
    );
}

#[tokio::test]
async fn a_404_is_an_unknown_trunk_not_an_error() {
    let stub = stub("404 Not Found", "").await;
    let outcome = source(&stub.base, true).lookup_row(AOR).await;
    assert!(matches!(outcome, Ok(None)), "{outcome:?}");
}

#[tokio::test]
async fn any_other_failure_is_an_error() {
    let server_error = stub("500 Internal Server Error", "").await;
    assert!(source(&server_error.base, true)
        .lookup_row(AOR)
        .await
        .is_err());

    let forbidden = stub("403 Forbidden", "").await;
    assert!(source(&forbidden.base, true).lookup_row(AOR).await.is_err());

    let garbage = stub("200 OK", "not json").await;
    assert!(source(&garbage.base, true).lookup_row(AOR).await.is_err());

    // Nothing listening: the connection is refused.
    assert!(source("http://127.0.0.1:1", true)
        .lookup_row(AOR)
        .await
        .is_err());
}

#[tokio::test]
async fn without_a_lookup_url_there_is_no_lookup() {
    let source = source("http://127.0.0.1:1", false);
    assert!(!source.lookup_configured());
    assert!(source.lookup_row(AOR).await.is_err());
    assert!(!CredentialLookup::is_configured(&source));
}

fn row(json: &str) -> RegistrantRow {
    serde_json::from_str(json).expect("a row")
}

#[test]
fn credentials_are_read_from_a_disabled_row_and_take_a_password_or_an_ha1() {
    let credentials = credentials_from_row(&row(ROW)).expect("credentials");
    assert_eq!(credentials.username, "looked-up");
    assert_eq!(credentials.realm.as_deref(), Some("carrier.example"));
    assert!(matches!(credentials.secret, StoredSecret::Ha1 { .. }));

    let credentials = credentials_from_row(&row(
        r#"{"aor":"sip:a@b.example","registrar":"sip:r.example","username":"u","password":"p"}"#,
    ))
    .expect("credentials");
    assert!(matches!(credentials.secret, StoredSecret::Password(_)));
}

#[test]
fn a_row_without_a_username_or_a_secret_gives_no_credentials() {
    assert!(credentials_from_row(&row(
        r#"{"aor":"sip:a@b.example","registrar":"sip:r.example","username":"","password":"p"}"#
    ))
    .is_err());
    assert!(credentials_from_row(&row(
        r#"{"aor":"sip:a@b.example","registrar":"sip:r.example","username":"u"}"#
    ))
    .is_err());
}

/// What a pass reports to the start-up cleanup: rows siphon rejected are
/// "still listed", disabled ones are not.
#[tokio::test]
async fn a_pass_reports_the_rejected_rows_and_the_loop_marks_the_first_read() {
    let body = r#"{"registrants":[
        {"aor":"sip:good@carrier.example","registrar":"sip:198.51.100.10:5060","username":"u","password":"p"},
        {"aor":"sip:bad@carrier.example","registrar":"sip:198.51.100.10:5060","username":"","password":"p"},
        {"aor":"sip:off@carrier.example","registrar":"sip:198.51.100.10:5060","username":"u","password":"p","enabled":false}
    ]}"#;
    let stub = stub("200 OK", body).await;
    let manager = Arc::new(test_support::manager());
    let source = Arc::new(source(&stub.base, false));

    let report = reconcile_once(&manager, &source).await.expect("a pass");
    assert_eq!(report.rejected, 1);

    // A bad row is still listed: its binding is left at restart. A disabled
    // one and an unlisted one are not.
    assert!(manager.source_row_unusable("sip:bad@carrier.example"));
    assert!(!manager.source_row_unusable("sip:off@carrier.example"));
    assert!(!manager.source_row_unusable("sip:gone@carrier.example"));

    assert!(!manager
        .restart
        .source_loaded
        .load(std::sync::atomic::Ordering::SeqCst));
    let loop_manager = Arc::clone(&manager);
    let task = tokio::spawn(reconcile_loop(loop_manager, source));
    for _ in 0..100 {
        if manager
            .restart
            .source_loaded
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        manager
            .restart
            .source_loaded
            .load(std::sync::atomic::Ordering::SeqCst),
        "the loop's first successful read marks the source loaded"
    );
    task.abort();
}

#[tokio::test]
async fn a_failed_first_read_does_not_mark_the_source_loaded() {
    let manager = Arc::new(test_support::manager());
    let source = Arc::new(source("http://127.0.0.1:1", false));
    let loop_manager = Arc::clone(&manager);
    let task = tokio::spawn(reconcile_loop(loop_manager, source));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!manager
        .restart
        .source_loaded
        .load(std::sync::atomic::Ordering::SeqCst));
    task.abort();
}

/// A row siphon cannot build an entry for (the registrar does not resolve) is
/// still listed, like a malformed one: its binding is left alone at restart.
#[tokio::test]
async fn a_row_whose_entry_cannot_be_built_still_counts_as_listed() {
    let body = r#"{"registrants":[
        {"aor":"sip:nodns@carrier.example","registrar":"sip:no-such-host.invalid:5060","username":"u","password":"p"}
    ]}"#;
    let stub = stub("200 OK", body).await;
    let manager = Arc::new(test_support::manager());
    let source = source(&stub.base, false);

    let report = reconcile_once(&manager, &source).await.expect("a pass");

    assert_eq!(report.rejected, 1);
    assert!(manager.source_row_unusable("sip:nodns@carrier.example"));
}

/// A slow DNS answer in a later pass must not unprotect the row: the old set
/// holds until the new one is complete.
#[tokio::test]
async fn a_rejected_row_stays_protected_while_a_later_pass_is_still_resolving() {
    let aor = "sip:slowdns@carrier.example";
    let body = format!(
        r#"{{"registrants":[{{"aor":"{aor}","registrar":"sip:no-such-host.invalid:5060","username":"u","password":"p"}}]}}"#
    );
    let stub = stub("200 OK", &body).await;
    let manager = Arc::new(test_support::manager());
    let source = source(&stub.base, false);
    reconcile_once(&manager, &source).await.expect("first pass");
    assert!(manager.source_row_unusable(aor));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    let watched = Arc::clone(&manager);
    let hook: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |building: &str| {
        if building == aor {
            if let Ok(mut seen) = observed.lock() {
                seen.push(watched.source_row_unusable(aor));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    if let Ok(mut slot) = BUILD_HOOK.lock() {
        *slot = Some(hook);
    }
    let second = reconcile_once(&manager, &source).await;
    if let Ok(mut slot) = BUILD_HOOK.lock() {
        *slot = None;
    }

    second.expect("second pass");
    assert_eq!(seen.lock().expect("lock").as_slice(), [true]);
    assert!(manager.source_row_unusable(aor));
}
