//! APIBAN parameters changed at run time: the poller reads them each
//! iteration, a reload wakes it, and it is never respawned. Driven against a
//! mock feed on loopback.

use std::sync::Mutex;

use super::*;

const KEY_A: &str = "key-for-account-a";
const KEY_B: &str = "key-for-account-b";

/// Every `(key, id)` the mock feed was asked for, in order.
#[derive(Clone, Default)]
struct Requests(Arc<Mutex<Vec<(String, String)>>>);

impl Requests {
    fn snapshot(&self) -> Vec<(String, String)> {
        self.0.lock().expect("the request log").clone()
    }

    /// Wait (real time, bounded) until `predicate` holds over the log.
    async fn wait_for(&self, what: &str, predicate: impl Fn(&[(String, String)]) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !predicate(&self.snapshot()) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}: {:?}",
                self.snapshot()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// A feed that lists one address per key on the first page (id 100) and has
/// nothing new after. A key starting `echo` answers 500 with the request path
/// in the body, as a server that echoes it would.
async fn mock_feed() -> (String, Requests) {
    use axum::extract::{Path, State};
    use axum::http::StatusCode;

    async fn banned(
        State(requests): State<Requests>,
        Path((key, id)): Path<(String, String)>,
    ) -> (StatusCode, String) {
        requests
            .0
            .lock()
            .expect("the request log")
            .push((key.clone(), id.clone()));
        if key.starts_with("echo") {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("no route for /{key}/banned/{id}"),
            );
        }
        if id == INITIAL_ID {
            let address = if key == KEY_B {
                "198.51.100.66"
            } else {
                "203.0.113.66"
            };
            return (
                StatusCode::OK,
                format!(r#"{{"ID":"200","ipaddress":["{address}"]}}"#),
            );
        }
        (StatusCode::OK, "no new bans".to_owned())
    }

    let requests = Requests::default();
    let router = axum::Router::new()
        .route("/{key}/banned/{id}", axum::routing::get(banned))
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("its address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}"), requests)
}

fn config(api_key: &str, interval_secs: u64, ban_ttl_secs: u64) -> ApiBanConfig {
    ApiBanConfig {
        api_key: api_key.to_owned(),
        interval_secs,
        ban_ttl_secs,
    }
}

fn client(base_url: String, api_key: &str, interval_secs: u64) -> ApiBanClient {
    ApiBanClient::new(&config(api_key, interval_secs, 3600), &[])
        .expect("client builds")
        .with_base_url(base_url)
}

/// A new key restarts the cursor (it belongs to the old account) and is the
/// one fetched with from then on, by the same poller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_change_restarts_from_the_first_id_on_the_same_poller() {
    let (base_url, requests) = mock_feed().await;
    let client = client(base_url, KEY_A, 3600);
    let banned = client.banned();
    let control = client.spawn_poller();
    requests
        .wait_for("the first fetch", |log| !log.is_empty())
        .await;
    assert_eq!(
        requests.snapshot(),
        [(KEY_A.to_owned(), INITIAL_ID.to_owned())]
    );
    let tasks = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();

    control.apply(ApiBanParams::from_config(&config(KEY_B, 3600, 3600)));
    requests
        .wait_for("a fetch with the new key", |log| log.len() >= 2)
        .await;
    assert_eq!(
        requests.snapshot()[1],
        (KEY_B.to_owned(), INITIAL_ID.to_owned()),
        "from the first id, with the new key"
    );
    assert!(banned.contains(&"198.51.100.66".parse().expect("an address")));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(requests.snapshot().len(), 2, "one poller, one fetch each");
    assert_eq!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        tasks,
        "no poller was spawned for the new key"
    );
}

/// A shorter interval takes effect at once: the reload wakes the poller
/// rather than leaving it to sleep out the old hour. Real time, bounded: a
/// paused clock would also auto-advance through the HTTP client's own
/// timeouts while a request is in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interval_change_does_not_wait_out_the_old_interval() {
    let (base_url, requests) = mock_feed().await;
    let control = client(base_url, KEY_A, 3600).spawn_poller();
    requests
        .wait_for("the first fetch", |log| !log.is_empty())
        .await;

    control.apply(ApiBanParams::from_config(&config(KEY_A, 1, 3600)));
    requests
        .wait_for("the fetch the reload woke", |log| log.len() >= 2)
        .await;
    assert_eq!(
        requests.snapshot()[1],
        (KEY_A.to_owned(), "200".to_owned()),
        "same key: the cursor carries on"
    );
    // And the new interval, a second, is what it sleeps from now on.
    requests
        .wait_for("a fetch one new interval later", |log| log.len() >= 3)
        .await;

    // An unchanged reload does not wake it.
    let before = requests.snapshot().len();
    control.apply(ApiBanParams::from_config(&config(KEY_A, 3600, 3600)));
    requests
        .wait_for("the fetch the change woke", |log| log.len() > before)
        .await;
    // Let a wake that landed mid-fetch play out before counting.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let settled = requests.snapshot().len();
    control.apply(ApiBanParams::from_config(&config(KEY_A, 3600, 3600)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(requests.snapshot().len(), settled);
}

/// A new entry lifetime applies to what is ingested from then on; an entry
/// already held keeps its deadline.
#[test]
fn a_ban_ttl_change_applies_to_new_entries_only() {
    let client = ApiBanClient::new(&config(KEY_A, 300, 7200), &[]).expect("client builds");
    let control = client.control();
    assert_eq!(client.ingest(&["203.0.113.1".to_owned()]), 1);
    control.apply(ApiBanParams::from_config(&config(KEY_A, 300, 60)));
    assert_eq!(client.ingest(&["203.0.113.2".to_owned()]), 1);

    let remaining = |text: &str| {
        let address: IpAddr = text.parse().expect("an address");
        client
            .banned
            .entries
            .get(&address)
            .and_then(|entry| *entry.value())
            .expect("a timed entry")
            .saturating_duration_since(Instant::now())
    };
    assert!(remaining("203.0.113.1") > Duration::from_secs(3600));
    assert!(remaining("203.0.113.2") <= Duration::from_secs(60));
}

/// The key is part of the request path, so it is one careless format away
/// from every error line. Neither a transport error, nor a server echoing the
/// path, nor a `Debug` of the parameters or the config prints it.
///
/// In its own process: tracing's per-callsite interest is process-wide, and a
/// test elsewhere in the binary registering a quieter subscriber at the same
/// moment can leave this one's lines unrecorded.
#[test]
fn the_key_never_reaches_a_log_line() {
    crate::own_process::run(
        concat!(module_path!(), "::the_key_never_reaches_a_log_line"),
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime")
                .block_on(key_never_reaches_a_log_line());
        },
    );
}

async fn key_never_reaches_a_log_line() {
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // A server that echoes the path in a 500.
    let (base_url, requests) = mock_feed().await;
    let control = client(base_url, "echo-secret-one", 3600).spawn_poller();
    requests
        .wait_for("the echoing fetch", |log| !log.is_empty())
        .await;
    // A transport error, whose message names the URL unless stripped.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let closed_url = format!("http://{}", closed.local_addr().expect("its address"));
    drop(closed);
    let _unreachable = client(closed_url, "echo-secret-two", 3600).spawn_poller();
    // A reload to another key on the first poller.
    control.apply(ApiBanParams::from_config(&config(
        "echo-secret-three",
        3600,
        3600,
    )));
    requests
        .wait_for("the fetch with the new key", |log| log.len() >= 2)
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while log.rendered().matches("APIBAN fetch failed").count() < 3 {
        assert!(tokio::time::Instant::now() < deadline, "{}", log.rendered());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let rendered = log.rendered();
    assert!(rendered.contains("<redacted>"), "{rendered}");
    for secret in ["echo-secret-one", "echo-secret-two", "echo-secret-three"] {
        assert!(!rendered.contains(secret), "{secret} logged: {rendered}");
    }
    let params = format!("{:?}", control.params());
    let config = format!("{:?}", config("echo-secret-four", 300, 60));
    assert!(!params.contains("echo-secret") && !config.contains("echo-secret"));
}
