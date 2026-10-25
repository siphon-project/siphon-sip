//! A destination whose connect just failed costs one connect timeout per
//! backoff window, not one per send queued behind it, and concurrent sends to
//! one destination share a single connect. Real loopback sockets throughout.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;

use super::ConnectionPool;

/// The connect timeout the tests drive, short so a timeout costs milliseconds.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// Abort the test binary if a test wedges, rather than hanging CI. Drop the
/// returned sender when the test is done.
pub(crate) fn watchdog(name: &'static str) -> std::sync::mpsc::Sender<()> {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            finished.recv_timeout(Duration::from_secs(60))
        {
            eprintln!("{name}: wedged for 60 s, aborting");
            std::process::abort();
        }
    });
    done
}

/// A pool whose connects time out after [`CONNECT_TIMEOUT`].
pub(crate) fn pool() -> ConnectionPool {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut pool = ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("an address"),
        None,
        None,
        None,
        super::build_outbound_tls_config(None, crate::config::TlsMethod::default())
            .expect("outbound tls config"),
    );
    pool.set_connect_timeout(CONNECT_TIMEOUT);
    pool
}

/// A peer that is up but accepts nothing: a listener with a zero backlog whose
/// accept queue is full, so further SYNs are dropped and a connect runs its
/// whole timeout, as an overloaded node slow to accept does. The returned
/// sockets keep it that way while held. `None` when this kernel answers anyway
/// (the test then has nothing to show).
pub(crate) fn blackholed_peer() -> Option<(SocketAddr, Vec<std::net::TcpStream>, socket2::Socket)> {
    let listener = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).ok()?;
    let address: SocketAddr = "127.0.0.1:0".parse().ok()?;
    listener.bind(&address.into()).ok()?;
    listener.listen(0).ok()?;
    let peer = listener.local_addr().ok()?.as_socket()?;
    let mut held = Vec::new();
    for _ in 0..16 {
        match std::net::TcpStream::connect_timeout(&peer, Duration::from_millis(200)) {
            Ok(stream) => held.push(stream),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Some((peer, held, listener));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Start accepting on a blackholed peer's listener, so connects to it complete
/// again: the peer has caught up.
pub(crate) fn start_accepting(listener: socket2::Socket) -> Arc<AtomicUsize> {
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let listener: std::net::TcpListener = listener.into();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    accepted
}

/// A port nothing listens on, so a connect to it is refused.
fn refusing_peer() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("bound")
}

fn ping() -> Bytes {
    Bytes::from_static(b"OPTIONS sip:peer SIP/2.0\r\nContent-Length: 0\r\n\r\n")
}

/// Sends queued one after another behind a peer that never answers the SYN,
/// the way a fallback lane runs them: the first pays the connect timeout and
/// every one after it fails at once, so 64 of them cost about one timeout
/// instead of 64.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serial_sends_to_a_blackholed_peer_cost_one_connect_timeout() {
    let _watchdog = watchdog("serial_sends_to_a_blackholed_peer_cost_one_connect_timeout");
    let Some((peer, _held, _listener)) = blackholed_peer() else {
        eprintln!("kernel completes connects past a full accept queue; nothing to show");
        return;
    };
    let pool = pool();
    let started = Instant::now();
    let drained = tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..64 {
            assert!(pool.send_tcp(peer, ping()).await.is_err());
        }
    })
    .await;
    let elapsed = started.elapsed();
    eprintln!("64 serial sends to a blackholed peer: {elapsed:?}");
    assert!(
        drained.is_ok() && elapsed < CONNECT_TIMEOUT * 3,
        "64 sends to a blackholed peer took {elapsed:?} (or more than 3 s), \
         one connect timeout is {CONNECT_TIMEOUT:?}"
    );
}

/// Concurrent sends to a peer that never answers the SYN share the one connect
/// in flight: they all fail inside about one timeout, instead of queueing on
/// the establishment lock and each connecting in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sends_to_a_blackholed_peer_share_one_connect() {
    let _watchdog = watchdog("concurrent_sends_to_a_blackholed_peer_share_one_connect");
    let Some((peer, _held, _listener)) = blackholed_peer() else {
        eprintln!("kernel completes connects past a full accept queue; nothing to show");
        return;
    };
    let pool = Arc::new(pool());
    let started = Instant::now();
    let sends: Vec<_> = (0..16)
        .map(|_| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.send_tcp(peer, ping()).await })
        })
        .collect();
    let finished = tokio::time::timeout(Duration::from_secs(3), async {
        for send in sends {
            assert!(send.await.expect("the send task").is_err());
        }
    })
    .await;
    let elapsed = started.elapsed();
    eprintln!("16 concurrent sends to a blackholed peer: {elapsed:?}");
    assert!(
        finished.is_ok() && elapsed < CONNECT_TIMEOUT * 3,
        "16 concurrent sends to a blackholed peer took {elapsed:?} (or more than 3 s), \
         one connect timeout is {CONNECT_TIMEOUT:?}"
    );
}

/// Concurrent TLS sends coalesce onto one connect, as TCP sends do: a peer
/// that accepts the TCP connection but never completes the handshake sees one
/// connection, not one per send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tls_sends_make_one_connect() {
    let _watchdog = watchdog("concurrent_tls_sends_make_one_connect");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    let peer = listener.local_addr().expect("bound");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    let pool = Arc::new(pool());
    let sends: Vec<_> = (0..8)
        .map(|_| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.send_tls(peer, None, ping()).await })
        })
        .collect();
    for send in sends {
        let outcome = tokio::time::timeout(Duration::from_secs(5), send)
            .await
            .expect("a TLS send is bounded")
            .expect("the send task");
        assert!(outcome.is_err(), "the handshake never completes");
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "8 concurrent TLS sends opened more than one connection"
    );
}

/// A refused connect marks the peer down: a send inside the window fails at
/// once without connecting, even though the peer is back, and the first send
/// after the window connects and succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_peer_fails_fast_then_recovers_after_the_window() {
    let _watchdog = watchdog("a_refused_peer_fails_fast_then_recovers_after_the_window");
    let peer = refusing_peer();
    let pool = pool();
    assert!(pool.send_tcp(peer, ping()).await.is_err(), "refused");

    // The peer comes back inside the window.
    let listener = std::net::TcpListener::bind(peer).expect("rebind the refused port");
    let accepted = Arc::new(AtomicUsize::new(0));
    {
        let counter = Arc::clone(&accepted);
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept() {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
    }
    let started = Instant::now();
    let inside = pool.send_tcp(peer, ping()).await;
    assert!(
        inside.is_err(),
        "a send inside the backoff window must fail fast, not connect"
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no connect inside the window"
    );

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    pool.send_tcp(peer, ping())
        .await
        .expect("the first send after the window connects");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        pool.connect_state_len(),
        (0, 0),
        "the success clears the record"
    );
}

/// Per-module leak gate: a backoff record and an establishment lock exist per
/// destination only while a connect to it is failing or running, so after a
/// batch of destinations fail and then recover both stores are back to empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_state_drains_to_empty_once_destinations_recover() {
    let _watchdog = watchdog("connect_state_drains_to_empty_once_destinations_recover");
    let pool = Arc::new(pool());
    for batch in 0..2 {
        // A set: a port freed by one probe can be handed out again.
        let peers: std::collections::BTreeSet<SocketAddr> =
            (0..50).map(|_| refusing_peer()).collect();
        for peer in &peers {
            assert!(pool.send_tcp(*peer, ping()).await.is_err());
        }
        assert_eq!(
            pool.connect_state_len(),
            (peers.len(), 0),
            "batch {batch}: one record per failing destination, no lock left behind"
        );
        let _listeners: Vec<std::net::TcpListener> = peers
            .iter()
            .map(|peer| std::net::TcpListener::bind(peer).expect("rebind"))
            .collect();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        for peer in &peers {
            pool.send_tcp(*peer, ping())
                .await
                .expect("a recovered peer is connected to");
        }
        assert_eq!(
            pool.connect_state_len(),
            (0, 0),
            "batch {batch}: records or locks left behind after every destination recovered"
        );
    }
}

/// A peer slow to accept recovers: once the window has passed and it accepts
/// again, the next send connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blackholed_peer_is_retried_after_the_window() {
    let _watchdog = watchdog("a_blackholed_peer_is_retried_after_the_window");
    let Some((peer, _held, listener)) = blackholed_peer() else {
        eprintln!("kernel completes connects past a full accept queue; nothing to show");
        return;
    };
    let pool = pool();
    assert!(pool.send_tcp(peer, ping()).await.is_err(), "timed out");
    let accepted = start_accepting(listener);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    tokio::time::timeout(Duration::from_secs(3), pool.send_tcp(peer, ping()))
        .await
        .expect("bounded")
        .expect("the send after the window connects to the recovered peer");
    assert!(accepted.load(Ordering::SeqCst) >= 1);
}
