//! Over-MTU requests to a dead next hop: 2000 of them cost one TCP probe in
//! total, none of the others waits on a connect, the forced-UDP warning is
//! logged once, and the process does not grow threads while they run.
//!
//! Run two ways: from plain OS threads attached to the interpreter, as
//! script-executor jobs are, and as tasks on a tokio runtime, where a probe's
//! `block_in_place` hands the worker's core to a replacement thread.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use super::super::{mtu_tcp_upgrade, probe_cache};
use crate::dns::SipResolver;
use crate::log_capture::LogBuffer;
use crate::transport::Transport;

const THREADS: usize = 8;
const REQUESTS: usize = 2000;
const WARNING: &str = "forced UDP over-MTU send (no reachable TCP path)";

/// A next hop that is up but accepts nothing: a listener with a zero backlog
/// whose accept queue is full, so further SYNs are dropped and a connect runs
/// its whole timeout. The returned sockets keep it that way while held.
/// `None` when this kernel answers anyway (the test then has nothing to show).
fn blackholed_peer() -> Option<(SocketAddr, Vec<std::net::TcpStream>, socket2::Socket)> {
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

/// A next hop that refuses: a port nothing listens on.
fn refusing_peer() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("bound")
}

/// This process's thread count.
fn threads() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Threads:"))
                .and_then(|count| count.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Sample the thread count every few milliseconds until stopped; the peak.
struct ThreadPeak {
    peak: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    sampler: std::thread::JoinHandle<()>,
}

impl ThreadPeak {
    fn start() -> Self {
        let peak = Arc::new(AtomicUsize::new(threads()));
        let stop = Arc::new(AtomicBool::new(false));
        let sampler = {
            let peak = Arc::clone(&peak);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(threads(), Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(2));
                }
            })
        };
        Self {
            peak,
            stop,
            sampler,
        }
    }

    fn stop(self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.sampler.join();
        self.peak.load(Ordering::Relaxed)
    }
}

fn upgrade(peer: SocketAddr, resolver: &SipResolver) -> Duration {
    let began = Instant::now();
    let upgrade = mtu_tcp_upgrade(
        Some(1280),
        Transport::Udp,
        1494,
        &peer.to_string(),
        peer,
        resolver,
    );
    assert_eq!(upgrade, None, "a dead next hop keeps UDP");
    began.elapsed()
}

/// What a storm cost.
#[derive(Debug)]
struct Storm {
    wall: Duration,
    /// Every request's own duration.
    durations: Vec<Duration>,
    /// Forced-UDP warnings logged.
    warnings: usize,
    /// Threads above the count before the storm, at its peak.
    extra_threads: usize,
}

/// 2000 over-MTU requests to `peer` from attached OS threads.
fn storm_from_threads(peer: SocketAddr) -> Storm {
    pyo3::Python::initialize();
    let resolver = Arc::new(SipResolver::from_system().expect("a system resolver"));
    let log = LogBuffer::default();
    let start_line = Arc::new(Barrier::new(THREADS));
    let before = threads();
    let peak = ThreadPeak::start();
    let started = Instant::now();
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let resolver = Arc::clone(&resolver);
            let start_line = Arc::clone(&start_line);
            let log = log.clone();
            std::thread::spawn(move || {
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::WARN)
                    .with_writer(log)
                    .finish();
                let _guard = tracing::subscriber::set_default(subscriber);
                // Lined up before attaching: on an interpreter with a GIL, a
                // thread waiting attached would hold the others out.
                start_line.wait();
                pyo3::Python::attach(|_python| {
                    (0..REQUESTS / THREADS)
                        .map(|_| upgrade(peer, &resolver))
                        .collect::<Vec<_>>()
                })
            })
        })
        .collect();
    let mut durations = Vec::new();
    for worker in workers {
        durations.extend(worker.join().expect("a request thread"));
    }
    let wall = started.elapsed();
    let extra_threads = peak.stop().saturating_sub(before + THREADS + 1);
    Storm {
        wall,
        durations,
        warnings: log.rendered().matches(WARNING).count(),
        extra_threads,
    }
}

/// 2000 over-MTU requests to `peer` as concurrent tasks on a tokio runtime.
fn storm_on_tokio(peer: SocketAddr) -> Storm {
    // As in a running node, where the interpreter is up before any request.
    pyo3::Python::initialize();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let resolver = Arc::new(SipResolver::from_system().expect("a system resolver"));
    // Wait for the workers to exist before the baseline is taken.
    runtime.block_on(async { tokio::task::yield_now().await });
    let before = threads();
    let peak = ThreadPeak::start();
    let started = Instant::now();
    let durations = runtime.block_on(async {
        let tasks: Vec<_> = (0..REQUESTS)
            .map(|_| {
                let resolver = Arc::clone(&resolver);
                tokio::spawn(async move { upgrade(peer, &resolver) })
            })
            .collect();
        let mut durations = Vec::new();
        for task in tasks {
            durations.push(task.await.expect("a request task"));
        }
        durations
    });
    let wall = started.elapsed();
    let extra_threads = peak.stop().saturating_sub(before + 1);
    runtime.shutdown_background();
    Storm {
        wall,
        durations,
        warnings: 0,
        extra_threads,
    }
}

/// Everything but the one request that probed, summed.
fn time_spent_not_probing(durations: &[Duration]) -> Duration {
    let mut durations = durations.to_vec();
    durations.sort();
    durations.pop();
    durations.iter().sum()
}

/// Abort the binary if a storm wedges, rather than hanging CI.
fn watchdog() -> std::sync::mpsc::Sender<()> {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            finished.recv_timeout(Duration::from_secs(120))
        {
            eprintln!("over-MTU probe storm: wedged for 120 s, aborting");
            std::process::abort();
        }
    });
    done
}

/// Threads a storm may add beyond the ones it starts itself: the one request
/// that probes hands its worker's core to one replacement, and the rest of the
/// test binary keeps running beside it.
const THREAD_ALLOWANCE: usize = 24;

#[test]
fn two_thousand_over_mtu_requests_to_a_blackholed_peer_probe_once() {
    // Thread counts are the whole process's: run alone.
    crate::own_process::run(
        concat!(
            module_path!(),
            "::two_thousand_over_mtu_requests_to_a_blackholed_peer_probe_once"
        ),
        || {
            let _watchdog = watchdog();
            let Some((peer, _held, _listener)) = blackholed_peer() else {
                eprintln!("this kernel completes connects past a full backlog: nothing to show");
                return;
            };
            let storm = storm_from_threads(peer);
            let others = time_spent_not_probing(&storm.durations);
            eprintln!(
            "blackholed, executor threads: wall {:?}, others {others:?}, warnings {}, extra threads {}, probes {}",
            storm.wall,
            storm.warnings,
            storm.extra_threads,
            probe_cache().probes_started(peer)
        );
            assert_eq!(
                probe_cache().probes_started(peer),
                1,
                "one probe per window"
            );
            assert_eq!(storm.warnings, 1, "one warning per window");
            assert!(
                others < Duration::from_millis(250),
                "the other 1999 requests did not wait on a connect: {others:?}"
            );
            assert!(storm.wall < Duration::from_millis(1800), "{:?}", storm.wall);
            assert!(storm.extra_threads <= THREAD_ALLOWANCE, "{storm:?}");
        },
    );
}

#[test]
fn two_thousand_over_mtu_requests_to_a_refusing_peer_probe_once() {
    // Thread counts are the whole process's: run alone.
    crate::own_process::run(
        concat!(
            module_path!(),
            "::two_thousand_over_mtu_requests_to_a_refusing_peer_probe_once"
        ),
        || {
            let _watchdog = watchdog();
            let peer = refusing_peer();
            let storm = storm_from_threads(peer);
            let total: Duration = storm.durations.iter().sum();
            eprintln!(
            "refusing, executor threads: wall {:?}, total {total:?}, warnings {}, extra threads {}, probes {}",
            storm.wall,
            storm.warnings,
            storm.extra_threads,
            probe_cache().probes_started(peer)
        );
            assert_eq!(
                probe_cache().probes_started(peer),
                1,
                "one probe per window"
            );
            assert_eq!(storm.warnings, 1, "one warning per window");
            assert!(
                total < Duration::from_millis(500),
                "well under a second of probing in total: {total:?}"
            );
            assert!(storm.wall < Duration::from_secs(1), "{:?}", storm.wall);
        },
    );
}

/// On tokio workers each blocking probe hands its core to a fresh thread: the
/// thread count stays near its baseline only because one request probes.
#[test]
fn two_thousand_over_mtu_tasks_to_a_blackholed_peer_add_no_threads() {
    // Thread counts are the whole process's: run alone.
    crate::own_process::run(
        concat!(
            module_path!(),
            "::two_thousand_over_mtu_tasks_to_a_blackholed_peer_add_no_threads"
        ),
        || {
            let _watchdog = watchdog();
            let Some((peer, _held, _listener)) = blackholed_peer() else {
                eprintln!("this kernel completes connects past a full backlog: nothing to show");
                return;
            };
            let storm = storm_on_tokio(peer);
            eprintln!(
                "blackholed, tokio tasks: wall {:?}, extra threads {}, probes {}",
                storm.wall,
                storm.extra_threads,
                probe_cache().probes_started(peer)
            );
            assert_eq!(
                probe_cache().probes_started(peer),
                1,
                "one probe per window"
            );
            assert!(storm.extra_threads <= THREAD_ALLOWANCE, "{storm:?}");
            assert!(storm.wall < Duration::from_millis(1800), "{:?}", storm.wall);
        },
    );
}
