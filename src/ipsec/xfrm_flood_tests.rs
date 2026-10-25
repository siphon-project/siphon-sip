//! A re-REGISTER wave on the netlink backend: thousands of pairs allocated at
//! once must not take a thread each. Each kernel operation used to be a
//! `spawn_blocking` of its own, so a wave ran tokio's blocking pool up to its
//! 512-thread cap; the fixed worker pool keeps the count where it was.
//! Against the fake kernel (a round trip of 200 us), no `CAP_NET_ADMIN`. With
//! a job per `spawn_blocking` this test peaks at about 190 runtime threads,
//! and with a 2 ms round trip at the 512 cap.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::netlink::fake_kernel::FakeKernel;
use super::netlink::XfrmWorkers;
use super::*;

const PCSCF: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
const UES: usize = 2000;
const RUNTIME_THREAD: &str = "xfrm-wave-rt";
const WORKER_THREAD: &str = "xfrm-wave";
const RUNTIME_WORKERS: usize = 4;

/// Threads of this process whose name starts with `prefix`.
fn threads_named(prefix: &str) -> usize {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    tasks
        .filter_map(Result::ok)
        .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
        .filter(|name| name.trim_end().starts_with(prefix))
        .count()
}

/// `Threads:` of /proc/self/status.
fn process_threads() -> usize {
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

fn pair(manager: &IpsecManager, index: usize) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("an SPI pair");
    SecurityAssociationPair {
        ue_addr: IpAddr::V4(std::net::Ipv4Addr::new(
            203,
            0,
            113,
            1 + (index % 200) as u8,
        )),
        pcscf_addr: PCSCF,
        ue_port_c: 20_000 + index as u16,
        ue_port_s: 40_000 + index as u16,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: 1_000_000 + 2 * index as u32,
        spi_us: 1_000_001 + 2 * index as u32,
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

#[test]
fn a_register_wave_of_pair_installs_keeps_the_thread_count_flat() {
    let kernel = Arc::new(FakeKernel {
        latency: Duration::from_micros(200),
        ..FakeKernel::default()
    });
    let workers = Arc::new(XfrmWorkers::new(
        kernel.connect(),
        WORKER_THREAD,
        netlink::worker_count(),
        netlink::queue_capacity(),
        Duration::from_secs(2),
        Duration::from_secs(30),
    ));
    let manager = Arc::new(IpsecManager::with_xfrm_workers(
        Arc::clone(&workers),
        10_000,
        8192,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKERS)
        .thread_name(RUNTIME_THREAD)
        .enable_all()
        .build()
        .expect("runtime");

    let baseline = process_threads();
    let stop = Arc::new(AtomicBool::new(false));
    let peak_runtime = Arc::new(AtomicUsize::new(0));
    let peak_workers = Arc::new(AtomicUsize::new(0));
    let peak_process = Arc::new(AtomicUsize::new(0));
    let sampler = std::thread::spawn({
        let (stop, peak_runtime, peak_workers, peak_process) = (
            Arc::clone(&stop),
            Arc::clone(&peak_runtime),
            Arc::clone(&peak_workers),
            Arc::clone(&peak_process),
        );
        move || {
            while !stop.load(Ordering::SeqCst) {
                // `xfrm-wave-rt` also starts with `xfrm-wave`.
                let runtime_threads = threads_named(RUNTIME_THREAD);
                peak_runtime.fetch_max(runtime_threads, Ordering::SeqCst);
                peak_workers.fetch_max(
                    threads_named(WORKER_THREAD).saturating_sub(runtime_threads),
                    Ordering::SeqCst,
                );
                peak_process.fetch_max(process_threads(), Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });

    let started = Instant::now();
    let installed = runtime.block_on(async {
        let wave: Vec<_> = (0..UES)
            .map(|index| {
                let manager = Arc::clone(&manager);
                let sa = pair(&manager, index);
                tokio::spawn(async move { manager.create_sa_pair(sa).await })
            })
            .collect();
        let mut installed = 0;
        for install in wave {
            if install.await.expect("joined").is_ok() {
                installed += 1;
            }
        }
        installed
    });
    let took = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    sampler.join().expect("sampler");

    let (peak_runtime, peak_workers, peak_process) = (
        peak_runtime.load(Ordering::SeqCst),
        peak_workers.load(Ordering::SeqCst),
        peak_process.load(Ordering::SeqCst),
    );
    eprintln!(
        "xfrm wave: {UES} pairs in {took:?}; process threads {baseline} -> peak {peak_process}; \
         runtime threads peak {peak_runtime}; netlink workers peak {peak_workers}"
    );
    assert_eq!(installed, UES);
    assert_eq!(manager.active_count(), UES);
    // Eight deletes clearing leftovers and eight installs per pair.
    assert_eq!(kernel.requests.load(Ordering::SeqCst), 16 * UES);
    // The runtime's own workers, plus a few for anything tokio starts itself;
    // a blocking thread per kernel operation would be hundreds.
    assert!(
        peak_runtime <= RUNTIME_WORKERS + 4,
        "runtime threads peaked at {peak_runtime}"
    );
    assert!(peak_workers <= netlink::worker_count());
    assert_eq!(workers.in_flight(), 0);
    assert_eq!(workers.queued(), 0);
}
