/// Regression guard for the reaped-thread `PyThreadState` leak.
///
/// `pin_python_thread_state` runs on every tokio runtime thread, including
/// the elastic blocking pool whose threads are reaped after their idle
/// keep-alive. `PyGILState_Ensure` allocates the thread state through
/// CPython's raw domain (`PyMem_RawCalloc` → `malloc`), so an unreleased
/// pin orphans it on the **glibc** heap where neither jemalloc nor
/// `siphon_memory_*` can see it.
///
/// Two arms so the test cannot pass vacuously: the unpaired pin (the old
/// behaviour) must visibly grow the C-side pool, and the paired
/// pin/unpin must not.
///
/// `read_stats` reports the whole **process**, and the harness runs other
/// tests on other threads throughout, so every window also measures
/// whatever they allocated while it was open. That is not an occasional
/// outlier a median would absorb — it is a steady background of roughly
/// 50-140 KB per window, comparable to the ~240 KB signal, and it made the
/// bare `retained * 4 < leaked` comparison fail by fractions of a percent.
///
/// So a third arm measures it. The **control** spawns and joins the same
/// threads without touching Python at all, which is exactly the ambient
/// cost of the window plus the neighbours' noise and none of the leak.
/// Subtracting it from both real arms leaves the thread-state allocation on
/// its own. The three arms are interleaved and taken on the median, so a
/// slow stretch of the suite biases all three alike rather than one.
///
/// glibc-only: `malloc_info` is what `read_stats` reads.
///
/// `#[ignore]`d because it must own the process, not because it is
/// optional. `read_stats` reports the whole process, and inside the parallel
/// test binary the neighbours allocate on the same order as the signal — the
/// control arm below subtracts the average of that, but not its variance,
/// and the test failed roughly one run in four. Alone it is exact: ambient
/// 0 B, 241664 B leaked, 0 B retained, every time. CI runs it on its own
/// (see the "Python thread-state leak guard" step), the same way the
/// CAP_NET_ADMIN tests are run.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
#[ignore = "process-global glibc measurement — run alone: cargo test --lib -- --ignored --exact server::tests::reaped_thread_releases_its_python_thread_state --test-threads=1"]
fn reaped_thread_releases_its_python_thread_state() {
    const WARM: usize = 32;
    const BATCH: usize = 256;
    // Odd, so the median is a real sample rather than an average of two.
    const ROUNDS: usize = 3;

    pyo3::Python::initialize();

    let in_use = || crate::metrics::glibc::read_stats().map(|stats| stats.in_use_bytes);
    let Some(_) = in_use() else {
        eprintln!("[reaped_thread_releases_its_python_thread_state] no glibc stats — skipping");
        return;
    };

    /// Which of the three arms a batch runs.
    #[derive(Clone, Copy, PartialEq)]
    enum Arm {
        /// Spawn + join only — the ambient cost of the window.
        Control,
        /// Pin without unpinning: the old behaviour, which leaks.
        Leaky,
        /// Pin and unpin, as the runtime hooks do.
        Paired,
    }

    let churn = |count: usize, arm: Arm| {
        for _ in 0..count {
            std::thread::spawn(move || {
                if arm == Arm::Control {
                    return;
                }
                pin_python_thread_state();
                if arm == Arm::Paired {
                    unpin_python_thread_state();
                }
            })
            .join()
            .expect("churn thread joins");
        }
    };

    // Warm up every path so first-touch arena growth lands outside the
    // measured batches.
    churn(WARM, Arm::Control);
    churn(WARM, Arm::Paired);
    churn(WARM, Arm::Leaky);

    let measure = |arm: Arm| {
        let before = in_use().unwrap_or(0);
        churn(BATCH, arm);
        in_use().unwrap_or(0).saturating_sub(before)
    };

    let mut control_samples = Vec::with_capacity(ROUNDS);
    let mut leaky_samples = Vec::with_capacity(ROUNDS);
    let mut paired_samples = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        control_samples.push(measure(Arm::Control));
        leaky_samples.push(measure(Arm::Leaky));
        paired_samples.push(measure(Arm::Paired));
    }
    let median = |samples: &[u64]| {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    };
    let ambient = median(&control_samples);
    // What the pin cost beyond simply running the window.
    let leaked = median(&leaky_samples).saturating_sub(ambient);
    let retained = median(&paired_samples).saturating_sub(ambient);

    eprintln!(
        "ambient {ambient} B {control_samples:?}; \
         unpaired pin: {leaked} B net over {BATCH} threads ({:.1} B/thread) {leaky_samples:?}; \
         paired pin/unpin: {retained} B net ({:.1} B/thread) {paired_samples:?}",
        leaked as f64 / BATCH as f64,
        retained as f64 / BATCH as f64,
    );

    // The leak must be visible, else the test proves nothing.
    assert!(
        leaked > BATCH as u64 * 64,
        "unpaired pin did not reproduce the leak ({leaked} B net over {BATCH} threads, \
         ambient {ambient} B) — the guard cannot prove the fix"
    );
    // ...and pairing must remove essentially all of it.
    assert!(
        retained * 4 < leaked,
        "pairing pin with unpin did not release the thread state: \
         {retained} B retained vs {leaked} B leaked over {BATCH} threads \
         (ambient {ambient} B subtracted from both)"
    );
}

use crate::config::{ListenConfig, ListenEntry};

fn listen_on(addresses: &[&str]) -> Vec<ListenEntry> {
    addresses
        .iter()
        .map(|a| ListenEntry::Plain((*a).to_string()))
        .collect()
}

#[test]
fn mux_pairs_tcp_with_ws_on_a_shared_address() {
    let listen = ListenConfig {
        tcp: listen_on(&["0.0.0.0:5060", "0.0.0.0:5070"]),
        ws: listen_on(&["0.0.0.0:5060"]),
        ..ListenConfig::default()
    };
    let (tcp_ws, tls_wss) = resolve_mux_addresses(&listen).unwrap();
    assert_eq!(tcp_ws, vec!["0.0.0.0:5060".parse().unwrap()]);
    assert!(tls_wss.is_empty());
}

#[test]
fn mux_pairs_tls_with_wss_on_a_shared_address() {
    let listen = ListenConfig {
        tls: listen_on(&["0.0.0.0:5061"]),
        wss: listen_on(&["0.0.0.0:5061"]),
        ..ListenConfig::default()
    };
    let (tcp_ws, tls_wss) = resolve_mux_addresses(&listen).unwrap();
    assert!(tcp_ws.is_empty());
    assert_eq!(tls_wss, vec!["0.0.0.0:5061".parse().unwrap()]);
}

#[test]
fn distinct_addresses_are_never_muxed() {
    let listen = ListenConfig {
        tcp: listen_on(&["0.0.0.0:5060"]),
        ws: listen_on(&["0.0.0.0:5080"]),
        tls: listen_on(&["0.0.0.0:5061"]),
        wss: listen_on(&["0.0.0.0:5081"]),
        ..ListenConfig::default()
    };
    let (tcp_ws, tls_wss) = resolve_mux_addresses(&listen).unwrap();
    assert!(tcp_ws.is_empty() && tls_wss.is_empty());
}

#[test]
fn plaintext_and_tls_may_not_share_a_socket() {
    // A TLS ClientHello is not a SIP message — there is nothing to sniff.
    let listen = ListenConfig {
        tcp: listen_on(&["0.0.0.0:5060"]),
        tls: listen_on(&["0.0.0.0:5060"]),
        ..ListenConfig::default()
    };
    let error = resolve_mux_addresses(&listen).unwrap_err();
    assert!(error.contains("listen.tcp and listen.tls"), "{error}");
    assert!(error.contains("0.0.0.0:5060"), "{error}");
}

#[test]
fn mismatched_security_pairings_are_rejected() {
    for (label, listen) in [
        (
            "tcp+wss",
            ListenConfig {
                tcp: listen_on(&["0.0.0.0:5060"]),
                wss: listen_on(&["0.0.0.0:5060"]),
                ..ListenConfig::default()
            },
        ),
        (
            "tls+ws",
            ListenConfig {
                tls: listen_on(&["0.0.0.0:5061"]),
                ws: listen_on(&["0.0.0.0:5061"]),
                ..ListenConfig::default()
            },
        ),
        (
            "ws+wss",
            ListenConfig {
                ws: listen_on(&["0.0.0.0:5062"]),
                wss: listen_on(&["0.0.0.0:5062"]),
                ..ListenConfig::default()
            },
        ),
    ] {
        assert!(
            resolve_mux_addresses(&listen).is_err(),
            "{label} must be rejected"
        );
    }
}

#[test]
fn udp_may_reuse_a_stream_listener_address() {
    // Different socket type — no conflict to resolve.
    let listen = ListenConfig {
        udp: listen_on(&["0.0.0.0:5060"]),
        tcp: listen_on(&["0.0.0.0:5060"]),
        ws: listen_on(&["0.0.0.0:5060"]),
        ..ListenConfig::default()
    };
    let (tcp_ws, _) = resolve_mux_addresses(&listen).unwrap();
    assert_eq!(tcp_ws, vec!["0.0.0.0:5060".parse().unwrap()]);
}

#[test]
fn malformed_listen_address_is_reported() {
    let listen = ListenConfig {
        ws: listen_on(&["not-an-address"]),
        ..ListenConfig::default()
    };
    let error = resolve_mux_addresses(&listen).unwrap_err();
    assert!(error.contains("Invalid WS listen address"), "{error}");
}

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

// --- default_udp_egress_addr ---

#[test]
fn default_udp_egress_addr_picks_first_configured() {
    let entries = vec![
        config::ListenEntry::Plain("10.0.0.1:5060".to_string()),
        config::ListenEntry::Plain("10.0.0.2:5060".to_string()),
    ];
    assert_eq!(
        default_udp_egress_addr(&entries),
        Some("10.0.0.1:5060".parse().unwrap()),
        "default egress must be the first configured listener, not the second"
    );
}

#[test]
fn default_udp_egress_addr_is_config_order_not_sorted() {
    // A higher-then-lower address ordering proves we honour config order and
    // are not accidentally min/sorting the set.
    let entries = vec![
        config::ListenEntry::Plain("192.0.2.9:5090".to_string()),
        config::ListenEntry::Plain("192.0.2.1:5060".to_string()),
    ];
    assert_eq!(
        default_udp_egress_addr(&entries),
        Some("192.0.2.9:5090".parse().unwrap())
    );
}

#[test]
fn default_udp_egress_addr_skips_unparseable_first_entry() {
    // The channel-build loop `continue`s past an unparseable addr; the
    // default must land on the first entry that actually parses so it maps
    // to a real listener channel.
    let entries = vec![
        config::ListenEntry::Plain("not-an-address".to_string()),
        config::ListenEntry::Plain("203.0.113.7:5060".to_string()),
    ];
    assert_eq!(
        default_udp_egress_addr(&entries),
        Some("203.0.113.7:5060".parse().unwrap())
    );
}

#[test]
fn default_udp_egress_addr_empty_is_none() {
    assert_eq!(default_udp_egress_addr(&[]), None);
}

#[test]
fn default_udp_egress_addr_honours_extended_form() {
    // The extended (struct) listen form must resolve the same way as the
    // plain string form — selection keys on `address()`, not the variant.
    let entries = vec![config::ListenEntry::Extended {
        address: "198.51.100.4:5062".to_string(),
        advertise: Some(config::AdvertisedAddress::host_only("sip.example.org")),
        dscp: None,
        proxy_protocol: None,
    }];
    assert_eq!(
        default_udp_egress_addr(&entries),
        Some("198.51.100.4:5062".parse().unwrap())
    );
}

#[test]
fn record_advertised_pairs_the_port_with_the_host_of_the_same_listener() {
    let mut hosts = std::collections::HashMap::new();
    let mut ports = std::collections::HashMap::new();
    let with_port = config::AdvertisedAddress::parse("sip.example.com:5061").unwrap();
    let host_only = config::AdvertisedAddress::host_only("other.example.com");

    // No advertise: nothing recorded.
    record_advertised(&mut hosts, &mut ports, transport::Transport::Tls, None);
    assert!(hosts.is_empty() && ports.is_empty());

    // First advertising listener wins, host and port together.
    record_advertised(
        &mut hosts,
        &mut ports,
        transport::Transport::Tls,
        Some(&with_port),
    );
    record_advertised(
        &mut hosts,
        &mut ports,
        transport::Transport::Tls,
        Some(&host_only),
    );
    assert_eq!(
        hosts.get(&transport::Transport::Tls).map(String::as_str),
        Some("sip.example.com")
    );
    assert_eq!(ports.get(&transport::Transport::Tls), Some(&5061));

    // A host-only first listener leaves the transport on its bound port, and a
    // later listener's port cannot attach itself to that host.
    record_advertised(
        &mut hosts,
        &mut ports,
        transport::Transport::Udp,
        Some(&host_only),
    );
    record_advertised(
        &mut hosts,
        &mut ports,
        transport::Transport::Udp,
        Some(&with_port),
    );
    assert_eq!(
        hosts.get(&transport::Transport::Udp).map(String::as_str),
        Some("other.example.com")
    );
    assert_eq!(ports.get(&transport::Transport::Udp), None);
}

#[test]
fn register_task_records_in_order() {
    let server = SiphonServer::builder()
        .register_task(|_| {})
        .register_task(|_| {})
        .register_task(|_| {});
    assert_eq!(server.extension_task_count(), 3);
}

#[test]
fn register_task_empty_by_default() {
    let server = SiphonServer::builder();
    assert_eq!(server.extension_task_count(), 0);
}

#[test]
fn register_task_accepts_move_closures_carrying_state() {
    // Verify the closure signature is `FnOnce` so callers can move
    // state in (e.g. an Arc holding extension config). Compile-only
    // contract test — the closure body is not executed here.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let owned: Vec<&'static str> = vec!["a", "b", "c"];
    let server = SiphonServer::builder().register_task(move |_| {
        // owned is moved in.
        COUNTER.fetch_add(owned.len(), Ordering::Relaxed);
    });
    assert_eq!(server.extension_task_count(), 1);
}
