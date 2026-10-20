//! Criterion perf gates for the per-message SIP hot paths.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench sip_hot_path`.
//!
//! These lock the cost of the work the proxy/B2BUA does on *every* SIP message —
//! parse, header touch, transaction keying, serialize — so a regression on the
//! datapath fails the release-cut gate (`scripts/bench_regression.sh`, wired into
//! `scripts/cut-release.sh`).  The end-to-end SIPp baseline in README.md measures
//! aggregate CPS; these microbenches isolate the individual per-message costs —
//! string sharing, header clone, branch keying — so an improvement or regression
//! in one is visible directly, not averaged into a CPS number.
//!
//! Fixtures use only RFC 5737 documentation addresses (192.0.2.0/24) and generic
//! example.com hosts — never real IPs or subscriber identities.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use siphon::sip::parse_sip_message;
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::sip::validate::validate_message;
use siphon::transaction::TransactionManager;
use siphon::transport::tcp::{frame_sip_message, FrameVerdict};
use std::hint::black_box;

/// A realistic offer SDP — the common INVITE body the parser walks on every call.
const SDP_BODY: &str = concat!(
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 atlanta.example.com\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.143\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 96\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:96 telephone-event/8000\r\n",
    "a=fmtp:96 0-15\r\n",
    "a=sendrecv\r\n",
);

/// INVITE carrying the SDP offer above. Built with `format!` so Content-Length
/// always matches the body byte count exactly (the parser slices on it).
fn invite_with_sdp() -> String {
    format!(
        concat!(
            "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n",
            "Max-Forwards: 70\r\n",
            "To: Bob <sip:bob@biloxi.example.com>\r\n",
            "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:alice@pc33.atlanta.example.com>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        SDP_BODY.len(),
        SDP_BODY,
    )
}

/// Bodyless INVITE — the lower bound for request parse cost.
const INVITE_NO_SDP: &str = concat!(
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n",
    "Max-Forwards: 70\r\n",
    "To: Bob <sip:bob@biloxi.example.com>\r\n",
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:alice@pc33.atlanta.example.com>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const REGISTER: &str = concat!(
    "REGISTER sip:registrar.biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP bobspc.biloxi.example.com:5060;branch=z9hG4bKnashds7\r\n",
    "Max-Forwards: 70\r\n",
    "To: Bob <sip:bob@biloxi.example.com>\r\n",
    "From: Bob <sip:bob@biloxi.example.com>;tag=456248\r\n",
    "Call-ID: 843817637684230@998sdasdh09\r\n",
    "CSeq: 1826 REGISTER\r\n",
    "Contact: <sip:bob@192.0.2.4>\r\n",
    "Expires: 7200\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const RESPONSE_200: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n",
    "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n",
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:bob@192.0.2.4>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// Parse cost — the first thing every inbound byte stream pays.
fn bench_parse(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("parse");

    group.throughput(Throughput::Bytes(invite_sdp.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) =
                parse_sip_message(black_box(invite_sdp.as_str())).expect("parse invite+sdp");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(INVITE_NO_SDP.len() as u64));
    group.bench_function("invite_no_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) = parse_sip_message(black_box(INVITE_NO_SDP)).expect("parse invite");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(REGISTER.len() as u64));
    group.bench_function("register", |bencher| {
        bencher.iter(|| {
            let (_, message) = parse_sip_message(black_box(REGISTER)).expect("parse register");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(RESPONSE_200.len() as u64));
    group.bench_function("response_200", |bencher| {
        bencher.iter(|| {
            let (_, message) = parse_sip_message(black_box(RESPONSE_200)).expect("parse 200");
            black_box(message)
        });
    });

    group.finish();
}

/// What the datapath actually calls.
///
/// `parse/*` above measures `parse_sip_message(&str)`; the only production
/// parse site is `parse_sip_message_bytes(&[u8])`, which additionally walks the
/// header block for the boundary, validates line endings, checks UTF-8, and
/// re-reads Content-Length with the RFC 4475 overrun check. Every hardening
/// pass added to that path was invisible to the gate. Keep both groups: the
/// delta between them is the cost of the byte-level entry.
fn bench_parse_bytes(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("parse_bytes");

    for (name, raw) in [
        ("invite_sdp", invite_sdp.as_str()),
        ("invite_no_sdp", INVITE_NO_SDP),
        ("register", REGISTER),
        ("response_200", RESPONSE_200),
    ] {
        group.throughput(Throughput::Bytes(raw.len() as u64));
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                let message =
                    parse_sip_message_bytes(black_box(raw.as_bytes())).expect("parse bytes");
                black_box(message)
            });
        });
    }

    group.finish();
}

/// Shape/version/CSeq/address-header checks, run on every inbound message right
/// after parse and before any routing decision. Nothing measured it, so a
/// careless addition here taxes every message invisibly.
fn bench_validate(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("validate");

    for (name, raw) in [
        ("invite_sdp", invite_sdp.as_str()),
        ("register", REGISTER),
        ("response_200", RESPONSE_200),
    ] {
        let (_, message) = parse_sip_message(raw).expect("setup parse");
        group.bench_function(name, |bencher| {
            bencher.iter(|| black_box(validate_message(black_box(&message))).is_ok());
        });
    }

    group.finish();
}

/// Parse + validate in one region: the exact pre-dispatch cost of an inbound
/// message, and the number to quote as "what siphon pays before the dispatcher
/// sees anything".
fn bench_inbound(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("inbound");

    group.throughput(Throughput::Bytes(invite_sdp.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| {
            let message =
                parse_sip_message_bytes(black_box(invite_sdp.as_bytes())).expect("parse bytes");
            let accepted = validate_message(&message).is_ok();
            black_box((message, accepted))
        });
    });

    group.finish();
}

/// A relayed INVITE is deep-cloned two to four times (relay, proxy session,
/// each transaction's stored copy). The `Arc<SipMessage>` experiment in the
/// perf log was reached for because of this cost, and no row measured it.
fn bench_clone(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, message) = parse_sip_message(&invite_sdp).expect("setup parse invite+sdp");
    let mut group = criterion.benchmark_group("message");

    group.bench_function("clone_invite_sdp", |bencher| {
        bencher.iter(|| black_box(black_box(&message).clone()));
    });

    group.finish();
}

/// Serialize cost — what every relayed/forwarded message pays on the way out.
fn bench_serialize(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, message) = parse_sip_message(&invite_sdp).expect("setup parse invite+sdp");
    let wire_len = message.to_bytes().len() as u64;

    // Same message with its headers out of canonical order, so serialization
    // takes the sorting path instead of the already-ordered one. This is what a
    // B2BUA leg looks like after the capability settling (a `remove` + re-add)
    // and the post-body header injections: a handful of entries that belong
    // before `Content-Length` sitting after it.
    let mut unsorted = message.clone();
    for name in ["Supported", "Allow", "P-Charging-Vector"] {
        let value = unsorted
            .headers
            .get(name)
            .cloned()
            .unwrap_or_else(|| "timer,replaces".to_string());
        unsorted.headers.remove(name);
        unsorted.headers.add(name, value);
    }

    let mut group = criterion.benchmark_group("serialize");
    group.throughput(Throughput::Bytes(wire_len));
    group.bench_function("invite_sdp_to_bytes", |bencher| {
        bencher.iter(|| black_box(black_box(&message).to_bytes()));
    });
    group.bench_function("invite_unsorted_to_bytes", |bencher| {
        bencher.iter(|| black_box(black_box(&unsorted).to_bytes()));
    });
    group.finish();
}

/// Full proxy touch: parse an inbound INVITE then serialize it back out.
fn bench_roundtrip(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("roundtrip");
    group.throughput(Throughput::Bytes(invite_sdp.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) =
                parse_sip_message(black_box(invite_sdp.as_str())).expect("roundtrip parse");
            black_box(message.to_bytes())
        });
    });
    group.finish();
}

/// Header access + mutation. `set`/`add` go through the copy-on-write
/// `Arc<HeadersInner>`, so the batched setup clones a fresh (cheap, Arc-bump)
/// message and the timed routine pays the make_mut deep-clone — exactly the
/// cost a fork/relay incurs when it rewrites a header.
fn bench_headers(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, message) = parse_sip_message(&invite_sdp).expect("setup parse invite+sdp");
    let mut group = criterion.benchmark_group("headers");

    group.bench_function("get_via", |bencher| {
        bencher.iter(|| black_box(black_box(&message).headers.get("Via")));
    });

    group.bench_function("has_route", |bencher| {
        bencher.iter(|| black_box(black_box(&message).headers.has("Route")));
    });

    group.bench_function("set_max_forwards", |bencher| {
        bencher.iter_batched(
            || message.clone(),
            |mut owned| {
                owned
                    .headers
                    .set("Max-Forwards", black_box("69".to_string()));
                black_box(owned)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("add_via", |bencher| {
        bencher.iter_batched(
            || message.clone(),
            |mut owned| {
                owned.headers.add(
                    "Via",
                    black_box("SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy-1".to_string()),
                );
                black_box(owned)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Transaction-key extraction (RFC 3261 §17) — done for every message that
/// reaches the transaction layer, to match it to an existing transaction.
fn bench_txn_key(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, invite) = parse_sip_message(&invite_sdp).expect("setup parse invite");
    let (_, response) = parse_sip_message(RESPONSE_200).expect("setup parse 200");

    let mut group = criterion.benchmark_group("txn_key");
    group.bench_function("invite", |bencher| {
        bencher.iter(|| {
            black_box(TransactionManager::key_from_message(black_box(&invite)).expect("invite key"))
        });
    });
    group.bench_function("response", |bencher| {
        bencher.iter(|| {
            black_box(
                TransactionManager::key_from_message(black_box(&response)).expect("response key"),
            )
        });
    });
    group.finish();
}

/// Stream framing (RFC 3261 §18.3) — the first thing every message over
/// TCP/TLS/WS goes through, before the parser sees a byte. It scans for the
/// end-of-headers marker, reads `Content-Length`, and checks the start line is
/// SIP (a complete HTTP request block also ends `\r\n\r\n`, so length alone
/// cannot tell a scanner's probe from a message).
///
/// Not benched before this, and it runs per message on every stream transport,
/// so it belongs in the release-cut gate alongside parse and serialize.
fn bench_framing(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let invite = invite_sdp.as_bytes();
    let response = RESPONSE_200.as_bytes();
    // Two messages back to back — the pipelined case a busy TCP connection
    // actually presents, where framing has to find the first boundary without
    // being confused by the second message behind it.
    let mut pipelined = invite_sdp.clone();
    pipelined.push_str(RESPONSE_200);
    let pipelined = pipelined.into_bytes();

    let ceiling = 256 * 1024;
    let mut group = criterion.benchmark_group("framing");
    group.throughput(Throughput::Bytes(invite.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| black_box(frame_sip_message(black_box(invite), ceiling)));
    });
    group.bench_function("response_200", |bencher| {
        bencher.iter(|| black_box(frame_sip_message(black_box(response), ceiling)));
    });
    group.bench_function("pipelined", |bencher| {
        bencher.iter(|| black_box(frame_sip_message(black_box(&pipelined), ceiling)));
    });
    // The rejection path: a scanner's HTTP probe, which must be refused rather
    // than framed. Cheap by construction — it is decided on the first line.
    let probe = b"GET / HTTP/1.1\r\nHost: sip.example.com\r\n\r\n";
    group.bench_function("http_probe_refused", |bencher| {
        bencher.iter(|| {
            debug_assert!(matches!(
                frame_sip_message(black_box(probe), ceiling),
                FrameVerdict::Garbage
            ));
            black_box(frame_sip_message(black_box(probe), ceiling))
        });
    });
    group.finish();
}

/// Traffic counting — `siphon_requests_total` / `siphon_responses_total`.
///
/// These run on *every* SIP message in both directions, which is why the
/// children are pre-resolved into dense arrays at startup rather than looked up
/// per call: `IntCounterVec::with_label_values` takes an `RwLock` read and
/// hashes the label slice, and at 30k cps that would be 60k lock+hash per
/// second to increment a counter.
///
/// `record_request` / `record_response` are the inbound path (typed, so the
/// index is computed directly). `record_frame` is the outbound path, which sits
/// below serialization and has to recover the kind from the start line — the
/// `with_label_values` case is benched alongside it to keep the reason for the
/// pre-resolved arrays measurable rather than assumed.
fn bench_traffic_counters(criterion: &mut Criterion) {
    use siphon::metrics::Direction;
    use siphon::sip::message::Method;

    // `init` is idempotent and returns Err only if metrics were already built.
    let _ = siphon::metrics::init();
    let Some(metrics) = siphon::metrics::try_metrics() else {
        return;
    };

    let invite_sdp = invite_with_sdp();
    let invite_bytes = invite_sdp.as_bytes();
    let response_bytes = RESPONSE_200.as_bytes();

    let mut group = criterion.benchmark_group("traffic_counters");

    group.bench_function("record_request", |bencher| {
        bencher
            .iter(|| metrics.record_request(black_box(&Method::Invite), black_box(Direction::In)));
    });
    group.bench_function("record_response", |bencher| {
        bencher.iter(|| metrics.record_response(black_box(200), black_box(Direction::In)));
    });
    // Outbound: classify a serialized frame, then increment.
    group.bench_function("record_frame_request", |bencher| {
        bencher.iter(|| metrics.record_frame(black_box(invite_bytes), black_box(Direction::Out)));
    });
    group.bench_function("record_frame_response", |bencher| {
        bencher.iter(|| metrics.record_frame(black_box(response_bytes), black_box(Direction::Out)));
    });
    // The CRLF keepalive shares the outbound path and must fall out cheaply
    // without touching a counter.
    group.bench_function("record_frame_keepalive", |bencher| {
        bencher.iter(|| metrics.record_frame(black_box(b"\r\n\r\n"), black_box(Direction::Out)));
    });
    // The label-map lookup the pre-resolved arrays exist to avoid. Kept as a
    // reference point: if this ever stops being materially slower, the arrays
    // are no longer earning their complexity.
    group.bench_function("with_label_values_reference", |bencher| {
        bencher.iter(|| {
            metrics
                .requests_total
                .with_label_values(black_box(&["INVITE", "in"]))
                .inc()
        });
    });
    group.finish();
}

/// The trusted-source check the request filter runs on every inbound request
/// (`security.trusted_cidrs`, plus the gateway view under
/// `security.trust_gateways`).
///
/// `configured_only` is the check with the key off — a scan of a short CIDR
/// list, what every request paid before. The gateway cases run against 10 000
/// merged host ranges, far more carriers than any estate holds, so the binary
/// search's cost is visible: a miss (a stranger, the common case) and a hit.
fn bench_source_trust(criterion: &mut Criterion) {
    use siphon::gateway::view::{AdmittedRange, GatewayView};
    use siphon::security::trust::SourceTrust;
    use std::net::IpAddr;
    use std::sync::Arc;

    let configured = vec!["198.51.100.0/24".to_string(), "203.0.113.0/24".to_string()];
    // Documentation space (2001:db8::/32): 10 000 distinct, non-adjacent hosts.
    let host = |index: u128| {
        IpAddr::V6(std::net::Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (index * 3),
        ))
    };
    let view = Arc::new(GatewayView::new());
    view.publish(|| {
        (0..10_000u32)
            .map(|index| AdmittedRange {
                network: ipnet::IpNet::new(host(u128::from(index)), 128).expect("host prefix"),
                group: Arc::from("carriers"),
            })
            .collect()
    });
    let off = SourceTrust::from_cidrs(&configured);
    let on = SourceTrust::from_cidrs(&configured).with_gateways(Some(view));
    let stranger: IpAddr = "2001:db8:ffff::77".parse().expect("address");
    let gateway = host(4_242);

    let mut group = criterion.benchmark_group("source_trust");
    group.bench_function("configured_only", |bencher| {
        bencher.iter(|| off.is_trusted(black_box(stranger)));
    });
    group.bench_function("gateways_10k_miss", |bencher| {
        bencher.iter(|| on.is_trusted(black_box(stranger)));
    });
    group.bench_function("gateways_10k_hit", |bencher| {
        bencher.iter(|| on.is_trusted(black_box(gateway)));
    });
    group.finish();
}

/// The `Allow` lookup a relayed B2BUA response, an OPTIONS answer and a B-leg
/// INVITE pay (`gateway.groups[].allow_methods`). With no group narrowing
/// `Allow` it is one atomic load; with one it is a membership check of the
/// peer against that group, the same one `call.from_gateway()` makes.
fn bench_allow_methods(criterion: &mut Criterion) {
    use siphon::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
    use siphon::transport::Transport;
    use std::net::IpAddr;

    let group = |allow: Option<&str>| {
        let destination = Destination::new(
            "sip:198.51.100.7:5060".to_string(),
            "198.51.100.7:5060".parse().expect("address"),
            Transport::Udp,
            1,
            1,
        );
        DispatcherGroup::new("trunk".to_string(), Algorithm::Weighted, vec![destination])
            .with_source_networks(vec!["203.0.113.0/24".parse().expect("CIDR")])
            .with_allow_methods(allow.map(str::to_string))
    };
    let plain = DispatcherManager::new();
    plain.add_group(group(None));
    let narrowed = DispatcherManager::new();
    narrowed.add_group(group(Some("INVITE, ACK, CANCEL, BYE, OPTIONS")));
    let member: IpAddr = "203.0.113.40".parse().expect("address");
    let stranger: IpAddr = "192.0.2.10".parse().expect("address");

    let mut benchmarks = criterion.benchmark_group("allow_methods");
    benchmarks.bench_function("no_group_narrows", |bencher| {
        bencher.iter(|| {
            black_box(plain.narrows_allow());
        });
    });
    benchmarks.bench_function("narrowed_member", |bencher| {
        bencher.iter(|| narrowed.allow_methods_for_peer(black_box(member)));
    });
    benchmarks.bench_function("narrowed_stranger", |bencher| {
        bencher.iter(|| narrowed.allow_methods_for_peer(black_box(stranger)));
    });
    benchmarks.finish();
}

/// A locally built response stamping `Server`, read the way the dispatcher
/// reads it since `POST /admin/config/reload` made it swappable.
///
/// The cost the reload added is the `ArcSwap` read itself, so that is measured
/// on its own in `identity_headers`, next to the plain `Option<String>` read it
/// replaced. Two whole-response rows differing only in that read are not a
/// like-for-like comparison: on the reference machine a second copy of the
/// *identical* owned-read body measured 693–851 ns against the first copy's
/// 679 ns, depending on which row ran first, so the gap between two such rows is
/// code placement, not the read. `build_response/server_header_arcswap` stays
/// as the product-shaped row for the regression gate.
fn bench_build_response(criterion: &mut Criterion) {
    use siphon::config::IdentityHeaders;
    use siphon::sip::builder::build_response_skeleton;

    let (_, invite) = parse_sip_message(&invite_with_sdp()).expect("the fixture parses");
    let owned: Option<String> = Some("SIPhon/1.0".to_string());
    let identity = IdentityHeaders {
        server: Some("SIPhon/1.0".to_string()),
        user_agent: None,
    }
    .shared();

    let mut group = criterion.benchmark_group("build_response");
    group.bench_function("server_header_arcswap", |bencher| {
        bencher.iter(|| {
            let mut response = build_response_skeleton(black_box(&invite), 200, "OK");
            if let Some(server) = black_box(&identity).load().server.as_deref() {
                response.headers.set("Server", server.to_string());
            }
            response
        });
    });
    group.finish();

    // The read alone: what each locally built message pays for the header
    // being reloadable.
    let mut group = criterion.benchmark_group("identity_headers");
    group.bench_function("owned_read", |bencher| {
        bencher.iter(|| black_box(&owned).as_deref().map(str::len));
    });
    group.bench_function("arcswap_load", |bencher| {
        bencher.iter(|| black_box(&identity).load().server.as_deref().map(str::len));
    });
    group.finish();
}

/// The request filter every inbound request passes through when `rate_limit`
/// or `scanner_block` is configured: one load of the reloadable policy, the
/// trusted-list check, the scanner match and the rate-limit window.
///
/// `untrusted_counted` is the common case (a source under the limit, its
/// window bumped); `trusted` returns at the trusted-list check;
/// `scanner_user_agent` matches a signature.
fn bench_security_filter(criterion: &mut Criterion) {
    use siphon::config::SecurityConfig;
    use siphon::security::SecurityFilter;
    use std::net::IpAddr;

    let config: SecurityConfig = siphon::config::yaml::from_str(concat!(
        "trusted_cidrs: [\"198.51.100.0/24\", \"192.0.2.7\"]\n",
        "rate_limit: { window_secs: 60, max_requests: 4000000000, ban_duration_secs: 600 }\n",
        "scanner_block: { user_agents: [\"friendly-scanner\", \"sipvicious\"] }\n",
    ))
    .expect("the fixture parses");
    let filter = SecurityFilter::from_config(&config).expect("the filter is on");
    let untrusted: IpAddr = "203.0.113.9".parse().expect("an address");
    let trusted: IpAddr = "198.51.100.20".parse().expect("an address");

    let mut group = criterion.benchmark_group("security_filter");
    group.bench_function("untrusted_counted", |bencher| {
        bencher.iter(|| filter.evaluate(black_box(untrusted), black_box(Some("SIPhon/1.0"))));
    });
    group.bench_function("trusted", |bencher| {
        bencher.iter(|| filter.evaluate(black_box(trusted), black_box(Some("SIPhon/1.0"))));
    });
    group.bench_function("scanner_user_agent", |bencher| {
        bencher.iter(|| filter.evaluate(black_box(untrusted), black_box(Some("friendly-scanner"))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_parse_bytes,
    bench_validate,
    bench_inbound,
    bench_clone,
    bench_serialize,
    bench_roundtrip,
    bench_headers,
    bench_txn_key,
    bench_framing,
    bench_traffic_counters,
    bench_source_trust,
    bench_allow_methods,
    bench_build_response,
    bench_security_filter
);
criterion_main!(benches);
