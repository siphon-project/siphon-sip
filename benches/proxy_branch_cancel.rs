//! Criterion bench for what RFC 3261 §9.1 costs the proxy response path.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench proxy_branch_cancel`.
//!
//! A CANCEL for a proxied INVITE that has drawn no response waits, in that
//! INVITE's client transaction, for its first provisional. The response path
//! already holds the transaction when it feeds it a response, so finding out
//! whether a CANCEL waits is a compare on a field of it: no map read, no lock
//! and no allocation of its own. These rows are the transaction's step for a
//! response, which is where that compare sits:
//!
//! - `first_provisional` is the datapath: the first 1xx of an INVITE nobody
//!   asked to cancel, `Calling` to `Proceeding`, with the compare.
//! - `first_provisional_releases_a_cancel` is the same response when a CANCEL
//!   waited for it and is handed out to be sent.
//! - `later_provisional` is a 1xx in `Proceeding`, which the change does not
//!   touch, for scale.
//! - `final_response_2xx` is a 2xx to an INVITE in `Calling`, the other place
//!   the compare sits.
//!
//! and the request to cancel itself, through the transaction manager as the
//! dispatcher makes it:
//!
//! - `request/deferred` for an INVITE with no response yet (the CANCEL is
//!   kept);
//! - `request/nothing_to_send` for one whose CANCEL already went.
//!
//! Fixtures use RFC 5737 addresses and example.com AoRs.

use std::hint::black_box;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use siphon::sip::message::SipMessage;
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::transaction::state::{BranchHop, Ict, IctEvent, Transport};
use siphon::transaction::timer::TimerConfig;
use siphon::transaction::TransactionManager;
use siphon::transport::ConnectionId;

fn invite(branch: &str) -> SipMessage {
    parse_sip_message_bytes(
        format!(
            concat!(
                "INVITE sip:callee@198.51.100.20 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
                "Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bK-caller\r\n",
                "Max-Forwards: 69\r\n",
                "From: <sip:caller@example.com>;tag=caller-tag\r\n",
                "To: <sip:callee@example.com>\r\n",
                "Call-ID: {branch}@example.com\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.50:5060>\r\n",
                "Content-Length: 0\r\n\r\n",
            ),
            branch = branch
        )
        .as_bytes(),
    )
    .expect("the INVITE parses")
}

fn response(branch: &str, status_line: &str) -> SipMessage {
    parse_sip_message_bytes(
        format!(
            concat!(
                "SIP/2.0 {status_line}\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
                "Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bK-caller\r\n",
                "From: <sip:caller@example.com>;tag=caller-tag\r\n",
                "To: <sip:callee@example.com>;tag=callee-tag\r\n",
                "Call-ID: {branch}@example.com\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:callee@198.51.100.20:5060>\r\n",
                "Content-Length: 0\r\n\r\n",
            ),
            status_line = status_line,
            branch = branch
        )
        .as_bytes(),
    )
    .expect("the response parses")
}

fn hop() -> BranchHop {
    BranchHop {
        destination: "198.51.100.20:5060".parse().expect("a literal address"),
        transport: siphon::transport::Transport::Udp,
        connection_id: ConnectionId::default(),
        source_local_addr: None,
    }
}

/// An INVITE client transaction that has drawn no response.
fn calling(frame: &Bytes) -> Ict {
    Ict::new(frame.clone(), Transport::Udp, TimerConfig::default()).0
}

fn bench_response_step(criterion: &mut Criterion) {
    const BRANCH: &str = "z9hG4bK-bench";
    let frame = Bytes::from(invite(BRANCH).to_bytes());
    let ringing = response(BRANCH, "180 Ringing");
    let answer = response(BRANCH, "200 OK");

    criterion.bench_function("proxy_branch_cancel/first_provisional", |bencher| {
        bencher.iter_batched(
            || (calling(&frame), ringing.clone()),
            |(mut transaction, ringing)| {
                let actions = transaction.process(IctEvent::Provisional(ringing));
                black_box((transaction, actions))
            },
            BatchSize::SmallInput,
        );
    });
    criterion.bench_function(
        "proxy_branch_cancel/first_provisional_releases_a_cancel",
        |bencher| {
            bencher.iter_batched(
                || {
                    let mut transaction = calling(&frame);
                    black_box(transaction.request_cancel(hop(), &[]));
                    (transaction, ringing.clone())
                },
                |(mut transaction, ringing)| {
                    let actions = transaction.process(IctEvent::Provisional(ringing));
                    black_box((transaction, actions))
                },
                BatchSize::SmallInput,
            );
        },
    );
    let mut proceeding = calling(&frame);
    black_box(proceeding.process(IctEvent::Provisional(ringing.clone())));
    criterion.bench_function("proxy_branch_cancel/later_provisional", |bencher| {
        bencher.iter_batched(
            || ringing.clone(),
            |ringing| black_box(proceeding.process(IctEvent::Provisional(ringing))),
            BatchSize::SmallInput,
        );
    });
    criterion.bench_function("proxy_branch_cancel/final_response_2xx", |bencher| {
        bencher.iter_batched(
            || (calling(&frame), answer.clone()),
            |(mut transaction, answer)| {
                let actions = transaction.process(IctEvent::Response2xx(answer));
                black_box((transaction, actions))
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_cancel_request(criterion: &mut Criterion) {
    criterion.bench_function("proxy_branch_cancel/request/deferred", |bencher| {
        bencher.iter_batched(
            || {
                let manager = TransactionManager::default();
                let request = invite("z9hG4bK-silent");
                let (key, _) = manager
                    .new_client_transaction(
                        &request,
                        Bytes::from(request.to_bytes()),
                        Transport::Udp,
                    )
                    .expect("the client transaction starts");
                (manager, key)
            },
            |(manager, key)| {
                let outcome = manager.cancel_invite_client(&key, hop(), &[]);
                black_box((manager, outcome))
            },
            BatchSize::SmallInput,
        );
    });

    // 1000 INVITEs in flight, each ringing and already sent its CANCEL: what a
    // second request for one of them costs, which is the lookup and a compare.
    let manager = TransactionManager::default();
    let mut keys = Vec::new();
    for index in 0..1000u32 {
        let branch = format!("z9hG4bK-ringing-{index}");
        let request = invite(&branch);
        let (key, _) = manager
            .new_client_transaction(&request, Bytes::from(request.to_bytes()), Transport::Udp)
            .expect("the client transaction starts");
        manager
            .process_client_event(
                &key,
                siphon::transaction::ClientEvent::Ict(IctEvent::Provisional(response(
                    &branch,
                    "180 Ringing",
                ))),
            )
            .expect("the transaction is live");
        black_box(manager.cancel_invite_client(&key, hop(), &[]));
        keys.push(key);
    }
    let key = keys[500].clone();
    criterion.bench_function("proxy_branch_cancel/request/nothing_to_send", |bencher| {
        bencher.iter(|| black_box(manager.cancel_invite_client(black_box(&key), hop(), &[])));
    });
}

criterion_group!(benches, bench_response_step, bench_cancel_request);
criterion_main!(benches);
