//! The worker pool against the fake kernel: sequence matching on a reused
//! socket, timeouts, a full queue, and the in-flight count draining.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use super::super::fake_kernel::FakeKernel;
use super::super::{
    del_policy_message, del_sa_message, PolicyDirection, XFRM_MSG_DELPOLICY, XFRM_MSG_DELSA,
};
use super::*;
use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};

const UE: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const ENOENT: i32 = 2;

fn pool(kernel: &Arc<FakeKernel>, workers: usize, capacity: usize, wait: Duration) -> XfrmWorkers {
    XfrmWorkers::new(
        kernel.connect(),
        "xfrm-test",
        workers,
        capacity,
        Duration::from_millis(50),
        wait,
    )
}

fn add_sa(spi: u32) -> Vec<u8> {
    super::super::add_sa_message(
        &PCSCF,
        5066,
        &UE,
        40000,
        spi,
        EncryptionAlgorithm::Null,
        IntegrityAlgorithm::HmacSha1,
        &[],
        &[0u8; 20],
        17,
        Some(3600),
    )
}

fn del_policy() -> Vec<u8> {
    del_policy_message(&UE, 40000, &PCSCF, 5066, PolicyDirection::In, 17)
}

fn os_error(result: &Result<(), IpsecError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => error.to_string(),
    }
}

#[tokio::test]
async fn each_message_of_a_batch_gets_its_own_ack() {
    let kernel = Arc::new(FakeKernel {
        errno_of: [(XFRM_MSG_DELSA, ENOENT)].into(),
        ..FakeKernel::default()
    });
    let workers = pool(&kernel, 1, 8, QUEUE_WAIT);
    let results = workers
        .acknowledge(vec![add_sa(1001), del_sa_message(&UE, 1002), del_policy()])
        .await
        .expect("sent");
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok(), "{}", os_error(&results[0]));
    assert!(
        os_error(&results[1]).contains("No such file or directory"),
        "{}",
        os_error(&results[1])
    );
    assert!(results[2].is_ok(), "{}", os_error(&results[2]));
    assert_eq!(kernel.requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn one_long_lived_socket_per_worker_serves_every_operation() {
    let kernel = Arc::new(FakeKernel::default());
    let workers = pool(&kernel, 2, 64, QUEUE_WAIT);
    for spi in 0..200 {
        workers
            .acknowledge_one(add_sa(2000 + spi))
            .await
            .expect("acked");
    }
    assert!(kernel.opened.load(Ordering::SeqCst) <= 2);
    assert_eq!(kernel.requests.load(Ordering::SeqCst), 200);
}

#[tokio::test]
async fn a_reply_that_never_comes_fails_the_operation_with_a_timeout() {
    let kernel = Arc::new(FakeKernel {
        never_ack: Some(XFRM_MSG_DELSA),
        ..FakeKernel::default()
    });
    let workers = pool(&kernel, 1, 8, QUEUE_WAIT);
    let result = workers.acknowledge_one(del_sa_message(&UE, 3001)).await;
    let text = os_error(&result);
    assert!(text.contains("no reply from the kernel within"), "{text}");
    // The worker is not wedged: the next operation goes through.
    workers.acknowledge_one(add_sa(3002)).await.expect("acked");
    assert_eq!(workers.in_flight(), 0);
}

/// The ack of an operation given up on arrives with the next one's: matched on
/// its sequence number, it is dropped, and the next operation gets its own.
#[tokio::test]
async fn a_late_ack_is_dropped_not_taken_for_the_next_operation() {
    let kernel = Arc::new(FakeKernel {
        errno_of: [(XFRM_MSG_DELSA, ENOENT)].into(),
        late_ack: Some(XFRM_MSG_DELSA),
        ..FakeKernel::default()
    });
    let workers = pool(&kernel, 1, 8, QUEUE_WAIT);
    let first = workers.acknowledge_one(del_sa_message(&UE, 4001)).await;
    assert!(
        os_error(&first).contains("no reply"),
        "{}",
        os_error(&first)
    );
    // The stale ENOENT is read ahead of this ack; taking it would fail this add.
    workers
        .acknowledge_one(add_sa(4002))
        .await
        .expect("its own ack, not the stale ENOENT");
    assert_eq!(
        kernel.undelivered.load(Ordering::SeqCst),
        0,
        "stale ack read"
    );
    assert_eq!(kernel.opened.load(Ordering::SeqCst), 1, "same socket kept");
}

#[tokio::test]
async fn a_dump_ends_on_its_own_done() {
    let kernel = Arc::new(FakeKernel::default());
    let workers = pool(&kernel, 1, 8, QUEUE_WAIT);
    let use_times = workers.dump_sa_use_times().await.expect("dumped");
    assert!(use_times.is_empty());
}

/// A full queue: the caller waits (asynchronously) for room, then fails with
/// a clear error and nothing sent; a job that waited past the bound in the
/// queue is refused unsent too. Every job is counted out either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_fails_with_a_clear_error_and_drains() {
    let (permits, gate) = std::sync::mpsc::channel();
    let kernel = Arc::new(FakeKernel {
        gate: Some(std::sync::Mutex::new(gate)),
        ..FakeKernel::default()
    });
    let workers = Arc::new(pool(&kernel, 1, 1, Duration::from_millis(100)));

    // Held inside its kernel round trip.
    let held = tokio::spawn({
        let workers = Arc::clone(&workers);
        async move { workers.acknowledge_one(add_sa(5001)).await }
    });
    while kernel.requests.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // Takes the one queue slot.
    let queued = tokio::spawn({
        let workers = Arc::clone(&workers);
        async move { workers.acknowledge_one(add_sa(5002)).await }
    });
    while workers.queued() == 0 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let refused = workers.acknowledge_one(add_sa(5003)).await;
    let text = os_error(&refused);
    assert!(
        text.contains("queue full") && text.contains("not sent"),
        "{text}"
    );

    // Past the bound, then let the held one finish.
    tokio::time::sleep(Duration::from_millis(150)).await;
    permits.send(()).expect("gate open");
    held.await.expect("joined").expect("acked");
    let stale = queued.await.expect("joined");
    let text = os_error(&stale);
    assert!(text.contains("in the queue, not sent"), "{text}");

    assert_eq!(
        kernel.requests.load(Ordering::SeqCst),
        1,
        "only the first sent"
    );
    assert_eq!(workers.in_flight(), 0);
    assert_eq!(workers.queued(), 0);
}

/// Per-module leak gate: after a batch of completed, timed-out, late-acked
/// and abandoned operations, nothing is left in flight or queued, and every
/// reply the fake kernel sent has been read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_and_queue_drain_after_completed_timed_out_and_abandoned_jobs() {
    let kernel = Arc::new(FakeKernel {
        errno_of: [(XFRM_MSG_DELSA, ENOENT)].into(),
        never_ack: Some(XFRM_MSG_DELPOLICY),
        late_ack: Some(XFRM_MSG_DELSA),
        ..FakeKernel::default()
    });
    // One worker, so the flush below reaches the one socket holding a late ack.
    let workers = Arc::new(pool(&kernel, 1, 16, QUEUE_WAIT));
    let mut tasks = Vec::new();
    for round in 0..300u32 {
        let workers = Arc::clone(&workers);
        tasks.push(tokio::spawn(async move {
            match round % 4 {
                0 => workers.acknowledge_one(add_sa(6000 + round)).await.is_ok(),
                1 => workers.acknowledge_one(del_policy()).await.is_err(),
                2 => workers
                    .acknowledge(vec![
                        del_sa_message(&UE, 7000 + round),
                        add_sa(8000 + round),
                    ])
                    .await
                    .is_ok(),
                // Abandoned by its caller while queued or in flight.
                _ => {
                    let _ = tokio::time::timeout(
                        Duration::from_micros(50),
                        workers.acknowledge_one(add_sa(9000 + round)),
                    )
                    .await;
                    true
                }
            }
        }));
    }
    for task in tasks {
        assert!(task.await.expect("joined"));
    }
    // Abandoned jobs are still carried out by a worker; wait them out.
    for _ in 0..200 {
        if workers.in_flight() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(workers.in_flight(), 0);
    assert_eq!(workers.queued(), 0);
    // Flush the last late ack the socket may still hold back.
    workers.acknowledge_one(add_sa(9999)).await.expect("acked");
    assert_eq!(kernel.undelivered.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.opened.load(Ordering::SeqCst), 1);
}
