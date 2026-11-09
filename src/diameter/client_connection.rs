//! Client peer reconnect loop, shared by fixed peers and DNS members.
use super::{
    backoff::ReconnectSchedule,
    peer::{DiameterPeer, IncomingRequest, PeerConfig},
    DiameterManager,
};
use std::sync::Arc;
use tracing::{info, warn};

pub type Incoming = tokio::sync::mpsc::Sender<(IncomingRequest, Arc<DiameterPeer>)>;

pub fn spawn(
    peer_name: String,
    peer_config: PeerConfig,
    manager_for_task: Arc<DiameterManager>,
    tx: Incoming,
) -> tokio::task::JoinHandle<()> {
    let mut schedule = ReconnectSchedule::new(
        peer_config.reconnect_delay,
        peer_config.lifecycle.reconnect_delay_max,
    );

    // Publish the peer as down before the first connect attempt.
    // The reconnect task below only registers a client *after* a
    // successful connect, so without this a peer that has never
    // come up would be absent from the gauge rather than
    // reported down — the failure most worth seeing.
    crate::metrics::set_diameter_peer_up(&peer_name, false);

    // Spawn a persistent reconnect task per peer — reconnects
    // when the connection drops (watchdog failure, TCP reset, etc.)
    // and re-registers the client in the DiameterManager.
    tokio::spawn(async move {
        loop {
            let delay;
            match crate::diameter::peer::connect(peer_config.clone()).await {
                Ok((peer, mut incoming_rx)) => {
                    // After a failure the peer starts in REOPEN and takes no
                    // traffic before it has answered its watchdogs.
                    if schedule.connected() {
                        peer.enter_reopen().await;
                    }
                    let client = Arc::new(crate::diameter::DiameterClient::new(Arc::clone(&peer)));
                    manager_for_task.register(peer_name.clone(), client);
                    crate::metrics::set_diameter_peer_up(&peer_name, true);
                    info!(peer = %peer_name, "Diameter peer connected");

                    // Forward incoming requests until the peer disconnects.
                    //
                    // The awaiting send is deliberate, and is the one
                    // shape of it that is correct: this task does nothing
                    // else, holds no lock, no handler thread and no read
                    // loop, so parking it on a full dispatch queue is
                    // backpressure rather than a stall. It resumes in
                    // order when capacity frees, losing nothing.
                    //
                    // What must not happen is that backpressure reaching
                    // the peer's *reader* task, which is also what
                    // correlates answers — that would fail every
                    // in-flight request on the peer at once. It cannot:
                    // the reader sheds into `incoming_rx` rather than
                    // awaiting it, so a wedged dispatcher degrades to
                    // dropped inbound requests (the peer retries) and
                    // never to a stalled connection.
                    let tx_inner = tx.clone();
                    let peer_for_forward = Arc::clone(&peer);
                    while let Some(request) = incoming_rx.recv().await {
                        if tx_inner
                            .send((request, Arc::clone(&peer_for_forward)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }

                    // incoming_rx closed — peer disconnected
                    crate::metrics::set_diameter_peer_up(&peer_name, false);
                    match schedule.ended(&peer) {
                        None => {
                            info!(peer = %peer_name, "Diameter peer disconnected by this node, not reconnecting");
                            return;
                        }
                        Some(wait) => {
                            warn!(
                                peer = %peer_name, wait_secs = wait.as_secs(),
                                cause = ?peer.remote_disconnect_cause(),
                                "Diameter peer disconnected, reconnecting",
                            );
                            delay = wait;
                        }
                    }
                }
                Err(error) => {
                    crate::metrics::set_diameter_peer_up(&peer_name, false);
                    delay = schedule.failed();
                    warn!(
                        peer = %peer_name, %error,
                        "Diameter connection failed, retrying in {}s",
                        delay.as_secs(),
                    );
                }
            }
            tokio::time::sleep(delay).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn a_peer_that_stays_away_is_dialled_at_growing_jittered_intervals_up_to_the_ceiling() {
        // A peer that accepts and hangs up on the CER: every attempt fails.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
                let _ = seen_tx.send(Instant::now());
            }
        });
        let config = PeerConfig {
            host: "127.0.0.1".to_string(),
            port,
            origin_host: "node.example.org".to_string(),
            origin_realm: "example.org".to_string(),
            destination_host: None,
            destination_realm: "example.org".to_string(),
            local_ip: "127.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 1,
            source_address: None,
            lifecycle: crate::diameter::lifecycle::PeerLifecycle {
                reconnect_delay_max: 2,
                ..Default::default()
            },
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let task = spawn(
            "away".to_string(),
            config,
            Arc::new(DiameterManager::new()),
            tx,
        );

        let mut dials = Vec::new();
        for _ in 0..5 {
            let at = tokio::time::timeout(Duration::from_secs(10), seen_rx.recv())
                .await
                .expect("the peer is dialled again")
                .unwrap();
            dials.push(at);
        }
        task.abort();

        let gaps: Vec<f64> = dials
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]).as_secs_f64())
            .collect();
        // Nominal 1 s, 2 s, then held at the 2 s ceiling; each up to 30 %
        // shorter by jitter, plus the time an attempt itself takes.
        let nominal = [1.0, 2.0, 2.0, 2.0];
        for (gap, nominal) in gaps.iter().zip(nominal) {
            assert!(
                *gap >= nominal * 0.7 - 0.05 && *gap <= nominal + 0.5,
                "gap {gap:.2}s outside the window of a {nominal}s wait: {gaps:?}"
            );
        }
        assert!(gaps[1] > gaps[0] - 0.4, "the wait grows: {gaps:?}");
    }
}
