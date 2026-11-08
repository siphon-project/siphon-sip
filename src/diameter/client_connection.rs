//! Client peer reconnect loop, shared by fixed peers and DNS members.
use super::{
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
    let reconnect_delay = peer_config.reconnect_delay;

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
            match crate::diameter::peer::connect(peer_config.clone()).await {
                Ok((peer, mut incoming_rx)) => {
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
                    warn!(peer = %peer_name, "Diameter peer disconnected, reconnecting");
                }
                Err(error) => {
                    crate::metrics::set_diameter_peer_up(&peer_name, false);
                    warn!(
                        peer = %peer_name, %error,
                        "Diameter connection failed, retrying in {reconnect_delay}s",
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(reconnect_delay)).await;
        }
    })
}
