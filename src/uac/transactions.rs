//! The client transaction a request the UAC sender originates is sent under.
//!
//! RFC 3261 §17.1.2.2: a non-INVITE request sent over an unreliable transport
//! is retransmitted on Timer E, at T1 doubling to T2 while no response has
//! come and at T2 once a provisional has, until a final response or Timer F
//! (64·T1); Timer K then holds the transaction for T4 to absorb repeats of the
//! final response. Over a reliable transport there is no Timer E and Timer K
//! is zero.
//!
//! The state machine, its timers and the timer sweep are the dispatcher's
//! ([`crate::transaction`]), the ones a relayed request and a registrant
//! REGISTER run on. The sender reaches them through [`UacTransactions`], which
//! the dispatcher attaches once it is built, and decides nothing about
//! retransmission itself: it names the transport the request leaves over, and
//! the transaction does what §17.1.2.2 says for that transport. So whatever
//! picks the transport (a flow, a resolve, a switch to TCP for size, §18.1.1)
//! stays apart from this.
//!
//! Not sent under a transaction:
//!
//! * the OPTIONS probes of `send_options*` (NAT keepalive, gateway health,
//!   registrar liveness). Each is one datagram by contract: its caller waits a
//!   few seconds, counts a miss and sends a fresh probe on its own schedule;
//! * an INVITE or an ACK, which are not non-INVITE transactions (§17.1.1);
//! * a request whose topmost Via branch is not a UAC one
//!   ([`UAC_BRANCH_PREFIX`]): its response would never be handed back here,
//!   so nothing could stop the retransmissions.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tracing::debug;

use super::UacSender;
use crate::sip::message::{Method, SipMessage};
use crate::transaction::key::TransactionKey;
use crate::transport::{ConnectionId, OutboundMessage, Transport};

/// What every Via branch of a request the UAC sender originates starts with,
/// and what the dispatcher recognises its responses by.
pub const UAC_BRANCH_PREFIX: &str = "z9hG4bK-uac-";

/// Whether `branch` is the Via branch of a request the UAC sender originated.
pub fn is_uac_branch(branch: &str) -> bool {
    branch.starts_with(UAC_BRANCH_PREFIX)
}

/// The topmost Via branch of `message` when it is a UAC one.
pub fn uac_branch(message: &SipMessage) -> Option<String> {
    let via = message
        .headers
        .get("Via")
        .or_else(|| message.headers.get("v"))?;
    crate::sip::headers::via::Via::parse_multi(via)
        .ok()?
        .into_iter()
        .next()?
        .branch
        .filter(|branch| is_uac_branch(branch))
}

/// The transaction layer a request the UAC sender originates is sent under.
///
/// Implemented by the dispatcher, whose timer sweep drives the transaction's
/// timers and whose response path feeds it the answers.
pub trait UacTransactions: Send + Sync {
    /// Open a non-INVITE client transaction for `request`, whose wire form is
    /// `message`, before `message` is sent. Its retransmissions are
    /// `message.data` again, to where `message` goes and from the same local
    /// address.
    fn open(
        &self,
        request: &SipMessage,
        message: &OutboundMessage,
    ) -> Result<TransactionKey, String>;

    /// End the transaction `key` now, with its timers: its request never
    /// left, or nobody waits for its response any more.
    fn abandon(&self, key: &TransactionKey);
}

impl UacSender {
    /// Send every request from here on under a client transaction of
    /// `transactions`. The first layer attached stays.
    pub fn attach_transactions(&self, transactions: Arc<dyn UacTransactions>) {
        let _ = self.transactions.set(transactions);
    }

    /// Open the client transaction of `request`, which is about to go on the
    /// wire as `message` (RFC 3261 §17.1.2.2). The sender's own sends call
    /// this; so does a path that puts a request of this sender's on the wire
    /// itself, such as a NOTIFY the dispatcher sends behind the reply it has
    /// to follow.
    ///
    /// `None` when the request goes out once, as it did before: no layer is
    /// attached, or it is one of the requests the module documentation lists.
    pub fn track_request(
        &self,
        request: &SipMessage,
        message: &OutboundMessage,
    ) -> Option<TransactionKey> {
        let transactions = self.transactions.get()?;
        if matches!(request.method()?, Method::Invite | Method::Ack) {
            return None;
        }
        let branch = uac_branch(request)?;
        // Whoever waits on this branch ends the transaction when it stops
        // waiting (`expire_branch`). Its entry is held across the open, so
        // that cannot happen between the transaction opening and its key
        // being put where the waiter finds it. Nothing the open takes is ever
        // held while this map is taken.
        let mut waiter = self.pending.get_mut(&branch);
        let opened = match transactions.open(request, message) {
            Ok(key) => Some(key),
            Err(error) => {
                // The branch is already in use by a transaction still
                // running: the request goes out once and that one stands.
                debug!(branch = %branch, %error, "UAC request sent outside a transaction");
                None
            }
        };
        if let Some(waiter) = waiter.as_mut() {
            // On a branch a transaction already runs on, that transaction is
            // the one retransmitting what this waiter waits on.
            waiter.transaction = opened
                .clone()
                .or_else(|| crate::transaction::TransactionManager::key_from_message(request).ok());
        }
        opened
    }

    /// End a transaction [`track_request`](Self::track_request) opened.
    pub(super) fn abandon_transaction(&self, key: Option<&TransactionKey>) {
        if let (Some(key), Some(transactions)) = (key, self.transactions.get()) {
            transactions.abandon(key);
        }
    }

    /// Put `message` on the wire under its client transaction: the one place
    /// a pre-built request of this sender leaves from, whether or not its
    /// response is waited for.
    ///
    /// The egress is settled first ([`UacSender::egress`]), so the transaction
    /// retransmits to the address and from the socket the first copy really
    /// used: a retransmission that left another socket would be outside the
    /// security association the first one went over (TS 33.203 clause 7.1).
    pub(super) fn put_on_wire(
        &self,
        message: &SipMessage,
        destination: SocketAddr,
        transport: Transport,
        connection_id: ConnectionId,
        source_local_addr: Option<SocketAddr>,
    ) -> Result<(), String> {
        let data = Bytes::from(message.to_bytes());
        let (destination, source_local_addr) =
            self.egress(transport, destination, source_local_addr);

        if let Some(ref hep) = self.hep_sender {
            // The pinned socket is the one the request leaves from.
            let addr = source_local_addr.unwrap_or_else(|| self.addr_for(&transport));
            hep.capture_outbound(addr, destination, transport, &data);
        }

        let outbound_message = OutboundMessage {
            followups: None,
            connection_id,
            transport,
            destination,
            data,
            source_local_addr,
            server_name: None,
            verify_server: None,
        };

        // Opened before the send, so a response that overtakes the rest of
        // this function still finds its transaction.
        let transaction = self.track_request(message, &outbound_message);
        self.outbound.send(outbound_message).map_err(|error| {
            // Not on its way: nothing to retransmit.
            self.abandon_transaction(transaction.as_ref());
            error.to_string()
        })
    }
}
