//! The request a native handler receives, and relaying it.

use std::sync::Arc;
use std::time::Duration;

use super::NativeAnswer;
use crate::diameter::codec::{Avp, DiameterMsg};
use crate::diameter::dictionary::avp;
use crate::diameter::forward::{self, ForwardError};
use crate::diameter::peer::DiameterPeer;
use crate::diameter::pool::PeerPool;
use crate::diameter::relay::{self, RelayOptions};
use crate::diameter::DiameterClient;

/// An inbound request, with the connection it arrived on and the identity
/// this node answers it as.
#[derive(Clone)]
pub struct NativeRequest {
    message: DiameterMsg,
    inbound_hop_by_hop: u32,
    inbound_end_to_end: u32,
    peer: Arc<DiameterPeer>,
    peer_name: String,
    tenant: String,
    origin_host: String,
    origin_realm: String,
}

impl NativeRequest {
    pub(super) fn new(
        message: DiameterMsg,
        peer: Arc<DiameterPeer>,
        peer_name: &str,
        tenant: &str,
        origin: (&str, &str),
    ) -> Self {
        Self {
            inbound_hop_by_hop: message.hop_by_hop,
            inbound_end_to_end: message.end_to_end,
            message,
            peer,
            peer_name: peer_name.to_owned(),
            tenant: tenant.to_owned(),
            origin_host: origin.0.to_owned(),
            origin_realm: origin.1.to_owned(),
        }
    }

    /// The request as a message tree.
    pub fn message(&self) -> &DiameterMsg {
        &self.message
    }

    /// The request as a message tree, to change before relaying it. The
    /// identifiers a relayed copy and its answer carry are the received
    /// ones, whatever is written to the header here.
    pub fn message_mut(&mut self) -> &mut DiameterMsg {
        &mut self.message
    }

    pub fn application_id(&self) -> u32 {
        self.message.application_id
    }

    pub fn command_code(&self) -> u32 {
        self.message.command_code
    }

    pub fn session_id(&self) -> Option<String> {
        self.message.get_str(avp::SESSION_ID)
    }

    /// The first top-level AVP with `code` and `vendor`.
    pub fn avp(&self, code: u32, vendor: u32) -> Option<&Avp> {
        self.message.find(code, vendor)
    }

    /// The connection the request arrived on.
    pub fn peer(&self) -> &Arc<DiameterPeer> {
        &self.peer
    }

    /// The configured name of the peer the request arrived from.
    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    /// The tenant the connection belongs to (`"default"` on a single-domain
    /// server).
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The Origin-Host this node answers as on this connection.
    pub fn origin_host(&self) -> &str {
        &self.origin_host
    }

    /// The Origin-Realm this node answers as on this connection.
    pub fn origin_realm(&self) -> &str {
        &self.origin_realm
    }

    /// An answer carrying `result_code` and this node's identity, to fill in
    /// with [`NativeAnswer::set_avp`]. Session-Id, the Hop-by-Hop and
    /// End-to-End Identifiers and the P bit are the request's; the E bit is
    /// set for a protocol error (3xxx) only. It carries the request's
    /// Vendor-Specific-Application-Id and Auth-Session-State when the
    /// request has them, unless `result_code` is a protocol error.
    pub fn answer(&self, result_code: u32) -> NativeAnswer {
        self.build_answer(result_code, None)
    }

    /// [`answer`](Self::answer) with an Error-Message.
    pub fn answer_with_message(&self, result_code: u32, error_message: &str) -> NativeAnswer {
        self.build_answer(result_code, Some(error_message))
    }

    /// [`answer`](Self::answer) with Experimental-Result { Vendor-Id,
    /// Experimental-Result-Code } in the place of the Result-Code (RFC 6733
    /// section 7.6), where the 3GPP applications put the codes they define.
    pub fn answer_experimental(&self, vendor_id: u32, code: u32) -> NativeAnswer {
        // The envelope of an answer that is not a protocol error.
        let mut answer = self.build_answer(crate::diameter::dictionary::DIAMETER_SUCCESS, None);
        answer.set_experimental_result(vendor_id, code);
        answer
    }

    fn build_answer(&self, result_code: u32, error_message: Option<&str>) -> NativeAnswer {
        // Answered with the identifiers it was received with.
        let (answer, copied) = forward::build_handler_answer(
            &self.message,
            &self.origin_host,
            &self.origin_realm,
            result_code,
            error_message,
        );
        let mut answer = NativeAnswer::for_handler(answer, copied);
        answer.message_mut().hop_by_hop = self.inbound_hop_by_hop;
        answer.message_mut().end_to_end = self.inbound_end_to_end;
        answer
    }

    /// The directly connected peer of this request's tenant whose
    /// Origin-Host is `host`: see [`peer_for_host`].
    pub fn peer_for_host(&self, host: &str) -> Option<Arc<DiameterPeer>> {
        peer_for_host(&self.tenant, host)
    }

    /// Relay the request, as it is now, to `target` and wait for the answer:
    /// the path `request.forward_to` takes. The peer the request came from is
    /// recorded in a Route-Record, the relayed copy gets a fresh Hop-by-Hop
    /// Identifier and keeps its End-to-End Identifier, and the answer comes
    /// back with the received ones. A loop, a target that cannot be reached
    /// and a timeout are answered here (3005, 3002, 3004), so the result can
    /// be returned as it is.
    pub async fn relay(&self, target: RelayTarget, options: RelayOptions) -> NativeAnswer {
        let Some(backends) = target.backends else {
            let unreachable = ForwardError::PeerUnreachable;
            return NativeAnswer::from_message(forward::build_error_answer(
                &self.received_header(),
                &self.origin_host,
                &self.origin_realm,
                unreachable.result_code(),
                &unreachable.to_string(),
            ));
        };
        let inbound = relay::Inbound {
            hop_by_hop: self.inbound_hop_by_hop,
            end_to_end: self.inbound_end_to_end,
            previous_hop: self
                .peer
                .remote_origin_host()
                .unwrap_or_default()
                .to_owned(),
            local_origin: (self.origin_host.clone(), self.origin_realm.clone()),
        };
        let answer = relay::relay(self.message.clone(), inbound, backends, options).await;
        NativeAnswer::from_message(answer)
    }

    /// What an error answer reads of the request, with the identifiers it
    /// was received with.
    pub(super) fn received_header(&self) -> DiameterMsg {
        DiameterMsg {
            flags: self.message.flags,
            command_code: self.message.command_code,
            application_id: self.message.application_id,
            hop_by_hop: self.inbound_hop_by_hop,
            end_to_end: self.inbound_end_to_end,
            avps: self
                .message
                .find(avp::SESSION_ID, 0)
                .cloned()
                .into_iter()
                .collect(),
        }
    }
}

impl std::fmt::Debug for NativeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRequest")
            .field("application_id", &self.message.application_id)
            .field("command_code", &self.message.command_code)
            .field("peer_name", &self.peer_name)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

/// The directly connected peer whose Origin-Host is `host` in `tenant`, or
/// None when no open connection has it. Covers every connection of the
/// server, whichever side opened it; hosts compare without regard to case.
/// A relay sends a request whose Destination-Host is a directly connected
/// peer to that peer (RFC 6733 section 6.1.6).
pub fn peer_for_host(tenant: &str, host: &str) -> Option<Arc<DiameterPeer>> {
    crate::diameter::directory::find(tenant, host).map(|(_, peer)| peer)
}

/// Where [`NativeRequest::relay`] sends a request.
#[derive(Clone)]
pub struct RelayTarget {
    /// None: there is no peer to send to, and the relay answers 3002.
    backends: Option<relay::Backends>,
}

/// A [`RelayTarget`] picked from a pool, with what was picked.
pub struct PoolPick {
    /// Where to relay: the picked peer first, the pool's other open peers
    /// after it, as [`RelayTarget::pool`] gives.
    pub target: RelayTarget,
    /// The configured name of the picked peer, None when the pool has no
    /// open peer.
    pub peer: Option<String>,
    /// For a sticky pick, whether the key was already bound to that peer.
    /// False for a first pick, a re-pick, and every round-robin pick.
    pub affinity_hit: bool,
}

impl RelayTarget {
    /// One connection, with nowhere else to go when it cannot serve: no
    /// other peer is tried, whatever `diameter.retry` allows. For a peer of
    /// a pool use [`pool`](Self::pool) or [`pool_peer`](Self::pool_peer),
    /// which keep the pool's other peers.
    pub fn peer(peer: Arc<DiameterPeer>) -> Self {
        Self::client(Arc::new(DiameterClient::new(peer)))
    }

    /// One connection, by its client handle. Like [`peer`](Self::peer), it
    /// has no other peer to go to.
    pub fn client(client: Arc<DiameterClient>) -> Self {
        Self {
            backends: Some(relay::Backends {
                first: client,
                alternates: Vec::new(),
                configured: 0,
            }),
        }
    }

    /// The next open peer of `pool` in round-robin order. Its other open
    /// peers take the request once when that one cannot serve it and
    /// `diameter.retry` allows it.
    pub fn pool(pool: &PeerPool) -> Self {
        Self::picked(pool, pool.pick_round_robin())
    }

    /// The peer of `pool` that `key` (a Session-Id, a user) is bound to for
    /// `ttl`, picked round-robin the first time.
    pub fn pool_sticky(pool: &PeerPool, key: &str, ttl: Duration) -> Self {
        Self::picked(pool, pool.pick_sticky(key, ttl))
    }

    /// [`pool`](Self::pool), also naming the peer it picked.
    pub fn pool_named(pool: &PeerPool) -> PoolPick {
        let (peer, client) = pool.pick_round_robin_named().unzip();
        PoolPick {
            target: Self::picked(pool, client),
            peer,
            affinity_hit: false,
        }
    }

    /// [`pool_sticky`](Self::pool_sticky), also naming the peer it picked
    /// and saying whether `key` was already bound to it.
    pub fn pool_sticky_named(pool: &PeerPool, key: &str, ttl: Duration) -> PoolPick {
        match pool.pick_sticky_reported(key, ttl) {
            Some(pick) => PoolPick {
                target: Self::picked(pool, Some(pick.client)),
                peer: Some(pick.name),
                affinity_hit: pick.affinity_hit,
            },
            None => PoolPick {
                target: Self::picked(pool, None),
                peer: None,
                affinity_hit: false,
            },
        }
    }

    /// `client`, a peer of `pool` the caller picked itself (by weight, by
    /// its own rule), with the pool's other open peers to take the request
    /// once when that one cannot serve it and `diameter.retry` allows it.
    pub fn pool_peer(pool: &PeerPool, client: Arc<DiameterClient>) -> Self {
        Self::picked(pool, Some(client))
    }

    fn picked(pool: &PeerPool, picked: Option<Arc<DiameterClient>>) -> Self {
        Self {
            backends: picked.map(|first| relay::Backends {
                alternates: pool.alternates_to(&first),
                configured: pool.peer_names().len(),
                first,
            }),
        }
    }

    /// Whether there is a peer to send to. A pool with no open peer gives a
    /// target that is not reachable, and relaying to it answers 3002.
    pub fn is_reachable(&self) -> bool {
        self.backends.is_some()
    }
}
