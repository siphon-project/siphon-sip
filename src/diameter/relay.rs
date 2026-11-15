//! The relay driver: send a received request on to another peer and return
//! the answer for the peer it came from.
//!
//! One path for every relay this node makes, whoever decided it: Route-Record
//! and loop detection ([`forward::prepare_forward`]), a fresh Hop-by-Hop
//! Identifier towards the backend, the wait for its answer, and the error
//! answer when there is none ([`overload_agent::relay`]).

use std::sync::Arc;
use std::time::Duration;

use super::codec::{DiameterMsg, FLAG_RETRANSMITTED};
use super::dictionary::avp;
use super::{forward, overload_agent, retry, DiameterClient};

/// How a request is relayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOptions {
    /// Origin-Host and Origin-Realm to put in the request's place (topology
    /// hiding). None leaves the request's own.
    pub identity: Option<(String, String)>,
    /// How long to wait for the answer.
    pub timeout: Duration,
    /// Set the T flag: the request is sent again after a failover (RFC 6733
    /// sections 5.5.4 and 6.1.8).
    pub retransmitted: bool,
}

impl Default for RelayOptions {
    /// The request's own origin, ten seconds, not a retransmission.
    fn default() -> Self {
        Self {
            identity: None,
            timeout: Duration::from_secs(10),
            retransmitted: false,
        }
    }
}

impl RelayOptions {
    /// Wait `timeout` for the answer.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the request's Origin-Host and Origin-Realm.
    pub fn identity(mut self, origin_host: &str, origin_realm: &str) -> Self {
        self.identity = Some((origin_host.to_owned(), origin_realm.to_owned()));
        self
    }

    /// Set the T flag on the relayed request.
    pub fn retransmitted(mut self, retransmitted: bool) -> Self {
        self.retransmitted = retransmitted;
        self
    }
}

/// What the relay keeps of the request as it was received.
pub(crate) struct Inbound {
    pub(crate) hop_by_hop: u32,
    pub(crate) end_to_end: u32,
    /// Origin-Host of the peer the request was received from; empty when
    /// that peer gave none.
    pub(crate) previous_hop: String,
    /// This node's Origin-Host and Origin-Realm.
    pub(crate) local_origin: (String, String),
}

/// Where a relayed request may go.
#[derive(Clone)]
pub(crate) struct Backends {
    pub(crate) first: Arc<DiameterClient>,
    /// The other open members of the pool `first` came from.
    pub(crate) alternates: Vec<Arc<DiameterClient>>,
    /// How many members that pool has, open or not (0 when unknown).
    pub(crate) configured: usize,
}

/// Relay `tree` to `backends` and return the answer for the peer it came
/// from, carrying the inbound identifiers. A loop, an unreachable backend or
/// a timeout is answered here (3005 / 3002 / 3004).
pub(crate) async fn relay(
    mut tree: DiameterMsg,
    inbound: Inbound,
    backends: Backends,
    options: RelayOptions,
) -> DiameterMsg {
    let (local_origin_host, local_origin_realm) = inbound.local_origin;
    // Every identity this node uses on the request: its own and the one it
    // may put in the request's place (topology hiding).
    let mut identities = vec![local_origin_host.clone()];
    if let Some((origin_host, origin_realm)) = options.identity {
        forward::rewrite_origin(&mut tree, &origin_host, &origin_realm);
        identities.push(origin_host);
    }
    // The peer it came from; for a connection whose peer gave no identity,
    // the request's own origin.
    let previous_hop = if inbound.previous_hop.is_empty() {
        tree.get_str(avp::ORIGIN_HOST).unwrap_or_default()
    } else {
        inbound.previous_hop
    };

    // Loop detection + Route-Record append.
    let identities: Vec<&str> = identities.iter().map(String::as_str).collect();
    if let Err(error) = forward::prepare_forward(&mut tree, &identities, &previous_hop) {
        return forward::build_error_answer(
            &tree,
            &local_origin_host,
            &local_origin_realm,
            error.result_code(),
            &error.to_string(),
        );
    }

    // Fresh outbound hop-by-hop; End-to-End is preserved. Every answer this
    // node makes from here on goes back with the inbound one (RFC 6733
    // section 6.2).
    // A retransmission keeps its T bit on the relayed copy (RFC 6733 section
    // 3); answers mask it off (forward::answer_in keeps only P).
    if options.retransmitted {
        tree.flags |= FLAG_RETRANSMITTED;
    }
    tree.hop_by_hop = inbound.hop_by_hop;
    tree.end_to_end = inbound.end_to_end;
    let policy = retry::current();
    overload_agent::relay(
        &policy,
        &mut tree,
        overload_agent::Target {
            first: &backends.first,
            alternates: &backends.alternates,
            configured: backends.configured,
        },
        options.timeout,
        (&local_origin_host, &local_origin_realm),
    )
    .await
}
