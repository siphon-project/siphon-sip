//! Calling native handlers without a server, for a handler crate's tests.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::dispatch::{answer_wire, Inbound};
use super::NativeHandlers;
use crate::diameter::codec::DiameterMsg;
use crate::diameter::peer::{DiameterPeer, PeerConfig};

/// What [`NativeHarness::call`] got for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessOutcome {
    /// The answer a handler gave, on the wire. A handler that failed or
    /// panicked gives the 5012 the server sends for it.
    Answer(Vec<u8>),
    /// The handler returned [`NativeOutcome::Script`](super::NativeOutcome),
    /// or the request does not parse: the server hands it to the script.
    Script,
    /// No handler is registered for the request's application and command.
    Unregistered,
}

impl HarnessOutcome {
    /// The answer as a message tree, None when there is none.
    pub fn answer(&self) -> Option<DiameterMsg> {
        match self {
            HarnessOutcome::Answer(wire) => DiameterMsg::from_wire(wire).ok(),
            _ => None,
        }
    }
}

/// Runs a request through a set of handlers the way the server does, short
/// of sending the answer: the lookup by (application id, command code), the
/// handler, and the 5012 for one that fails or panics. The answer comes back
/// as the bytes the server would send, before any overload report.
///
/// The peer the request "arrived on" is a connection to nothing: what a
/// handler sends on it goes nowhere and is never answered.
///
/// ```rust
/// use siphon::diameter::codec::{Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
/// use siphon::diameter::dictionary::{self, avp};
/// use siphon::diameter::native::{NativeHandlers, NativeHarness, NativeOutcome};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let handlers = NativeHandlers::new().handle(
///     dictionary::S6A_APP_ID,
///     dictionary::CMD_PURGE_UE,
///     |request| async move { Ok(NativeOutcome::Answer(request.answer(2001))) },
/// )?;
/// let request = DiameterMsg {
///     flags: FLAG_REQUEST | FLAG_PROXIABLE,
///     command_code: dictionary::CMD_PURGE_UE,
///     application_id: dictionary::S6A_APP_ID,
///     hop_by_hop: 1,
///     end_to_end: 2,
///     avps: vec![Avp::utf8(avp::SESSION_ID, 0, "mme.example.com;1;1")],
/// };
/// let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// let outcome = runtime.block_on(NativeHarness::new(handlers).call(&request));
/// let answer = outcome.answer().ok_or("no answer")?;
/// assert_eq!(answer.answer_result_codes().0, Some(2001));
/// # Ok(())
/// # }
/// ```
pub struct NativeHarness {
    handlers: NativeHandlers,
    peer: Arc<DiameterPeer>,
    /// Holds the other end of the peer's write channel open.
    _written: mpsc::Receiver<Vec<u8>>,
    peer_name: String,
    tenant: String,
    origin: (String, String),
}

impl NativeHarness {
    /// A harness over `handlers`, answering as `siphon.example.com` in
    /// `example.com`, for a peer `peer` of tenant `default` that gave
    /// `client.example.com` in its capabilities exchange.
    pub fn new(handlers: NativeHandlers) -> Self {
        let origin = ("siphon.example.com".to_owned(), "example.com".to_owned());
        let (peer, written) = unconnected_peer(&origin);
        peer.set_remote_identity("client.example.com", "example.com");
        Self {
            handlers,
            peer,
            _written: written,
            peer_name: "peer".to_owned(),
            tenant: "default".to_owned(),
            origin,
        }
    }

    /// Answer as `origin_host` in `origin_realm`.
    pub fn with_origin(mut self, origin_host: &str, origin_realm: &str) -> Self {
        self.origin = (origin_host.to_owned(), origin_realm.to_owned());
        self
    }

    /// The request arrives from the configured peer `peer_name` of `tenant`.
    pub fn with_peer(mut self, peer_name: &str, tenant: &str) -> Self {
        self.peer_name = peer_name.to_owned();
        self.tenant = tenant.to_owned();
        self
    }

    /// The request arrives on a connection whose other end gave
    /// `origin_host` and `origin_realm` in its capabilities exchange.
    pub fn with_peer_identity(mut self, origin_host: &str, origin_realm: &str) -> Self {
        let (peer, written) = unconnected_peer(&self.origin);
        peer.set_remote_identity(origin_host, origin_realm);
        self.peer = peer;
        self._written = written;
        self
    }

    /// Run `request` through the handlers.
    pub async fn call(&self, request: &DiameterMsg) -> HarnessOutcome {
        let Some(handler) = self
            .handlers
            .get(request.application_id, request.command_code)
        else {
            return HarnessOutcome::Unregistered;
        };
        let inbound = Inbound {
            peer: &self.peer,
            peer_name: &self.peer_name,
            tenant: &self.tenant,
            origin: (&self.origin.0, &self.origin.1),
        };
        match answer_wire(handler, request.clone(), &inbound).await {
            Some(wire) => HarnessOutcome::Answer(wire),
            None => HarnessOutcome::Script,
        }
    }

    /// Run the request in `wire` through the handlers.
    pub async fn call_wire(&self, wire: &[u8]) -> HarnessOutcome {
        match DiameterMsg::from_wire(wire) {
            Ok(request) => self.call(&request).await,
            Err(_) => HarnessOutcome::Script,
        }
    }
}

/// An open peer handle with no connection behind it.
fn unconnected_peer(origin: &(String, String)) -> (Arc<DiameterPeer>, mpsc::Receiver<Vec<u8>>) {
    let (write_tx, written) = mpsc::channel(64);
    let config = PeerConfig {
        host: "client.example.com".to_owned(),
        port: 3868,
        origin_host: origin.0.clone(),
        origin_realm: origin.1.clone(),
        destination_host: None,
        destination_realm: origin.1.clone(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: Vec::new(),
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "SIPhon".to_owned(),
        firmware_revision: 0,
    };
    (
        Arc::new(DiameterPeer::new_for_test(config, write_tx)),
        written,
    )
}
