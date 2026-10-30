//! What a REGISTER's registration events carry, and when they are published.
//!
//! A registrar-of-record answers a REGISTER with the 200 OK, and only then
//! tells anyone the registration changed (the third-party REGISTER of
//! TS 24.229 §5.4.1.7, a reg-event NOTIFY under RFC 3680). `save()` runs while
//! the script handler is still deciding the reply, so its events are held in a
//! [`RegisterEventHold`] and published once the reply has been handed to the
//! transport, or when the hold is dropped, whichever the request's path
//! reaches: a relay, a silent drop, a handler that raised and a timeout all
//! drop it, so no event is ever lost.
//!
//! The same hold carries the [`RegisterExchange`]: the REGISTER as it was
//! received and the 200 OK that answered it, which TS 24.229 §5.4.1.7 puts in
//! the body of the third-party REGISTER.

use std::sync::{Arc, OnceLock};

use bytes::Bytes;

use super::{Registrar, RegistrationEvent};

/// One REGISTER and the 200 OK that answered it, as they went on the wire.
///
/// One REGISTER is one device, so an event carrying it names that device's
/// request, not the AoR's whole registration. The request is a right-sized
/// copy: queued in the registrar's event channel, a slice of the receive buffer
/// would keep 8 to 64 KiB alive per held event.
#[derive(Debug, PartialEq, Eq)]
pub struct RegisterExchange {
    request: Bytes,
    response: OnceLock<Bytes>,
}

impl RegisterExchange {
    /// An exchange for the REGISTER received as `received_request`; the
    /// response follows with [`set_response`](Self::set_response).
    pub fn new(received_request: &[u8]) -> Self {
        Self {
            request: Bytes::copy_from_slice(received_request),
            response: OnceLock::new(),
        }
    }

    /// The REGISTER, byte for byte as it was received.
    pub fn request(&self) -> &Bytes {
        &self.request
    }

    /// The 200 OK as it was sent, `None` until it is known (or when siphon did
    /// not answer the REGISTER itself).
    pub fn response(&self) -> Option<&Bytes> {
        self.response.get()
    }

    /// Record the response that answered the REGISTER. The first one wins;
    /// returns whether this call set it.
    pub fn set_response(&self, response: Bytes) -> bool {
        self.response.set(response).is_ok()
    }
}

/// The events one REGISTER's `save()` calls produced, and the exchange they
/// share. Publishes what it still holds when dropped.
pub struct RegisterEventHold {
    registrar: Arc<Registrar>,
    exchange: Option<Arc<RegisterExchange>>,
    deferring: bool,
    held: Vec<RegistrationEvent>,
}

impl RegisterEventHold {
    /// A hold for a REGISTER received as `request_wire` (`None` when the bytes
    /// are not known: no exchange is attached). With `deferring`, events are
    /// kept until [`flush`](Self::flush) or the drop; without, they are
    /// published as they happen and the hold only carries the exchange.
    pub fn new(registrar: Arc<Registrar>, request_wire: Option<&[u8]>, deferring: bool) -> Self {
        Self {
            registrar,
            exchange: request_wire.map(|wire| Arc::new(RegisterExchange::new(wire))),
            deferring,
            held: Vec::new(),
        }
    }

    /// The exchange attached to this REGISTER's events.
    pub fn exchange(&self) -> Option<&Arc<RegisterExchange>> {
        self.exchange.as_ref()
    }

    /// How many events are held, not yet published.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Announce one event, built around this hold's exchange: published now, or
    /// kept for the flush.
    pub(super) fn record(
        &mut self,
        registrar: &Registrar,
        make: impl FnOnce(Option<Arc<RegisterExchange>>) -> RegistrationEvent,
    ) {
        let event = make(self.exchange.clone());
        if self.deferring {
            self.held.push(event);
        } else {
            registrar.emit_event(event);
        }
    }

    /// Publish every held event, in the order they were recorded.
    pub fn flush(&mut self) {
        for event in std::mem::take(&mut self.held) {
            self.registrar.emit_event(event);
        }
    }
}

impl Drop for RegisterEventHold {
    fn drop(&mut self) {
        self.flush();
    }
}

impl Registrar {
    /// Announce `make`'s event: through `hold` when the change belongs to a
    /// REGISTER, else straight onto the channel, carrying no exchange.
    pub(super) fn announce(
        &self,
        hold: Option<&mut RegisterEventHold>,
        make: impl FnOnce(Option<Arc<RegisterExchange>>) -> RegistrationEvent,
    ) {
        match hold {
            Some(hold) => hold.record(self, make),
            None => self.emit_event(make(None)),
        }
    }
}
