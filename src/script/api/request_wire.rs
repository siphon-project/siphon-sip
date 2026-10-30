//! What a request remembers of the wire: the bytes it was received as
//! (`request.wire`), and the registrar events its `registrar.save()` calls are
//! holding back until the REGISTER's reply has gone out.

use std::sync::Arc;

use bytes::Bytes;

use crate::registrar::{RegisterEventHold, Registrar};

/// Received bytes and held registrar events of one request.
#[derive(Default)]
pub(crate) struct WireCapture {
    /// The datagram or stream frame as it arrived. A refcount on the receive
    /// buffer, so it lives only as long as the request does; anything queued
    /// beyond that copies what it needs (see `RegisterExchange`).
    wire: Option<Bytes>,
    /// Hold `registrar.save()` events until the reply is out (set by the
    /// dispatcher for the main request dispatch only).
    deferring: bool,
    hold: Option<RegisterEventHold>,
}

impl WireCapture {
    pub(crate) fn set_wire(&mut self, wire: Bytes) {
        self.wire = Some(wire);
    }

    pub(crate) fn wire(&self) -> Option<&Bytes> {
        self.wire.as_ref()
    }

    pub(crate) fn defer_registrar_events(&mut self) {
        self.deferring = true;
    }

    /// The hold this request's saves record into, made on first use.
    pub(crate) fn hold(&mut self, registrar: &Arc<Registrar>) -> &mut RegisterEventHold {
        let (wire, deferring) = (&self.wire, self.deferring);
        self.hold.get_or_insert_with(|| {
            RegisterEventHold::new(Arc::clone(registrar), wire.as_deref(), deferring)
        })
    }

    /// Hand the hold to the dispatcher, which publishes it after the reply.
    pub(crate) fn take_hold(&mut self) -> Option<RegisterEventHold> {
        self.hold.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::RegistrationEvent;
    use crate::sip::uri::SipUri;

    fn save(registrar: &Registrar, hold: &mut RegisterEventHold, user: &str) {
        registrar
            .apply_register_in(
                &format!("sip:{user}@example.com"),
                vec![crate::registrar::update::ContactUpdate {
                    uri: SipUri::new("192.0.2.10".to_string()).with_user(user.to_string()),
                    expires_secs: 3600,
                    q: 1.0,
                    call_id: "call".to_string(),
                    cseq: 1,
                    source_addr: None,
                    source_transport: None,
                    sip_instance: None,
                    reg_id: None,
                    path: Vec::new(),
                    flow: crate::registrar::FlowCapture::default(),
                    params: Vec::new(),
                    auth_user: None,
                }],
                false,
                Some(hold),
            )
            .expect("saved");
    }

    #[test]
    fn a_capture_without_bytes_makes_a_hold_without_an_exchange() {
        let registrar = Arc::new(Registrar::default());
        let mut capture = WireCapture::default();
        assert!(capture.wire().is_none());
        assert!(capture.hold(&registrar).exchange().is_none());
    }

    #[test]
    fn the_hold_is_made_once_and_taken_once() {
        let registrar = Arc::new(Registrar::default());
        let mut capture = WireCapture::default();
        capture.set_wire(Bytes::from_static(b"REGISTER sip:x SIP/2.0\r\n\r\n"));
        let first = Arc::as_ptr(capture.hold(&registrar).exchange().expect("exchange"));
        let second = Arc::as_ptr(capture.hold(&registrar).exchange().expect("exchange"));
        assert_eq!(first, second);
        assert!(capture.take_hold().is_some());
        assert!(capture.take_hold().is_none());
    }

    #[test]
    fn deferring_holds_events_until_the_flush() {
        let registrar = Arc::new(Registrar::default());
        let mut receiver = registrar.subscribe_events();
        let mut capture = WireCapture::default();
        capture.set_wire(Bytes::from_static(b"wire"));
        capture.defer_registrar_events();
        save(&registrar, capture.hold(&registrar), "alice");
        assert!(receiver.try_recv().is_err(), "nothing published yet");
        assert_eq!(capture.hold(&registrar).held(), 1);
        capture.hold(&registrar).flush();
        match receiver.try_recv().expect("published") {
            RegistrationEvent::Registered { exchange, .. } => {
                assert_eq!(exchange.expect("exchange").request().as_ref(), b"wire");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_dropped_hold_publishes_what_it_holds() {
        let registrar = Arc::new(Registrar::default());
        let mut receiver = registrar.subscribe_events();
        {
            let mut capture = WireCapture::default();
            capture.defer_registrar_events();
            save(&registrar, capture.hold(&registrar), "bob");
            assert!(receiver.try_recv().is_err());
        }
        assert!(matches!(
            receiver.try_recv(),
            Ok(RegistrationEvent::Registered { .. })
        ));
    }

    #[test]
    fn without_deferring_events_go_out_at_once_and_the_hold_stays_empty() {
        let registrar = Arc::new(Registrar::default());
        let mut receiver = registrar.subscribe_events();
        let mut capture = WireCapture::default();
        capture.set_wire(Bytes::from_static(b"wire"));
        save(&registrar, capture.hold(&registrar), "carol");
        assert!(receiver.try_recv().is_ok());
        assert_eq!(capture.hold(&registrar).held(), 0);
    }

    #[test]
    fn exchanges_and_held_events_drain_back_to_nothing() {
        let registrar = Arc::new(Registrar::default());
        let mut receiver = registrar.subscribe_events();
        let mut observed = Vec::new();
        for round in 0..50 {
            let mut capture = WireCapture::default();
            capture.set_wire(Bytes::from(format!("REGISTER {round}")));
            capture.defer_registrar_events();
            save(&registrar, capture.hold(&registrar), "dave");
            let exchange = Arc::clone(capture.hold(&registrar).exchange().expect("exchange"));
            observed.push(exchange);
            // Every second request is abandoned, as a raising handler would.
            if round % 2 == 0 {
                capture.hold(&registrar).flush();
            }
            drop(capture);
        }
        while receiver.try_recv().is_ok() {}
        for exchange in observed {
            // This vector's clone is the only reference left: the capture, the
            // hold and every published event have let go.
            assert_eq!(Arc::strong_count(&exchange), 1);
        }
        assert_eq!(Arc::strong_count(&registrar), 1);
    }
}
