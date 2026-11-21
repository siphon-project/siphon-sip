//! Startup eviction of the stream bindings a backend restore brings back.

use tracing::warn;

/// Evict the stream-transport bindings the backend restore brought back, and
/// say how many.
///
/// A TCP, TLS or WebSocket binding names a connection that ended with the
/// process that accepted it, so restored as live it reads as registered while
/// nothing can reach it until the UE registers again. Must run after the
/// restore and after [`reconcile_ipsec_restart`] (a protected binding goes
/// there first, with the egress bars for its endpoints that this eviction
/// would not set), and before any listener accepts, so a REGISTER cannot land
/// in the gap and have its fresh binding evicted with the stale ones.
pub(super) fn evict_restored_stream_bindings_at_startup() {
    if let Some(registrar) = crate::script::api::registrar_arc() {
        evict_restored_stream_bindings(registrar);
    }
}

/// [`evict_restored_stream_bindings_at_startup`] on a registrar at hand.
pub(super) fn evict_restored_stream_bindings(registrar: &crate::registrar::Registrar) -> usize {
    let evicted = registrar.evict_connection_oriented();
    if evicted > 0 {
        warn!(
            evicted,
            "restored stream-transport bindings evicted: their connections ended with the \
             previous process, the UE re-registers"
        );
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::{backend, FlowCapture, InstanceIdentity, Registrar};
    use crate::sip::uri::SipUri;
    use crate::transport::Transport;

    fn save_over(registrar: &Registrar, aor: &str, transport: Transport) {
        registrar
            .save_full(
                aor,
                SipUri::new("192.0.2.10".to_string()).with_user("phone".to_string()),
                3600,
                1.0,
                format!("call-{aor}"),
                1,
                None,
                Some(transport),
                None,
                None,
                vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();
    }

    /// The restore brings a TCP phone back; the eviction removes it and keeps
    /// the UDP one. A phone that registers after the restore, over a live
    /// connection, survives an eviction that runs afterwards.
    #[tokio::test]
    async fn only_what_the_restore_brought_back_is_evicted() {
        let store = backend::MemoryBackend::new();
        let previous = Registrar::default();
        previous.set_instance_identity(InstanceIdentity {
            id: "node-a".into(),
            epoch: "previous-boot".into(),
        });
        save_over(&previous, "sip:tcp@example.com", Transport::Tcp);
        save_over(&previous, "sip:udp@example.com", Transport::Udp);
        for aor in ["sip:tcp@example.com", "sip:udp@example.com"] {
            let stored: Vec<backend::StoredContact> = previous
                .lookup_all(aor)
                .iter()
                .map(backend::StoredContact::from_contact)
                .collect();
            backend::RegistrarBackend::save(&store, aor, &stored)
                .await
                .unwrap();
        }

        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "node-a".into(),
            epoch: "this-boot".into(),
        });
        backend::restore_from_backend(&store, &registrar)
            .await
            .unwrap();
        assert!(registrar.is_registered("sip:tcp@example.com"));

        // A REGISTER processed after the restore and before the eviction.
        save_over(&registrar, "sip:fresh@example.com", Transport::Tls);

        assert_eq!(evict_restored_stream_bindings(&registrar), 1);
        assert!(!registrar.is_registered("sip:tcp@example.com"));
        assert!(registrar.is_registered("sip:udp@example.com"));
        assert!(registrar.is_registered("sip:fresh@example.com"));
    }

    /// The gap the eviction closes: it has to run before the first listener
    /// accepts, or a REGISTER processed meanwhile is evicted with the stale
    /// bindings. A source scan, because startup cannot run in a unit test.
    #[test]
    fn startup_evicts_before_any_listener_starts() {
        let startup = include_str!("mod.rs");
        let eviction = startup
            .find("evict_restored_stream_bindings_at_startup();")
            .expect("startup evicts the restored stream bindings");
        for listener in [
            "starting UDP transport",
            "starting TCP transport",
            "starting TLS transport",
            "starting WS transport",
        ] {
            let started = startup.find(listener).expect(listener);
            assert!(eviction < started, "the eviction runs after: {listener}");
        }
        let restore = startup
            .find("init_registrar_backend(&config).await")
            .expect("startup restores the registrar");
        assert!(restore < eviction, "the eviction runs before the restore");
    }
}
