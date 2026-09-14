//! Channel ownership: registering, offering, reattaching and releasing
//! controlled channels, the ownership check a command is authorised against,
//! and per-call variables.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{debug, warn};

use crate::control::protocol::EventFrame;

use super::queue::record_push_outcome;
use super::{ChannelEntry, ChannelRef, ConnHandle, ControlBus, OfferOutcome, Ownership};

impl ControlBus {
    /// Register a controlled channel to an owning connection.
    #[allow(clippy::too_many_arguments)]
    pub fn register_channel(
        &self,
        channel_id: &str,
        conn: &ConnHandle,
        call_actor_id: &str,
        sip_call_id: &str,
        on_lost: &str,
        vars: HashMap<String, String>,
    ) {
        self.channels.insert(
            channel_id.to_string(),
            Arc::new(ChannelEntry {
                app: conn.app.clone(),
                conn_id: AtomicU64::new(conn.id),
                call_actor_id: call_actor_id.to_string(),
                sip_call_id: sip_call_id.to_string(),
                on_lost: on_lost.to_string(),
                vars: Mutex::new(vars),
                outbound_transfer: Mutex::new(None),
            }),
        );
        self.app_calls
            .entry(conn.app.clone())
            .or_default()
            .insert(channel_id.to_string());
        crate::metrics::try_metrics().inspect(|m| {
            m.control_controlled_calls
                .with_label_values(&[&conn.app])
                .inc()
        });
    }

    /// Remove a channel and drop it from the app index. Returns whether it was
    /// present.
    pub fn remove_channel(&self, channel_id: &str) -> bool {
        match self.channels.remove(channel_id) {
            Some((_, entry)) => {
                if let Some(mut set) = self.app_calls.get_mut(&entry.app) {
                    set.remove(channel_id);
                }
                self.app_calls
                    .remove_if(&entry.app, |_, set| set.is_empty());
                crate::metrics::try_metrics().inspect(|m| {
                    m.control_controlled_calls
                        .with_label_values(&[&entry.app])
                        .dec()
                });
                true
            }
            None => false,
        }
    }

    /// The channel id owning `sip_call_id`, if controlled (for a `StasisEnd` /
    /// release before removal). O(channels) — a per-call teardown path, not
    /// per-packet.
    pub fn channel_id_for_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.channels
            .iter()
            .find(|entry| entry.value().sip_call_id == sip_call_id)
            .map(|entry| entry.key().clone())
    }

    /// Release a controlled channel back to siphon (the controller handed control
    /// back with a routing decision — `route`), emitting a `StasisEnd` with the
    /// given `reason` to the owning connection and draining the channel from the
    /// bus. **Distinct from teardown-on-hangup** ([`on_call_terminated`]): the
    /// underlying call lives on — siphon now owns it and drives the B-leg dial
    /// itself. Idempotent — a no-op when the channel is unknown. Returns whether
    /// a channel was released.
    ///
    /// [`on_call_terminated`]: Self::on_call_terminated
    pub fn release_channel(&self, channel_id: &str, reason: &str) -> bool {
        let (app, call_actor_id, sip_call_id) = match self.channels.get(channel_id) {
            Some(entry) => (
                entry.app.clone(),
                entry.call_actor_id.clone(),
                entry.sip_call_id.clone(),
            ),
            None => return false,
        };
        // A transfer still awaiting its verdict can never get one once the
        // channel is gone — report it before the StasisEnd that ends the stream.
        self.flush_outbound_transfer(channel_id, &sip_call_id);
        self.publish_to_channel(
            channel_id,
            EventFrame::new(
                "StasisEnd",
                channel_id,
                &app,
                &call_actor_id,
                &sip_call_id,
                serde_json::json!({ "reason": reason }),
            ),
        );
        self.remove_channel(channel_id);
        debug!(%channel_id, %sip_call_id, reason, "control plane: channel released (control returned to siphon)");
        true
    }

    /// Whether the given connection owns the channel (authZ for a command).
    pub fn owns(&self, channel_id: &str, app: &str, conn_id: u64) -> Ownership {
        match self.channels.get(channel_id) {
            None => Ownership::Unknown,
            Some(entry) => {
                if entry.app != app {
                    Ownership::Forbidden
                } else if entry.conn_id.load(Ordering::SeqCst) == conn_id
                    || entry.conn_id.load(Ordering::SeqCst) == 0
                {
                    // Same connection, or an orphaned channel of the same app
                    // being addressed by a reconnecting owner (post-resync).
                    Ownership::Owned(ChannelRef {
                        channel_id: channel_id.to_string(),
                        call_actor_id: entry.call_actor_id.clone(),
                        sip_call_id: entry.sip_call_id.clone(),
                        app: entry.app.clone(),
                    })
                } else {
                    Ownership::Forbidden
                }
            }
        }
    }

    /// Offer a handed-over call to an app: assign a persistent owner (round
    /// robin) and push `StasisStart`, or launch a per-call-connect dial. Returns
    /// the outcome so the dispatcher knows whether to arm the handoff deadline
    /// or apply the default action immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_channel(
        self: &Arc<Self>,
        app: &str,
        channel_id: &str,
        call_actor_id: &str,
        sip_call_id: &str,
        on_lost: &str,
        vars: HashMap<String, String>,
        stasis_payload: serde_json::Value,
    ) -> OfferOutcome {
        let per_call_connect = self
            .app_config
            .get(app)
            .map(|config| config.per_call_connect)
            .unwrap_or(false);

        if per_call_connect {
            let config = match self.app_config.get(app) {
                Some(config) => config.clone(),
                None => return OfferOutcome::NoController,
            };
            let Some(connect_url) = config.connect_url.clone() else {
                warn!(%app, "control plane: per_call_connect app has no connect_url");
                return OfferOutcome::NoController;
            };
            crate::control::outbound::dial_and_own(
                Arc::clone(self),
                config.name.clone(),
                config.token.clone(),
                connect_url,
                config.ca_file.clone(),
                crate::control::outbound::PendingOwn {
                    channel_id: channel_id.to_string(),
                    call_actor_id: call_actor_id.to_string(),
                    sip_call_id: sip_call_id.to_string(),
                    on_lost: on_lost.to_string(),
                    vars,
                    stasis_payload,
                },
            );
            return OfferOutcome::Dialing;
        }

        // Persistent inbound mode: round-robin a live connection.
        match self.pick_connection(app) {
            Some(conn) => {
                self.register_channel(channel_id, &conn, call_actor_id, sip_call_id, on_lost, vars);
                record_push_outcome(
                    app,
                    conn.events.try_push_event(EventFrame::new(
                        "StasisStart",
                        channel_id,
                        app,
                        call_actor_id,
                        sip_call_id,
                        stasis_payload,
                    )),
                );
                OfferOutcome::Assigned
            }
            None => OfferOutcome::NoController,
        }
    }

    /// Re-claim (reattach) an app's orphaned channels to a reconnecting
    /// connection, and return the current snapshot of everything it now owns
    /// (for the `resync` reply).
    pub fn reattach(&self, conn: &ConnHandle) -> Vec<ChannelRef> {
        let channel_ids: Vec<String> = self
            .app_calls
            .get(&conn.app)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default();
        let mut owned = Vec::new();
        for channel_id in channel_ids {
            if let Some(entry) = self.channels.get(&channel_id) {
                let current = entry.conn_id.load(Ordering::SeqCst);
                // Re-point orphaned channels (or channels whose owner conn is no
                // longer live) at this connection.
                if current == 0 || !self.is_conn_live(&conn.app, current) {
                    entry.conn_id.store(conn.id, Ordering::SeqCst);
                }
                owned.push(ChannelRef {
                    channel_id: channel_id.clone(),
                    call_actor_id: entry.call_actor_id.clone(),
                    sip_call_id: entry.sip_call_id.clone(),
                    app: entry.app.clone(),
                });
            }
        }
        owned
    }

    fn is_conn_live(&self, app: &str, conn_id: u64) -> bool {
        self.apps
            .get(app)
            .map(|fanout| fanout.contains(conn_id))
            .unwrap_or(false)
    }

    /// Snapshot the channels an app owns (for resync enumeration + `/admin`).
    pub fn owned_channels(&self, app: &str) -> Vec<ChannelRef> {
        self.app_calls
            .get(app)
            .map(|entry| {
                entry
                    .value()
                    .iter()
                    .filter_map(|channel_id| {
                        self.channels.get(channel_id).map(|entry| ChannelRef {
                            channel_id: channel_id.clone(),
                            call_actor_id: entry.call_actor_id.clone(),
                            sip_call_id: entry.sip_call_id.clone(),
                            app: entry.app.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set a per-call variable. Returns false when the channel is unknown.
    pub fn set_var(&self, channel_id: &str, key: &str, value: &str) -> bool {
        match self.channels.get(channel_id) {
            Some(entry) => {
                if let Ok(mut vars) = entry.vars.lock() {
                    vars.insert(key.to_string(), value.to_string());
                }
                true
            }
            None => false,
        }
    }

    /// Read a per-call variable (None when the channel or key is unknown).
    pub fn get_var(&self, channel_id: &str, key: &str) -> Option<String> {
        let entry = self.channels.get(channel_id)?;
        let vars = entry.vars.lock().ok()?;
        vars.get(key).cloned()
    }

    /// Snapshot all per-call variables for a channel.
    pub fn vars(&self, channel_id: &str) -> HashMap<String, String> {
        self.channels
            .get(channel_id)
            .and_then(|entry| entry.vars.lock().ok().map(|vars| vars.clone()))
            .unwrap_or_default()
    }

    /// The app that owns the call identified by `sip_call_id`, if controlled.
    pub fn controlling_app(&self, sip_call_id: &str) -> Option<String> {
        self.channels
            .iter()
            .find(|entry| entry.value().sip_call_id == sip_call_id)
            .map(|entry| entry.value().app.clone())
    }
}
