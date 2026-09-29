//! Channel tombstones: who owned a call for a short while after its
//! `StasisEnd`, so the media engine's end-of-call `MediaSummary` still reaches
//! them.
//!
//! Teardown emits `StasisEnd` and removes the channel synchronously, but the
//! media session is deleted on a spawned task and the engine reports the
//! call's summary only once that delete has run. Without a tombstone the
//! summary would find no channel and be dropped. The tombstone keeps exactly
//! what routing it needs (the owning connection, the channel id the call had,
//! the app) and nothing else, keyed by the SIP Call-ID the summary names.
//!
//! A tombstone is removed when its summary is delivered, when
//! [`CHANNEL_TOMBSTONE_GRACE`] passes, and when its owner's connection goes,
//! whichever comes first, so the map drains to empty under any workload.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tracing::debug;

use super::queue::record_push_outcome;
use super::{ChannelEntry, ControlBus};
use crate::control::protocol::EventFrame;

/// How long a hung-up call's owner stays reachable for its media summary.
///
/// The summary follows the engine `delete` siphon issues on a spawned task at
/// teardown, whose round trip is bounded by the media client's command timeout
/// (`media.siphon_rtp.timeout_ms`, default 2 s). Before it emits the summary
/// the engine also finalises the call's recordings and closes its streams, all
/// local work. 30 s is an order of magnitude over that path, so a summary is
/// not lost to a slow delete, while the map holds at most `teardown rate × 30 s`
/// small entries (a few strings each).
pub const CHANNEL_TOMBSTONE_GRACE: Duration = Duration::from_secs(30);

/// What routes a post-`StasisEnd` event to the connection that owned the call.
#[derive(Debug, Clone)]
pub(super) struct ChannelTombstone {
    channel_id: String,
    app: String,
    call_actor_id: String,
    conn_id: u64,
    expires_at: tokio::time::Instant,
}

/// The tombstones, keyed by SIP Call-ID. Shared with the expiry tasks.
pub(super) type Tombstones = Arc<DashMap<String, ChannelTombstone>>;

impl ControlBus {
    /// Record who owned `sip_call_id` as its channel is removed at teardown.
    ///
    /// Only a channel with a live owner leaves one: an orphaned channel has
    /// nobody to deliver to. Expiry is a timer on the current runtime; with no
    /// runtime (never the case in the running server) expired tombstones are
    /// swept here instead, so none is ever left behind.
    pub(super) fn retain_tombstone(
        &self,
        sip_call_id: &str,
        channel_id: &str,
        entry: &ChannelEntry,
    ) {
        let conn_id = entry.conn_id.load(Ordering::SeqCst);
        if conn_id == 0 || self.connection(&entry.app, conn_id).is_none() {
            return;
        }
        let expires_at = tokio::time::Instant::now() + CHANNEL_TOMBSTONE_GRACE;
        self.tombstones.insert(
            sip_call_id.to_string(),
            ChannelTombstone {
                channel_id: channel_id.to_string(),
                app: entry.app.clone(),
                call_actor_id: entry.call_actor_id.clone(),
                conn_id,
                expires_at,
            },
        );
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let tombstones = Arc::clone(&self.tombstones);
                let sip_call_id = sip_call_id.to_string();
                runtime.spawn(async move {
                    tokio::time::sleep_until(expires_at).await;
                    // Only this tombstone: a later call reusing the Call-ID
                    // after a fresh teardown keeps its own window.
                    tombstones.remove_if(&sip_call_id, |_, tombstone| {
                        tombstone.expires_at <= expires_at
                    });
                });
            }
            Err(_) => {
                let now = tokio::time::Instant::now();
                self.tombstones
                    .retain(|_, tombstone| tombstone.expires_at > now);
            }
        }
    }

    /// Drop every tombstone owned by connection `conn_id`: the connection is
    /// gone, and a tombstone never outlives it.
    pub(super) fn drop_tombstones_of(&self, conn_id: u64) {
        self.tombstones
            .retain(|_, tombstone| tombstone.conn_id != conn_id);
    }

    /// Deliver the media engine's summary for `sip_call_id` as `MediaSummary`.
    ///
    /// To the live channel when the call still has one, the way every channel
    /// event goes; otherwise to the connection its tombstone names, carrying
    /// the channel id the call had, spending the tombstone. Returns whether an
    /// event was queued. A summary for a call nobody controlled, one past the
    /// grace window, or one whose owner has disconnected is dropped.
    pub fn forward_media_summary(&self, sip_call_id: &str, payload: serde_json::Value) -> bool {
        if self.forward_channel_event(sip_call_id, "MediaSummary", payload.clone()) {
            return true;
        }
        let Some((_, tombstone)) = self.tombstones.remove(sip_call_id) else {
            return false;
        };
        if tombstone.expires_at <= tokio::time::Instant::now() {
            debug!(%sip_call_id, "control plane: media summary after the owner's grace window, dropped");
            return false;
        }
        let Some(conn) = self.connection(&tombstone.app, tombstone.conn_id) else {
            debug!(
                %sip_call_id,
                channel = %tombstone.channel_id,
                "control plane: media summary for an owner that disconnected, dropped"
            );
            return false;
        };
        record_push_outcome(
            &tombstone.app,
            conn.events.try_push_event(EventFrame::new(
                "MediaSummary",
                &tombstone.channel_id,
                &tombstone.app,
                &tombstone.call_actor_id,
                sip_call_id,
                payload,
            )),
        );
        true
    }

    /// Number of tombstones held (drains to baseline — leak gate).
    pub fn channel_tombstone_count(&self) -> usize {
        self.tombstones.len()
    }
}
