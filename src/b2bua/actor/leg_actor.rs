//! [`LegActor`]: the async wrapper around a [`Leg`].
//!
//! Owns a leg, receives [`LegMessage`]s, and classifies inbound SIP into
//! [`CallEvent`]s for the dispatcher. The dispatcher deliberately discards most
//! of what comes back — the round trip exists so the actor's own copy of the
//! leg advances.

use tracing::debug;

use crate::sip::message::SipMessage;

use super::*;

// ---------------------------------------------------------------------------

/// Messages sent to a leg actor's mailbox (for async mode).
///
/// `large_enum_variant` is intentionally allowed: `SipInbound` is the hot,
/// overwhelmingly-common variant (one per inbound SIP message on the leg),
/// while `Cancel`/`Shutdown` are rare one-shots. Boxing `SipInbound.message`
/// to shrink the enum would add a heap allocation to the hot path purely to
/// save stack space on the rare variants — the opposite of what this lint
/// optimizes for.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LegMessage {
    /// A SIP message arrived from the network.
    SipInbound {
        message: SipMessage,
        source: TransportInfo,
    },
    /// Cancel this leg.
    Cancel,
    /// Shut down.
    Shutdown,
}
/// Events from a leg actor back to the call supervisor.
#[derive(Debug)]
pub enum CallEvent {
    /// Provisional response (1xx).
    Provisional {
        leg_id: LegId,
        status_code: u16,
        message: SipMessage,
    },
    /// Success response (2xx).
    Answered { leg_id: LegId, message: SipMessage },
    /// Error response (3xx-6xx).
    Failed {
        leg_id: LegId,
        status_code: u16,
        message: SipMessage,
    },
    /// BYE received.
    Bye {
        leg_id: LegId,
        from_side: LegSide,
        message: SipMessage,
    },
    /// re-INVITE received.
    ReInvite { leg_id: LegId, message: SipMessage },
    /// REFER received.
    Refer { leg_id: LegId, message: SipMessage },
    /// Leg actor terminated.
    Terminated { leg_id: LegId },
}
/// Async leg actor — wraps a `Leg` + channels for SIP message classification.
///
/// Receives inbound SIP messages via [`LegMessage`] and emits classified
/// [`CallEvent`]s back to the dispatcher for orchestration.
pub struct LegActor {
    /// The leg's state.
    pub leg: Leg,
    /// Mailbox receiver.
    rx: tokio::sync::mpsc::Receiver<LegMessage>,
    /// Event sender to call supervisor.
    call_tx: tokio::sync::mpsc::Sender<CallEvent>,
}
/// Handle to an async leg actor.
#[derive(Debug, Clone)]
pub struct LegHandle {
    /// Leg identifier.
    pub id: LegId,
    /// Side.
    pub side: LegSide,
    /// Channel to send messages to the leg actor.
    pub tx: tokio::sync::mpsc::Sender<LegMessage>,
}
impl LegActor {
    /// Create a new leg actor. Returns `(actor, handle)`.
    pub fn new(leg: Leg, call_tx: tokio::sync::mpsc::Sender<CallEvent>) -> (Self, LegHandle) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let handle = LegHandle {
            id: leg.id.clone(),
            side: leg.side,
            tx,
        };
        let actor = Self { leg, rx, call_tx };
        (actor, handle)
    }

    /// Run the leg actor's message processing loop.
    pub async fn run(mut self) {
        debug!(
            leg_id = %self.leg.id,
            side = ?self.leg.side,
            call_id = %self.leg.dialog.call_id,
            "leg actor started"
        );

        while let Some(msg) = self.rx.recv().await {
            match msg {
                LegMessage::SipInbound { message, source: _ } => {
                    self.handle_sip_inbound(message).await;
                }
                LegMessage::Cancel => {
                    debug!(leg_id = %self.leg.id, "leg cancelled");
                    break;
                }
                LegMessage::Shutdown => {
                    debug!(leg_id = %self.leg.id, "leg shutting down");
                    break;
                }
            }
        }

        let _ = self
            .call_tx
            .send(CallEvent::Terminated {
                leg_id: self.leg.id.clone(),
            })
            .await;

        debug!(leg_id = %self.leg.id, "leg actor stopped");
    }

    async fn handle_sip_inbound(&mut self, message: SipMessage) {
        use crate::sip::message::Method;

        let method = message.method().cloned();
        let status = message.status_code();

        match (method, status) {
            (_, Some(code)) => {
                if (100..200).contains(&code) {
                    let _ = self
                        .call_tx
                        .send(CallEvent::Provisional {
                            leg_id: self.leg.id.clone(),
                            status_code: code,
                            message,
                        })
                        .await;
                } else if (200..300).contains(&code) {
                    if let Some(to_tag) = extract_to_tag(&message) {
                        self.leg.dialog.remote_tag = Some(to_tag);
                    }
                    let _ = self
                        .call_tx
                        .send(CallEvent::Answered {
                            leg_id: self.leg.id.clone(),
                            message,
                        })
                        .await;
                } else {
                    let _ = self
                        .call_tx
                        .send(CallEvent::Failed {
                            leg_id: self.leg.id.clone(),
                            status_code: code,
                            message,
                        })
                        .await;
                }
            }
            (Some(Method::Bye), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::Bye {
                        leg_id: self.leg.id.clone(),
                        from_side: self.leg.side,
                        message,
                    })
                    .await;
            }
            (Some(Method::Invite), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::ReInvite {
                        leg_id: self.leg.id.clone(),
                        message,
                    })
                    .await;
            }
            (Some(Method::Refer), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::Refer {
                        leg_id: self.leg.id.clone(),
                        message,
                    })
                    .await;
            }
            _ => {}
        }
    }
}
