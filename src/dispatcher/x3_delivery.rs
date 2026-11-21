//! Asking the media engine for one X3 content delivery, and ending one.
//!
//! [`super::intercept`] decides what a warranted session is owed and where.
//! This is each delivery on its way to the engine: recorded before it is
//! asked for, asked once, retried while the engine says to, reported to the
//! ADMF when it cannot be had, and detached when its session ends.
//!
//! How many deliveries an engine call carries depends on the engine. A
//! siphon-rtp that lists `x3_multi_delivery` in `node_info` (0.26.0 and later)
//! keys a delivery by its warrant, its delivery address and its Correlation
//! ID, so a call takes one per warrant, per destination and per session, and
//! each is detached on its own. An engine before that holds one delivery per
//! call and ends it, in silence, for the next one asked for. There a second
//! delivery is never asked for: it is reported to the ADMF as content that is
//! not being delivered, which is what it is.

use super::intercept::report_destination_fault;
use super::*;
use crate::li::x1::types::{DId, TaskReportType, XId};
use crate::li::{ActiveIntercept, LiManager, X3Registration};
use crate::rtpengine::backend::{ConferenceSeat, X3TargetLeg};
use crate::rtpengine::events::X3Delivery;
use crate::rtpengine::siphon_rtp::X3Feature;
use crate::rtpengine::{CallScope, MediaBackend};

/// One content delivery to ask the engine for.
#[derive(Debug, Clone)]
pub(super) struct X3Ask {
    /// The key of its record ([`LiManager::x3_register`]).
    pub(super) record: String,
    /// The joined conference seat it is on; `None` for an engine call.
    pub(super) seat: Option<ConferenceSeat>,
    /// The engine call-id, or the seat's room.
    pub(super) call_id: String,
    /// What is recorded of it: the warrant, the destination and where it is
    /// dialled, the session and its Correlation ID, the leg.
    pub(super) attachment: ActiveIntercept,
    /// The number of the leg's attempt it was decided in.
    pub(super) attempt: u64,
    pub(super) target_leg: X3TargetLeg,
}

impl X3Ask {
    fn scope(&self) -> Option<&CallScope> {
        self.attachment.scope.as_ref()
    }

    /// Whether the engine that holds it lists `x3_multi_delivery`; `None`
    /// while that engine has not been asked.
    fn engine_carries_several(&self, backend: &MediaBackend) -> Option<bool> {
        let feature = X3Feature::MultiDelivery;
        match self.seat.as_ref() {
            Some(seat) => backend.x3_room_feature(feature, &seat.conference_id),
            None => backend.x3_feature(feature, &self.call_id, self.scope()),
        }
    }

    /// [`Self::engine_carries_several`], asking the engine.
    async fn learn_engine_carries_several(&self, backend: &MediaBackend) -> bool {
        let feature = X3Feature::MultiDelivery;
        let learned = match self.seat.as_ref() {
            Some(seat) => {
                backend
                    .learn_x3_room_feature(feature, &seat.conference_id)
                    .await
            }
            None => {
                backend
                    .learn_x3_feature(feature, &self.call_id, self.scope())
                    .await
            }
        };
        learned.unwrap_or_else(|error| {
            // An engine that cannot say is taken to hold one delivery: a
            // second is then reported, where asking for it could end the
            // first without a word.
            warn!(
                call_id = %self.call_id, %error,
                "LI: could not read the media engine's features, it is taken to hold one \
                 X3 delivery per call"
            );
            false
        })
    }
}

/// Record `ask` and ask the engine for it, unless it is on record already or
/// the engine cannot carry it beside what its call holds.
///
/// `several` is whether the engine carries several deliveries on one call,
/// when the caller has learnt it. It only matters when the call already holds
/// a delivery, so an engine that has not said is asked then, off this path,
/// and never for the first delivery of a call. Decides and spawns; waits on
/// nothing.
pub(super) fn ask_for(
    li: &LiManager,
    backend: &Arc<MediaBackend>,
    ask: X3Ask,
    several: Option<bool>,
) {
    let several = several.or_else(|| ask.engine_carries_several(backend));
    let (x_id, d_id) = (ask.attachment.x_id, ask.attachment.d_id);
    let wanted = ask.attachment.correlation_id;
    let registered = li.x3_register(&ask.record, ask.attachment.clone(), ask.attempt, several);
    match registered {
        X3Registration::Recorded => {
            tokio::spawn(attach(li.clone(), Arc::clone(backend), ask));
        }
        X3Registration::Known => {}
        X3Registration::Undecided => {
            let (li, backend) = (li.clone(), Arc::clone(backend));
            tokio::spawn(async move {
                let several = ask.learn_engine_carries_several(&backend).await;
                ask_for(&li, &backend, ask, Some(several));
            });
        }
        X3Registration::OtherCorrelation { held } => undeliverable(
            li,
            (x_id, d_id),
            &ask.call_id,
            format!(
                "X3 for task {x_id} cannot be delivered under correlation {wanted}: its \
                 content is on an engine call shared with the session of correlation {held}, \
                 and is delivered under {held} only"
            ),
        ),
        X3Registration::OtherDelivery { held } => undeliverable(
            li,
            (x_id, d_id),
            &ask.call_id,
            format!(
                "X3 for task {x_id} cannot be delivered to destination {d_id}: the media \
                 engine holds one delivery per call, and this call's is task {} to \
                 destination {}",
                held.0, held.1
            ),
        ),
    }
}

/// A delivery a warrant is owed cannot be asked for: the engine call holds
/// one already, and the engine holds one per call, so asking would end that
/// one for this. Two sessions sharing the engine call (two calls bridged onto
/// it) under one warrant, a second warrant, a second destination. That is
/// warranted content not being delivered as the warrant's records say, and
/// the ADMF is told what is delivered in its place, so the mediation function
/// can tie the two together.
fn undeliverable(li: &LiManager, (x_id, d_id): (XId, DId), call_id: &str, detail: String) {
    error!(
        %x_id, %d_id, %call_id,
        "X3 content is NOT being delivered: {detail}"
    );
    li.audit(
        crate::li::AuditOperation::MediaCaptureStarted,
        Some(&x_id.to_string()),
        format!("X3 attach FAILED call_id={call_id}: {detail}"),
    );
    let li = li.clone();
    tokio::spawn(async move {
        report_destination_fault(&li, d_id, TaskReportType::TerminatingFault, detail).await;
    });
}

/// How long to wait before each further try of an attach the engine refused
/// for a reason that passes: three more within a second.
const X3_ATTACH_RETRY_DELAYS: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(300),
    std::time::Duration::from_millis(600),
];

/// Ask the engine for a delivery that is on record, and settle the record by
/// its answer.
async fn attach(li: LiManager, backend: Arc<MediaBackend>, ask: X3Ask) {
    let ActiveIntercept {
        x_id,
        d_id,
        correlation_id,
        ..
    } = ask.attachment;
    let (call_id, attempt, target_leg) = (ask.call_id.as_str(), ask.attempt, ask.target_leg);
    let (delivery, from_tag) = (&ask.attachment.delivery, &ask.attachment.from_tag);
    let xid = x_id.as_bytes();
    let leg = backend.leg(call_id, ask.scope());
    let failed = |li: &LiManager| {
        li.x3_attach_failed(
            &ask.record,
            leg.scope(),
            (x_id, d_id, correlation_id),
            attempt,
        )
    };
    let request = || async {
        match ask.seat.as_ref() {
            // A room verb: no scope, on the engine that holds the room.
            Some(seat) => {
                backend
                    .attach_x3_seat(seat, delivery, xid, correlation_id, target_leg)
                    .await
            }
            None => {
                leg.run(backend.attach_x3(
                    leg.call_id(),
                    from_tag,
                    delivery,
                    xid,
                    correlation_id,
                    target_leg,
                ))
                .await
            }
        }
    };
    // The engine refuses an attach while the call is changing shape under it
    // (a re-answer, a pipeline being rebuilt) and says to ask again. That
    // passes in a moment, so it is asked again a few times before it is a
    // fault. Nothing is held across the wait, and the attempt is given up once
    // siphon has ended its engine call.
    let mut delays = X3_ATTACH_RETRY_DELAYS.into_iter();
    let attached = loop {
        let attached = request().await;
        let retryable = matches!(&attached, Err(error) if error.is_x3_attach_retryable());
        let Some(delay) = delays.next().filter(|_| retryable) else {
            break attached;
        };
        tokio::time::sleep(delay).await;
        if !li.x3_attempt_in_progress(&ask.record, leg.scope(), attempt) {
            failed(&li);
            debug!(
                %x_id, %d_id, %call_id,
                "LI: the media was released while an X3 attach was being retried"
            );
            return;
        }
    };
    let error = match attached {
        Ok(()) => {
            info!(
                %x_id, %d_id, %call_id, %delivery, correlation_id,
                scope = leg.scope().map(CallScope::as_str),
                "X3 content delivery attached"
            );
            li.audit(
                crate::li::AuditOperation::MediaCaptureStarted,
                Some(&x_id.to_string()),
                format!(
                    "X3 attached call_id={call_id} leg={} destination={delivery}",
                    leg_name(leg.scope())
                ),
            );
            return;
        }
        Err(error) => error,
    };
    // The record goes either way: nothing is being delivered on it.
    if failed(&li) == crate::li::FailedAttach::EndedBySiphon && error.is_call_not_found() {
        // siphon deleted the engine call while the attach was on its way (a
        // CANCEL, a rejection): there is no call to intercept and nothing
        // warranted went undelivered.
        debug!(
            %x_id, %d_id, %call_id, %error,
            "LI: the media was released before X3 could attach, no content to deliver"
        );
        return;
    }
    // Warranted content is not being delivered. The ADMF has to hear about
    // it — this is the whole point of the network-element-to-ADMF direction.
    error!(
        %x_id, %d_id, %call_id, %error,
        "could not attach X3 content delivery — warranted content is \
         NOT being delivered for this call"
    );
    li.audit(
        crate::li::AuditOperation::MediaCaptureStarted,
        Some(&x_id.to_string()),
        format!(
            "X3 attach FAILED call_id={call_id} leg={}: {error}",
            leg_name(leg.scope())
        ),
    );
    report_destination_fault(
        &li,
        d_id,
        TaskReportType::TerminatingFault,
        format!("could not attach X3 delivery for task {x_id}: {error}"),
    )
    .await;
}

/// How an audit record names a leg: its per-call scope, or `call` for the
/// call's own media.
fn leg_name(scope: Option<&CallScope>) -> &str {
    scope.map_or("call", CallScope::as_str)
}

/// The delivery an attachment is at the engine: what its `attach_x3` named,
/// and what a `detach_x3` of it alone names.
fn delivery_of(attachment: &ActiveIntercept) -> X3Delivery {
    X3Delivery {
        xid: attachment.x_id.as_bytes(),
        address: attachment.delivery.clone(),
        correlation_id: attachment.correlation_id,
    }
}

/// Stop content delivery for a session, if any was attached: its own
/// deliveries on its engine call, each leg on the leg it was attached on, and
/// on each conference seat a party of it joined.
///
/// Only the session's own. Its engine call can hold another session's media
/// (two calls bridged onto it), whose deliveries go on. So on an engine that
/// carries several deliveries on a call each of the session's is detached by
/// name: its warrant, its delivery address and its Correlation ID. An engine
/// that holds one delivery per call has only this session's on it (a second
/// is never asked for there) and reads no name, so it is detached as the
/// call's.
///
/// siphon ending the engine call itself needs no detach at all: the `delete`
/// ends every delivery on it, and is told of where it is sent
/// ([`super::intercept::watch_engine_calls`]).
///
/// What is detached stays on record until the engine reports its delivery
/// ended ([`LiManager::x3_detaching`]): that report says whether content was
/// dropped on the way out, and a transport failure can beat the detach to it.
/// Either is a fault, and a fault needs the warrant it is reported against.
///
/// Not on an engine call whose leg sits in a conference room: see below.
pub(super) fn detach_x3(session: &crate::li::SessionView, state: &Arc<DispatcherState>) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let call_id: &str = &session.engine_call_id;
    // A call whose leg was moved into a conference room
    // (`b2bua.adopt_replaced`) goes on without the dialog that was merged
    // away, and a BYE on that dialog, or on any other of the session, is not
    // the end of the media the engine delivers from the room. Detached there,
    // the delivery would stop cleanly and silently with the target still in
    // the room. Its interception ends with the engine call and with nothing
    // else: siphon's `delete`, whose `call_ended` is then clean, or the
    // engine's own, which is a fault.
    let seated = MediaBackend::seated_call_room(call_id).is_some();
    let on_call = match seated {
        true => Vec::new(),
        false => li.x3_detaching(call_id, &session.session_id),
    };
    let on_seats: Vec<_> = session
        .seats
        .iter()
        .map(|seat| {
            let attachments = li.x3_detaching(&seat.record(), &session.session_id);
            (seat.clone(), attachments)
        })
        .filter(|(_, attachments)| !attachments.is_empty())
        .collect();
    if on_call.is_empty() && on_seats.is_empty() {
        return;
    }
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    let backend = Arc::clone(backend);
    let li = li.clone();
    let call_id = call_id.to_string();
    tokio::spawn(async move {
        detach_from_call(&li, &backend, &call_id, on_call).await;
        for (seat, attachments) in on_seats {
            // The seat is the session's alone, and so is everything on it:
            // one detach of the seat ends each of its deliveries.
            let held = ConferenceSeat {
                conference_id: seat.conference_id.to_string(),
                from_tag: seat.tag.to_string(),
            };
            let detached = backend.detach_x3_seat(&held).await;
            for attachment in attachments {
                if let Err(error) = &detached {
                    warn!(
                        x_id = %attachment.x_id, conference_id = %seat.conference_id, %error,
                        "could not detach X3 content delivery from a conference seat"
                    );
                }
                li.audit(
                    crate::li::AuditOperation::MediaCaptureStopped,
                    Some(&attachment.x_id.to_string()),
                    format!(
                        "X3 detached conference_id={} seat={}",
                        seat.conference_id, seat.tag
                    ),
                );
            }
        }
    });
}

/// Detach a session's deliveries from its engine call, each leg's on the leg
/// it was attached on.
async fn detach_from_call(
    li: &LiManager,
    backend: &MediaBackend,
    call_id: &str,
    attachments: Vec<ActiveIntercept>,
) {
    // The legs with a delivery whose detach was already sent for the leg as a
    // whole, on an engine that reads no name.
    let mut detached_whole: Vec<Option<CallScope>> = Vec::new();
    for attachment in attachments {
        let scope = attachment.scope.as_ref();
        let leg = backend.leg(call_id, scope);
        let feature = X3Feature::MultiDelivery;
        let by_name = match backend.x3_feature(feature, call_id, scope) {
            Some(listed) => listed,
            None => backend
                .learn_x3_feature(feature, call_id, scope)
                .await
                .unwrap_or(false),
        };
        // Idempotent on the engine, so a duplicate teardown is harmless.
        let detached = if by_name {
            let delivery = delivery_of(&attachment);
            let detach = backend.detach_x3_delivery(leg.call_id(), &attachment.from_tag, &delivery);
            leg.run(detach).await
        } else if detached_whole.contains(&attachment.scope) {
            Ok(())
        } else {
            detached_whole.push(attachment.scope.clone());
            leg.run(backend.detach_x3(leg.call_id(), &attachment.from_tag))
                .await
        };
        if let Err(error) = detached {
            warn!(
                x_id = %attachment.x_id, %call_id, %error,
                "could not detach X3 content delivery"
            );
        }
        li.audit(
            crate::li::AuditOperation::MediaCaptureStopped,
            Some(&attachment.x_id.to_string()),
            format!("X3 detached call_id={call_id} leg={}", leg_name(scope)),
        );
    }
}
