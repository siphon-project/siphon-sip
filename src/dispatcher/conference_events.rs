//! `@b2bua.on_conference_change`, and the conference dialog that ends with the
//! last call it adopted (`b2bua.adopt_replaced(on_last_leave="end_owner")`).
//!
//! Both are driven by the roster's committed changes
//! ([`crate::rtpengine::conference_roster`]), taken off a channel by a task of
//! their own, so neither runs on the SIP message path and neither depends on
//! which script, or which version of it, was running when the seat was taken.
//! A change is handed to the handlers the script has *now*, from the roster as
//! it stood once the change was made.

use super::*;
use crate::rtpengine::backend::ConferenceSeat;
use crate::rtpengine::conference_roster::{self, Change, ConferenceChange, SeatKind};

/// Follow the roster's changes: run the script's handlers for each, then end
/// the conference dialog a change leaves alone in its room when it asked to be.
///
/// The task holds `dispatcher` for as long as it runs, and ends with the
/// dispatcher: in production the process's running B2BUA, in a test its own.
pub fn spawn_conference_change_events(dispatcher: Arc<dyn DispatcherHandle>) {
    let mut changes = conference_roster::subscribe();
    tokio::spawn(async move {
        while let Some(change) = changes.recv().await {
            if dispatcher.state().is_none() {
                return;
            }
            run_conference_change_handlers(&dispatcher, &change).await;
            end_owner_left_alone(&dispatcher, &change).await;
        }
    });
}

/// The `@b2bua.on_conference_change` handlers for one change, as one executor
/// job: nothing is held while a handler runs but the job's own worker, and an
/// `async` handler is run to completion on it as the other event hooks' are.
async fn run_conference_change_handlers(
    dispatcher: &Arc<dyn DispatcherHandle>,
    change: &ConferenceChange,
) {
    let Some(state) = dispatcher.state() else {
        return;
    };
    if state
        .engine
        .state()
        .handlers_for(&HandlerKind::B2buaConferenceChange)
        .is_empty()
    {
        return;
    }
    let dispatcher = Arc::clone(dispatcher);
    let change = change.clone();
    run_event_handler("b2bua.on_conference_change", move || {
        let Some(state) = dispatcher.state() else {
            return;
        };
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaConferenceChange);
        Python::attach(|python| {
            for handler in handlers {
                // Each handler gets a roster of its own: one that edits it
                // does not change what the next is shown.
                let roster = match crate::script::api::conference_roster::roster_list(
                    python,
                    &change.roster,
                ) {
                    Ok(roster) => roster,
                    Err(error) => {
                        error!(conference_id = %change.conference_id, "B2BUA on_conference_change: could not build the roster: {error}");
                        return;
                    }
                };
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    change.conference_id.as_str(),
                    change.owner_call_id.as_deref(),
                    change.change.label(),
                    change.call_id.as_str(),
                    roster,
                ));
                match result {
                    Ok(returned) if handler.is_async => {
                        if let Err(error) = run_coroutine(python, &returned) {
                            record_script_error("async B2BUA on_conference_change", &error);
                        }
                    }
                    Ok(_) => {}
                    Err(error) => record_script_error("B2BUA on_conference_change", &error),
                }
            }
        });
    })
    .await;
}

/// A call adopted with `on_last_leave="end_owner"` has left: when no seat but
/// the conference dialog's own remains in the room, end that dialog through the
/// normal teardown (BYE with `Reason: Q.850;cause=16`, Rf and Ro stop, CDR),
/// and free its seat, whose "left" is reported in turn.
async fn end_owner_left_alone(dispatcher: &Arc<dyn DispatcherHandle>, change: &ConferenceChange) {
    let Some(state) = dispatcher.state() else {
        return;
    };
    let seat = &change.seat;
    if change.change != Change::Left || seat.kind != SeatKind::Adopted || !seat.end_owner_on_last {
        return;
    }
    let Some(owner) = seat.owner_call_id.as_deref() else {
        return;
    };
    if change.roster.iter().any(|other| other.call_id != owner) {
        debug!(conference_id = %change.conference_id, owner = %owner, "conference: seats remain besides the conference dialog's own — keeping it");
        return;
    }
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(owner) else {
        debug!(conference_id = %change.conference_id, owner = %owner, "conference: the conference dialog is already gone");
        return;
    };
    info!(conference_id = %change.conference_id, owner = %owner, "conference: the last adopted call left — ending the conference dialog");
    let handle = Arc::clone(dispatcher);
    run_event_handler("b2bua.adopt_replaced on_last_leave", move || {
        if let Some(state) = handle.state() {
            b2bua_terminate_call_inner(
                &internal_call_id,
                Some(CONFERENCE_ENDED_REASON),
                "b2bua",
                state,
            );
        }
    })
    .await;
    // The dialog's seat goes with it. A script that frees it too finds it gone.
    let (Some(backend), Some(held)) = (
        state.rtpengine_set.as_ref(),
        crate::rtpengine::MediaBackend::conference_seat(owner),
    ) else {
        return;
    };
    let seat = ConferenceSeat {
        conference_id: held.conference_id,
        from_tag: held.from_tag,
    };
    if let Err(error) = backend.conference_leave(owner, &seat).await {
        warn!(conference_id = %seat.conference_id, owner = %owner, "conference: could not free the ended conference dialog's seat: {error}");
    }
}
