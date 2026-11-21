//! A warrant activated while a call is up starts at once.
//!
//! The call's dialog-forming INVITE is remembered whatever is provisioned
//! ([`crate::li::live_dialogs`]), and activating a warrant scans what is
//! remembered ([`super::intercept::warrants_changed`]): the call is decided as
//! its INVITE would have been and its content attached on the sites its
//! messages use, with no further SIP message from either party and no X2 until
//! the next one.
//!
//! Driven as [`super::li_conference_tests`] drives a call, against the
//! in-process native engine, with the warrant held back until the call is up.

use super::li_session_tests::{
    arrives, attach_outcomes, backend_of, drain_iri, intercepting_on_the_engine, leg_session,
    proxied_response, CALLER, CALLER_ACK, CALLER_INVITE,
};
use super::*;
use crate::li::x1::message::TaskDetails;
use crate::li::x1::types::TargetIdentifier;
use crate::li::{AuditEntry, IriEvent, LiManager};
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::rtpengine::NgFlags;
use tokio::sync::mpsc;

const BASE_CALL_ID: &str = "caller-call@192.0.2.10";
/// The number the caller dials, which a warrant on the called party names.
const CALLED: &str = "sip:15550100042@siphon.example.com";

/// `raw`, a message of the shared caller dialog, on the dialog `call_id`.
fn on_call(raw: &str, call_id: &str) -> String {
    raw.replace(BASE_CALL_ID, call_id)
}

/// The caller's BYE on the dialog `call_id`.
fn bye(call_id: &str) -> String {
    on_call(CALLER_ACK, call_id)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye")
}

/// The caller's CANCEL of the INVITE on the dialog `call_id`.
fn cancel(call_id: &str) -> String {
    on_call(CALLER_INVITE, call_id)
        .replace("INVITE sip:", "CANCEL sip:")
        .replace("CSeq: 1 INVITE", "CSeq: 1 CANCEL")
}

/// An intercepting dispatcher whose warrant is held back: nothing is
/// provisioned until [`Rig::activate`], as on a node that has no warrant yet.
struct Rig {
    state: Arc<DispatcherState>,
    engine: NativeTestEngine,
    li: LiManager,
    iri: mpsc::Receiver<IriEvent>,
    audit: mpsc::Receiver<AuditEntry>,
    warrant: TaskDetails,
}

impl Rig {
    async fn on(engine: NativeTestEngine) -> Self {
        let (state, engine, li, iri, audit) = intercepting_on_the_engine(engine).await;
        let warrant = li.tasks().list()[0].details.clone();
        li.tasks()
            .deactivate(warrant.x_id)
            .expect("the warrant is held back");
        assert!(li.tasks().is_empty());
        Self {
            state,
            engine,
            li,
            iri,
            audit,
            warrant,
        }
    }

    /// The warrant names `target` instead of the caller.
    fn names(mut self, target: &str) -> Self {
        self.warrant.target_identifiers = vec![TargetIdentifier::SipUri(target.to_string())];
        self
    }

    /// The warrant arrives, in the middle of whatever call is up.
    fn activate(&self) {
        self.li
            .tasks()
            .activate(self.warrant.clone())
            .expect("the warrant arrives mid-call");
    }

    fn attached(&self) -> Vec<crate::rtpengine::test_native_engine::NativeCommand> {
        self.engine.commands("attach_x3")
    }

    /// What the media path holds for a proxied call: a session, answered or
    /// not, and the engine call under it.
    async fn proxied_media(&self, call_id: &str, answered: bool) {
        let sessions = self.state.rtpengine_sessions.as_ref().expect("a store");
        sessions.insert(leg_session(call_id));
        let flags = NgFlags::default();
        backend_of(&self.state)
            .offer(call_id, "caller-tag", b"v=0\r\n", &flags)
            .await
            .expect("offered");
        if answered {
            backend_of(&self.state)
                .answer(call_id, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
                .await
                .expect("answered");
            sessions.set_to_tag(call_id, "callee-tag".to_string());
        }
    }

    /// A B2BUA call whose caller's INVITE has arrived, with its media at the
    /// engine; answered when `answered`.
    async fn b2bua_call(&self, call_id: &str, answered: bool) -> String {
        arrives(&self.state, CALLER, &on_call(CALLER_INVITE, call_id));
        let a_leg = Leg::new_a_leg(
            call_id.to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-caller-invite".to_string(),
            LegTransport {
                remote_addr: CALLER.parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let internal_id = create_b2bua_call(&self.state, a_leg);
        self.proxied_media(call_id, answered).await;
        if answered {
            self.state
                .call_actors
                .set_state(&internal_id, crate::b2bua::actor::CallState::Answered);
        }
        internal_id
    }
}

/// The caller is the target of an answered B2BUA call. Its audio is attached
/// at the activation, on the caller's engine call and as the caller's, with
/// no X2 and no message from either party; the call's next message carries on
/// from the decision made, and its BYE ends the delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_b2bua_call_is_attached_at_the_activation_with_the_caller_as_target() {
    const CALL: &str = "mid-b2bua-caller@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    let internal_id = rig.b2bua_call(CALL, true).await;
    assert_eq!(rig.li.live_dialog_count(), 1, "remembered with no warrant");

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    let attached = rig.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, CALL);
    assert_eq!(attached[0].from_tag, "caller-tag");
    assert_eq!(attached[0].detail.as_deref(), Some("caller"));
    assert!(!attached[0].refused);
    assert!(
        drain_iri(&mut rig.iri).is_empty(),
        "no X2 at the activation"
    );
    assert_eq!(
        rig.li
            .session_of_leg(CALL)
            .expect("the call is decided")
            .session_id
            .as_ref(),
        internal_id,
        "the call's own session"
    );

    // The next message resumes X2 under the same session and asks for nothing.
    arrives(&rig.state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert_eq!(rig.attached().len(), 1, "not asked again");
    let events = drain_iri(&mut rig.iri);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sip_method, "ACK");

    arrives(&rig.state, CALLER, &bye(CALL));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        rig.engine.commands("detach_x3").len(),
        1,
        "the BYE detaches"
    );
    assert_eq!(rig.li.live_dialog_count(), 0);
}

/// The called party is the target: what the caller sends is to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_b2bua_call_is_attached_at_the_activation_with_the_callee_as_target() {
    const CALL: &str = "mid-b2bua-callee@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await)
        .await
        .names(CALLED);
    rig.b2bua_call(CALL, true).await;

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    let attached = rig.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, CALL);
    assert_eq!(attached[0].detail.as_deref(), Some("callee"));
    assert!(drain_iri(&mut rig.iri).is_empty());
}

/// A proxied call with anchored media, answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_proxied_call_is_attached_at_the_activation() {
    const CALL: &str = "mid-proxied@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, CALL));
    rig.proxied_media(CALL, true).await;
    arrives(
        &rig.state,
        "198.51.100.77:5060",
        &on_call(&proxied_response("200 OK"), CALL),
    );

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    let attached = rig.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, CALL);
    assert_eq!(attached[0].detail.as_deref(), Some("caller"));
    assert!(drain_iri(&mut rig.iri).is_empty());
    backend_of(&rig.state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// A call offered and not answered is attached at the activation on an engine
/// that takes an interception at the offer, and left to its ACK on one that
/// does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_call_is_attached_at_the_activation_on_an_engine_that_takes_it() {
    for (case, engine, attached) in [
        (
            "at-offer engine",
            NativeTestEngine::start_with_x3_at_offer().await,
            1,
        ),
        ("engine without it", NativeTestEngine::start().await, 0),
    ] {
        let call = format!("mid-unanswered-{attached}@192.0.2.10");
        let mut rig = Rig::on(engine).await;
        rig.b2bua_call(&call, false).await;

        rig.activate();
        assert_eq!(attach_outcomes(&mut rig.audit).await.0, attached, "{case}");
        assert_eq!(rig.attached().len(), attached, "{case}");
        if attached == 1 {
            assert_eq!(rig.attached()[0].call_id, call, "{case}");
            assert_eq!(
                rig.attached()[0].detail.as_deref(),
                Some("caller"),
                "{case}"
            );
        }
        assert!(drain_iri(&mut rig.iri).is_empty(), "{case}");
        backend_of(&rig.state)
            .delete(&call, "caller-tag")
            .await
            .expect("released");
    }
}

/// A call that ended before the warrant arrived is no business of it: a
/// B2BUA call that is gone, a proxied call whose media is gone and one a BYE
/// ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_that_ended_before_the_activation_is_left_alone() {
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    let gone = rig.b2bua_call("mid-gone-b2bua@192.0.2.10", true).await;
    rig.state.call_actors.remove_call(&gone);
    // Its media goes with it, as a call's does.
    let sessions = rig.state.rtpengine_sessions.as_ref().expect("a store");
    sessions.remove("mid-gone-b2bua@192.0.2.10");

    arrives(
        &rig.state,
        CALLER,
        &on_call(CALLER_INVITE, "mid-gone-proxied@192.0.2.10"),
    );
    arrives(
        &rig.state,
        CALLER,
        &on_call(CALLER_INVITE, "mid-hung-up@192.0.2.10"),
    );
    rig.proxied_media("mid-hung-up@192.0.2.10", true).await;
    arrives(&rig.state, CALLER, &bye("mid-hung-up@192.0.2.10"));
    assert_eq!(rig.li.live_dialog_count(), 2, "the BYE released its own");

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert!(rig.attached().is_empty());
    assert_eq!(rig.li.remembered_session_count(), 0, "nothing decided");
    assert!(drain_iri(&mut rig.iri).is_empty());
}

/// A call no warrant names is not decided, however many are up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_warrant_that_names_nobody_on_the_call_attaches_nothing() {
    const CALL: &str = "mid-someone-else@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await)
        .await
        .names("sip:carol@example.com");
    rig.b2bua_call(CALL, true).await;
    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert!(rig.attached().is_empty());
    assert_eq!(rig.li.remembered_session_count(), 0);
}

/// A warrant modified, or a second one provisioned, asks for nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_change_of_the_warrants_does_not_attach_the_call_again() {
    const CALL: &str = "mid-changed@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3_026().await).await;
    rig.b2bua_call(CALL, true).await;
    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));

    rig.li
        .tasks()
        .modify(rig.warrant.clone())
        .expect("modified");
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert_eq!(rig.attached().len(), 1);

    // A second warrant on the same target is a second delivery, and only it.
    let mut second = rig.warrant.clone();
    second.x_id = crate::li::x1::types::XId::generate();
    rig.li.tasks().activate(second).expect("second warrant");
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    assert_eq!(rig.attached().len(), 2);
}

/// A call whose media moved onto an engine call siphon minted is attached
/// there, and as the target's end of it: the engine call's offerer is the
/// caller, or, where a transfer offered the called party's media, the other
/// party.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_whose_media_moved_is_attached_on_the_engine_call_it_moved_to() {
    for (case, offerer_is_caller, expected) in [
        ("offered by the caller", true, "caller"),
        ("offered by the called party", false, "callee"),
    ] {
        let call = format!("mid-minted-{expected}@192.0.2.10");
        let minted = format!("minted-{expected}");
        let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
        arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, &call));
        let flags = NgFlags::default();
        let backend = backend_of(&rig.state);
        backend
            .offer(&minted, "caller-tag", b"v=0\r\n", &flags)
            .await
            .expect("offered");
        backend
            .answer(&minted, "caller-tag", "target-tag", b"v=0\r\n", &flags)
            .await
            .expect("answered");
        let sessions = rig.state.rtpengine_sessions.as_ref().expect("a store");
        sessions.insert(crate::rtpengine::MediaSession {
            rtpengine_call_id: minted.clone(),
            to_tag: Some("target-tag".to_string()),
            ..leg_session(&call)
        });
        let offerer = if offerer_is_caller {
            call.as_str()
        } else {
            "far-party@192.0.2.77"
        };
        sessions.record_parties(&call, &minted, &[(offerer, Some("caller-tag"))]);

        rig.activate();
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");
        let attached = rig.attached();
        assert_eq!(attached.len(), 1, "{case}");
        assert_eq!(
            attached[0].call_id, minted,
            "{case}: on the live allocation"
        );
        assert_eq!(attached[0].detail.as_deref(), Some(expected), "{case}");
        backend
            .delete(&minted, "caller-tag")
            .await
            .expect("released");
    }
}

/// A caller seated in a conference room when the warrant arrives is attached
/// on the seat, as it would have been when it joined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_party_seated_in_a_room_is_attached_on_the_seat_at_the_activation() {
    use crate::rtpengine::backend::{ConferenceRole, ConferenceSeat};
    const CALL: &str = "mid-seated@192.0.2.10";
    const ROOM: &str = "room-mid-seated";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&rig.state)
        .conference_join(
            CALL,
            ConferenceSeat {
                conference_id: ROOM.to_string(),
                from_tag: "caller-tag".to_string(),
            },
            "v=0\r\n",
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("the engine seats the caller");

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    let attached = rig.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, ROOM, "the room stands for the call");
    assert_eq!(attached[0].from_tag, "caller-tag");
    assert_eq!(attached[0].detail.as_deref(), Some("caller"));
    assert!(!attached[0].refused);

    arrives(&rig.state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert_eq!(rig.attached().len(), 1, "the ACK finds the seat attached");
    backend_of(&rig.state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
}

/// The watcher ends with the dispatcher it serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_warrant_watcher_ends_when_the_dispatcher_is_dropped() {
    let rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    let li = rig.li.clone();
    let warrant = rig.warrant.clone();
    assert_eq!(li.tasks().subscriber_count(), 1);
    drop(rig);
    li.tasks().activate(warrant).expect("a change wakes it");
    for _ in 0..50 {
        if li.tasks().subscriber_count() == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the watcher outlived the dispatcher");
}

/// The index drains with the calls: completed, refused and cancelled ones,
/// B2BUA and proxied, with nothing provisioned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_dialog_index_drains_after_completed_refused_and_cancelled_calls() {
    const CALLS: usize = 20;
    let rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    let state = &rig.state;
    let sessions = state.rtpengine_sessions.as_ref().expect("a store");
    let callee = "198.51.100.77:5060";

    for index in 0..CALLS {
        // Proxied: every end arrives as a message.
        let done = format!("leak-proxied-done-{index}@192.0.2.10");
        arrives(state, CALLER, &on_call(CALLER_INVITE, &done));
        sessions.insert(leg_session(&done));
        arrives(state, callee, &on_call(&proxied_response("200 OK"), &done));
        arrives(state, CALLER, &on_call(CALLER_ACK, &done));
        arrives(state, CALLER, &bye(&done));
        sessions.remove(&done);

        let refused = format!("leak-proxied-refused-{index}@192.0.2.10");
        arrives(state, CALLER, &on_call(CALLER_INVITE, &refused));
        arrives(
            state,
            callee,
            &on_call(&proxied_response("486 Busy Here"), &refused),
        );

        let cancelled = format!("leak-proxied-cancelled-{index}@192.0.2.10");
        arrives(state, CALLER, &on_call(CALLER_INVITE, &cancelled));
        arrives(state, CALLER, &cancel(&cancelled));

        // B2BUA: the caller's BYE and CANCEL arrive; a refusal is siphon's own
        // answer, which no message reports, and the sweep releases it.
        let b2bua_done = format!("leak-b2bua-done-{index}@192.0.2.10");
        let first = rig.b2bua_call(&b2bua_done, true).await;
        arrives(state, CALLER, &bye(&b2bua_done));
        state.call_actors.remove_call(&first);
        sessions.remove(&b2bua_done);

        let b2bua_cancelled = format!("leak-b2bua-cancelled-{index}@192.0.2.10");
        let second = rig.b2bua_call(&b2bua_cancelled, false).await;
        arrives(state, CALLER, &cancel(&b2bua_cancelled));
        state.call_actors.remove_call(&second);
        sessions.remove(&b2bua_cancelled);

        let b2bua_refused = format!("leak-b2bua-refused-{index}@192.0.2.10");
        let third = rig.b2bua_call(&b2bua_refused, false).await;
        state.call_actors.remove_call(&third);
        sessions.remove(&b2bua_refused);
    }
    assert_eq!(
        rig.li.live_dialog_count(),
        CALLS,
        "only the refused B2BUA calls, which no message ends, are left"
    );
    rig.li.sweep_live_dialogs(
        std::time::Instant::now() + crate::li::live_dialogs::LIVE_DIALOG_GRACE * 2,
        |call_id| {
            state.call_actors.find_by_sip_call_id(call_id).is_some()
                || sessions.get(call_id).is_some()
        },
    );
    assert_eq!(rig.li.live_dialog_count(), 0, "and the sweep releases them");
    assert_eq!(rig.li.remembered_session_count(), 0);
}
