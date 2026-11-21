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
    arrives, attach_outcomes, backend_of, capture_log, drain_iri, engine_events, engine_reports,
    faults_reported, intercepting_on_the_engine_watching, leg_session, proxied_response, CALLER,
    CALLER_ACK, CALLER_INVITE,
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
        Self::watching(engine, true).await
    }

    /// With no watcher: the test drives the scan itself.
    async fn unwatched(engine: NativeTestEngine) -> Self {
        Self::watching(engine, false).await
    }

    async fn watching(engine: NativeTestEngine, watching: bool) -> Self {
        let (state, engine, li, iri, audit) =
            intercepting_on_the_engine_watching(engine, watching).await;
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
    super::intercept::sweep_live_dialogs(
        state,
        &rig.li,
        std::time::Instant::now() + crate::li::live_dialogs::LIVE_DIALOG_GRACE * 2,
    );
    assert_eq!(rig.li.live_dialog_count(), 0, "and the sweep releases them");
    assert_eq!(rig.li.remembered_session_count(), 0);
}

/// A second warrant on the same target, to the same destination.
fn second_warrant(rig: &Rig) -> crate::li::x1::types::XId {
    let mut second = rig.warrant.clone();
    second.x_id = crate::li::x1::types::XId::generate();
    let x_id = second.x_id;
    rig.li.tasks().activate(second).expect("second warrant");
    x_id
}

/// A warrant on somebody who is not on any call here, so that interception
/// stays on while the warrant under test comes and goes.
fn keep_intercepting(rig: &Rig) {
    let mut bystander = rig.warrant.clone();
    bystander.x_id = crate::li::x1::types::XId::generate();
    bystander.target_identifiers = vec![TargetIdentifier::SipUri("sip:carol@example.com".into())];
    rig.li
        .tasks()
        .activate(bystander)
        .expect("bystander warrant");
}

/// The engine says each delivery siphon detached has ended.
async fn engine_reports_its_ends(rig: &Rig) -> usize {
    let events = engine_events(&rig.state);
    let ends = rig.engine.take_x3_ends();
    let count = ends.len();
    for end in ends {
        engine_reports(&events, end).await;
    }
    count
}

/// A warrant deactivated while its call is up stops its delivery: one detach,
/// the end the engine reports is the one siphon asked for, so it is clean and
/// nothing reaches the ADMF as a fault, and the record drains.
#[tokio::test]
async fn a_deactivated_warrant_detaches_its_delivery_cleanly() {
    const CALL: &str = "mid-deactivated@192.0.2.10";
    let (log, _guard) = capture_log();
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    rig.b2bua_call(CALL, true).await;
    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));

    rig.li
        .tasks()
        .deactivate(rig.warrant.x_id)
        .expect("deactivated");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(rig.engine.commands("detach_x3").len(), 1, "exactly one");
    assert_eq!(engine_reports_its_ends(&rig).await, 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert!(!log.rendered().contains("ERROR"), "{}", log.rendered());
    assert_eq!(rig.li.x3_attachment_count(), 0, "the record drains");
    assert!(rig.li.x3_attachments_for(CALL).is_empty());
}

/// Of two warrants on a call on an engine that carries several deliveries,
/// the one deactivated is detached by its own name and the other goes on.
#[tokio::test]
async fn only_the_deactivated_warrants_delivery_is_detached() {
    const CALL: &str = "mid-two-warrants@192.0.2.10";
    let (log, _guard) = capture_log();
    let mut rig = Rig::on(NativeTestEngine::start_with_x3_026().await).await;
    rig.b2bua_call(CALL, true).await;
    rig.activate();
    let second = second_warrant(&rig);
    assert_eq!(attach_outcomes(&mut rig.audit).await, (2, 0));
    assert_eq!(rig.attached().len(), 2);

    rig.li.tasks().deactivate(second).expect("deactivated");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let detached = rig.engine.commands("detach_x3");
    assert_eq!(detached.len(), 1);
    assert_eq!(
        detached[0].x3_delivery.as_ref().expect("by name").xid,
        second.as_bytes(),
        "only its triple"
    );
    assert_eq!(engine_reports_its_ends(&rig).await, 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    let live = rig.li.x3_attachments_for(CALL);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].x_id, rig.warrant.x_id, "the other goes on");
}

/// A warrant changed to ask for no content stops its delivery; a destination
/// removed does too; and a warrant retargeted at somebody else no longer
/// covers the call.
#[tokio::test]
async fn a_warrant_that_no_longer_asks_for_the_delivery_detaches_it() {
    use crate::li::x1::types::DeliveryType;
    for case in ["x2 only", "destination removed", "target changed"] {
        let call = format!("mid-withdrawn-{}@192.0.2.10", case.replace(' ', "-"));
        let (log, _guard) = capture_log();
        let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
        rig.b2bua_call(&call, true).await;
        rig.activate();
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");

        match case {
            "x2 only" => {
                let mut details = rig.warrant.clone();
                details.delivery_type = DeliveryType::X2Only;
                rig.li.tasks().modify(details).expect("modified");
            }
            "destination removed" => {
                let d_id = rig.warrant.list_of_dids[0];
                rig.li.destinations().remove(d_id).expect("removed");
            }
            _ => {
                let mut details = rig.warrant.clone();
                details.target_identifiers =
                    vec![TargetIdentifier::SipUri("sip:carol@example.com".into())];
                rig.li.tasks().modify(details).expect("modified");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(rig.engine.commands("detach_x3").len(), 1, "{case}");
        assert_eq!(engine_reports_its_ends(&rig).await, 1, "{case}");
        assert_eq!(faults_reported(&log), 0, "{case}: {}", log.rendered());
        assert_eq!(rig.li.x3_attachment_count(), 0, "{case}");
        backend_of(&rig.state)
            .delete(&call, "caller-tag")
            .await
            .expect("released");
    }
}

/// A warrant deactivated is not attached again by the call's next ACK.
#[tokio::test]
async fn a_deactivated_warrant_is_not_attached_again_by_a_later_ack() {
    const CALL: &str = "mid-no-reattach@192.0.2.10";
    let mut rig = Rig::on(NativeTestEngine::start_with_x3().await).await;
    rig.b2bua_call(CALL, true).await;
    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    keep_intercepting(&rig);
    rig.li
        .tasks()
        .deactivate(rig.warrant.x_id)
        .expect("deactivated");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(rig.engine.commands("detach_x3").len(), 1);

    arrives(&rig.state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0));
    assert_eq!(rig.attached().len(), 1, "not asked again");
    assert!(rig.li.x3_attachments_for(CALL).is_empty());
}

/// A call that ends between the scan copying the index and deciding it is
/// left alone.
#[tokio::test]
async fn a_bye_between_the_snapshot_and_the_decision_attaches_nothing() {
    const CALL: &str = "mid-bye-before-decide@192.0.2.10";
    let mut rig = Rig::unwatched(NativeTestEngine::start_with_x3().await).await;
    arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, CALL));
    rig.proxied_media(CALL, true).await;
    rig.activate();
    let snapshot = rig.li.live_dialogs();
    assert_eq!(snapshot.len(), 1);

    arrives(&rig.state, CALLER, &bye(CALL));
    let decided = rig.li.remembered_session_count();
    assert!(
        super::intercept::decide_live_dialog(&rig.state, &rig.li, &snapshot[0]).is_none(),
        "a dialog that ended is not decided, though its media is still up"
    );
    super::intercept::warrant_live_dialog(&rig.state, &rig.li, &snapshot[0]);
    assert_eq!(
        rig.li.remembered_session_count(),
        decided,
        "the scan decided nothing of its own"
    );
    assert_eq!(attach_outcomes(&mut rig.audit).await.0, 0);
    assert!(rig.attached().is_empty());
}

/// A call that ends between the scan deciding it and attaching it is not
/// attached, and the decision the scan made is released.
#[tokio::test]
async fn a_bye_between_the_decision_and_the_attach_attaches_nothing() {
    const CALL: &str = "mid-bye-before-attach@192.0.2.10";
    let mut rig = Rig::unwatched(NativeTestEngine::start_with_x3().await).await;
    arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, CALL));
    rig.proxied_media(CALL, true).await;
    rig.activate();
    let snapshot = rig.li.live_dialogs();

    let decided = super::intercept::decide_live_dialog(&rig.state, &rig.li, &snapshot[0])
        .expect("a warrant covers the call and it is up");
    assert_eq!(rig.li.remembered_session_count(), 1);
    // The BYE the dispatcher takes meanwhile releases the dialog.
    rig.li.live_dialog_ended(CALL);
    super::intercept::attach_live_dialog(&rig.state, &rig.li, &snapshot[0], decided);
    assert_eq!(attach_outcomes(&mut rig.audit).await.0, 0);
    assert!(rig.attached().is_empty());
    assert_eq!(
        rig.li.remembered_session_count(),
        0,
        "the decision is released"
    );
}

/// A message of the dialog and the scan that decide one session at once make
/// one decision, one Correlation ID, and one delivery for each warrant and
/// destination, whichever inserts first.
#[tokio::test]
async fn a_concurrent_ack_and_scan_make_one_decision_and_one_delivery() {
    for (case, scan_first) in [("the ack wins", true), ("the scan wins", false)] {
        let call = format!("mid-race-{}@192.0.2.10", scan_first);
        let mut rig = Rig::unwatched(NativeTestEngine::start_with_x3().await).await;
        arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, &call));
        rig.proxied_media(&call, true).await;
        rig.activate();
        let snapshot = rig.li.live_dialogs();

        if scan_first {
            // The ACK decides the session while the scan is between looking
            // and inserting.
            let state = Arc::clone(&rig.state);
            let ack = on_call(CALLER_ACK, &call);
            crate::li::session::pause::once_before_insert(move |_| {
                arrives(&state, CALLER, &ack);
            });
            super::intercept::warrant_live_dialog(&rig.state, &rig.li, &snapshot[0]);
        } else {
            super::intercept::warrant_live_dialog(&rig.state, &rig.li, &snapshot[0]);
            arrives(&rig.state, CALLER, &on_call(CALLER_ACK, &call));
        }
        assert_eq!(rig.li.remembered_session_count(), 1, "{case}: one decision");
        // The ACK was recorded on the decision that stands, so its
        // retransmission is recognised and writes nothing again: a decision
        // written over the first one would have lost that.
        let before = drain_iri(&mut rig.iri).len();
        assert_eq!(before, 1, "{case}: the ACK is one X2 record");
        arrives(&rig.state, CALLER, &on_call(CALLER_ACK, &call));
        assert!(
            drain_iri(&mut rig.iri).is_empty(),
            "{case}: the retransmitted ACK is a duplicate"
        );
        let session = rig.li.session_of_leg(&call).expect("decided");
        assert_eq!(
            &*session.session_id,
            call.as_str(),
            "{case}: the dialog's key"
        );
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");
        assert_eq!(rig.attached().len(), 1, "{case}: one delivery");
        let live = rig.li.x3_attachments_for(&call);
        assert_eq!(live.len(), 1, "{case}");
        assert_eq!(
            live[0].correlation_id,
            rig.li
                .correlation_for(&rig.li.tasks().list()[0], &session.session_id),
            "{case}: one correlation"
        );
        backend_of(&rig.state)
            .delete(&call, "caller-tag")
            .await
            .expect("released");
    }
}

/// A party seated in a room with no call actor and no media session is a call
/// that is up: the sweep keeps its dialog past the grace, and a warrant
/// activated later attaches on its seat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conference_only_dialog_survives_the_sweep_and_is_attached_on_its_seat() {
    use crate::rtpengine::backend::{ConferenceRole, ConferenceSeat};
    const CALL: &str = "mid-seat-sweep@192.0.2.10";
    const ROOM: &str = "room-mid-seat-sweep";
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
        .expect("seated");
    assert!(rig
        .state
        .rtpengine_sessions
        .as_ref()
        .expect("a store")
        .get(CALL)
        .is_none());

    super::intercept::sweep_live_dialogs(
        &rig.state,
        &rig.li,
        std::time::Instant::now() + crate::li::live_dialogs::LIVE_DIALOG_GRACE * 2,
    );
    assert_eq!(rig.li.live_dialog_count(), 1, "the seat keeps it");

    rig.activate();
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));
    let attached = rig.attached();
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, ROOM);
    backend_of(&rig.state)
        .delete(CALL, "caller-tag")
        .await
        .expect("freed");
}

/// An attach the engine has taken and not yet answered when its warrant is
/// deactivated is detached when the answer comes: the engine is delivering,
/// and nothing else would stop it. One more detach follows the answer, the end
/// the engine reports is the one siphon asked for, nothing reaches the ADMF as
/// a fault, and the record drains. The same for a warrant changed to ask for
/// no content and for a destination removed.
#[tokio::test]
async fn an_attach_answered_after_its_warrant_was_withdrawn_is_detached() {
    use crate::li::x1::types::DeliveryType;
    for case in ["deactivated", "x2 only", "destination removed"] {
        let call = format!("mid-late-{}@192.0.2.10", case.replace(' ', "-"));
        let (log, _guard) = capture_log();
        let mut rig = Rig::on(NativeTestEngine::start_with_x3_026().await).await;
        rig.b2bua_call(&call, true).await;
        rig.engine.hold_attaches();
        rig.activate();
        // The attach is out: the engine has it, and its answer is held.
        for _ in 0..100 {
            if !rig.attached().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(rig.attached().len(), 1, "{case}");

        match case {
            "deactivated" => {
                rig.li
                    .tasks()
                    .deactivate(rig.warrant.x_id)
                    .expect("deactivated");
            }
            "x2 only" => {
                let mut details = rig.warrant.clone();
                details.delivery_type = DeliveryType::X2Only;
                rig.li.tasks().modify(details).expect("modified");
            }
            _ => {
                let d_id = rig.warrant.list_of_dids[0];
                rig.li.destinations().remove(d_id).expect("removed");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        rig.engine.release_attaches();
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(
            rig.engine.commands("detach_x3").len(),
            2,
            "{case}: the withdrawal's, and the one the late answer owes"
        );
        assert_eq!(engine_reports_its_ends(&rig).await, 1, "{case}");
        assert_eq!(faults_reported(&log), 0, "{case}: {}", log.rendered());
        assert!(
            log.rendered().contains("landed after its warrant"),
            "{case}: {}",
            log.rendered()
        );
        assert_eq!(
            rig.engine.x3_delivery_count(),
            0,
            "{case}: nothing delivers"
        );
        assert_eq!(rig.li.x3_attachment_count(), 0, "{case}: the record drains");
        let _ = attach_outcomes(&mut rig.audit).await;
        backend_of(&rig.state)
            .delete(&call, "caller-tag")
            .await
            .expect("released");
    }
}

/// Of two deliveries on one call the one whose warrant is withdrawn while its
/// attach is out is on record as withdrawn in the same step as the change, with
/// nothing awaited: the engine's answer, released afterwards or in the middle
/// of whatever the detach is waiting for, finds it withdrawn and detaches it
/// by name, and the other delivery goes on untouched.
#[tokio::test]
async fn a_withdrawal_is_on_record_at_once_while_another_delivery_stays() {
    const CALL: &str = "mid-late-two@192.0.2.10";
    let (log, _guard) = capture_log();
    let mut rig = Rig::unwatched(NativeTestEngine::start_with_x3_026().await).await;
    rig.b2bua_call(CALL, true).await;
    let mut known = super::intercept::known_targets(&rig.li);
    rig.activate();
    super::intercept::warrants_changed(&rig.state, &mut known).await;
    assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0));

    rig.engine.hold_attaches();
    let second = second_warrant(&rig);
    super::intercept::warrants_changed(&rig.state, &mut known).await;
    for _ in 0..100 {
        if rig.attached().len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(rig.attached().len(), 2, "the second attach is out");
    let withdrawn = rig
        .li
        .x3_attachments_for(CALL)
        .into_iter()
        .find(|attachment| attachment.x_id == second)
        .expect("the second delivery is on record");

    rig.li.tasks().deactivate(second).expect("deactivated");
    super::intercept::warrants_changed(&rig.state, &mut known).await;
    // Nothing has been awaited since the change.
    assert!(
        rig.li.x3_delivery_withdrawn(
            CALL,
            None,
            (withdrawn.x_id, withdrawn.d_id, withdrawn.correlation_id)
        ),
        "the withdrawal is on record before the engine is asked anything"
    );

    rig.engine.release_attaches();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let detached = rig.engine.commands("detach_x3");
    assert!(!detached.is_empty());
    for command in &detached {
        assert_eq!(
            command.x3_delivery.as_ref().expect("by name").xid,
            second.as_bytes(),
            "only the withdrawn delivery is detached"
        );
    }
    assert_eq!(engine_reports_its_ends(&rig).await, 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    let live = rig.li.x3_attachments_for(CALL);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].x_id, rig.warrant.x_id, "the other goes on");
    assert_eq!(rig.engine.x3_delivery_count(), 1);
}

const HOLD_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=sendonly\r\n",
);

/// The caller's hold re-INVITE on the dialog `call_id`, with its SDP.
fn hold_reinvite(call_id: &str) -> String {
    on_call(CALLER_INVITE, call_id)
        .replace(
            "To: <sip:15550100042@siphon.example.com>",
            "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag",
        )
        .replace("CSeq: 1 INVITE", "CSeq: 2 INVITE")
        .replace("z9hG4bK-caller-invite", "z9hG4bK-caller-hold")
        .replace(
            "Content-Length: 0\r\n\r\n",
            &format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{HOLD_SDP}",
                HOLD_SDP.len()
            ),
        )
}

/// The ACK of the hold re-INVITE.
fn hold_ack(call_id: &str) -> String {
    on_call(CALLER_ACK, call_id)
        .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-hold-ack")
}

/// A hold re-INVITE the script relays through the engine (offer and answer),
/// then its ACK, on a call a warrant was activated on in the middle of.
async fn hold_relayed(rig: &Rig, call: &str, callee_leg: Option<&str>, replacing_offer: bool) {
    arrives(&rig.state, CALLER, &hold_reinvite(call));
    let backend = backend_of(&rig.state);
    let mut flags = NgFlags::default();
    flags.stamp_sip_call_id(call);
    match replacing_offer {
        true => {
            backend
                .offer(call, "caller-tag", HOLD_SDP.as_bytes(), &flags)
                .await
        }
        false => {
            backend
                .reoffer(call, "caller-tag", HOLD_SDP.as_bytes(), &flags)
                .await
        }
    }
    .expect("the engine takes the hold offer");
    // The callee's 200 reaches interception first, and the answer it carries
    // goes through the engine stamped with the callee's own dialog.
    let mut answer_flags = NgFlags::default();
    answer_flags.stamp_sip_call_id(callee_leg.unwrap_or(call));
    if let Some(callee_leg) = callee_leg {
        arrives(
            &rig.state,
            super::li_session_tests::CALLEE,
            &super::li_session_tests::callee_response(callee_leg, "200 OK")
                .replace("CSeq: 1 INVITE", "CSeq: 2 INVITE"),
        );
    }
    backend
        .answer(
            call,
            "caller-tag",
            "callee-tag",
            HOLD_SDP.as_bytes(),
            &answer_flags,
        )
        .await
        .expect("and its answer");
    arrives(&rig.state, CALLER, &hold_ack(call));
}

/// A call a warrant was activated on in the middle of is attached once, and
/// stays attached once through a hold re-INVITE relayed through the engine and
/// through a second scan: no further `attach_x3`, no detach, the delivery live.
#[tokio::test]
async fn a_mid_call_attach_is_not_asked_again_by_the_next_reinvite_or_scan() {
    for (case, b2bua, replacing_offer) in [
        ("proxied, re-offer", false, false),
        ("b2bua, re-offer", true, false),
    ] {
        let call = format!("mid-reinvite-{}@192.0.2.10", case.replace([' ', ','], "-"));
        let mut rig = Rig::on(NativeTestEngine::start_with_x3_026().await).await;
        let mut callee_leg = None;
        match b2bua {
            true => {
                let internal_id = rig.b2bua_call(&call, true).await;
                let leg = format!("callee-of-{call}");
                super::li_session_tests::dial(&rig.state, &internal_id, &leg);
                callee_leg = Some(leg);
            }
            false => {
                arrives(&rig.state, CALLER, &on_call(CALLER_INVITE, &call));
                rig.proxied_media(&call, true).await;
            }
        }
        rig.activate();
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");
        assert_eq!(rig.attached().len(), 1, "{case}");

        // The warrants change before the call's next message, as they do on a
        // node provisioning others: its next message finds the generation
        // moved.
        keep_intercepting(&rig);
        assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0), "{case}");
        hold_relayed(&rig, &call, callee_leg.as_deref(), replacing_offer).await;
        assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0), "{case}");
        assert_eq!(rig.attached().len(), 1, "{case}: not attached again");
        assert!(rig.engine.commands("detach_x3").is_empty(), "{case}");
        assert_eq!(rig.li.x3_attachments_for(&call).len(), 1, "{case}: live");
        assert_eq!(rig.engine.x3_delivery_count(), 1, "{case}");

        // An unrelated warrant changes the generation: a second scan.
        keep_intercepting(&rig);
        assert_eq!(attach_outcomes(&mut rig.audit).await, (0, 0), "{case}");
        assert_eq!(
            rig.attached().len(),
            1,
            "{case}: a second scan asks nothing"
        );
        assert!(rig.engine.commands("detach_x3").is_empty(), "{case}");
        let _ = drain_iri(&mut rig.iri);
        backend_of(&rig.state)
            .delete(&call, "caller-tag")
            .await
            .expect("released");
    }
}

/// A hold relayed as a replacing `offer` ends the engine call (the engine tears
/// the old one down, ending its delivery) and starts a new one, which is
/// attached once: two `attach_x3` in all, one for each engine call, the end of
/// the first one siphon asked for and so clean, no detach and one delivery live
/// at the end. This is true of a call decided at its INVITE and of one decided
/// mid-call alike.
#[tokio::test]
async fn a_replacing_offer_ends_the_engine_call_and_attaches_the_new_one_once() {
    for (case, mid_call) in [("decided at the invite", false), ("decided mid-call", true)] {
        let call = format!("mid-replace-{}@192.0.2.10", mid_call);
        let (log, _guard) = capture_log();
        let mut rig = Rig::on(NativeTestEngine::start_with_x3_026().await).await;
        if !mid_call {
            rig.activate();
        }
        rig.b2bua_call(&call, true).await;
        if mid_call {
            rig.activate();
        }
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");

        hold_relayed(&rig, &call, None, true).await;
        assert_eq!(attach_outcomes(&mut rig.audit).await, (1, 0), "{case}");
        assert_eq!(rig.attached().len(), 2, "{case}");
        assert!(rig.engine.commands("detach_x3").is_empty(), "{case}");
        assert_eq!(engine_reports_its_ends(&rig).await, 1, "{case}");
        assert_eq!(faults_reported(&log), 0, "{case}: {}", log.rendered());
        assert_eq!(rig.engine.x3_delivery_count(), 1, "{case}");
        assert_eq!(rig.li.x3_attachments_for(&call).len(), 1, "{case}");
    }
}
