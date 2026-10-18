//! `@b2bua.on_reoffer` and `@b2bua.on_reoffer_answered`: a script shown an
//! in-dialog offer on a bridged call before it is relayed, and the final
//! response its offerer got.
//!
//! The relay paths for a re-INVITE ([`handle_b2bua_reinvite`]) and an UPDATE
//! ([`handle_b2bua_update`]) call [`run_reoffer_hook`] once the request is
//! known to cross: after the glare checks (a `491`, RFC 3261 §14.1, is siphon's
//! to answer and the script never sees it) and after the `100 Trying`, so a
//! slow handler does not draw retransmissions. What the handler decides:
//!
//! * **relay** (the default, and what a raise or a timeout leaves): the offer
//!   goes on as it would without the hook, with any header or body the script
//!   set on `offer.request`;
//! * **refuse**: siphon answers the offerer with the script's status and
//!   relays nothing; the session stays as it was;
//! * **take over**: siphon answers the offerer itself and relays nothing
//!   ([`answer_reoffer_here`]).
//!
//! A media engine cannot answer one party of a two-party session on its own:
//! its local answer is for a session it is the far side of. So the answer is
//! built from the session in force toward the offerer, the description siphon
//! last sent that party (the engine's ports on an anchored call), with the
//! formats both list and the direction the offer leaves (RFC 3264 §6). The
//! engine is told nothing, and keeps relaying the other party's media, which a
//! script can then replace with an announcement.
//!
//! [`notify_reoffer_answered`] runs once the offerer has its final response,
//! whoever gave it.

use crate::b2bua::reoffer::{ReofferAnswer, ReofferDecision, ReofferFacts};
use crate::dispatcher::*;
use crate::script::api::reoffer::PyReoffer;

/// What `@b2bua.on_reoffer` made of an offer.
pub struct ReofferHook {
    pub decision: ReofferDecision,
    /// The request as the handler left it, to relay in place of the one that
    /// arrived. `None` when no handler ran or one raised.
    pub edited: Option<SipMessage>,
    /// The offer as `@b2bua.on_reoffer_answered` is to be shown it, `None`
    /// when the script has no such handler.
    pub facts: Option<Arc<ReofferFacts>>,
}

impl ReofferHook {
    fn relay(facts: Option<Arc<ReofferFacts>>) -> Self {
        Self {
            decision: ReofferDecision::Relay,
            edited: None,
            facts,
        }
    }
}

/// The party an offer came from: the caller, or the callee's leg by the Via
/// branch of its INVITE (a leg's position on the call moves).
#[derive(Clone, Copy)]
pub struct Offerer<'a> {
    pub from_a_leg: bool,
    pub b_leg_branch: Option<&'a str>,
}

impl Offerer<'_> {
    /// Read `read` off the offering party's leg.
    fn read<T>(
        &self,
        call_id: &str,
        state: &DispatcherState,
        read: impl FnOnce(&Leg) -> T,
    ) -> Option<T> {
        if self.from_a_leg {
            return state
                .call_actors
                .get_call(call_id)
                .map(|call| read(&call.a_leg));
        }
        let branch = self.b_leg_branch?;
        state.call_actors.read_b_leg_on(call_id, branch, read)
    }

    /// Change the offering party's leg with `change`.
    fn update<T>(
        &self,
        call_id: &str,
        state: &DispatcherState,
        change: impl FnOnce(&mut Leg) -> T,
    ) -> Option<T> {
        if self.from_a_leg {
            return state
                .call_actors
                .get_call_mut(call_id)
                .map(|mut call| change(&mut call.a_leg));
        }
        let branch = self.b_leg_branch?;
        state.call_actors.update_b_leg_on(call_id, branch, change)
    }

    /// The description this party last gave on its dialog, its own SDP.
    pub fn last_sdp(&self, call_id: &str, state: &DispatcherState) -> Option<Vec<u8>> {
        self.read(call_id, state, |leg| leg.last_sdp.clone())
            .flatten()
    }
}

/// The `Call` a handler is shown: over the caller's INVITE as every other
/// `@b2bua.*` handler, or `fallback` when the call has none stored.
pub(crate) fn py_call_for(
    call_id: &str,
    fallback: Option<&SipMessage>,
    state: &DispatcherState,
) -> Option<PyCall> {
    let call = state.call_actors.get_call(call_id)?;
    let message = match (&call.a_leg_invite, fallback) {
        (Some(invite), _) => Arc::clone(invite),
        (None, Some(message)) => Arc::new(std::sync::Mutex::new(message.clone())),
        (None, None) => return None,
    };
    let transport = &call.a_leg.transport;
    Some(
        PyCall::new(
            call_id.to_string(),
            message,
            transport.remote_addr.ip().to_string(),
            format!("{}", transport.transport).to_lowercase(),
        )
        .with_flow(py_flow_from_leg(transport)),
    )
}

/// Show `message`, an in-dialog offer from `offerer` on `call_id`, to
/// `@b2bua.on_reoffer`, and read what it decided. `early` when it crosses
/// between early dialogs. A script with neither hook costs one look at its
/// handler table.
pub fn run_reoffer_hook(
    call_id: &str,
    inbound: &InboundMessage,
    message: &SipMessage,
    offerer: Offerer<'_>,
    early: bool,
    in_force: Option<&[u8]>,
    state: &DispatcherState,
) -> ReofferHook {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaReoffer);
    let answered = !engine_state
        .handlers_for(&HandlerKind::B2buaReofferAnswered)
        .is_empty();
    if handlers.is_empty() && !answered {
        return ReofferHook::relay(None);
    }
    let method = if message.method() == Some(&Method::Update) {
        "UPDATE"
    } else {
        "INVITE"
    };
    let offer = sdp_in_body(message_content_type(message), &message.body);
    let facts = Arc::new(ReofferFacts::read(
        method,
        offerer.from_a_leg,
        offer.as_deref(),
        in_force,
        early,
    ));
    let kept = answered.then(|| Arc::clone(&facts));
    if handlers.is_empty() {
        return ReofferHook::relay(kept);
    }
    let Some(py_call) = py_call_for(call_id, Some(message), state) else {
        return ReofferHook::relay(kept);
    };
    let request = Arc::new(std::sync::Mutex::new(message.clone()));
    let py_request = PyRequest::new(
        Arc::clone(&request),
        format!("{}", inbound.transport).to_lowercase(),
        inbound.remote_addr.ip().to_string(),
        inbound.remote_addr.port(),
    );

    let outcome = Python::attach(|python| {
        let (call_object, request_object) = match (
            Py::new(python, py_call),
            Py::new(python, py_request),
        ) {
            (Ok(call), Ok(request)) => (call, request),
            (Err(error), _) | (_, Err(error)) => {
                error!(call_id = %call_id, "B2BUA on_reoffer: could not build its arguments: {error}");
                return None;
            }
        };
        let reoffer = match Py::new(
            python,
            PyReoffer::offered(Arc::clone(&facts), request_object.clone_ref(python)),
        ) {
            Ok(reoffer) => reoffer,
            Err(error) => {
                error!(call_id = %call_id, "B2BUA on_reoffer: could not build the offer: {error}");
                return None;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            let raised = match callable.call1((call_object.bind(python), reoffer.bind(python))) {
                Ok(returned) if handler.is_async => run_coroutine(python, &returned).err(),
                Ok(_) => None,
                Err(error) => Some(error),
            };
            if let Some(error) = raised {
                record_script_error("B2BUA on_reoffer", &error);
                return None;
            }
        }
        // The decisions of an offer are the offer's own. One taken on the call
        // or the request would read as done and do nothing.
        if !matches!(call_object.borrow(python).action(), CallAction::None) {
            warn!(call_id = %call_id, "B2BUA on_reoffer: a call action has no effect here; decide the offer with offer.reject() or offer.answer()");
        }
        if !matches!(request_object.borrow(python).action(), RequestAction::None) {
            warn!(call_id = %call_id, "B2BUA on_reoffer: request.reply()/relay() have no effect here; decide the offer with offer.reject() or offer.answer()");
        }
        let decision = reoffer.borrow(python).decision().clone();
        Some(decision)
    });

    match outcome {
        // A raise decides nothing, and the offer goes on as it came.
        None => {
            warn!(call_id = %call_id, "B2BUA on_reoffer raised: relaying the offer as it arrived");
            ReofferHook::relay(kept)
        }
        Some(decision) => ReofferHook {
            decision,
            edited: request.lock().ok().map(|edited| edited.clone()),
            facts: kept,
        },
    }
}

/// Show the final response the offerer got to `@b2bua.on_reoffer_answered`.
pub fn notify_reoffer_answered(
    call_id: &str,
    facts: Arc<ReofferFacts>,
    answer: ReofferAnswer,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaReofferAnswered);
    if handlers.is_empty() {
        return;
    }
    let Some(py_call) = py_call_for(call_id, None, state) else {
        debug!(call_id = %call_id, "B2BUA on_reoffer_answered: the call is gone");
        return;
    };
    Python::attach(|python| {
        let (call_object, reoffer) = match (
            Py::new(python, py_call),
            Py::new(python, PyReoffer::answered(facts, answer)),
        ) {
            (Ok(call), Ok(reoffer)) => (call, reoffer),
            (Err(error), _) | (_, Err(error)) => {
                error!(call_id = %call_id, "B2BUA on_reoffer_answered: could not build its arguments: {error}");
                return;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_object.bind(python), reoffer.bind(python))) {
                Ok(returned) if handler.is_async => {
                    if let Err(error) = run_coroutine(python, &returned) {
                        record_script_error("async B2BUA on_reoffer_answered", &error);
                    }
                }
                Ok(_) => {}
                Err(error) => record_script_error("B2BUA on_reoffer_answered", &error),
            }
        }
    });
}

/// The offer kept on the tracking leg `branch` for `@b2bua.on_reoffer_answered`,
/// taken off it when `status_code` is final, so only one response shows it.
pub fn take_reoffer_for_final(
    call_id: &str,
    branch: &str,
    status_code: u16,
    state: &DispatcherState,
) -> Option<Arc<ReofferFacts>> {
    if status_code < 200 {
        return None;
    }
    state
        .call_actors
        .update_b_leg_on(call_id, branch, |leg| leg.reoffer.take())
        .flatten()
}

/// Notify `@b2bua.on_reoffer_answered` of the final response `response` the
/// offerer was sent, when the offer was kept for it.
pub fn notify_reoffer_response(
    call_id: &str,
    facts: Option<Arc<ReofferFacts>>,
    response: &SipMessage,
    local: bool,
    state: &DispatcherState,
) {
    let (Some(facts), Some(status_code)) = (facts, response.status_code()) else {
        return;
    };
    if status_code < 200 {
        return;
    }
    let sdp = sdp_in_body(message_content_type(response), &response.body)
        .map(|sdp| String::from_utf8_lossy(&sdp).into_owned());
    notify_reoffer_answered(
        call_id,
        facts,
        ReofferAnswer {
            status_code,
            sdp,
            local,
        },
        state,
    );
}

/// Notify `@b2bua.on_reoffer_answered` of a refusal siphon sent the offerer
/// itself without a script asking for it: a media engine that would not take
/// the offer.
pub fn notify_reoffer_refused_here(
    call_id: &str,
    facts: Option<Arc<ReofferFacts>>,
    status_code: u16,
    state: &DispatcherState,
) {
    if let Some(facts) = facts {
        notify_reoffer_answered(
            call_id,
            facts,
            ReofferAnswer {
                status_code,
                sdp: None,
                local: true,
            },
            state,
        );
    }
}

/// Put back the description the offering party had in force before an offer
/// that was refused (RFC 3261 §14.1): the offer never became its media.
pub fn restore_offerer_sdp(
    call_id: &str,
    offerer: Offerer<'_>,
    in_force: Option<Vec<u8>>,
    state: &DispatcherState,
) {
    offerer.update(call_id, state, move |leg| leg.last_sdp = in_force);
}

/// The final response to an offer `@b2bua.on_reoffer` refused or took over,
/// sent to the offerer. Returns the response sent.
pub fn decide_reoffer_here(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    offerer: Offerer<'_>,
    early: bool,
    decision: &ReofferDecision,
    state: &DispatcherState,
) -> SipMessage {
    let response = match decision {
        ReofferDecision::Refuse { code, reason } => {
            debug!(call_id = %call_id, code, "B2BUA: on_reoffer refused the offer");
            build_response(message, *code, reason, state.server_header.as_deref(), &[])
        }
        ReofferDecision::TakeOver { sdp } => {
            answer_reoffer_here(message, call_id, offerer, early, sdp.as_deref(), state)
        }
        // Not this function's to send; answered as an error rather than not
        // at all should a caller ever get here with it.
        ReofferDecision::Relay => {
            error!(call_id = %call_id, "B2BUA: an offer to relay was answered here: 500");
            build_response(
                message,
                500,
                "Server Internal Error",
                state.server_header.as_deref(),
                &[],
            )
        }
    };
    send_message_from(
        response.clone(),
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    response
}

/// The `200 OK` with which siphon answers an offer itself, or the `488` when
/// it has nothing to answer from.
///
/// `script_sdp` is the script's answer. Without one the answer is the session
/// in force toward the offerer (`Dialog::last_sent_sdp`) answering the offer
/// ([`crate::media::answer::answer_from`]); an offerless re-INVITE gets that
/// session as siphon's offer (RFC 3261 §14.1), and an UPDATE without an offer
/// a 200 without a body. siphon's `o=` goes on whatever changed (RFC 3264 §8),
/// and the SDP becomes the session in force on the offerer's dialog.
fn answer_reoffer_here(
    message: &SipMessage,
    call_id: &str,
    offerer: Offerer<'_>,
    early: bool,
    script_sdp: Option<&str>,
    state: &DispatcherState,
) -> SipMessage {
    let offer = sdp_in_body(message_content_type(message), &message.body);
    let (in_force, contact) = offerer
        .read(call_id, state, |leg| {
            (
                leg.dialog.last_sent_sdp.clone(),
                leg.dialog.local_contact.clone(),
            )
        })
        .unwrap_or((None, None));
    let refuse = |why: &str| {
        error!(call_id = %call_id, "B2BUA: on_reoffer took the offer over and it cannot be answered here: {why}: 488");
        build_response(
            message,
            488,
            "Not Acceptable Here",
            state.server_header.as_deref(),
            &[],
        )
    };

    // The body, and whether it is new on the dialog (and so takes a new `o=`
    // version) rather than the session in force sent again.
    let body: Option<(Vec<u8>, bool)> = match (script_sdp, &offer, &in_force) {
        (Some(sdp), _, _) => Some((sdp.as_bytes().to_vec(), true)),
        (None, Some(offer), Some(in_force)) => {
            let parse =
                |sdp: &[u8]| crate::media::sdp::SdpBody::parse(&String::from_utf8_lossy(sdp));
            // siphon answers for the media path, which runs both ways: the
            // direction is the offer's to restrict (RFC 3264 §6.1), not a
            // restriction an earlier answer here left on the description.
            let description = crate::b2bua::bridge::set_media_direction(
                in_force,
                crate::b2bua::bridge::MediaDirection::SendRecv,
            );
            match crate::media::answer::answer_from(&parse(offer), &parse(&description)) {
                Ok(answer) => {
                    let answer = answer.to_string().into_bytes();
                    let changed = answer != *in_force;
                    Some((answer, changed))
                }
                Err(why) => return refuse(why),
            }
        }
        (None, Some(_), None) => return refuse("no session in force toward the offerer"),
        (None, None, Some(in_force)) if message.method() == Some(&Method::Invite) => {
            Some((in_force.clone(), false))
        }
        (None, None, None) if message.method() == Some(&Method::Invite) => {
            return refuse("an offerless re-INVITE and no session in force to offer")
        }
        (None, None, _) => None,
    };

    let mut response = build_response(message, 200, "OK", state.server_header.as_deref(), &[]);
    // A 2xx to a target refresh request carries the answerer's Contact
    // (RFC 3261 §12.2.2): what siphon advertises on this dialog.
    if let Some(contact) = contact {
        response.headers.set("Contact", contact);
    }
    if !early {
        note_session_refresh_request(call_id, offerer.from_a_leg, &message.headers, state);
        negotiate_relayed_session_timer(
            call_id,
            offerer.from_a_leg,
            Some(&message.headers),
            &mut response.headers,
            state,
        );
    }
    if let Some((mut body, changed)) = body {
        if changed {
            let identity = offerer.update(call_id, state, |leg| {
                let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
                leg.dialog.sdp_version += 1;
                identity
            });
            if let Some((session_id, version)) = identity {
                stamp_sdp_origin(&mut body, &state.sdp_name, session_id, version, None);
            }
        }
        let sent = body.clone();
        let offered = offer.clone();
        offerer.update(call_id, state, move |leg| {
            leg.dialog.last_sent_sdp = Some(sent);
            if let Some(offered) = offered {
                leg.last_sdp = Some(offered);
            }
        });
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", body.len().to_string());
        response.body = body;
    } else if let Some(offered) = offer {
        offerer.update(call_id, state, move |leg| leg.last_sdp = Some(offered));
    }
    debug!(call_id = %call_id, "B2BUA: on_reoffer answered the offer itself");
    response
}
