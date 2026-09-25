//! Calls siphon places itself, with no A-leg INVITE behind them
//! (`b2bua.originate()`), and the responses they get back.
use crate::dispatcher::*;

// ---------------------------------------------------------------------------
// originate — a call siphon places itself (no inbound INVITE)
// ---------------------------------------------------------------------------

/// The media plan of an [`OriginateParams`] — how the originated INVITE gets an
/// offer/answer. There is deliberately no "neither" variant: an INVITE with no
/// offer and no plan to answer the callee's would leave a 2xx un-answerable
/// (RFC 3261 §13.2.2.4 requires the answer in the ACK when the INVITE carried
/// no offer), i.e. a connected call with no media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginateMedia {
    /// The controller supplied the body; it rides on the INVITE verbatim under
    /// `content_type`, and the callee's answer arrives in the 2xx (RFC 3264 §5).
    /// Works on every media backend, and on none at all.
    ///
    /// `content_type` is `application/sdp` for a plain offer, or a `multipart/*`
    /// carrying the offer as one of its parts (RFC 5621 §3) — beside ISUP on a
    /// SIP-I trunk, a PIDF-LO location object, an operator-specific document.
    /// Either way the body has to carry an SDP offer, and
    /// [`build_originate_invite`] refuses one that does not: a callee that reads
    /// the INVITE as offerless offers in its own 2xx, and this plan has nothing
    /// to answer that with (RFC 3261 §13.2.2.4).
    Offer {
        /// The bytes carried on the INVITE.
        body: Vec<u8>,
        /// The `Content-Type` they are carried under.
        content_type: String,
    },
    /// siphon anchors the leg on the configured media backend: the INVITE goes
    /// out **offerless**, the callee's 2xx carries the offer, and siphon answers
    /// it locally (`answer_local`) with the answer riding on the ACK — RFC 3261
    /// §13.2.2.4 / RFC 3264 §5, the delayed-offer half of RFC 3725's 3PCC flows.
    /// The resulting media session is keyed on this leg's SIP Call-ID, so every
    /// media verb (`play` / `dtmf` / `hold` / `stream_start`) resolves against it
    /// exactly as it does for an inbound-anchored channel.
    Anchor {
        /// Media profile whose `answer` flags the local anchor uses.
        profile: String,
        /// Per-call WebSocket bridge URI (templated), overriding the profile's.
        ws_uri: Option<String>,
    },
}

/// Everything an [`b2bua_originate_prepare`] needs. Every field is applied to
/// the INVITE that goes on the wire — none is decorative.
#[derive(Debug, Clone)]
pub struct OriginateParams {
    /// Called party — the Request-URI and the To URI (RFC 3261 §8.1.1.1/§8.1.1.2).
    pub to: String,
    /// Optional To display name.
    pub to_display: Option<String>,
    /// Calling identity — the From URI (RFC 3261 §8.1.1.3). Defaults to
    /// `sip:<advertised-host>` when absent.
    pub from: Option<String>,
    /// Optional From display name.
    pub from_display: Option<String>,
    /// Route the INVITE here instead of resolving the Request-URI — the R-URI
    /// still carries the called party's shape (IMS edge / trunk steering).
    pub next_hop: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1).
    pub p_asserted_identity: Option<String>,
    /// Calling-identity presentation (RFC 3323 §4.1 / TS 24.607). `Restricted`
    /// anonymises From and asserts `Privacy: id`, keeping the real identity in
    /// `P-Asserted-Identity` for the trusted next hop.
    pub privacy: Option<crate::sip::privacy::CallerIdPresentation>,
    /// Arbitrary custom headers, applied last.
    pub headers: Vec<(String, String)>,
    /// Ring timeout in seconds; `0` disables it (the orphan sweep stays the
    /// backstop). The call is CANCELled (RFC 3261 §9.1) when it elapses.
    pub timeout_secs: u32,
    /// The media plan.
    pub media: OriginateMedia,
    /// The RFC 4028 session timer the script set on the originate, over the
    /// `session_timer:` block. `None` runs the configured one, if any.
    pub session_timer: Option<crate::script::api::call::SessionTimerOverride>,
}

/// Why an originate was refused. Each variant maps to its own control-plane
/// error code — a caller must be able to tell "your URI is wrong" from "no
/// route" from "this backend cannot do that".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginateError {
    /// The dispatcher is not running (headless / shutting down).
    Unavailable(String),
    /// A supplied URI did not parse.
    InvalidUri {
        /// Which argument.
        field: &'static str,
        /// Parser detail.
        detail: String,
    },
    /// No wire destination could be resolved for the target / next hop.
    Unroutable(String),
    /// The configured backend cannot serve the requested media plan.
    Unsupported(String),
    /// The supplied body is not one an INVITE can carry an offer in: a
    /// `Content-Type` naming neither SDP nor a multipart carrying it, a
    /// multipart body that does not parse, or one with no SDP part in it.
    InvalidBody(String),
    /// The INVITE could not be built (should not happen; surfaced, never panicked).
    BuildFailed(String),
}

impl std::fmt::Display for OriginateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OriginateError::Unavailable(detail) => write!(formatter, "{detail}"),
            OriginateError::InvalidUri { field, detail } => {
                write!(formatter, "invalid {field}: {detail}")
            }
            OriginateError::Unroutable(detail) => write!(formatter, "{detail}"),
            OriginateError::Unsupported(detail) => write!(formatter, "{detail}"),
            OriginateError::InvalidBody(detail) => write!(formatter, "{detail}"),
            OriginateError::BuildFailed(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// A staged originate: the call exists in the store and is addressable, but its
/// INVITE has **not** left the socket yet.
///
/// The two-phase split exists so the control plane can register the channel
/// under the caller-supplied id *before* anything is on the wire. Dialing first
/// would open a window where a fast callee's `180`/`200` arrives with no channel
/// registered and its event is dropped on the floor — an outcome the controller
/// could never recover from, since a missed `answered` looks identical to a call
/// that never answered.
#[derive(Debug)]
pub struct PreparedOriginate {
    /// The internal `CallActor` id.
    pub internal_call_id: String,
    /// The originated leg's SIP Call-ID (CDR / HEP / media-session join key).
    pub sip_call_id: String,
    /// Our From-tag on the originated dialog.
    pub from_tag: String,
    pub invite: SipMessage,
    pub destination: SocketAddr,
    pub transport: Transport,
    pub timeout_secs: u32,
}

/// Stage a call siphon places: build the INVITE, create the `CallActor` whose
/// A-leg is the outbound (UAC) dialog, and index the INVITE's branch so its
/// responses reach [`handle_originated_call_response`]. Nothing is sent — call
/// [`b2bua_originate_dial`] to put it on the wire.
pub fn b2bua_originate_prepare(
    params: OriginateParams,
) -> Result<PreparedOriginate, OriginateError> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(OriginateError::Unavailable(
            "b2bua is not running — nothing to originate from".to_string(),
        ));
    };
    prepare_originate(&control.state, params)
}

/// [`b2bua_originate_prepare`] on the dispatcher the caller already holds, which
/// is what lets a test stage an originate: the control handle is set once per
/// process, and tests elsewhere rely on it being absent.
pub fn prepare_originate(
    state: &DispatcherState,
    params: OriginateParams,
) -> Result<PreparedOriginate, OriginateError> {
    let target_uri =
        parse_uri_standalone(&params.to).map_err(|error| OriginateError::InvalidUri {
            field: "to",
            detail: error.to_string(),
        })?;
    for (field, value) in [
        ("from", params.from.as_deref()),
        ("next_hop", params.next_hop.as_deref()),
        ("p_asserted_identity", params.p_asserted_identity.as_deref()),
    ] {
        if let Some(value) = value {
            parse_uri_standalone(value).map_err(|error| OriginateError::InvalidUri {
                field,
                detail: error.to_string(),
            })?;
        }
    }

    // Validate the media plan against the *configured* backend before anything
    // is created: a plan this deployment cannot serve must fail visibly at the
    // command, never as a connected call with no audio.
    if let OriginateMedia::Anchor { profile, .. } = &params.media {
        originate_validate_anchor(profile, state)?;
    }

    // Resolve the wire destination. `next_hop` steers egress without touching
    // the R-URI (the called party's shape is preserved on the wire) — the same
    // split `call.dial(next_hop=…)` and `proxy.send_request(next_hop=…)` make.
    let routing_uri = params.next_hop.as_deref().unwrap_or(&params.to);
    let relay_target = resolve_target(routing_uri, &state.dns_resolver).ok_or_else(|| {
        OriginateError::Unroutable(format!("cannot resolve a destination for '{routing_uri}'"))
    })?;
    let destination = relay_target.address;
    let transport = relay_target.transport.unwrap_or(Transport::Udp);

    let sip_call_id = crate::b2bua::actor::generate_call_id();
    let from_tag = crate::b2bua::actor::generate_tag();
    let branch = TransactionKey::generate_branch();
    let (via_host, via_port) = (state.via_host(&transport), state.via_port(&transport));

    let contact = build_b_leg_contact(&via_host, via_port, transport, None, None);
    let invite = build_originate_invite(
        &params,
        target_uri,
        OriginateIdentity {
            sip_call_id: &sip_call_id,
            from_tag: &from_tag,
            branch: &branch,
            via_host: &via_host,
            via_port,
            transport,
            contact: &contact,
            user_agent: state
                .user_agent_header
                .as_deref()
                .or(state.server_header.as_deref()),
        },
        session_timer_policy_for(state, params.session_timer.as_ref()),
    )?;

    let mut leg = crate::b2bua::actor::Leg::new_originating_leg(
        sip_call_id.clone(),
        from_tag.clone(),
        params.to.clone(),
        branch.clone(),
        LegTransport {
            remote_addr: destination,
            connection_id: ConnectionId::default(),
            transport,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some(contact);
    leg.dialog.local_from_uri = invite.headers.from().cloned();
    leg.dialog.remote_to_uri = invite.headers.to().cloned();
    if !invite.body.is_empty() {
        // The SDP alone, never the whole body: `last_sdp` is this leg's current
        // media description and a later re-INVITE (hold, bridge) re-offers it,
        // while the other parts of a multipart body belong to the initial
        // INVITE only. `build_originate_invite` has already refused a body with
        // no SDP in it, so this cannot quietly drop an offer.
        leg.last_sdp =
            crate::media::body::sdp_from_body(message_content_type(&invite), &invite.body).ok();
    }

    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    state
        .call_actors
        .mark_originated(&internal_call_id, &branch);
    if let OriginateMedia::Anchor { profile, ws_uri } = &params.media {
        state.call_actors.set_originate_anchor(
            &internal_call_id,
            crate::b2bua::actor::OriginateAnchor {
                profile: profile.clone(),
                ws_uri: ws_uri.clone(),
            },
        );
    }

    // The event channel every leg actor on this call shares. An originated call
    // has no B-leg today, but the store's teardown paths expect the pair to
    // exist, and a later bridge dials one.
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = state.call_actors.get_call_mut(&internal_call_id) {
        call.event_tx = Some(event_tx);
        // What a refresh, a bridge re-INVITE and the 2xx read the call's session
        // timer policy from.
        call.session_timer_override = params.session_timer.clone();
        // An originate aimed at a configured gateway answers that gateway's
        // challenges with its credentials. The `originate` verb carries none of
        // its own — a controller should not be shipping trunk passwords over
        // the control rail when the gateway already holds them.
        call.outbound_credentials = originate_gateway_credentials(routing_uri, destination);
    }
    state
        .call_event_receivers
        .insert(internal_call_id.clone(), event_rx);

    info!(
        call_id = %internal_call_id,
        %sip_call_id,
        target = %params.to,
        %destination,
        %transport,
        "B2BUA: originate staged"
    );
    Ok(PreparedOriginate {
        internal_call_id,
        sip_call_id,
        from_tag,
        invite,
        destination,
        transport,
        timeout_secs: params.timeout_secs,
    })
}

/// The dialog identity + local socket identity an originate INVITE advertises.
/// Grouped so [`build_originate_invite`] stays a pure, testable function rather
/// than a nine-argument one.
pub struct OriginateIdentity<'a> {
    pub sip_call_id: &'a str,
    pub from_tag: &'a str,
    pub branch: &'a str,
    pub via_host: &'a str,
    pub via_port: u16,
    pub transport: Transport,
    pub contact: &'a str,
    pub user_agent: Option<&'a str>,
}

/// Build the INVITE an originate puts on the wire. Pure — no state, no I/O — so
/// the identity rules that matter (From/To shape, PAI, CLIR ordering, the
/// reserved-header guard, offer vs offerless body) are unit-testable.
///
/// `session_timer` is the RFC 4028 session timer siphon runs on the call, the
/// script's or the configured one. The INVITE asks for it the way every INVITE
/// siphon sends does (§7.1): `Session-Expires` with the refresher siphon prefers,
/// `Min-SE`, and `timer` in `Supported`.
pub fn build_originate_invite(
    params: &OriginateParams,
    target_uri: SipUri,
    identity: OriginateIdentity<'_>,
    session_timer: Option<crate::b2bua::session_timer::SessionTimerPolicy>,
) -> Result<SipMessage, OriginateError> {
    let from_uri = params
        .from
        .clone()
        .unwrap_or_else(|| format!("sip:{}", identity.via_host));
    let from_header = match params.from_display.as_deref().filter(|d| !d.is_empty()) {
        Some(display) => format!("\"{display}\" <{from_uri}>;tag={}", identity.from_tag),
        None => format!("<{from_uri}>;tag={}", identity.from_tag),
    };
    // RFC 3261 §12.1.2: the UAC's To carries no tag until the callee assigns one.
    let to_header = match params.to_display.as_deref().filter(|d| !d.is_empty()) {
        Some(display) => format!("\"{display}\" <{}>", params.to),
        None => format!("<{}>", params.to),
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Invite, target_uri)
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            identity.transport, identity.via_host, identity.via_port, identity.branch
        ))
        .from(from_header)
        .to(to_header)
        .call_id(identity.sip_call_id.to_string())
        .cseq("1 INVITE".to_string())
        .header("Max-Forwards", "70".to_string())
        .header("Contact", identity.contact.to_string())
        .header("Allow", crate::sip::SUPPORTED_METHODS.to_string());
    if let Some(user_agent) = identity.user_agent {
        builder = builder.header("User-Agent", user_agent.to_string());
    }
    if let Some(ref asserted) = params.p_asserted_identity {
        builder = builder.header(
            "P-Asserted-Identity",
            crate::sip::privacy::asserted_identity_value(asserted),
        );
    }
    let builder = match &params.media {
        OriginateMedia::Offer { body, content_type } => builder
            .content_type(content_type.clone())
            // `body` derives Content-Length from the bytes themselves, so the
            // framing always describes what is actually carried.
            .body(body.clone()),
        // Offerless: the callee offers in its 2xx and we answer in the ACK.
        OriginateMedia::Anchor { .. } => builder.content_length(0),
    };
    let mut invite = builder
        .build()
        .map_err(|error| OriginateError::BuildFailed(format!("cannot build INVITE: {error}")))?;
    if let Some(policy) = session_timer {
        invite
            .headers
            .set("Session-Expires", policy.uac_request_value());
        invite.headers.set("Min-SE", policy.min_se.to_string());
        advertise_supported_options(&mut invite.headers);
        advertise_option_tag(&mut invite.headers, "timer");
    }

    // Custom headers last, so a caller can shape anything the framework set
    // above short of the dialog-defining ones it must not touch.
    for (name, value) in &params.headers {
        if is_originate_reserved_header(name) {
            warn!(
                sip_call_id = %identity.sip_call_id,
                header = %name,
                "originate: ignoring a dialog-defining header supplied in args.headers"
            );
            continue;
        }
        invite.headers.set(name, value.clone());
    }

    // The body and the Content-Type describing it have to still agree once
    // `headers` has had its say. Content-Type is deliberately not reserved —
    // rewriting it is how a caller wraps its offer in a `multipart/*` beside a
    // part SIP does not interpret (RFC 5621 §3) — but rewriting it to something
    // that carries no offer at all is a different act: the callee then reads an
    // offerless INVITE and offers in its own 2xx, which an `Offer` plan has
    // nothing to answer with (RFC 3261 §13.2.2.4). That is a connected call
    // with no audio, so it is refused here rather than placed.
    originate_check_body(&invite, &params.media)?;

    // A restricted originate needs something for `Privacy: id` to withhold
    // (RFC 3325 §7): the trusted next hop identifies the caller by the PAI, so
    // anonymising the From over an absent one leaves a privacy request nobody
    // can honour correctly. Asserted from the From while it still holds the
    // real identity, and only when the caller did not supply its own
    // `p_asserted_identity` — an explicit one is the caller's decision and is
    // already on the message, so this is a no-op there.
    //
    // Scoped to the restricted path on purpose. An unrestricted originate is a
    // call the caller composed header by header; the B-leg builder's assertion
    // exists because a *relayed* leg has had its P-* stripped by the header
    // policy, which never happened here.
    if params.privacy == Some(crate::sip::privacy::CallerIdPresentation::Restricted) {
        crate::sip::privacy::assert_calling_identity(&mut invite);
        // CLIR last of all — anonymisation is the final identity step, or a
        // custom From / P-Asserted-Identity header set after it would undo it
        // (RFC 3323 §4.1 / TS 24.607).
        crate::sip::privacy::restrict_calling_identity(&mut invite);
    }
    Ok(invite)
}

/// The `Content-Type` a built message carries, compact form included: a caller
/// can spell the header either way in `headers` (RFC 3261 §7.3.1, §20).
pub fn message_content_type(message: &SipMessage) -> &str {
    message
        .headers
        .get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .map(String::as_str)
        .unwrap_or_default()
}

/// Refuse an originate whose body and `Content-Type` no longer match its media
/// plan once `headers` has been applied. See the call site for why this runs
/// after the custom headers rather than before them.
pub fn originate_check_body(
    invite: &SipMessage,
    media: &OriginateMedia,
) -> Result<(), OriginateError> {
    let content_type = message_content_type(invite);
    match media {
        OriginateMedia::Offer { .. } => crate::media::body::sdp_from_body(content_type, &invite.body)
            .map(|_| ())
            .map_err(OriginateError::InvalidBody),
        // An anchored originate sends no body at all, so a Content-Type on it
        // describes a body that is not there.
        OriginateMedia::Anchor { .. } if !content_type.is_empty() => {
            Err(OriginateError::InvalidBody(format!(
                "originate with media anchoring sends an offerless INVITE, so the Content-Type '{content_type}' supplied in headers describes a body that is not there"
            )))
        }
        OriginateMedia::Anchor { .. } => Ok(()),
    }
}

/// Headers an `originate` caller must not set: the dialog identity and framing
/// the stack owns (RFC 3261 §8.1.1). Setting them from `args.headers` would
/// desynchronise the stored dialog from the wire — the leg would be
/// unaddressable for its own ACK / BYE.
pub fn is_originate_reserved_header(name: &str) -> bool {
    [
        "via",
        "from",
        "to",
        "call-id",
        "cseq",
        "contact",
        "max-forwards",
        "content-length",
        "route",
        "record-route",
    ]
    .contains(&name.trim().to_ascii_lowercase().as_str())
}

/// Gate an [`OriginateMedia::Anchor`] plan against the configured backend +
/// profile registry. Pure enough to unit-test through
/// [`originate_anchor_rejection`]; returns the typed refusal the caller
/// surfaces verbatim.
pub fn originate_validate_anchor(
    profile: &str,
    state: &DispatcherState,
) -> Result<(), OriginateError> {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return Err(OriginateError::Unsupported(
            "originate media anchoring requires a media backend (media.backend), none configured"
                .to_string(),
        ));
    };
    let Some(registry) = state.rtpengine_profiles.as_ref() else {
        return Err(OriginateError::Unsupported(
            "originate media anchoring requires media profiles, none configured".to_string(),
        ));
    };
    originate_anchor_rejection(backend.kind(), registry.get(profile).is_some(), profile)
        .map_or(Ok(()), Err)
}

/// The refusal an anchor plan draws, if any — split out so both gates (backend
/// kind, profile existence) are testable without a `DispatcherState`.
pub fn originate_anchor_rejection(
    kind: crate::config::MediaBackendKind,
    profile_known: bool,
    profile: &str,
) -> Option<OriginateError> {
    // `answer_local` is the siphon-rtp native verb; rtpengine / rtpproxy have no
    // equivalent, so an anchored originate on them must fail here rather than
    // connect a call whose 2xx offer nothing can answer.
    if !matches!(kind, crate::config::MediaBackendKind::SiphonRtp) {
        return Some(OriginateError::Unsupported(format!(
            "originate media anchoring requires the siphon-rtp media backend; media.backend is {}",
            kind.as_str()
        )));
    }
    if !profile_known {
        return Some(OriginateError::Unsupported(format!(
            "unknown media profile '{profile}' for originate"
        )));
    }
    None
}

/// Put a staged originate on the wire: arm the RFC 3261 §17.1.1.2 retransmit
/// schedule (UDP), send the INVITE, and arm the ring timeout. Returns `false`
/// (never panics) when the call was torn down between prepare and dial.
pub fn b2bua_originate_dial(prepared: &PreparedOriginate) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread (the control command consumer, an async-pool loop).
    let _enter = control.runtime.enter();
    dial_originate(&control.state, prepared)
}

/// [`b2bua_originate_dial`] on the dispatcher the caller already holds, inside a
/// tokio runtime: the dial half of [`prepare_originate`], and what lets a test
/// place a staged originate the way the control plane does.
pub fn dial_originate(state: &DispatcherState, prepared: &PreparedOriginate) -> bool {
    if state
        .call_actors
        .get_call(&prepared.internal_call_id)
        .is_none()
    {
        return false;
    }

    let data = Bytes::from(prepared.invite.to_bytes());
    arm_b2bua_retransmit(
        &prepared.invite,
        &data,
        prepared.transport,
        prepared.destination,
        udp_egress_source(prepared.transport, prepared.destination, None),
        state,
    );
    let relay_target = RelayTarget {
        address: prepared.destination,
        transport: Some(prepared.transport),
        server_name: None,
    };
    send_to_target(
        data,
        &relay_target,
        prepared.transport,
        ConnectionId::default(),
        None,
        state,
    );
    set_b2bua_answer_deadline(&prepared.internal_call_id, prepared.timeout_secs, state);
    debug!(
        call_id = %prepared.internal_call_id,
        sip_call_id = %prepared.sip_call_id,
        destination = %prepared.destination,
        "B2BUA: originate INVITE sent"
    );
    true
}

/// Stage **and** dial in one step, for the in-process `b2bua.originate()`
/// surface (there is no channel to register between the two phases there).
pub fn b2bua_originate(params: OriginateParams) -> Result<PreparedOriginate, OriginateError> {
    let prepared = b2bua_originate_prepare(params)?;
    if !b2bua_originate_dial(&prepared) {
        return Err(OriginateError::Unavailable(
            "originate was staged but the call vanished before dialling".to_string(),
        ));
    }
    Ok(prepared)
}

/// Handle a response to an INVITE **siphon originated**.
///
/// The UAC-side twin of [`handle_b2bua_response`]. Nothing here is relayed:
/// there is no A-leg to forward to — this call *is* the A-leg — so the response
/// is turned into control-plane events and the local dialog transitions the
/// RFC 3261 §17.1.1 client transaction owes the callee:
///
/// * **1xx** — record the early dialog's remote tag/target (§12.1.2) and surface
///   `ChannelStateChange`. `100 Trying` never reaches here (absorbed upstream).
/// * **2xx** — confirm the dialog (§13.2.2.4): capture the remote tag, Contact
///   and reversed Record-Route as the route set, ACK (carrying the local media
///   answer when the INVITE went out offerless), mark the call answered.
/// * **3xx-6xx** — ACK the final (§17.1.1.3, on the INVITE's own branch), then
///   tear the call down with the cause the callee gave.
pub fn handle_originated_call_response(
    internal_call_id: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    let Some((mut leg, sip_call_id, already_answered)) =
        state.call_actors.get_call(internal_call_id).map(|call| {
            (
                call.a_leg.clone(),
                call.a_leg.dialog.call_id.clone(),
                matches!(call.state, CallState::Answered),
            )
        })
    else {
        warn!(call_id = %internal_call_id, "originate: response for a call that is gone");
        return;
    };

    // A response to our CANCEL shares the INVITE's top Via branch (RFC 3261
    // §9.1); it is not the callee's answer and needs nothing here.
    let cseq_method = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default();
    if !cseq_method.eq_ignore_ascii_case("INVITE") {
        debug!(
            call_id = %internal_call_id,
            status = status_code,
            method = %cseq_method,
            "originate: absorbing a non-INVITE response on the originate branch"
        );
        return;
    }

    if (100..200).contains(&status_code) {
        // RFC 3261 §12.1.2: the first provisional with a To-tag opens the early
        // dialog; record its identity so a CANCEL/BYE has a target before answer.
        let remote_tag = crate::b2bua::actor::extract_to_tag(message);
        if let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) {
            // §12.1.2 sets the remote target once from the dialog-creating
            // response; a downstream fork puts several early dialogs on this one
            // branch, so later provisionals must not overwrite the first's
            // target. The confirming 2xx below refreshes both to the winner.
            if call.a_leg.dialog.remote_tag.is_none() {
                call.a_leg.dialog.remote_tag = remote_tag.clone();
            }
            if call.a_leg.dialog.remote_contact.is_none() {
                if let Some(contact) = message.headers.get("Contact") {
                    call.a_leg.dialog.remote_contact =
                        Some(crate::b2bua::actor::extract_contact_uri(contact));
                }
            }
        }
        let early_media = !message.body.is_empty();
        state
            .call_actors
            .set_state(internal_call_id, CallState::Ringing);
        let phase = if early_media { "progress" } else { "ringing" };
        control_notify_channel_event(
            &sip_call_id,
            "ChannelStateChange",
            serde_json::json!({
                "state": phase,
                "code": status_code,
                "early_media": early_media,
                "sdp": originate_body_text(message),
            }),
        );
        debug!(
            call_id = %internal_call_id,
            status = status_code,
            early_media,
            "originate: provisional"
        );
        return;
    }

    if (200..300).contains(&status_code) {
        // A retransmitted 200 (our ACK was lost) must be re-ACKed and nothing
        // else — the dialog is already confirmed and the controller has already
        // been told (RFC 3261 §13.2.2.4).
        if already_answered {
            originate_ack_2xx(&leg, message, None, state);
            return;
        }

        // Confirm the dialog from the 2xx (RFC 3261 §12.1.2).
        let remote_tag = crate::b2bua::actor::extract_to_tag(message);
        let remote_contact = message
            .headers
            .get("Contact")
            .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
        // §12.1.2: the UAC's route set is the Record-Route of the 2xx, reversed.
        let route_set: Vec<String> = message
            .headers
            .get_all("Record-Route")
            .map(|values| {
                values
                    .iter()
                    .flat_map(|value| value.split(','))
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .rev()
                    .collect()
            })
            .unwrap_or_default();

        // Anchor the media before the ACK is built: an offerless originate owes
        // the callee its answer *in* the ACK, so the engine round-trip has to
        // complete first. A failure is loud and terminal — a connected call with
        // no answer would be a call with no audio.
        let anchor_answer = match state.call_actors.originate_anchor(internal_call_id) {
            Some(anchor) => {
                match originate_anchor_2xx(
                    &sip_call_id,
                    remote_tag.as_deref().unwrap_or_default(),
                    message,
                    &anchor,
                    state,
                ) {
                    Ok(answer) => Some(answer),
                    Err(reason) => {
                        error!(
                            call_id = %internal_call_id,
                            %sip_call_id,
                            %reason,
                            "originate: media anchor failed on the callee's answer — ACK + BYE"
                        );
                        // ACK (the 2xx must be acknowledged either way, §13.2.2.4)
                        // then release the dialog we cannot carry audio for (§15).
                        originate_ack_2xx(&leg, message, None, state);
                        if let Some(tag) = remote_tag.clone() {
                            leg.dialog.remote_tag = Some(tag);
                        }
                        leg.dialog.remote_contact = remote_contact.clone();
                        leg.dialog.local_cseq = leg.dialog.local_cseq.saturating_add(1);
                        if let Some(bye) = build_b2bua_bye(&leg, state) {
                            send_b2bua_to_bleg(
                                bye,
                                leg.transport.transport,
                                leg.transport.remote_addr,
                                leg.transport.local_addr,
                                state,
                            );
                        }
                        control_notify_terminated_with_cause(
                            &sip_call_id,
                            "media_failed",
                            Some(status_code),
                            Some(&reason),
                        );
                        state.call_actors.remove_call(internal_call_id);
                        state.call_event_receivers.remove(internal_call_id);
                        return;
                    }
                }
            }
            None => None,
        };

        if let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) {
            call.a_leg.dialog.remote_tag = remote_tag.clone();
            if remote_contact.is_some() {
                call.a_leg.dialog.remote_contact = remote_contact.clone();
            }
            if !route_set.is_empty() {
                call.a_leg.dialog.route_set = route_set;
            }
            if !message.body.is_empty() {
                call.a_leg.last_sdp = Some(message.body.clone());
            }
            // The INVITE used CSeq 1; every later in-dialog request (BYE,
            // re-INVITE) must exceed it (RFC 3261 §12.2.1.1).
            call.a_leg.dialog.local_cseq = 2;
            leg = call.a_leg.clone();
        }
        originate_answered_session(internal_call_id, message, anchor_answer.as_deref(), state);
        state
            .call_actors
            .set_state(internal_call_id, CallState::Answered);
        originate_ack_2xx(&leg, message, anchor_answer.as_deref(), state);
        if crate::cdr::auto_emit_enabled() {
            cdr_mark_answer(state, internal_call_id, status_code);
        }
        control_notify_channel_event(
            &sip_call_id,
            "ChannelStateChange",
            serde_json::json!({
                "state": "answered",
                "code": status_code,
                "sdp": originate_body_text(message),
            }),
        );
        originate_fire_answer_handlers(internal_call_id, &leg, message, state);
        info!(call_id = %internal_call_id, %sip_call_id, status = status_code, "originate: answered");
        return;
    }

    // RFC 3261 §22: a trunk that challenges gets a credentialed re-INVITE,
    // provided this call has credentials — its own or the gateway's. Handled
    // here rather than through the B-leg's `retry_with_credentials`, because an
    // originated call has no B-leg: siphon is the UAC on its A-leg, which is
    // why this response path is separate in the first place.
    if retry_originate_with_credentials(internal_call_id, &leg, message, status_code, state) {
        return;
    }

    // Final non-2xx. RFC 3261 §17.1.1.3: the INVITE client transaction ACKs it
    // on the INVITE's own Via branch — without that the callee retransmits its
    // final on Timer G until Timer H.
    let reason_phrase = match &message.start_line {
        StartLine::Response(status_line) => status_line.reason_phrase.clone(),
        StartLine::Request(_) => String::new(),
    };
    let (via_host, via_port) =
        b_leg_sent_by(leg.transport.local_addr, state, &leg.transport.transport);
    let ack = build_b2bua_ack_for_non2xx(
        message,
        &leg.branch,
        leg.dialog.target_uri.as_deref(),
        leg.transport.transport,
        &via_host,
        via_port,
    );
    send_b2bua_to_bleg(
        ack,
        leg.transport.transport,
        leg.transport.remote_addr,
        leg.transport.local_addr,
        state,
    );

    // A copy of the rejection handled while the first is still concluding the
    // call (its @b2bua.on_failure runs without the lock) is owed the ACK above
    // and nothing more.
    if state.call_actors.claim_failure_conclusion(internal_call_id)
        == crate::b2bua::actor::FailureConclusion::AlreadyConcluding
    {
        debug!(
            call_id = %internal_call_id,
            status = status_code,
            "originate: absorbing a retransmitted rejection"
        );
        return;
    }
    warn!(
        call_id = %internal_call_id,
        %sip_call_id,
        status = status_code,
        "originate: rejected by the callee"
    );
    if crate::cdr::auto_emit_enabled() {
        cdr_finalize_b2bua_fail(state, internal_call_id, status_code);
    }
    run_originated_failure_handlers(internal_call_id, status_code, &reason_phrase, state);
    control_notify_terminated_with_cause(
        &sip_call_id,
        "rejected",
        Some(status_code),
        Some(&reason_phrase),
    );
    originate_delete_media(&sip_call_id, state);
    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
}

/// The credentials of the configured gateway an originate is aimed at, if any.
///
/// The originate twin of the stamp `b2bua_send_b_leg_invite` does for a dialled
/// leg, and matched the same way: by configured hostname, then by resolved
/// address.
fn originate_gateway_credentials(
    routing_uri: &str,
    destination: SocketAddr,
) -> Option<Arc<crate::auth::StoredCredentials>> {
    let manager = crate::script::api::gateway_manager()?;
    let (group, credentials) = gateway_credentials_for(manager, routing_uri, destination)?;
    debug!(
        %group,
        username = %credentials.username,
        "originate: this gateway's configured credentials will answer its challenges"
    );
    Some(credentials)
}

/// Answer a `401`/`407` on a call siphon placed itself with a credentialed
/// re-INVITE (RFC 3261 §22). Returns `true` when a retry went out, in which
/// case the caller must not treat the response as a failure.
///
/// The B-leg twin is `retry_with_credentials` in `response/failed.rs`. This is
/// a second implementation of the same rule rather than a shared one because an
/// originated call has no B-leg — it is a UAC on its own A-leg — so none of the
/// `BLegResponseSnapshot` the other path works from exists here. What is shared
/// is the order (ACK the non-2xx first, §17.1.1.3), the retry cap, and the
/// message builder.
///
/// Returning `false` falls through to the ordinary failure path, which ACKs and
/// reports — so an uncredentialed call, an unparseable challenge and an
/// exhausted retry budget all behave exactly as they did before.
fn retry_originate_with_credentials(
    internal_call_id: &str,
    leg: &Leg,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    if status_code != 401 && status_code != 407 {
        return false;
    }

    let Some(credentials) = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.outbound_credentials.clone())
    else {
        // No credentials: the challenge is the call's final answer, as before.
        return false;
    };

    // A trunk that rejects every fresh credentialed attempt (wrong password, or
    // a new nonce each time) would otherwise be re-authed for ever, since each
    // retry lands on a new branch and so never self-terminates.
    if state.call_actors.auth_retry_count(internal_call_id) >= MAX_B2BUA_AUTH_RETRIES {
        warn!(
            call_id = %internal_call_id,
            status = status_code,
            limit = MAX_B2BUA_AUTH_RETRIES,
            "originate: auth retry limit reached — failing the call instead of re-authing"
        );
        return false;
    }

    let challenge_header = if status_code == 401 {
        message.headers.get("WWW-Authenticate")
    } else {
        message.headers.get("Proxy-Authenticate")
    };
    let Some(challenge) = challenge_header.and_then(|value| crate::auth::parse_challenge(value))
    else {
        return false;
    };

    let Some(target_uri) = leg.dialog.target_uri.clone() else {
        return false;
    };
    let Some(stored_invite) = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.a_leg_invite.clone())
    else {
        return false;
    };
    let Ok(original) = stored_invite.lock().map(|invite| invite.clone()) else {
        return false;
    };

    // RFC 7616 §3.3: nc starts at 1 for a fresh nonce and increments on reuse.
    // The per-call counter resets itself when the nonce changes.
    let nc = state
        .call_actors
        .get_call(internal_call_id)
        .map(|call| call.digest_nc.next_for(&challenge.nonce))
        .unwrap_or(1);

    let auth_header_name = if status_code == 401 {
        "Authorization"
    } else {
        "Proxy-Authorization"
    };
    let auth_value = match crate::auth::format_stored_authorization_header(
        &challenge,
        &credentials.username,
        &credentials.secret,
        "INVITE",
        &target_uri,
        Some(nc),
        None,
    ) {
        Ok(value) => value,
        Err(mismatch) => {
            error!(
                call_id = %internal_call_id,
                status = status_code,
                realm = %challenge.realm,
                error = %mismatch,
                "originate: cannot answer the challenge with the stored credential"
            );
            return false;
        }
    };

    // ACK the challenge on its own branch before anything else (§17.1.1.3):
    // the callee's server transaction retransmits until it lands.
    let (via_host, via_port) =
        b_leg_sent_by(leg.transport.local_addr, state, &leg.transport.transport);
    let ack = build_b2bua_ack_for_non2xx(
        message,
        &leg.branch,
        Some(target_uri.as_str()),
        leg.transport.transport,
        &via_host,
        via_port,
    );
    send_b2bua_to_bleg(
        ack,
        leg.transport.transport,
        leg.transport.remote_addr,
        leg.transport.local_addr,
        state,
    );

    // A new transaction: new branch, next CSeq (§8.1.3.5).
    let branch = format!("z9hG4bK-{}", uuid::Uuid::new_v4().simple());
    let cseq = leg.dialog.local_cseq.saturating_add(1);
    let via = format!(
        "SIP/2.0/{} {}:{};branch={};rport",
        leg.transport.transport.to_string().to_uppercase(),
        via_host,
        via_port,
        branch
    );
    let retry = build_digest_retry_invite(&original, via, cseq, auth_header_name, auth_value);

    // Index the new branch before sending: on loopback the answer can arrive
    // before a post-send registration would finish, and an unindexed branch is
    // a response for an unknown call.
    state.call_actors.mark_originated(internal_call_id, &branch);
    if let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) {
        call.a_leg.branch = branch.clone();
        call.a_leg.dialog.local_cseq = cseq;
        call.a_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));
    }
    state.call_actors.incr_auth_retry_count(internal_call_id);

    info!(
        call_id = %internal_call_id,
        status = status_code,
        realm = %challenge.realm,
        nc = nc,
        "originate: {status_code} received, retrying with credentials"
    );
    send_b2bua_to_bleg(
        retry,
        leg.transport.transport,
        leg.transport.remote_addr,
        leg.transport.local_addr,
        state,
    );
    true
}

/// What the callee's 2xx settles on the dialog of a call siphon placed besides
/// the dialog itself: its RFC 4028 session timer (§7.2), and the session in force
/// on it. That is the SDP siphon sent the callee, under the `o=` it went out
/// with: the answer the ACK carries (`anchor_answer`), or else the INVITE's offer.
fn originate_answered_session(
    internal_call_id: &str,
    answer: &SipMessage,
    anchor_answer: Option<&str>,
    state: &DispatcherState,
) {
    let stored = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.a_leg_invite.clone());
    let invite = stored
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.clone()));
    negotiate_uac_answer_session_timer(
        internal_call_id,
        true,
        invite.as_ref().map(|invite| &invite.headers),
        &answer.headers,
        state,
    );
    match (anchor_answer, &invite) {
        (Some(sdp), _) => adopt_sdp_sent_to_leg(
            state,
            internal_call_id,
            true,
            "application/sdp",
            sdp.as_bytes(),
        ),
        (None, Some(invite)) => adopt_sdp_sent_to_leg(
            state,
            internal_call_id,
            true,
            message_content_type(invite),
            &invite.body,
        ),
        (None, None) => {}
    }
}

/// The response body as text, for a control event payload. `None` for an empty
/// or non-UTF-8 body — the rail is JSON text, so a binary body is reported by
/// its absence rather than mangled.
pub fn originate_body_text(message: &SipMessage) -> Option<String> {
    if message.body.is_empty() {
        return None;
    }
    std::str::from_utf8(&message.body).ok().map(str::to_string)
}

/// ACK a 2xx on an originated dialog (RFC 3261 §13.2.2.4), optionally carrying
/// the local media answer to an offer the callee made in that 2xx.
pub fn originate_ack_2xx(
    leg: &crate::b2bua::actor::Leg,
    response: &SipMessage,
    answer_sdp: Option<&str>,
    state: &DispatcherState,
) {
    let (via_host, via_port) =
        b_leg_sent_by(leg.transport.local_addr, state, &leg.transport.transport);
    let Some(mut ack) =
        build_b2bua_ack_for_2xx(response, leg.transport.transport, &via_host, via_port)
    else {
        return;
    };
    if let Some(sdp) = answer_sdp {
        ack.headers
            .set("Content-Type", "application/sdp".to_string());
        ack.body = sdp.as_bytes().to_vec();
        ack.headers
            .set("Content-Length", ack.body.len().to_string());
    }
    // The ACK carries the route set (built into it from the 2xx's Record-Route)
    // and so goes to its first hop, not the address the INVITE was dialled at
    // (RFC 3261 §12.2.1.1). A no-op when the callee's side does not record-route.
    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    send_b2bua_to_bleg(ack, transport, destination, leg.transport.local_addr, state);
}

/// Answer the callee's 2xx offer locally on the media backend and record the
/// media session under this leg's SIP Call-ID, so every media verb resolves
/// against it through [`b2bua_media_target`].
///
/// Returns the answer SDP for the ACK, or a short human reason on failure —
/// never a silent no-op, because an offerless INVITE with no answer is a
/// connected call with no audio.
pub fn originate_anchor_2xx(
    sip_call_id: &str,
    remote_tag: &str,
    response: &SipMessage,
    anchor: &crate::b2bua::actor::OriginateAnchor,
    state: &DispatcherState,
) -> Result<String, String> {
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or_else(|| "no media backend configured".to_string())?;
    let registry = state
        .rtpengine_profiles
        .as_ref()
        .ok_or_else(|| "no media profiles configured".to_string())?;
    let entry = registry
        .get(&anchor.profile)
        .ok_or_else(|| format!("unknown media profile '{}'", anchor.profile))?;
    let mut flags = entry.answer.clone();

    let offer_sdp = std::str::from_utf8(&response.body)
        .map_err(|_| "the callee's 2xx body is not valid UTF-8 SDP".to_string())?
        .to_string();
    if offer_sdp.trim().is_empty() {
        return Err("the callee answered with no SDP offer — nothing to anchor".to_string());
    }

    // ws_uri precedence: explicit per-call arg → the profile's own → none.
    let template = anchor.ws_uri.clone().or_else(|| flags.ws_uri.clone());
    if let Some(template) = template {
        let context = crate::script::api::rtpengine::WsUriContext {
            call_id: sip_call_id,
            from_tag: remote_tag,
            from_user: None,
            to_user: None,
        };
        flags.ws_uri = Some(
            crate::script::api::rtpengine::expand_ws_uri(&template, &context)
                .map_err(|error| format!("ws_uri templating failed: {error:?}"))?,
        );
    }
    let unsupported = backend.unsupported_flags(&flags);
    if !unsupported.is_empty() {
        return Err(format!(
            "media profile '{}' sets {} which the {} backend cannot honour",
            anchor.profile,
            unsupported.join(", "),
            backend.kind().as_str()
        ));
    }

    // The offerer here is the *callee* (it offered in its 2xx), so the engine's
    // monologue is keyed on the callee's tag — the same "key on the offerer's
    // tag" convention the inbound answer-first anchor uses.
    let answer = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer_local(
            sip_call_id,
            remote_tag,
            &offer_sdp,
            &flags,
        ))
    })
    .map_err(|error| format!("answer_local failed: {error}"))?;

    if let Some(sessions) = state.rtpengine_sessions.as_ref() {
        sessions.insert(crate::rtpengine::session::MediaSession {
            rtpengine_call_id: sip_call_id.to_string(),
            call_id: sip_call_id.to_string(),
            from_tag: remote_tag.to_string(),
            to_tag: None,
            profile: anchor.profile.clone(),
            ws_uri: flags.ws_uri.clone(),
            ws_tee: flags.ws_tee.clone(),
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
    }
    Ok(answer)
}

/// Drop any media session anchored for an originated call that failed before it
/// could be torn down the ordinary way.
pub fn originate_delete_media(sip_call_id: &str, state: &DispatcherState) {
    if let (Some(backend), Some(sessions)) = (&state.rtpengine_set, &state.rtpengine_sessions) {
        if let Some(session) = sessions.remove(sip_call_id) {
            let backend = Arc::clone(backend);
            tokio::spawn(async move {
                if let Err(error) = backend
                    .delete(session.rtpengine_id(), &session.from_tag)
                    .await
                {
                    if !error.is_call_not_found() {
                        warn!(call_id = %session.call_id, "originate: media delete failed: {error}");
                    }
                }
            });
        }
    }
}

/// Fire `@b2bua.on_answer(call, reply)` for an originated call, so an in-process
/// script driving `b2bua.originate()` sees the answer through the same handler
/// an inbound-driven call uses.
pub fn originate_fire_answer_handlers(
    internal_call_id: &str,
    leg: &crate::b2bua::actor::Leg,
    response: &SipMessage,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaAnswer);
    if handlers.is_empty() {
        return;
    }
    let Some(invite_arc) = state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.a_leg_invite.clone())
    else {
        return;
    };
    let response_arc = Arc::new(std::sync::Mutex::new(response.clone()));
    let py_call = PyCall::new(
        internal_call_id.to_string(),
        Arc::clone(&invite_arc),
        leg.transport.remote_addr.ip().to_string(),
        format!("{}", leg.transport.transport).to_lowercase(),
    );
    let py_reply = PyReply::new(Arc::clone(&response_arc)).with_a_leg(Arc::clone(&invite_arc));
    Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for originate on_answer: {error}");
                return;
            }
        };
        let reply_obj = match Py::new(python, py_reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply for originate on_answer: {error}");
                return;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                Ok(returned) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &returned) {
                            record_script_error("async originate on_answer", &error);
                        }
                    }
                }
                Err(error) => record_script_error("originate on_answer", &error),
            }
        }
    });
}

/// Abandon an originated call that has not been answered: CANCEL the INVITE
/// (RFC 3261 §9.1 — same Via branch and CSeq sequence as the request it
/// cancels), stop retransmitting it, emit `StasisEnd`, and tear the call down.
///
/// This is what `hangup` means on an un-answered leg siphon placed. The
/// inbound-call path answers its A-leg with a final non-2xx there, which is
/// exactly wrong here: siphon is the UAC, and sending a *response* to the party
/// it is calling is not a thing (RFC 3261 §8.1 — a UAC answers nothing).
/// Returns `false`, never panics, when the call is already gone.
pub fn b2bua_cancel_originated_call(sip_call_id: &str, reason: Option<&str>) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let state = &control.state;
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return false;
    };
    let _enter = control.runtime.enter();

    let staged = match state.call_actors.get_call(&internal_call_id) {
        Some(call) => call.a_leg_invite.clone().map(|invite| {
            (
                invite,
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.local_addr,
                call.a_leg.branch.clone(),
            )
        }),
        None => return false,
    };
    let Some((invite_arc, transport, destination, local_addr, branch)) = staged else {
        return false;
    };

    // Stop the INVITE's own retransmit schedule first: we are giving up on it,
    // and `arm_b2bua_retransmit` disarms it again when the CANCEL is armed —
    // this also covers a leg whose CANCEL cannot be built.
    state.b2bua_retransmits.disarm_branch(&branch);
    let cancel = match invite_arc.lock() {
        Ok(invite) => build_cancel_from_invite(&invite),
        Err(_) => {
            error!(call_id = %internal_call_id, "originate cancel: stored INVITE mutex poisoned");
            None
        }
    };
    if let Some(cancel) = cancel {
        send_b2bua_to_bleg(cancel, transport, destination, local_addr, state);
    }

    if crate::cdr::auto_emit_enabled() {
        cdr_finalize_b2bua_fail(state, &internal_call_id, 487);
    }
    // RFC 3261 §9.1: the callee answers a CANCELled INVITE `487 Request
    // Terminated`. We abandoned this leg before it was answered, so 487 is the
    // status that ends it — reported here because a controller driving a leg
    // siphon placed has no response frame of its own to read it off.
    control_notify_terminated_with_cause(
        sip_call_id,
        reason.unwrap_or("cancelled"),
        Some(487),
        Some("Request Terminated"),
    );
    // Keep the leg alive as a zombie so a 2xx that raced our CANCEL is still
    // ACKed + BYEd (RFC 3261 §9.1 glare) rather than left ringing on the callee.
    if state
        .call_actors
        .remove_call_after_cancel(&internal_call_id)
    {
        schedule_zombie_cancelled_cleanup(state.call_actors.clone());
    }
    state.call_event_receivers.remove(&internal_call_id);
    true
}
