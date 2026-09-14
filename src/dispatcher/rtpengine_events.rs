//! The media backend's asynchronous event stream.

use super::*;

/// Drain the media backend's asynchronous event stream — DTMF, the
/// WebSocket tee's lifecycle, a call the engine tore down on its own — and
/// dispatch each to the script handlers and the control plane.
pub fn spawn_rtpengine_events(
    state: &Arc<DispatcherState>,
    rtpengine_events_rx: tokio::sync::mpsc::Receiver<crate::rtpengine::events::RtpEngineEvent>,
) {
    // Spawn background task: rtpengine async events (DTMF, etc.)
    {
        let mut events_rx = rtpengine_events_rx;
        let state_for_events = Arc::clone(state);
        tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                match event {
                    crate::rtpengine::events::RtpEngineEvent::Dtmf(dtmf) => {
                        on_dtmf(&state_for_events, dtmf).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::MediaTimeout {
                        call_id,
                        from_tag,
                    } => {
                        on_media_timeout(&state_for_events, call_id, from_tag).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::CallSummary(summary) => {
                        on_call_summary(&state_for_events, summary).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::Text(text_event) => {
                        on_text(&state_for_events, text_event).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::WsTeeStarted(tee) => {
                        on_ws_tee_started(&state_for_events, tee).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::PlayFinished(play) => {
                        on_play_finished(&state_for_events, play).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::WsBridgeStarted(bridge) => {
                        on_ws_bridge_started(&state_for_events, bridge).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::WsBridgeEnded(bridge) => {
                        on_ws_bridge_ended(&state_for_events, bridge).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::WsTeeEnded(tee) => {
                        on_ws_tee_ended(&state_for_events, tee).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::BeepDetected(beep) => {
                        on_beep_detected(&state_for_events, beep).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::X3Started(started) => {
                        on_x3_started(&state_for_events, started).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::X3Loss(loss) => {
                        on_x3_loss(&state_for_events, loss).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::X3Ended(ended) => {
                        on_x3_ended(&state_for_events, ended).await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::Unknown {
                        event, call_id, ..
                    } => {
                        tracing::debug!(
                            %event,
                            ?call_id,
                            "unhandled rtpengine event"
                        );
                    }
                }
            }
        });
    }
}

/// Fan one DTMF digit out to the control plane and the script handlers.
///
/// Shared with the SIP INFO path (RFC 6086 `application/dtmf-relay`), so a
/// digit reaches a handler the same way whichever wire carried it — a script
/// reading `@rtpengine.on_dtmf` should not have to know.
pub async fn dispatch_dtmf_event(
    state: Arc<DispatcherState>,
    dtmf: crate::rtpengine::events::DtmfEvent,
) {
    on_dtmf(&state, dtmf).await
}

async fn on_dtmf(state: &Arc<DispatcherState>, dtmf: crate::rtpengine::events::DtmfEvent) {
    // Additive control-plane forward: a controlled channel
    // gets the digit as a ChannelDtmfReceived event too, so an
    // external IVR / AI app collects digits from the event
    // stream. Runs before the Python-handler short-circuit so
    // it fires whether or not @rtpengine.on_dtmf is registered.
    control_forward_dtmf(&dtmf);

    let engine_state = state.engine.state();
    let handlers = engine_state.dtmf_handlers(&dtmf.call_id, &dtmf.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let dtmf_clone = dtmf.clone();
    run_event_handler("rtpengine.on_dtmf", move || {
        let engine_state = state_ref.engine.state();
        let handlers = engine_state.dtmf_handlers(&dtmf_clone.call_id, &dtmf_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    dtmf_clone.call_id.as_str(),
                    dtmf_clone.from_tag.as_str(),
                    dtmf_clone.digit.as_str(),
                    dtmf_clone.duration_ms,
                    dtmf_clone.volume,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_dtmf handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_dtmf handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_media_timeout(state: &Arc<DispatcherState>, call_id: String, from_tag: String) {
    // The media engine owns the call and reaped it on timeout
    // (the reaper removes the call *before* emitting this
    // event), so drop our own per-call media bookkeeping now.
    // The teardown that any @rtpengine.on_media_timeout handler
    // drives (e.g. b2bua.terminate) then finds no record and
    // issues no safety-net delete against a call the engine
    // already dropped — no wasted round-trip, no "unknown call".
    clear_media_session_on_timeout(state.rtpengine_sessions.as_ref(), &call_id);
    // The media engine tore down a dead-path call. Log it for
    // visibility regardless of whether a script handles it,
    // then invoke any @rtpengine.on_media_timeout handlers so
    // the script can release the per-call state no BYE will
    // now clear (Rx/N5 QoS, charging, dialog).
    tracing::warn!(
        %call_id,
        %from_tag,
        "media engine reported media timeout (engine tore down call)"
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.media_timeout_handlers(&call_id, &from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let call_id_clone = call_id.clone();
    let from_tag_clone = from_tag.clone();
    run_event_handler("rtpengine.on_media_timeout", move || {
        let engine_state = state_ref.engine.state();
        let handlers = engine_state.media_timeout_handlers(&call_id_clone, &from_tag_clone);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((call_id_clone.as_str(), from_tag_clone.as_str()));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_media_timeout handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_media_timeout handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_call_summary(
    _state: &Arc<DispatcherState>,
    summary: crate::rtpengine::events::CallSummary,
) {
    // The media engine reports the end-of-call byte/packet
    // counters and (when a userspace actor measured them) the
    // RFC 3550 loss/jitter + ITU-T G.107 MOS shape. Write a
    // media CDR keyed on the SIP Call-ID so a collector joins
    // it to the SIP-side CDR — the structured twin of the
    // engine's `siphon_rtp::cdr` log, no log scraping. Gated
    // on auto-emit, same as the proxy/b2bua lifecycle CDRs.
    tracing::debug!(
        call_id = %summary.call_id,
        reason = %summary.reason,
        legs = summary.legs.len(),
        "media engine reported end-of-call summary"
    );
    if crate::cdr::auto_emit_enabled() {
        crate::cdr::write(media_summary_to_cdr(&summary));
    }
}

async fn on_text(state: &Arc<DispatcherState>, text_event: crate::rtpengine::events::TextEvent) {
    tracing::debug!(
        call_id = %text_event.call_id,
        from_tag = %text_event.from_tag,
        direction = text_event.direction.as_deref().unwrap_or("-"),
        characters = text_event.text.chars().count(),
        "media engine recovered a real-time text increment"
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.text_handlers(&text_event.call_id, &text_event.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let text_clone = text_event.clone();
    run_event_handler("rtpengine.on_text", move || {
        let engine_state = state_ref.engine.state();
        let handlers = engine_state.text_handlers(&text_clone.call_id, &text_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    text_clone.call_id.as_str(),
                    text_clone.from_tag.as_str(),
                    text_clone.to_tag.as_deref(),
                    text_clone.text.as_str(),
                    text_clone.direction.as_deref(),
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_text handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_text handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_ws_tee_started(
    state: &Arc<DispatcherState>,
    tee: crate::rtpengine::events::WsTeeStarted,
) {
    tracing::debug!(
        call_id = %tee.call_id,
        from_tag = %tee.from_tag,
        stream_id = %tee.stream_id,
        ws_uri = %tee.ws_uri,
        direction = %tee.direction.as_str(),
        channels = tee.channels,
        sample_rate = tee.sample_rate,
        "media engine started a websocket tee"
    );
    // Same rail as the bridge's lifecycle: a controller
    // that started this stream over the control plane has
    // no other way to learn its shape or that it died.
    crate::control::notify_channel_event(
        &tee.call_id,
        "WsTeeStarted",
        serde_json::json!({
            "from_tag": tee.from_tag,
            "stream_id": tee.stream_id,
            "ws_uri": tee.ws_uri,
            "direction": tee.direction.as_str(),
            "channels": tee.channels,
            "sample_rate": tee.sample_rate,
        }),
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.ws_tee_started_handlers(&tee.call_id, &tee.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let tee_clone = tee.clone();
    run_event_handler("rtpengine.on_ws_tee_started", move || {
        let engine_state = state_ref.engine.state();
        let handlers =
            engine_state.ws_tee_started_handlers(&tee_clone.call_id, &tee_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    tee_clone.call_id.as_str(),
                    tee_clone.from_tag.as_str(),
                    tee_clone.stream_id.as_str(),
                    tee_clone.ws_uri.as_str(),
                    tee_clone.direction.as_str(),
                    tee_clone.channels,
                    tee_clone.sample_rate,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_ws_tee_started handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_ws_tee_started handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_play_finished(
    state: &Arc<DispatcherState>,
    play: crate::rtpengine::events::PlayFinishedEvent,
) {
    tracing::debug!(
        call_id = %play.call_id,
        from_tag = %play.from_tag,
        play_id = play.play_id,
        reason = %play.reason.as_str(),
        played_ms = ?play.played_ms,
        "media engine finished a playback"
    );
    crate::control::notify_channel_event(
        &play.call_id,
        "PlayFinished",
        serde_json::json!({
            "from_tag": play.from_tag,
            "to_tag": play.to_tag,
            // Correlates with the play_id the accept and the
            // PlayStarted event both carry.
            "play_id": play.play_id,
            "reason": play.reason.as_str(),
            // Only `completed` means the prompt was heard in
            // full — a stop, a supersede and an error all end
            // a playback without that being true, and an app
            // queueing its next step needs the difference.
            "completed": play.reason.is_completed(),
            "played_ms": play.played_ms,
        }),
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.play_finished_handlers(&play.call_id, &play.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let play_clone = play.clone();
    run_event_handler("rtpengine.on_play_finished", move || {
        let engine_state = state_ref.engine.state();
        let handlers =
            engine_state.play_finished_handlers(&play_clone.call_id, &play_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    play_clone.call_id.as_str(),
                    play_clone.from_tag.as_str(),
                    play_clone.play_id,
                    play_clone.reason.as_str(),
                    play_clone.played_ms,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_play_finished handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_play_finished handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_ws_bridge_started(
    state: &Arc<DispatcherState>,
    bridge: crate::rtpengine::events::WsBridgeStarted,
) {
    tracing::debug!(
        call_id = %bridge.call_id,
        from_tag = %bridge.from_tag,
        stream_id = %bridge.stream_id,
        ws_uri = %bridge.ws_uri,
        sample_rate = bridge.sample_rate,
        "media engine started a websocket takeover bridge"
    );
    // The media session is keyed on the leg's SIP Call-ID,
    // which is what the control rail addresses channels by.
    crate::control::notify_channel_event(
        &bridge.call_id,
        "WsBridgeStarted",
        serde_json::json!({
            "from_tag": bridge.from_tag,
            "stream_id": bridge.stream_id,
            "ws_uri": bridge.ws_uri,
            "sample_rate": bridge.sample_rate,
        }),
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.ws_bridge_started_handlers(&bridge.call_id, &bridge.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let bridge_clone = bridge.clone();
    run_event_handler("rtpengine.on_ws_bridge_started", move || {
        let engine_state = state_ref.engine.state();
        let handlers =
            engine_state.ws_bridge_started_handlers(&bridge_clone.call_id, &bridge_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    bridge_clone.call_id.as_str(),
                    bridge_clone.from_tag.as_str(),
                    bridge_clone.stream_id.as_str(),
                    bridge_clone.ws_uri.as_str(),
                    bridge_clone.sample_rate,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_ws_bridge_started handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_ws_bridge_started handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_ws_bridge_ended(
    state: &Arc<DispatcherState>,
    bridge: crate::rtpengine::events::WsBridgeEnded,
) {
    // A bridge that ends for anything other than an explicit
    // detach or re-point leaves a *live call with no far
    // side* — worse than the tee case, where the call itself
    // was never in the streaming path.  WARN even with no
    // handler registered, so it is visible rather than
    // inferred from both parties going silent.
    if bridge.reason.is_unexpected() {
        tracing::warn!(
            call_id = %bridge.call_id,
            from_tag = %bridge.from_tag,
            stream_id = %bridge.stream_id,
            reason = %bridge.reason.as_str(),
            "websocket takeover bridge ended unexpectedly (call still up, no media far side)"
        );
    } else {
        tracing::debug!(
            call_id = %bridge.call_id,
            from_tag = %bridge.from_tag,
            stream_id = %bridge.stream_id,
            reason = %bridge.reason.as_str(),
            "websocket takeover bridge ended"
        );
    }
    crate::control::notify_channel_event(
        &bridge.call_id,
        "WsBridgeEnded",
        serde_json::json!({
            "from_tag": bridge.from_tag,
            "stream_id": bridge.stream_id,
            "reason": bridge.reason.as_str(),
            // Only `detached` is orderly. A controller that
            // branches on nothing else still has to be able
            // to see that this one needs acting on.
            "unexpected": bridge.reason.is_unexpected(),
        }),
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.ws_bridge_ended_handlers(&bridge.call_id, &bridge.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let bridge_clone = bridge.clone();
    run_event_handler("rtpengine.on_ws_bridge_ended", move || {
        let engine_state = state_ref.engine.state();
        let handlers =
            engine_state.ws_bridge_ended_handlers(&bridge_clone.call_id, &bridge_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    bridge_clone.call_id.as_str(),
                    bridge_clone.from_tag.as_str(),
                    bridge_clone.stream_id.as_str(),
                    bridge_clone.reason.as_str(),
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_ws_bridge_ended handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_ws_bridge_ended handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_ws_tee_ended(state: &Arc<DispatcherState>, tee: crate::rtpengine::events::WsTeeEnded) {
    // A tee that ends for anything other than an explicit
    // detach means audio stopped reaching the consumer while
    // the call is still up — the AI backend went away and the
    // caller is now talking to nothing.  Log that at WARN even
    // when no handler is registered, so it is visible rather
    // than inferred from missing audio.
    if tee.reason.is_unexpected() {
        tracing::warn!(
            call_id = %tee.call_id,
            from_tag = %tee.from_tag,
            stream_id = %tee.stream_id,
            reason = %tee.reason.as_str(),
            frames_sent = ?tee.frames_sent,
            frames_dropped = ?tee.frames_dropped,
            "websocket tee ended unexpectedly (call still up, audio no longer streaming)"
        );
    } else {
        tracing::debug!(
            call_id = %tee.call_id,
            from_tag = %tee.from_tag,
            stream_id = %tee.stream_id,
            reason = %tee.reason.as_str(),
            frames_sent = ?tee.frames_sent,
            frames_dropped = ?tee.frames_dropped,
            "websocket tee ended"
        );
    }
    crate::control::notify_channel_event(
        &tee.call_id,
        "WsTeeEnded",
        serde_json::json!({
            "from_tag": tee.from_tag,
            "stream_id": tee.stream_id,
            "reason": tee.reason.as_str(),
            // `detached` is the only orderly end; anything
            // else means audio stopped reaching the
            // consumer while the call carried on.
            "unexpected": tee.reason.is_unexpected(),
            // Non-zero means the consumer could not keep
            // up. The call was never affected — this is the
            // one number that tells a controller its own
            // side is the bottleneck.
            "frames_sent": tee.frames_sent,
            "frames_dropped": tee.frames_dropped,
        }),
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.ws_tee_ended_handlers(&tee.call_id, &tee.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let tee_clone = tee.clone();
    run_event_handler("rtpengine.on_ws_tee_ended", move || {
        let engine_state = state_ref.engine.state();
        let handlers = engine_state.ws_tee_ended_handlers(&tee_clone.call_id, &tee_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    tee_clone.call_id.as_str(),
                    tee_clone.from_tag.as_str(),
                    tee_clone.stream_id.as_str(),
                    tee_clone.reason.as_str(),
                    tee_clone.frames_sent,
                    tee_clone.frames_dropped,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_ws_tee_ended handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_ws_tee_ended handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_beep_detected(
    state: &Arc<DispatcherState>,
    beep: crate::rtpengine::events::BeepDetectedEvent,
) {
    tracing::debug!(
        call_id = %beep.call_id,
        from_tag = %beep.from_tag,
        frequency_hz = beep.frequency_hz,
        duration_ms = beep.duration_ms,
        offset_ms = beep.offset_ms,
        "media engine detected a record tone"
    );
    let engine_state = state.engine.state();
    let handlers = engine_state.beep_handlers(&beep.call_id, &beep.from_tag);
    if handlers.is_empty() {
        return;
    }
    let state_ref = Arc::clone(state);
    let beep_clone = beep.clone();
    run_event_handler("rtpengine.on_beep", move || {
        let engine_state = state_ref.engine.state();
        let handlers = engine_state.beep_handlers(&beep_clone.call_id, &beep_clone.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = callable.call1((
                    beep_clone.call_id.as_str(),
                    beep_clone.from_tag.as_str(),
                    beep_clone.to_tag.as_deref(),
                    beep_clone.frequency_hz,
                    beep_clone.duration_ms,
                    beep_clone.offset_ms,
                ));
                match result {
                    Ok(ret) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                tracing::error!(
                                    %error,
                                    "async rtpengine.on_beep handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "rtpengine.on_beep handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

async fn on_x3_started(
    _state: &Arc<DispatcherState>,
    started: crate::rtpengine::events::X3StartedEvent,
) {
    info!(
        call_id = %started.call_id,
        delivery = %started.delivery,
        correlation_id = started.correlation_id,
        "X3 content delivery started"
    );
}

async fn on_x3_loss(state: &Arc<DispatcherState>, loss: crate::rtpengine::events::X3LossEvent) {
    // Warranted content did not reach the agency. This is a
    // reportable compliance failure, not a degraded
    // recording, so it goes to the ADMF as a
    // destination-level report and not only to the log.
    error!(
        call_id = %loss.call_id,
        dropped = loss.dropped,
        delivered = loss.delivered,
        dropped_since_ms = loss.dropped_since_ms,
        "X3 content was DROPPED rather than delivered — warranted \
         content did not reach the agency"
    );
    if let Some(li) = state.li_manager.as_ref() {
        for attachment in li.x3_attachments_for(&loss.call_id) {
            let li = li.clone();
            let detail = format!(
                "X3 delivery loss on task {}: {} packet(s) dropped, {} \
             delivered, gap began {} ms into the interception",
                attachment.x_id, loss.dropped, loss.delivered, loss.dropped_since_ms
            );
            let d_id = attachment.d_id;
            tokio::spawn(async move {
                report_destination_fault(
                    &li,
                    d_id,
                    crate::li::x1::types::TaskReportType::NonTerminatingFault,
                    detail,
                )
                .await;
            });
        }
    }
}

async fn on_x3_ended(state: &Arc<DispatcherState>, ended: crate::rtpengine::events::X3EndedEvent) {
    // An orderly end is our own detach. Anything else means
    // delivery stopped for a reason the ADMF should hear,
    // and any drop at all means content was lost.
    if ended.orderly && ended.dropped == 0 {
        info!(
            call_id = %ended.call_id,
            delivered = ended.delivered,
            "X3 content delivery ended cleanly"
        );
    } else {
        error!(
            call_id = %ended.call_id,
            reason = %ended.reason,
            delivered = ended.delivered,
            dropped = ended.dropped,
            "X3 content delivery ended without a clean detach or with \
             dropped content"
        );
    }
    if let Some(li) = state.li_manager.as_ref() {
        // The engine has stopped; drop our record either
        // way so the map does not grow across calls.
        let attachments = if ended.orderly && ended.dropped == 0 {
            li.take_x3_attachments(&ended.call_id)
        } else {
            li.x3_attachments_for(&ended.call_id)
        };
        if !(ended.orderly && ended.dropped == 0) {
            for attachment in attachments {
                let li = li.clone();
                let detail = format!(
                    "X3 delivery ended for task {} ({}): {} delivered, {} \
                 dropped",
                    attachment.x_id, ended.reason, ended.delivered, ended.dropped
                );
                let d_id = attachment.d_id;
                tokio::spawn(async move {
                    report_destination_fault(
                        &li,
                        d_id,
                        crate::li::x1::types::TaskReportType::TerminatingFault,
                        detail,
                    )
                    .await;
                });
            }
            li.take_x3_attachments(&ended.call_id);
        }
    }
}
