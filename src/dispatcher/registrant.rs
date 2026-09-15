//! Responses to the outbound REGISTER client (`src/registrant/`): the
//! registrar's answer, and the IMS AKA challenge it may carry.
use super::*;

/// Extract the `expires=` parameter value from a Contact header value.
///
/// Skips URI parameters inside angle brackets so that only Contact-level
/// parameters (after the closing `>`) are considered.  Handles both
/// unquoted (`expires=3600`) and quoted (`expires="3600"`) forms.
pub(super) fn parse_contact_expires(contact: &str) -> Option<u32> {
    // If the Contact contains angle brackets, only look at params after '>'
    let params_part = if let Some(pos) = contact.find('>') {
        &contact[pos + 1..]
    } else {
        contact
    };
    params_part.split(';').find_map(|param| {
        let param = param.trim();
        param
            .strip_prefix("expires=")
            .and_then(|value| value.trim().trim_matches('"').parse::<u32>().ok())
    })
}

/// Handle a response to an outbound registration (z9hG4bK-reg- branch).
pub(super) fn handle_registrant_response(
    registrant: &Arc<crate::registrant::RegistrantManager>,
    message: &SipMessage,
    status_code: u16,
    _branch: &str,
    state: &DispatcherState,
) {
    // Match response to a registration entry by Call-ID
    let call_id = match message.headers.get("Call-ID") {
        Some(cid) => cid.clone(),
        None => {
            warn!("registrant response has no Call-ID");
            return;
        }
    };

    let aor = match registrant.find_by_call_id(&call_id) {
        Some(aor) => aor,
        None => {
            debug!(call_id = %call_id, "registrant response: no matching entry");
            return;
        }
    };

    let is_aka = registrant.auth_mode(&aor) == Some(crate::registrant::AuthMode::Aka);

    // A carrier / Teams Direct Routing registrar that rejects with a Retry-After
    // (RFC 3261 §20.33) is telling us exactly when to re-REGISTER — thread it
    // into the failure handler so it schedules the next attempt at that cooldown
    // instead of the local exponential backoff.
    let retry_after = crate::sip::headers::retry_after::parse_retry_after(&message.headers);

    match status_code {
        200 => {
            // Parse granted expires: top-level Expires header first,
            // then Contact expires= parameter (RFC 3261 §10.2.4),
            // finally fall back to the originally requested value.
            let expires = message
                .headers
                .get("Expires")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .or_else(|| {
                    message
                        .headers
                        .get("Contact")
                        .and_then(|contact| parse_contact_expires(contact))
                })
                .unwrap_or(registrant.default_interval);

            // IMS: capture the Service-Route / P-Associated-URI / Path the
            // S-CSCF granted, for MO call routing and implicit-set resolution
            // (Phase 3). Only for AKA entries so the carrier-trunk path is
            // byte-identical.
            if is_aka {
                registrant.store_registration_routes(
                    &aor,
                    collect_route_set(message, "Service-Route"),
                    collect_route_set(message, "P-Associated-URI"),
                    collect_route_set(message, "Path"),
                );
            }

            // IPsec: tighten the kernel SA hard-lifetime from the placeholder
            // installed on the 401 path down to the registrar's granted Expires
            // (+ RFC 3261 Timer F grace), so the SAs track the registration
            // lifetime (TS 33.203 §7.4).
            if is_aka && registrant.is_ipsec_entry(&aor) {
                if let (Some(ipsec_manager), Some(ue_port_c)) = (
                    state.ipsec_manager.clone(),
                    registrant.ue_protected_client_port(&aor),
                ) {
                    let ue_addr = state.local_addr.ip();
                    let hard_lifetime = (expires as u64) + 32;
                    tokio::spawn(async move {
                        if let Err(error) = ipsec_manager
                            .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(hard_lifetime))
                            .await
                        {
                            warn!(%error, "IPsec UE: failed to tighten SA lifetime");
                        }
                    });
                }
            }

            registrant.handle_success(&aor, expires);
        }
        401 | 407 => {
            // Parse challenge header
            let header_name = if status_code == 401 {
                "WWW-Authenticate"
            } else {
                "Proxy-Authenticate"
            };

            let challenge_raw = match message.headers.get(header_name) {
                Some(raw) => raw.clone(),
                None => {
                    warn!(aor = %aor, status_code, "registrant: {status_code} without {header_name}");
                    registrant.handle_failure(&aor, status_code, retry_after);
                    return;
                }
            };

            if let Some(challenge) = crate::auth::parse_challenge(&challenge_raw) {
                // IMS AKA + IPsec sec-agree: parse the P-CSCF's Security-Server,
                // build the protected re-REGISTER (which stashes CK/IK), install
                // the UE SAs, then send over the SA. The install MUST precede the
                // send so the kernel encrypts the protected REGISTER — both run
                // ordered inside one spawned task (TS 33.203 §7.4).
                if is_aka && registrant.is_ipsec_entry(&aor) {
                    handle_registrant_ipsec_challenge(
                        registrant,
                        message,
                        &aor,
                        &challenge,
                        status_code,
                        retry_after,
                        state,
                    );
                    return;
                }

                // IMS AKA entries run Milenage over the RAND/AUTN in the nonce;
                // carrier-trunk entries use password digest. The IMS challenge
                // always arrives as a 401 (WWW-Authenticate).
                let built = if is_aka {
                    registrant.build_register_aka(
                        &aor,
                        state.local_addr,
                        &state.listen_addrs,
                        &challenge,
                        registrant.default_interval,
                        None,
                    )
                } else {
                    registrant.build_register_with_auth(
                        &aor,
                        state.local_addr,
                        &state.listen_addrs,
                        &challenge,
                        status_code == 407,
                        registrant.default_interval,
                    )
                };

                if let Some((retry_message, _retry_branch, destination, transport)) = built {
                    let data = bytes::Bytes::from(retry_message.to_bytes());
                    send_outbound(
                        data,
                        transport,
                        destination,
                        crate::transport::ConnectionId::default(),
                        state,
                    );
                } else {
                    registrant.handle_failure(&aor, status_code, retry_after);
                }
            } else {
                warn!(aor = %aor, "failed to parse digest challenge from {header_name}");
                registrant.handle_failure(&aor, status_code, retry_after);
            }
        }
        _ => {
            registrant.handle_failure(&aor, status_code, retry_after);
        }
    }
}

/// Handle a 401 challenge for an IPsec sec-agree (UE) registration.
///
/// Records the P-CSCF's Security-Server answer, builds the protected
/// re-REGISTER (which stashes CK/IK on the entry), then installs the four UE
/// SAs and sends the REGISTER over them. The SA install and the send run
/// ordered inside one spawned task so the kernel encrypts the protected
/// REGISTER (3GPP TS 33.203 §7.4) — sourced from the UE protected client port
/// so the outbound XFRM selector matches.
pub(super) fn handle_registrant_ipsec_challenge(
    registrant: &Arc<crate::registrant::RegistrantManager>,
    message: &SipMessage,
    aor: &str,
    challenge: &crate::auth::DigestChallenge,
    status_code: u16,
    retry_after: Option<std::time::Duration>,
    state: &DispatcherState,
) {
    match message.headers.get("Security-Server").cloned() {
        Some(server_raw) => match crate::ipsec::parse_security_client(&server_raw) {
            Some(server) => registrant.store_security_server(aor, &server, &server_raw),
            None => {
                warn!(aor = %aor, "IPsec UE: unparseable Security-Server, failing registration");
                registrant.handle_failure(aor, status_code, retry_after);
                return;
            }
        },
        None => {
            warn!(aor = %aor, "IPsec UE: 401 without Security-Server, failing registration");
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    }

    // build_register_aka stashes CK/IK and targets the P-CSCF protected server
    // port; the Security-Verify echoes the Security-Server recorded above.
    let verify = registrant.security_server_value(aor);
    let built = registrant.build_register_aka(
        aor,
        state.local_addr,
        &state.listen_addrs,
        challenge,
        registrant.default_interval,
        verify.as_deref(),
    );
    let (retry_message, destination, transport) = match built {
        Some((retry_message, _branch, destination, transport)) => {
            (retry_message, destination, transport)
        }
        None => {
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    };

    let ue_addr = state.local_addr.ip();
    let pcscf_addr = destination.ip();
    let ue_port_c = registrant.ue_protected_client_port(aor).unwrap_or(0);
    // Placeholder lifetime; tightened to the granted Expires on the 200 OK.
    let sa = registrant.ue_sa_pair(
        aor,
        ue_addr,
        pcscf_addr,
        Some(registrant.default_interval as u64),
        crate::ipsec::SaProtocol::Any,
    );

    let ipsec_manager = match state.ipsec_manager.clone() {
        Some(manager) => manager,
        None => {
            warn!(aor = %aor, "IPsec UE: no IpsecManager configured, failing registration");
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    };

    let source = std::net::SocketAddr::new(ue_addr, ue_port_c);
    let data = bytes::Bytes::from(retry_message.to_bytes());
    let outbound = state.outbound.clone();
    // Sent from the task below, past `send_outbound_from`'s capture.
    let capture = TaskCapture::for_task(state, transport, Some(source));
    let registrant_task = Arc::clone(registrant);
    let aor_task = aor.to_string();

    tokio::spawn(async move {
        let sa = match sa {
            Some(sa) => sa,
            None => {
                warn!(aor = %aor_task, "IPsec UE: missing CK/IK or Security-Server, protected REGISTER not sent");
                registrant_task.handle_failure(&aor_task, 0, None);
                return;
            }
        };
        // Re-REGISTER rekey: tear down any prior SA pair on the same UE
        // protected client port before installing the new one. The UE keeps
        // fixed protected ports, so old and new cannot overlap (their XFRM
        // policy selectors would collide) — delete-before-install avoids the
        // collision and the leak; no-op on the first registration. (Full
        // TS 33.203 §6.3 old/new overlap would need fresh ports per
        // registration, i.e. runtime listener binding.)
        let _ = ipsec_manager.delete_sa_pair(&ue_addr, ue_port_c).await;
        if let Err(error) = ipsec_manager.create_ue_sa_pair(sa).await {
            warn!(aor = %aor_task, %error, "IPsec UE: SA install failed, protected REGISTER not sent");
            registrant_task.handle_failure(&aor_task, 0, None);
            return;
        }
        if let Some(capture) = &capture {
            capture.capture(destination, transport, &data);
        }
        let outbound_message = crate::transport::OutboundMessage {
            followups: None,
            connection_id: crate::transport::ConnectionId::default(),
            transport,
            destination,
            data,
            source_local_addr: Some(source),
            server_name: None,
        };
        if let Err(error) = outbound.send(outbound_message) {
            warn!(aor = %aor_task, %error, "IPsec UE: failed to send protected REGISTER");
        }
    });
}

/// Expand a route-set header (Service-Route, P-Associated-URI, Path) into its
/// individual values: each header line plus any comma-folded values within it,
/// splitting only on top-level commas (not inside `<...>` or quotes).
pub(super) fn collect_route_set(message: &SipMessage, header_name: &str) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(lines) = message.headers.get_all(header_name) {
        for line in lines {
            let mut start = 0;
            let mut depth = 0i32;
            let mut in_quotes = false;
            for (index, byte) in line.bytes().enumerate() {
                match byte {
                    b'"' => in_quotes = !in_quotes,
                    b'<' if !in_quotes => depth += 1,
                    b'>' if !in_quotes => depth -= 1,
                    b',' if !in_quotes && depth == 0 => {
                        let part = line[start..index].trim();
                        if !part.is_empty() {
                            values.push(part.to_string());
                        }
                        start = index + 1;
                    }
                    _ => {}
                }
            }
            let tail = line[start..].trim();
            if !tail.is_empty() {
                values.push(tail.to_string());
            }
        }
    }
    values
}
