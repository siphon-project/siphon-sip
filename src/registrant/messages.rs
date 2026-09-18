//! Building the REGISTER requests an outbound registration sends.
//!
//! Split out of [`super`] rather than living beside the manager's state because
//! it is a distinct job: the manager decides *when* a REGISTER goes out and what
//! happens to the answer, while this decides what the message looks like —
//! digest, IMS AKA (RFC 3310) and IPsec sec-agree (3GPP TS 33.203) included.
//!
//! An `impl RegistrantManager` block in a child module, so it keeps full access
//! to the manager's private state and every call site is unchanged.

use super::*;

impl RegistrantManager {
    /// Build a REGISTER request for an entry.
    ///
    /// `listen_addrs` maps each transport to its listen address. The entry's
    /// transport is used to pick the correct local address (and port) for the
    /// Contact and Via headers. Falls back to `local_addr` when no
    /// transport-specific address is configured.
    pub fn build_register(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(&entry.credentials.username, effective_addr, entry.transport)
        });

        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!("<{}>;tag=reg-{}", entry.aor, cseq))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header(
                "Contact",
                build_contact_header(&contact, entry.ims_contact.as_ref()),
            )
            .header("Expires", expires.to_string())
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        // IMS AKA: the initial (unprotected) REGISTER carries an Authorization
        // header with an empty response so the S-CSCF learns the IMPI and
        // fetches an authentication vector — the 401 challenge then comes back
        // through build_register_aka (RFC 3310 / TS 24.229 §5.1.1.2).
        if entry.auth_mode == AuthMode::Aka {
            let realm = entry
                .credentials
                .realm
                .clone()
                .unwrap_or_else(|| home_domain_from_aor(&entry.aor));
            let registrar_host = entry
                .registrar_uri
                .strip_prefix("sip:")
                .unwrap_or(&entry.registrar_uri);
            let digest_uri = format!("sip:{registrar_host}");
            builder = builder.header(
                "Authorization",
                initial_aka_authorization(&entry.credentials.username, &realm, &digest_uri),
            );
        }

        // IMS IPsec sec-agree: the initial (unprotected) REGISTER offers the
        // UE's transform, freshly allocated SPIs, and protected ports in
        // Security-Client, and demands the extension via Require/Proxy-Require
        // (RFC 3329 / TS 33.203 §7.2). The 401 answers with Security-Server.
        // Deregistration (expires == 0) rides the existing SA and does not
        // re-offer.
        if expires > 0 && entry.ue_ipsec.is_some() {
            let (spi_uc, spi_us) = self.allocate_ue_spi_pair();
            if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                ipsec.spi_uc = spi_uc;
                ipsec.spi_us = spi_us;
                let security_client = build_security_client(&ipsec.offer());
                builder = builder
                    .header("Security-Client", security_client)
                    .header("Require", "sec-agree".to_string())
                    .header("Proxy-Require", "sec-agree".to_string())
                    .header("Supported", "path, sec-agree".to_string())
                    .header("Allow", IMS_ALLOW_METHODS.to_string());
            }
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        if expires > 0 {
            entry.state = RegistrantState::Registering;
            entry.last_sent_at = Some(Instant::now());
        }

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build REGISTER");
                None
            }
        }
    }

    /// Build an authenticated REGISTER retry after receiving a 401/407 challenge.
    pub fn build_register_with_auth(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        challenge: &DigestChallenge,
        is_proxy_auth: bool,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri_str = entry
            .registrar_uri
            .strip_prefix("sip:")
            .unwrap_or(&entry.registrar_uri)
            .to_string();
        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(&entry.credentials.username, effective_addr, entry.transport)
        });

        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let nc = entry.nonce_counter.next_for(&challenge.nonce);
        let cnonce = format!("{:08x}", rand_u32());

        let digest_uri = format!("sip:{request_uri_str}");
        let credentials = DigestCredentials {
            username: entry.credentials.username.clone(),
            password: entry.credentials.password.clone(),
        };

        let auth_header_value = auth::format_authorization_header(
            challenge,
            &credentials,
            "REGISTER",
            &digest_uri,
            Some(nc),
            Some(&cnonce),
        );

        let auth_header_name = if is_proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        entry.state = RegistrantState::Challenging;
        entry.last_sent_at = Some(Instant::now());

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!("<{}>;tag=reg-{}", entry.aor, cseq))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header(
                "Contact",
                build_contact_header(&contact, entry.ims_contact.as_ref()),
            )
            .header("Expires", expires.to_string())
            .header(auth_header_name, auth_header_value)
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build authenticated REGISTER");
                None
            }
        }
    }

    /// Build an authenticated REGISTER in response to an IMS AKAv1-MD5 challenge.
    ///
    /// Runs Milenage over the challenge's RAND/AUTN (carried base64 in the
    /// nonce). On success, the Authorization response is computed from RES and
    /// `SQN_MS` advances; on a sequence-number mismatch the REGISTER instead
    /// carries an `auts=` re-synchronisation token (3GPP TS 33.102 §6.3.3); on
    /// a MAC failure (untrusted network) it returns `None` so the caller fails
    /// the registration.
    ///
    /// This is the Phase-1 (no-IPsec) shape — it does not yet emit
    /// `Security-Verify` or install SAs (Phase 2), and CK/IK are discarded.
    pub fn build_register_aka(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        challenge: &DigestChallenge,
        expires: u32,
        security_verify: Option<&str>,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;

        let credentials = entry.aka.clone()?;
        let (rand, autn) = match aka::decode_aka_nonce(&challenge.nonce) {
            Some(parts) => parts,
            None => {
                warn!(aor = %entry.aor, "AKA challenge nonce is not valid base64(RAND||AUTN)");
                return None;
            }
        };

        let (res, auts): (Vec<u8>, Option<String>) = match aka::aka_challenge(
            &credentials,
            &rand,
            &autn,
            &entry.sqn_ms,
        ) {
            aka::AkaOutcome::Success { res, ck, ik, sqn } => {
                entry.sqn_ms = sqn;
                // Stash CK/IK so the dispatcher can derive the IPsec SA
                // keys before sending the protected REGISTER (Phase 2).
                if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                    ipsec.ck = Some(ck);
                    ipsec.ik = Some(ik);
                }
                (res, None)
            }
            aka::AkaOutcome::SyncFailure { auts } => {
                warn!(aor = %entry.aor, "AKA SQN out of range — sending AUTS re-synchronisation");
                // RFC 3310 §3.4: the resync REGISTER carries the auts token;
                // the response is computed over an empty RES and the server
                // re-bases SQN and re-challenges.
                (Vec::new(), Some(aka::encode_auts(&auts)))
            }
            aka::AkaOutcome::MacFailure => {
                warn!(aor = %entry.aor, "AKA AUTN MAC failed — untrusted network challenge, aborting");
                return None;
            }
        };

        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri_str = entry
            .registrar_uri
            .strip_prefix("sip:")
            .unwrap_or(&entry.registrar_uri)
            .to_string();
        let request_uri = registrar_request_uri(&entry.registrar_uri);

        let contact = entry.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(&entry.credentials.username, effective_addr, entry.transport)
        });
        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            entry.transport, effective_addr, branch
        );

        let nc = entry.nonce_counter.next_for(&challenge.nonce);
        let cnonce = format!("{:08x}", rand_u32());
        let digest_uri = format!("sip:{request_uri_str}");

        let auth_header_value = auth::format_aka_authorization_header(
            challenge,
            &entry.credentials.username,
            &res,
            &digest_uri,
            Some(nc),
            Some(&cnonce),
            auts.as_deref(),
        );

        entry.state = RegistrantState::Challenging;
        entry.last_sent_at = Some(Instant::now());

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!("<{}>;tag=reg-{}", entry.aor, cseq))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header(
                "Contact",
                build_contact_header(&contact, entry.ims_contact.as_ref()),
            )
            .header("Expires", expires.to_string())
            .header("Authorization", auth_header_value)
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        // IPsec sec-agree: on the protected re-REGISTER, echo the P-CSCF's
        // Security-Server verbatim in Security-Verify and repeat Security-Client
        // (RFC 3329 §2.4 / TS 33.203 §7.4). This REGISTER egresses over the SA
        // the dispatcher installs from the stashed CK/IK.
        if let Some(verify) = security_verify {
            builder = builder.header("Security-Verify", verify.to_string());
            if let Some(ipsec) = entry.ue_ipsec.as_ref() {
                builder = builder
                    .header("Security-Client", build_security_client(&ipsec.offer()))
                    .header("Require", "sec-agree".to_string())
                    .header("Proxy-Require", "sec-agree".to_string())
                    .header("Supported", "path, sec-agree".to_string())
                    .header("Allow", IMS_ALLOW_METHODS.to_string());
            }
        }

        let message = builder.build();
        let transport = entry.transport;

        // The protected REGISTER goes to the P-CSCF's protected server port
        // (from Security-Server), not the default SIP port the initial REGISTER
        // used. Without a recorded answer, fall back to the default destination.
        let destination = match entry.ue_ipsec.as_ref() {
            Some(ipsec) if security_verify.is_some() && ipsec.pcscf_port_s != 0 => {
                SocketAddr::new(entry.destination.ip(), ipsec.pcscf_port_s)
            }
            _ => entry.destination,
        };

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build AKA REGISTER");
                None
            }
        }
    }
}
