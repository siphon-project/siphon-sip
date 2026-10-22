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

/// The process-wide addressing a REGISTER falls back to: what every entry
/// without a `local_addr` of its own registers from.
#[derive(Clone, Copy, Debug)]
pub struct EgressDefaults<'a> {
    /// The process's primary listen address.
    pub local_addr: SocketAddr,
    /// The first listener of each transport.
    pub listen_addrs: &'a HashMap<Transport, SocketAddr>,
    /// The UE side of a process-address entry's IPsec SAs (the dispatcher's
    /// resolved local address).
    pub ue_ip: IpAddr,
}

impl<'a> EgressDefaults<'a> {
    /// Defaults from the process's listen address and per-transport
    /// listeners; the IPsec UE address is `local_addr`'s IP.
    pub fn new(local_addr: SocketAddr, listen_addrs: &'a HashMap<Transport, SocketAddr>) -> Self {
        Self {
            local_addr,
            listen_addrs,
            ue_ip: local_addr.ip(),
        }
    }

    /// The port an entry's plain (unprotected) SIP socket uses on its own
    /// address: the first UDP listener's, else 5060.
    pub fn plain_port(&self) -> u16 {
        self.listen_addrs
            .get(&Transport::Udp)
            .map_or(5060, |addr| addr.port())
    }
}

/// Where one entry's REGISTER says it is and leaves from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryEgress {
    /// The Via sent-by and default Contact host:port.
    sent_by: SocketAddr,
    /// The UDP socket the REGISTER is pinned to; `None` for TCP/TLS, whose
    /// outbound connection is the pool's, not a listener's.
    source: Option<SocketAddr>,
    /// Whether this is the entry's own address rather than the process's.
    own_address: bool,
}

impl EntryEgress {
    fn of(entry: &RegistrantEntry, defaults: EgressDefaults<'_>) -> Self {
        match entry.local_addr {
            // The process's address: unchanged from before per-entry addresses.
            // UDP egresses from the same local address advertised in the Via,
            // so the source port matches the Via and the response / conntrack
            // return path is consistent. With multiple UDP listeners + IPsec, a
            // `None` source picks a non-deterministic default — the initial
            // REGISTER could egress from a protected port while the Via said
            // 5060, breaking the 401 return path.
            None => Self {
                sent_by: defaults
                    .listen_addrs
                    .get(&entry.transport)
                    .copied()
                    .unwrap_or(defaults.local_addr),
                source: (entry.transport == Transport::Udp).then(|| {
                    defaults
                        .listen_addrs
                        .get(&Transport::Udp)
                        .copied()
                        .unwrap_or(defaults.local_addr)
                }),
                own_address: false,
            },
            // An address of its own (UDP only, refused otherwise): Via, Contact
            // and source all name the plain port on that address.
            Some(ip) => {
                let addr = SocketAddr::new(ip, defaults.plain_port());
                Self {
                    sent_by: addr,
                    source: Some(addr),
                    own_address: true,
                }
            }
        }
    }
}

/// A REGISTER ready to send, and how it has to leave.
#[derive(Debug)]
pub struct BuiltRegister {
    pub message: SipMessage,
    /// The Via branch.
    pub branch: String,
    pub destination: SocketAddr,
    pub transport: Transport,
    /// The UDP socket it must leave from. `None` only for a stream transport.
    /// For a protected REGISTER, the UE protected client port (TS 33.203 §7.1).
    pub source_local_addr: Option<SocketAddr>,
    /// The Via sent-by.
    pub sent_by: SocketAddr,
    /// Whether the entry registers from an address of its own.
    pub own_address: bool,
}

impl RegistrantManager {
    /// Build a REGISTER request for an entry.
    ///
    /// An entry with a `local_addr` names that address (on the plain UDP
    /// port) in its Via and Contact and leaves from it. Every other entry uses
    /// `defaults`: the listener of its transport for the Contact and Via,
    /// falling back to `defaults.local_addr` when that transport has none.
    pub fn build_register(
        &self,
        aor: &str,
        defaults: EgressDefaults<'_>,
        expires: u32,
    ) -> Option<BuiltRegister> {
        let mut entry = self.entries.get_mut(aor)?;
        let egress = EntryEgress::of(&entry, defaults);
        let effective_addr = egress.sent_by;
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

        if let Some(ref user_agent) = self.identity.load().user_agent {
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
            Ok(message) => Some(BuiltRegister {
                message,
                branch,
                destination,
                transport,
                source_local_addr: egress.source,
                sent_by: egress.sent_by,
                own_address: egress.own_address,
            }),
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
        defaults: EgressDefaults<'_>,
        challenge: &DigestChallenge,
        is_proxy_auth: bool,
        expires: u32,
    ) -> Option<BuiltRegister> {
        let mut entry = self.entries.get_mut(aor)?;
        let egress = EntryEgress::of(&entry, defaults);
        let effective_addr = egress.sent_by;
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
        let auth_header_value = match auth::format_stored_authorization_header(
            challenge,
            &entry.credentials.username,
            &entry.credentials.secret,
            "REGISTER",
            &digest_uri,
            Some(nc),
            Some(&cnonce),
        ) {
            Ok(value) => value,
            Err(mismatch) => {
                // A stored ha1 for the wrong hash cannot answer this registrar.
                // Reported rather than answered wrongly: the wrong ha1 makes a
                // well-formed response the registrar reads as a bad password,
                // which looks like a credential fault instead of a
                // configuration one.
                error!(
                    aor = %entry.aor,
                    realm = %challenge.realm,
                    error = %mismatch,
                    "cannot answer the registrar's challenge with the stored credential"
                );
                return None;
            }
        };

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

        if let Some(ref user_agent) = self.identity.load().user_agent {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        match message {
            Ok(message) => Some(BuiltRegister {
                message,
                branch,
                destination,
                transport,
                source_local_addr: egress.source,
                sent_by: egress.sent_by,
                own_address: egress.own_address,
            }),
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
        defaults: EgressDefaults<'_>,
        challenge: &DigestChallenge,
        expires: u32,
        security_verify: Option<&str>,
    ) -> Option<BuiltRegister> {
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

        let egress = EntryEgress::of(&entry, defaults);
        let effective_addr = egress.sent_by;
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

        if let Some(ref user_agent) = self.identity.load().user_agent {
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
        // The protected REGISTER leaves from the UE protected client port on
        // the entry's address, the source its outbound SA selector names
        // (TS 33.203 §7.1); anything else from the plain socket.
        let source_local_addr = match entry.ue_ipsec.as_ref() {
            Some(ipsec) if security_verify.is_some() => Some(SocketAddr::new(
                entry.local_addr.unwrap_or(defaults.ue_ip),
                ipsec.ue_port_c,
            )),
            _ => egress.source,
        };

        match message {
            Ok(message) => Some(BuiltRegister {
                message,
                branch,
                destination,
                transport,
                source_local_addr,
                sent_by: egress.sent_by,
                own_address: egress.own_address,
            }),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build AKA REGISTER");
                None
            }
        }
    }
}
