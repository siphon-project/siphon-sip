//! PyO3 wrapper for outbound registration — exposed to Python as `registration`.
//!
//! Scripts use:
//! ```python
//! from siphon import registration
//!
//! registration.add("sip:bob@carrier.com", "sip:registrar.carrier.com",
//!                   user="bob", password="pass123", interval=3600)
//! registration.remove("sip:bob@carrier.com")
//! registration.refresh("sip:bob@carrier.com")
//!
//! for reg in registration.list():
//!     log.info(f"{reg['aor']}: {reg['state']} expires_in={reg['expires_in']}")
//!
//! # One process, many IMS UEs, each from its own address:
//! registration.add(impu, pcscf, user=impi, auth="aka", k=k, opc=opc,
//!                  ipsec=True, ue_port_c=6100, ue_port_s=6101,
//!                  local_addr="192.0.2.77")
//! registration.set_local_addr(impu, "192.0.2.78")   # the UE moved
//! aor = registration.find_by_local(call.flow.local_addr)  # MT: which UE?
//! ```

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager, UeIpsec};
use crate::transport::Transport;

/// Python-visible registration namespace.
#[pyclass(name = "RegistrationNamespace", skip_from_py_object)]
pub struct PyRegistration {
    inner: Arc<RegistrantManager>,
    _local_addr: std::net::SocketAddr,
}

impl PyRegistration {
    pub fn new(manager: Arc<RegistrantManager>, local_addr: std::net::SocketAddr) -> Self {
        Self {
            inner: manager,
            _local_addr: local_addr,
        }
    }
}

#[pymethods]
impl PyRegistration {
    /// Add a new outbound registration.
    ///
    /// Args:
    ///     aor: Address-of-Record (e.g. "sip:alice@carrier.com"). For IMS AKA
    ///         this is the IMPU (e.g. "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org").
    ///     registrar: Registrar URI (e.g. "sip:registrar.carrier.com:5060"). For
    ///         IMS this is the P-CSCF.
    ///     user: Authentication username. For IMS AKA this is the IMPI.
    ///     password: Authentication password (digest only; unused for AKA).
    ///     interval: Registration interval in seconds (default: manager default).
    ///     realm: Optional realm hint (derived from 401 if omitted; the home
    ///         domain for IMS).
    ///     contact: Optional Contact URI (auto-generated if omitted).
    ///     transport: Transport protocol: "udp" (default), "tcp", "tls"
    ///         (case-insensitive). Anything else raises ``ValueError``: siphon
    ///         dials no outbound SCTP association and no WebSocket, so a trunk
    ///         naming one could never register. An unrecognised value used to
    ///         register over UDP instead of being refused.
    ///     auth: "digest" (default) or "aka" for IMS AKAv1-MD5 (RFC 3310 / TS 33.203).
    ///     k: Subscriber key K as 32 hex chars (required when auth="aka").
    ///     op: Operator variant OP as 32 hex chars (supply op OR opc for AKA).
    ///     opc: Pre-computed OPc as 32 hex chars (supply op OR opc for AKA).
    ///     amf: Authentication Management Field as 4 hex chars (default "8000").
    ///     sqn: Initial stored sequence number SQN_MS as 12 hex chars
    ///         (default all-zeros — correct for a fresh soft-UE).
    ///     ipsec: True to establish IPsec sec-agree with the P-CSCF
    ///         (3GPP TS 33.203). Requires auth="aka", ue_port_c, ue_port_s.
    ///     ue_port_c: UE protected client port (must also be a listen.udp port).
    ///     ue_port_s: UE protected server port (must also be a listen.udp port).
    ///     ipsec_alg: Preferred integrity algorithm — "hmac-sha-1-96" (default),
    ///         "hmac-md5-96", or "hmac-sha-256-128". The Security-Client
    ///         offers it first, then "hmac-sha-1-96" and "hmac-md5-96", each
    ///         with ``ipsec_ealg`` (so the defaults offer exactly two
    ///         mechanisms: sha-1 and md5, both ``ealg=null``).
    ///     ipsec_ealg: Encryption algorithm paired with those — "null"
    ///         (default), "aes-cbc" or "des-ede3-cbc".
    ///     ipsec_offer: The Security-Client offer, explicitly: a non-empty
    ///         list of ``(alg, ealg)`` pairs, one ``ipsec-3gpp`` mechanism
    ///         each, in the order given (TS 33.203 clause 6.1, RFC 3329).
    ///         ``[("hmac-sha-1-96", "aes-cbc")]`` offers one mechanism;
    ///         ``[("hmac-sha-1-96", "null"), ("hmac-md5-96", "null")]`` is
    ///         the default offer. alg is "hmac-sha-1-96", "hmac-md5-96" or
    ///         "hmac-sha-256-128"; ealg is "null", "aes-cbc" or
    ///         "des-ede3-cbc". Raises ``ValueError`` for an empty list, an
    ///         unknown token, a repeated pair, without ``ipsec=True``, or
    ///         together with ``ipsec_alg`` / ``ipsec_ealg`` (name the
    ///         algorithms in one place).
    ///     imei: IMEI for the Contact +sip.instance (urn:gsma:imei). None → no
    ///         instance tag.
    ///     ims_features: Contact feature tags to advertise so the S-CSCF
    ///         registers the implied services — any of "mmtel", "video",
    ///         "smsip", "mcptt". "mcptt" adds `+g.3gpp.mcptt` and the MCPTT
    ///         ICSI to the Contact (TS 24.379 clause 7.2.1); with "mmtel" both
    ///         ICSIs share one `+g.3gpp.icsi-ref` parameter. Anything else
    ///         raises ``ValueError``.
    ///     register_body: ``(content_type, body)`` carried by every REGISTER
    ///         that registers: the initial one, each refresh, the answer to a
    ///         401 (digest or AKA) and the protected re-REGISTER. ``body`` is
    ///         ``bytes`` or ``str`` (UTF-8). The de-REGISTER carries none
    ///         (TS 24.379 clause 7.2.1 asks for it only to authorise a
    ///         binding). The MCPTT service authorisation goes here as
    ///         ``("application/vnd.3gpp.mcptt-info+xml", xml)``.
    ///     register_headers: ``{name: value}`` added to the same REGISTERs, in
    ///         order. A header siphon builds on a REGISTER (Via, From, To,
    ///         Call-ID, CSeq, Contact, Expires, Content-Type, Content-Length,
    ///         Authorization, Security-*, Require, Supported, ...) raises
    ///         ``ValueError``.
    ///     local_addr: The IP this entry registers from (Via/Contact host,
    ///         source, and with ipsec the UE side of its SAs, its protected
    ///         ports opened on this address). siphon opens the sockets itself,
    ///         so the address need not exist on the host yet. transport "udp"
    ///         or "tcp": over TCP siphon listens on ue_port_s (the plain port
    ///         without ipsec) for the P-CSCF's connection and connects from
    ///         ue_port_c. Over UDP with ipsec it also accepts TCP on ue_port_s
    ///         while an SA set stands (the P-CSCF's over-MTU requests), and
    ///         with ``listen.mtu`` set sends a REGISTER over the SA set that
    ///         exceeds mtu - 200 over TCP from ue_port_c (UDP if the connect
    ///         fails). None (default): the process's own address.
    ///     require_local_addr: Never register from the process's address:
    ///         without a local_addr the entry waits as "awaiting_address" until
    ///         set_local_addr() gives it one. Implied by local_addr.
    ///     refresh_window: (low, high) fractions of the granted Expires to
    ///         refresh within, drawn per refresh; 0 < low <= high < 1. None:
    ///         the registrant default.
    ///
    /// Raises ValueError for an address another entry already registers from
    /// with the same ue_port_c, a local_addr on transport "tls", a bad
    /// refresh window, or once the process is shutting down (it de-registered
    /// everything and registers nothing again). Secrets (password, k, op, opc)
    /// are never logged.
    // Wide by necessity: outbound registration exposes the full carrier-trunk
    // + AKA + IPsec credential set as keyword arguments to scripts.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (aor, registrar, *, user, password="", interval=None, realm=None, contact=None, transport=None, auth=None, k=None, op=None, opc=None, amf=None, sqn=None, ipsec=false, ue_port_c=None, ue_port_s=None, ipsec_alg=None, ipsec_ealg=None, ipsec_offer=None, imei=None, ims_features=None, register_body=None, register_headers=None, local_addr=None, require_local_addr=false, refresh_window=None))]
    fn add(
        &self,
        aor: &str,
        registrar: &str,
        user: &str,
        password: &str,
        interval: Option<u32>,
        realm: Option<String>,
        contact: Option<String>,
        transport: Option<&str>,
        auth: Option<&str>,
        k: Option<&str>,
        op: Option<&str>,
        opc: Option<&str>,
        amf: Option<&str>,
        sqn: Option<&str>,
        ipsec: bool,
        ue_port_c: Option<u16>,
        ue_port_s: Option<u16>,
        ipsec_alg: Option<&str>,
        ipsec_ealg: Option<&str>,
        ipsec_offer: Option<Bound<'_, PyAny>>,
        imei: Option<String>,
        ims_features: Option<Vec<String>>,
        register_body: Option<(String, Bound<'_, PyAny>)>,
        register_headers: Option<Bound<'_, PyDict>>,
        local_addr: Option<&str>,
        require_local_addr: bool,
        refresh_window: Option<(f64, f64)>,
    ) -> PyResult<()> {
        // The same set, from the same function, as the YAML validator — refused
        // rather than silently downgraded to UDP, which is how a script asking
        // for one transport got another.
        let transport_type = match transport {
            None => Transport::Udp,
            Some(token) => crate::config::parse_outbound_transport(token).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(crate::config::outbound_transport_error(
                    "registration.add(transport=)",
                    token,
                ))
            })?,
        };

        // Resolve registrar address from URI — supports both IP:port and hostname
        let registrar_host = registrar
            .strip_prefix("sip:")
            .or_else(|| registrar.strip_prefix("sips:"))
            .unwrap_or(registrar);

        let host_with_port = if registrar_host.contains(':') {
            registrar_host.to_string()
        } else {
            format!("{registrar_host}:5060")
        };

        let destination: std::net::SocketAddr = host_with_port.parse().or_else(|_| {
            // Not a raw IP:port — try DNS resolution, with the interpreter
            // released for the lookup (this runs attached, often at script top
            // level during a reload).
            crate::script::waits::resolve_socket_addrs(&host_with_port)
                .map(Vec::into_iter)
                .map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "cannot resolve registrar address '{registrar}': {e}"
                    ))
                })
                .and_then(|mut addrs| {
                    addrs.next().ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "DNS returned no addresses for '{registrar}'"
                        ))
                    })
                })
        })?;

        let entry = RegistrantEntry::new(
            aor.to_string(),
            registrar.to_string(),
            destination,
            transport_type,
            RegistrantCredentials::password(user.to_string(), password.to_string(), realm),
            interval.unwrap_or(self.inner.default_interval),
            contact,
        );

        // IMS AKAv1-MD5: attach the USIM secrets so the 401 challenge runs
        // through Milenage instead of password digest (RFC 3310 / TS 33.203).
        let entry = if auth.is_some_and(|mode| mode.eq_ignore_ascii_case("aka")) {
            let k = k.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(
                    "auth='aka' requires the subscriber key `k`",
                )
            })?;
            let credentials =
                crate::registrant::aka::AkaCredentials::from_hex(k, op, opc, amf.unwrap_or("8000"))
                    .map_err(|error| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "invalid AKA credentials: {error}"
                        ))
                    })?;
            let initial_sqn = parse_sqn(sqn.unwrap_or("000000000000"))?;
            entry.with_aka(credentials, initial_sqn)
        } else {
            entry
        };

        // The explicit Security-Client offer, read before anything is built so a
        // bad one raises without a half-added entry.
        let offer_pairs = ipsec_offer
            .as_ref()
            .map(offer_pairs_from_python)
            .transpose()?;
        if offer_pairs.is_some() && (ipsec_alg.is_some() || ipsec_ealg.is_some()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "ipsec_offer names the algorithms offered; drop ipsec_alg / ipsec_ealg",
            ));
        }

        // IPsec sec-agree (3GPP TS 33.203): the protected ports must also be
        // declared as listen.udp entries so the protected REGISTER can egress
        // from ue_port_c and MT requests arrive on ue_port_s.
        let entry = if ipsec {
            if entry.auth_mode != crate::registrant::AuthMode::Aka {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "ipsec=True requires auth='aka'",
                ));
            }
            let port_c = ue_port_c.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("ipsec=True requires ue_port_c")
            })?;
            let port_s = ue_port_s.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("ipsec=True requires ue_port_s")
            })?;
            let alg_token = ipsec_alg.unwrap_or("hmac-sha-1-96");
            let aalg = IntegrityAlgorithm::from_sec_agree_name(alg_token).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!("unknown ipsec_alg '{alg_token}'"))
            })?;
            let ealg_token = ipsec_ealg.unwrap_or("null");
            let ealg = EncryptionAlgorithm::from_sec_agree_name(ealg_token).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown ipsec_ealg '{ealg_token}'"
                ))
            })?;
            let ue_ipsec = UeIpsec::new(port_c, port_s, aalg, ealg);
            let ue_ipsec = match &offer_pairs {
                Some(pairs) => ue_ipsec.with_offer(
                    crate::registrant::ipsec_offer::parse_ipsec_offer(pairs)
                        .map_err(pyo3::exceptions::PyValueError::new_err)?,
                ),
                None => ue_ipsec,
            };
            entry.with_ipsec(ue_ipsec)
        } else {
            if offer_pairs.is_some() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "ipsec_offer requires ipsec=True",
                ));
            }
            entry
        };

        // IMS Contact feature tags (instance ID + MMTel/video/SMS) so the
        // S-CSCF registers the implied services (TS 24.229 / GSMA IR.92).
        let entry = if imei.is_some() || ims_features.is_some() {
            let params = crate::registrant::ImsContactParams::from_features(
                imei,
                &ims_features.unwrap_or_default(),
            )
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
            entry.with_ims_contact(params)
        } else {
            entry
        };

        // Headers and a body on every registering REGISTER (see
        // `registrant::register_extras`).
        let entry = if register_body.is_some() || register_headers.is_some() {
            let body = register_body
                .map(|(content_type, body)| {
                    let bytes = if let Ok(text) = body.extract::<String>() {
                        text.into_bytes()
                    } else if let Ok(bytes) = body.extract::<Vec<u8>>() {
                        bytes
                    } else {
                        return Err(pyo3::exceptions::PyTypeError::new_err(
                            "register_body is (content_type, body) with body bytes or str",
                        ));
                    };
                    Ok((content_type, bytes))
                })
                .transpose()?;
            let mut headers = Vec::new();
            if let Some(mapping) = register_headers {
                for (name, value) in mapping.iter() {
                    let (Ok(name), Ok(value)) =
                        (name.extract::<String>(), value.extract::<String>())
                    else {
                        return Err(pyo3::exceptions::PyTypeError::new_err(
                            "register_headers takes a mapping of str header names to str values",
                        ));
                    };
                    headers.push((name, value));
                }
            }
            entry.with_register_extras(
                crate::registrant::register_extras::RegisterExtras::new(body, headers)
                    .map_err(pyo3::exceptions::PyValueError::new_err)?,
            )
        } else {
            entry
        };

        // Its own address, or a promise of one (see `registrant::address`).
        let entry = match local_addr {
            Some(text) => entry.with_local_addr(parse_ip(text, "local_addr")?),
            None if require_local_addr => entry.requiring_local_addr(),
            None => entry,
        };
        let entry = match refresh_window {
            Some((low, high)) => entry.with_refresh_window(
                crate::registrant::RefreshWindow::new(low, high)
                    .map_err(pyo3::exceptions::PyValueError::new_err)?,
            ),
            None => entry,
        };

        self.inner
            .try_add(entry)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// Move a registration to another address, or take its address away.
    ///
    /// Args:
    ///     aor: The registration's AoR.
    ///     local_addr: The IP it registers from now, or None for none.
    ///
    /// Restating the current address changes nothing, so this can run on a
    /// timer for every UE. A real move tears down the IPsec SAs on the old
    /// address and starts a fresh registration from the new one at the next
    /// tick. None leaves an entry that has had an address (or was added with
    /// require_local_addr) "awaiting_address" until it gets one; any other
    /// entry falls back to the process's address.
    ///
    /// Returns False when there is no such registration. Raises ValueError for
    /// an address another entry already uses with the same ue_port_c, for a
    /// TLS registration, or for a move once the process is shutting down.
    #[pyo3(signature = (aor, local_addr))]
    fn set_local_addr(&self, aor: &str, local_addr: Option<&str>) -> PyResult<bool> {
        let local_addr = local_addr
            .map(|text| parse_ip(text, "local_addr"))
            .transpose()?;
        self.inner
            .set_local_addr(aor, local_addr)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// The AoR registering from an address, for routing an MT request to the
    /// UE it arrived for.
    ///
    /// Args:
    ///     local: "ip" or "ip:port" ("[v6]:port"), e.g. call.flow.local_addr.
    ///         With a port, the entry owning that port on the address (its plain
    ///         port, or its protected client or server port); without, the
    ///         first entry on the address.
    ///
    /// Returns the AoR, or None when no entry registers from there. A linear
    /// scan over the registrations, meant for once per call.
    fn find_by_local(&self, local: &str) -> PyResult<Option<String>> {
        let query = crate::registrant::address::LocalAddrQuery::parse(local)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(self.inner.find_by_local(query))
    }

    /// How many registrations are in each state.
    ///
    /// Returns a dict with every state as a key ("unregistered",
    /// "registering", "challenging", "registered", "failed",
    /// "awaiting_address"), zero when none is in it.
    fn counts<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(python);
        for (state, count) in self.inner.counts() {
            dict.set_item(state, count)?;
        }
        Ok(dict)
    }

    /// Remove an outbound registration by AoR.
    fn remove(&self, aor: &str) -> bool {
        self.inner.remove(aor).is_some()
    }

    /// Force an immediate re-registration for an AoR. False when there is no
    /// such registration, and for every AoR once the process is shutting down.
    fn refresh(&self, aor: &str) -> bool {
        self.inner.refresh(aor)
    }

    /// List all registrations with their current state.
    ///
    /// Returns a list of dicts with keys: aor, state, expires_in, local_addr
    /// (str, or None on the process's address), failure_count, and
    /// last_failure_status (int, or None once an attempt succeeded).
    fn list<'py>(&self, python: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let entries = self.inner.list();
        let mut result = Vec::with_capacity(entries.len());
        for (aor, state, expires_in) in entries {
            let dict = PyDict::new(python);
            let status = self.inner.status(&aor);
            let local_addr = self.inner.ue_addr(&aor).map(|ip| ip.to_string());
            dict.set_item("aor", aor)?;
            dict.set_item("state", state.to_string())?;
            dict.set_item("expires_in", expires_in)?;
            dict.set_item("local_addr", local_addr)?;
            dict.set_item(
                "failure_count",
                status.as_ref().map_or(0, |status| status.failure_count),
            )?;
            dict.set_item(
                "last_failure_status",
                status
                    .as_ref()
                    .and_then(|status| status.last_failure_status),
            )?;
            result.push(dict);
        }
        Ok(result)
    }

    /// Get the state of a specific registration.
    ///
    /// Returns state string or None if not found.
    fn status(&self, aor: &str) -> Option<String> {
        self.inner.state(aor).map(|state| state.to_string())
    }

    /// Number of configured registrations.
    fn count(&self) -> usize {
        self.inner.len()
    }

    /// The Service-Route set (RFC 3608) the S-CSCF granted this AoR on the
    /// 200 OK — the Route a B2BUA prepends to MO requests so they traverse the
    /// originating S-CSCF. Empty until the registration succeeds.
    fn service_route(&self, aor: &str) -> Vec<String> {
        self.inner.service_route(aor)
    }

    /// The P-Associated-URI list (implicit registration set) for this AoR.
    fn associated_uris(&self, aor: &str) -> Vec<String> {
        self.inner.associated_uris(aor)
    }

    /// A `Flow` over the established UE→P-CSCF IPsec SA for MO B2BUA calls.
    ///
    /// Pass the result to ``call.dial(flow=...)``: the B-leg INVITE is sent to
    /// the P-CSCF protected server port sourced from the UE protected client
    /// port, so it rides the SA. `ue_ip` is siphon's own address on the SA
    /// (the IP its protected ports are bound to); it defaults to the entry's
    /// local_addr, and is required for an entry without one. Returns ``None``
    /// until the sec-agree handshake has completed (no Security-Server
    /// recorded yet).
    #[pyo3(signature = (aor, ue_ip=None))]
    fn flow(
        &self,
        aor: &str,
        ue_ip: Option<&str>,
    ) -> PyResult<Option<crate::script::api::registrar::PyFlow>> {
        let ue_ip: std::net::IpAddr = match ue_ip {
            Some(text) => parse_ip(text, "ue_ip")?,
            None => match self.inner.ue_addr(aor) {
                Some(ip) => ip,
                None if self.inner.state(aor).is_none() => return Ok(None),
                None => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "{aor} registers from the process's address: pass ue_ip"
                    )))
                }
            },
        };
        Ok(crate::script::api::flow_kind::registrant_flow(
            &self.inner,
            aor,
            ue_ip,
        ))
    }

    /// Decorator to register a handler for outbound-registration state changes.
    ///
    /// The handler receives (aor, event_type, state) where:
    ///   - aor: str — Address of Record (e.g. "sip:trunk@carrier.com")
    ///   - event_type: str — "registered", "refreshed", "failed",
    ///     "deregistered", "awaiting_address" (it needs an address of its own
    ///     and has none), or "snapshot" (a re-report of every outbound
    ///     registration after the handler fell behind and events were lost)
    ///   - state: dict — {"expires_in": int, "failure_count": int,
    ///     "registrar": str, "state": str | None (the current state, None once
    ///     removed), "sequence": int (one higher per change, the `seq` of the
    ///     control plane's RegistrantChanged), "status_code": int (present when event_type is "failed",
    ///     and on a "snapshot" of a registration whose last attempt failed)}
    ///
    /// Mirrors `registrar.on_change`. The dispatcher invokes these handlers on
    /// `RegistrantManager` state changes (`HandlerKind::RegistrantOnChange`).
    /// Registering under the same `"registration.on_change"` key as the
    /// pre-startup `_RegistrationStub` keeps both code paths consistent — the
    /// stub had this method but the real Rust namespace did not, so once the
    /// real namespace shadowed the stub (`registrant` configured) the decorator
    /// raised `AttributeError`.
    #[staticmethod]
    fn on_change(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            (
                "registration.on_change",
                python.None(),
                func.bind(python),
                is_async,
            ),
        )?;
        Ok(func)
    }
}

/// Parse an IP address argument, naming the argument in the error.
fn parse_ip(text: &str, argument: &str) -> PyResult<std::net::IpAddr> {
    text.trim().parse().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!("{argument} '{text}' is not an IP address"))
    })
}

/// The `(alg, ealg)` pairs of `ipsec_offer=`: a list (or tuple) of two-item
/// tuples or lists of strings. A bad shape is a `TypeError`; the tokens are
/// checked by `parse_ipsec_offer` (a `ValueError`).
fn offer_pairs_from_python(offer: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    let shape = || {
        pyo3::exceptions::PyTypeError::new_err(
            "ipsec_offer is a list of (alg, ealg) pairs of str, e.g. [(\"hmac-sha-1-96\", \"null\")]",
        )
    };
    let mut pairs = Vec::new();
    for item in offer.try_iter().map_err(|_| shape())? {
        let item = item?;
        let tokens: Vec<String> = item.extract().map_err(|_| shape())?;
        match tokens.as_slice() {
            [alg, ealg] => pairs.push((alg.clone(), ealg.clone())),
            _ => return Err(shape()),
        }
    }
    Ok(pairs)
}

/// Parse an initial SQN_MS from a 12-hex-char string into 6 bytes.
fn parse_sqn(hex: &str) -> PyResult<[u8; 6]> {
    let bytes = crate::ipsec::milenage::hex_to_bytes(hex)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("sqn must be hex"))?;
    if bytes.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "sqn must be 6 bytes (12 hex chars)",
        ));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_manager() -> Arc<RegistrantManager> {
        Arc::new(RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            crate::config::IdentityHeaders::default().shared(),
        ))
    }

    #[test]
    fn py_registration_count_empty() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(py_reg.count(), 0);
    }

    #[test]
    fn py_registration_status_none_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(py_reg.status("sip:nobody@example.com").is_none());
    }

    #[test]
    fn py_registration_remove_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.remove("sip:nobody@example.com"));
    }

    #[test]
    fn py_registration_refresh_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.refresh("sip:nobody@example.com"));
    }

    // 3GPP test IMSI range (MCC 001 / MNC 01) + TS 35.208 Test Set 1 secrets.
    const AKA_AOR: &str = "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
    const AKA_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const AKA_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";

    fn add_aka(
        py_reg: &PyRegistration,
        k: Option<&str>,
        op: Option<&str>,
        opc: Option<&str>,
    ) -> PyResult<()> {
        // Use an IP:port registrar so the test never hits DNS.
        py_reg.add(
            AKA_AOR,
            "sip:10.0.0.1:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            Some("aka"),
            k,
            op,
            opc,
            Some("b9b9"),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )
    }

    fn add_aka_ipsec(
        py_reg: &PyRegistration,
        ue_port_c: Option<u16>,
        ue_port_s: Option<u16>,
        auth: Option<&str>,
    ) -> PyResult<()> {
        py_reg.add(
            AKA_AOR,
            "sip:10.0.0.1:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            auth,
            Some(AKA_K),
            None,
            Some(AKA_OPC),
            Some("b9b9"),
            None,
            true,
            ue_port_c,
            ue_port_s,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )
    }

    #[test]
    fn py_registration_add_aka_sets_aka_mode() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka(&py_reg, Some(AKA_K), None, Some(AKA_OPC)).unwrap();

        assert_eq!(py_reg.count(), 1);
        assert_eq!(
            manager.auth_mode(AKA_AOR),
            Some(crate::registrant::AuthMode::Aka)
        );
    }

    #[test]
    fn py_registration_add_aka_with_op_computes_opc() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka(
            &py_reg,
            Some(AKA_K),
            Some("cdc202d5123e20f62b6d676ac72cb318"),
            None,
        )
        .unwrap();
        assert_eq!(
            manager.auth_mode(AKA_AOR),
            Some(crate::registrant::AuthMode::Aka)
        );
    }

    #[test]
    fn py_registration_add_aka_requires_k() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(add_aka(&py_reg, None, None, Some(AKA_OPC)).is_err());
    }

    #[test]
    fn py_registration_add_aka_rejects_bad_key() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        // K too short → AkaConfigError surfaces as ValueError.
        assert!(add_aka(&py_reg, Some("465b5ce8"), None, Some(AKA_OPC)).is_err());
    }

    #[test]
    fn py_registration_add_digest_stays_digest() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        py_reg
            .add(
                "sip:alice@carrier.com",
                "sip:10.0.0.1:5060",
                "alice",
                "secret",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
            )
            .unwrap();
        assert_eq!(
            manager.auth_mode("sip:alice@carrier.com"),
            Some(crate::registrant::AuthMode::Digest)
        );
    }

    #[test]
    fn py_registration_add_aka_ipsec_sets_ipsec_entry() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka_ipsec(&py_reg, Some(6100), Some(6101), Some("aka")).unwrap();

        assert!(manager.is_ipsec_entry(AKA_AOR));
        assert_eq!(manager.ue_protected_client_port(AKA_AOR), Some(6100));
    }

    #[test]
    fn py_registration_ipsec_requires_ports_and_aka() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        // Missing ue_port_s.
        assert!(add_aka_ipsec(&py_reg, Some(6100), None, Some("aka")).is_err());
        // ipsec without auth='aka'.
        assert!(add_aka_ipsec(&py_reg, Some(6100), Some(6101), None).is_err());
    }

    /// Regression: the real Rust `registration` namespace must expose
    /// `on_change`, not just the pre-startup `_RegistrationStub`. Once a
    /// `registrant` is configured the singleton shadows the stub, and a script
    /// using `@registration.on_change` (e.g. the BGCF trunk-registration app)
    /// hit `AttributeError` because the method lived only on the stub.
    ///
    /// Mirrors `subscribe_state::tests::rust_namespace_replaces_stub_when_singleton_set_first`.
    #[test]
    fn rust_namespace_has_on_change_when_singleton_set_first() {
        use pyo3::Python;

        // Runs in a process of its own. Applying the decorator appends to the
        // process-wide handler registry outside any script load, and a script
        // another test is loading at that moment picked the entry up as one of
        // its own handlers. Setting the registration singleton also changes
        // the `siphon` module every later load in the process installs.
        crate::own_process::run(
            concat!(
                module_path!(),
                "::rust_namespace_has_on_change_when_singleton_set_first"
            ),
            || {
                Python::initialize();
                Python::attach(|python| {
                    let manager = make_manager();
                    let namespace = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
                    let _ = crate::script::api::set_registration_singleton(python, namespace);

                    crate::script::api::ensure_registry(python).expect("ensure registry");
                    crate::script::api::install_siphon_module(python)
                        .expect("install siphon module");

                    let script = r#"
import siphon
import _siphon_registry

ns = siphon.registration
# The real Rust namespace must be bound, not the pre-startup stub.
assert type(ns).__name__ != '_RegistrationStub', type(ns).__name__
assert hasattr(ns, 'on_change'), 'on_change'

# Exercise the decorator end-to-end — before the fix this raised
# AttributeError on the real namespace.
@ns.on_change
def on_trunk_change(aor, event_type, state):
    pass

# Decorator returns the function unchanged...
assert on_trunk_change.__name__ == 'on_trunk_change'
# ...and registers under the registrant kind.
kinds = [entry[0] for entry in _siphon_registry.entries()]
assert 'registration.on_change' in kinds, kinds
"#;
                    let assertions = std::ffi::CString::new(script).expect("CString");
                    python
                        .run(assertions.as_c_str(), None, None)
                        .expect("Rust registration namespace must expose on_change");
                });
            },
        );
    }

    /// `transport=` is the same narrow set the YAML validator enforces, and for
    /// the same reason: an outbound REGISTER leaves over UDP or over a
    /// connection the pool opens, and the pool opens TCP and TLS only.
    fn add_with_transport(py_reg: &PyRegistration, transport: Option<&str>) -> PyResult<()> {
        // IP:port registrar so the test never hits DNS.
        py_reg.add(
            "sip:trunk@carrier.example",
            "sip:198.51.100.20:5060",
            "trunk",
            "secret",
            None,
            None,
            None,
            transport,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )
    }

    /// siphon dials no outbound SCTP association, so this used to register over
    /// UDP instead — a trunk on a transport the script never asked for. The
    /// message itself is covered by the shared parser tests in `config::tests`
    /// (reading a `PyErr` needs an interpreter; the refusal does not).
    #[test]
    fn py_registration_add_refuses_sctp() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(
            add_with_transport(&py_reg, Some("sctp")).is_err(),
            "sctp must be refused"
        );
        assert_eq!(py_reg.count(), 0, "a refused entry must not be added");
    }

    #[test]
    fn py_registration_add_refuses_an_unknown_transport() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(add_with_transport(&py_reg, Some("tpc")).is_err());
        assert!(add_with_transport(&py_reg, Some("ws")).is_err());
        assert_eq!(py_reg.count(), 0);
    }

    #[test]
    fn py_registration_add_accepts_the_dialable_transports_case_insensitively() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        for transport in [None, Some("udp"), Some("tcp"), Some("TLS")] {
            // The error is deliberately not formatted: rendering a `PyErr` needs
            // an initialised interpreter, which this test does not want.
            add_with_transport(&py_reg, transport)
                .unwrap_or_else(|_| panic!("{transport:?} must be accepted"));
        }
        // One AoR, re-added each time; the last add won, so the entry is the
        // mixed-case TLS one.
        assert_eq!(py_reg.count(), 1);
        let crate::registrant::BuiltRegister { transport, .. } = manager
            .build_register(
                "sip:trunk@carrier.example",
                crate::registrant::EgressDefaults::new(
                    "127.0.0.1:5060".parse().expect("local addr"),
                    &std::collections::HashMap::new(),
                ),
                600,
            )
            .expect("the entry must be registrable");
        assert_eq!(
            transport,
            Transport::Tls,
            "a mixed-case token must not fall through to udp"
        );
    }

    /// An IMS UE added from a script on an address of its own.
    fn add_ue(
        py_reg: &PyRegistration,
        aor: &str,
        local_addr: Option<&str>,
        require_local_addr: bool,
        refresh_window: Option<(f64, f64)>,
    ) -> PyResult<()> {
        py_reg.add(
            aor,
            "sip:198.51.100.10:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            Some("aka"),
            Some(AKA_K),
            None,
            Some(AKA_OPC),
            None,
            None,
            true,
            Some(6100),
            Some(6101),
            None,
            None,
            None,
            Some("01234567-000001-0".to_string()),
            Some(vec!["mmtel".to_string()]),
            None,
            None,
            local_addr,
            require_local_addr,
            refresh_window,
        )
    }

    const UE_TWO: &str = "sip:001010000000002@ims.mnc01.mcc001.3gppnetwork.org";

    #[test]
    fn add_takes_a_local_addr_and_refuses_a_shared_one() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        add_ue(
            &py_reg,
            AKA_AOR,
            Some("192.0.2.77"),
            false,
            Some((0.4, 0.6)),
        )
        .unwrap();
        assert_eq!(
            manager.ue_addr(AKA_AOR),
            Some("192.0.2.77".parse().unwrap())
        );
        assert!(add_ue(&py_reg, UE_TWO, Some("192.0.2.77"), false, None).is_err());
        assert!(add_ue(&py_reg, UE_TWO, Some("not-an-ip"), false, None).is_err());
        assert!(add_ue(&py_reg, UE_TWO, Some("192.0.2.78"), false, Some((0.8, 0.2))).is_err());
        assert_eq!(py_reg.count(), 1);
    }

    #[test]
    fn set_local_addr_moves_and_takes_away() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        add_ue(&py_reg, AKA_AOR, None, true, None).unwrap();
        assert_eq!(py_reg.status(AKA_AOR).as_deref(), Some("awaiting_address"));

        assert!(py_reg.set_local_addr(AKA_AOR, Some("192.0.2.77")).unwrap());
        assert_eq!(py_reg.status(AKA_AOR).as_deref(), Some("unregistered"));
        assert!(py_reg.set_local_addr(AKA_AOR, None).unwrap());
        assert_eq!(py_reg.status(AKA_AOR).as_deref(), Some("awaiting_address"));
        assert!(!py_reg.set_local_addr(UE_TWO, None).unwrap());
        assert!(py_reg.set_local_addr(AKA_AOR, Some("bogus")).is_err());
    }

    #[test]
    fn find_by_local_and_flow_use_the_entrys_address() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        add_ue(&py_reg, AKA_AOR, Some("192.0.2.77"), false, None).unwrap();
        add_ue(&py_reg, UE_TWO, Some("192.0.2.78"), false, None).unwrap();
        assert_eq!(
            py_reg.find_by_local("192.0.2.78:6101").unwrap().as_deref(),
            Some(UE_TWO)
        );
        assert_eq!(py_reg.find_by_local("192.0.2.99").unwrap(), None);
        assert!(py_reg.find_by_local("nonsense").is_err());

        // No handshake yet: no flow, but no error either.
        assert!(py_reg.flow(AKA_AOR, None).unwrap().is_none());
        let server = crate::ipsec::parse_security_client(
            "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1111; spi-s=2222; port-c=5064; port-s=5066",
        )
        .unwrap();
        manager.store_security_server(AKA_AOR, &server, "raw");
        // A Security-Server alone is no SA set to send over.
        assert!(py_reg.flow(AKA_AOR, None).unwrap().is_none());
        manager
            .begin_authentication(AKA_AOR, "Digest username=\"ue\"")
            .unwrap();
        manager.conclude_ipsec_exchange(AKA_AOR).unwrap();
        let flow = py_reg.flow(AKA_AOR, None).unwrap().expect("a flow");
        assert_eq!(flow.local_addr, "192.0.2.77:6100".parse().unwrap());
        assert_eq!(flow.source_addr, "198.51.100.10:5066".parse().unwrap());
        // An explicit ue_ip still wins.
        let flow = py_reg
            .flow(AKA_AOR, Some("192.0.2.5"))
            .unwrap()
            .expect("a flow");
        assert_eq!(flow.local_addr, "192.0.2.5:6100".parse().unwrap());
        // Unknown AoR: None.
        assert!(py_reg
            .flow("sip:nobody@example.invalid", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn flow_needs_ue_ip_for_an_entry_on_the_process_address() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        add_ue(&py_reg, AKA_AOR, None, false, None).unwrap();
        assert!(py_reg.flow(AKA_AOR, None).is_err());
        assert!(py_reg.flow(AKA_AOR, Some("192.0.2.5")).is_ok());
    }

    #[test]
    fn counts_and_list_report_the_new_fields() {
        crate::own_process::run(
            concat!(module_path!(), "::counts_and_list_report_the_new_fields"),
            || {
                pyo3::Python::initialize();
                pyo3::Python::attach(|python| {
                    let manager = make_manager();
                    let py_reg = PyRegistration::new(
                        Arc::clone(&manager),
                        "127.0.0.1:5060".parse().unwrap(),
                    );
                    add_ue(&py_reg, AKA_AOR, Some("192.0.2.77"), false, None).unwrap();
                    add_ue(&py_reg, UE_TWO, None, true, None).unwrap();
                    let counts = py_reg.counts(python).unwrap();
                    let count = |state: &str| -> usize {
                        counts
                            .get_item(state)
                            .unwrap()
                            .expect("every state is a key")
                            .extract()
                            .unwrap()
                    };
                    assert_eq!(count("unregistered"), 1);
                    assert_eq!(count("awaiting_address"), 1);
                    assert_eq!(count("registered"), 0);
                    let listed = py_reg.list(python).unwrap();
                    let own = listed
                        .iter()
                        .find(|row| {
                            row.get_item("aor")
                                .unwrap()
                                .and_then(|aor| aor.extract::<String>().ok())
                                .as_deref()
                                == Some(AKA_AOR)
                        })
                        .expect("listed");
                    let local: Option<String> = own
                        .get_item("local_addr")
                        .unwrap()
                        .unwrap()
                        .extract()
                        .unwrap();
                    assert_eq!(local.as_deref(), Some("192.0.2.77"));
                    let failures: u32 = own
                        .get_item("failure_count")
                        .unwrap()
                        .unwrap()
                        .extract()
                        .unwrap();
                    assert_eq!(failures, 0);
                    assert!(own
                        .get_item("last_failure_status")
                        .unwrap()
                        .unwrap()
                        .is_none());
                });
            },
        );
    }

    /// A digest trunk added with the MCPTT-shaped keyword arguments.
    fn add_with_register_options(
        py_reg: &PyRegistration,
        features: Option<Vec<String>>,
        body: Option<(String, Bound<'_, PyAny>)>,
        headers: Option<Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        py_reg.add(
            "sip:trunk@carrier.example",
            "sip:198.51.100.20:5060",
            "trunk",
            "secret",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            features,
            body,
            headers,
            None,
            false,
            None,
        )
    }

    /// The first REGISTER of the trunk `add_with_register_options` added: its
    /// header block and body as sent.
    fn built_register(manager: &RegistrantManager) -> (String, Vec<u8>) {
        let listen = std::collections::HashMap::new();
        let built = manager
            .build_register(
                "sip:trunk@carrier.example",
                crate::registrant::messages::EgressDefaults::new(
                    "192.0.2.1:5060".parse().unwrap(),
                    &listen,
                ),
                3600,
            )
            .unwrap();
        let bytes = built.message.to_bytes();
        let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        (
            String::from_utf8_lossy(&bytes[..split + 2]).into_owned(),
            bytes[split + 4..].to_vec(),
        )
    }

    #[test]
    fn add_takes_register_body_register_headers_and_mcptt() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::add_takes_register_body_register_headers_and_mcptt"
            ),
            || {
                pyo3::Python::initialize();
                pyo3::Python::attach(|python| {
                    let manager = make_manager();
                    let py_reg = PyRegistration::new(
                        Arc::clone(&manager),
                        "127.0.0.1:5060".parse().unwrap(),
                    );
                    let headers = PyDict::new(python);
                    headers.set_item("X-First", "1").unwrap();
                    headers.set_item("X-Second", "2").unwrap();
                    let body = pyo3::types::PyBytes::new(python, b"<a/>\r\n\xff").into_any();
                    add_with_register_options(
                        &py_reg,
                        Some(vec!["MCPTT".to_string(), "mmtel".to_string()]),
                        Some(("application/vnd.3gpp.mcptt-info+xml".to_string(), body)),
                        Some(headers),
                    )
                    .unwrap();
                    let (head, wire_body) = built_register(&manager);
                    assert!(head.contains(
                        ";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel,urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";+g.3gpp.mcptt"
                    ));
                    assert!(head.contains("\r\nX-First: 1\r\nX-Second: 2\r\n"));
                    assert!(
                        head.contains("\r\nContent-Type: application/vnd.3gpp.mcptt-info+xml\r\n")
                    );
                    assert!(head.contains("\r\nContent-Length: 7\r\n"));
                    assert_eq!(wire_body, b"<a/>\r\n\xff".to_vec());
                });
            },
        );
    }

    #[test]
    fn add_takes_a_str_body_and_refuses_what_siphon_owns() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::add_takes_a_str_body_and_refuses_what_siphon_owns"
            ),
            || {
                pyo3::Python::initialize();
                pyo3::Python::attach(|python| {
                    let manager = make_manager();
                    let py_reg = PyRegistration::new(
                        Arc::clone(&manager),
                        "127.0.0.1:5060".parse().unwrap(),
                    );
                    let text = pyo3::types::PyString::new(python, "hello").into_any();
                    add_with_register_options(
                        &py_reg,
                        None,
                        Some(("text/plain".to_string(), text)),
                        None,
                    )
                    .unwrap();
                    let (_, wire_body) = built_register(&manager);
                    assert_eq!(wire_body, b"hello".to_vec());
                    drop(manager);

                    for owned in ["Via", "contact", "Content-Type", "Authorization", "l"] {
                        let manager = make_manager();
                        let py_reg =
                            PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
                        let headers = PyDict::new(python);
                        headers.set_item(owned, "x").unwrap();
                        let refused = add_with_register_options(&py_reg, None, None, Some(headers))
                            .expect_err(owned);
                        assert!(refused.is_instance_of::<pyo3::exceptions::PyValueError>(python));
                    }

                    let manager = make_manager();
                    let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
                    let refused = add_with_register_options(
                        &py_reg,
                        Some(vec!["mcptx".to_string()]),
                        None,
                        None,
                    )
                    .expect_err("unknown feature");
                    assert!(refused.is_instance_of::<pyo3::exceptions::PyValueError>(python));
                });
            },
        );
    }

    /// An IMS UE added with the algorithm keywords, the Security-Client of
    /// its first REGISTER returned (or the refusal).
    fn security_client_after_add(
        python: Python<'_>,
        ipsec: bool,
        alg: Option<&str>,
        ealg: Option<&str>,
        offer: Option<&str>,
    ) -> Result<String, PyErr> {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        let offer = offer.map(|source| {
            python
                .eval(&std::ffi::CString::new(source).expect("no nul"), None, None)
                .expect("a python literal")
        });
        py_reg.add(
            AKA_AOR,
            "sip:198.51.100.10:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            Some("aka"),
            Some(AKA_K),
            None,
            Some(AKA_OPC),
            None,
            None,
            ipsec,
            ipsec.then_some(6100),
            ipsec.then_some(6101),
            alg,
            ealg,
            offer,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )?;
        let listen = std::collections::HashMap::new();
        let built = manager
            .build_register(
                AKA_AOR,
                crate::registrant::messages::EgressDefaults::new(
                    "192.0.2.1:5060".parse().unwrap(),
                    &listen,
                ),
                3600,
            )
            .expect("a REGISTER");
        Ok(built
            .message
            .headers
            .get("Security-Client")
            .cloned()
            .unwrap_or_default())
    }

    #[test]
    fn ipsec_offer_sets_the_security_client_pairs() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::ipsec_offer_sets_the_security_client_pairs"
            ),
            || {
                pyo3::Python::initialize();
                pyo3::Python::attach(|python| {
                    // Default: the two mechanisms the registrant always sent.
                    let default =
                        security_client_after_add(python, true, None, None, None).expect("added");
                    assert_eq!(default.split(", ").count(), 2, "{default}");
                    assert!(default.contains("alg=hmac-sha-1-96;ealg=null"));
                    assert!(default.contains("alg=hmac-md5-96;ealg=null"));

                    // One pair, one mechanism.
                    let one = security_client_after_add(
                        python,
                        true,
                        None,
                        None,
                        Some("[('hmac-sha-1-96', 'aes-cbc')]"),
                    )
                    .expect("added");
                    assert!(one.contains("port-c=6100;port-s=6101;alg=hmac-sha-1-96;ealg=aes-cbc"));
                    assert!(!one.contains(','), "one mechanism: {one}");

                    // Two pairs, in order, lists accepted as pairs too.
                    let two = security_client_after_add(
                        python,
                        true,
                        None,
                        None,
                        Some("[['hmac-md5-96', 'null'], ('hmac-sha-1-96', 'aes-cbc')]"),
                    )
                    .expect("added");
                    let mechanisms: Vec<&str> = two.split(", ").collect();
                    assert_eq!(mechanisms.len(), 2, "{two}");
                    assert!(mechanisms[0].ends_with("alg=hmac-md5-96;ealg=null"));
                    assert!(mechanisms[1].ends_with("alg=hmac-sha-1-96;ealg=aes-cbc"));
                });
            },
        );
    }

    #[test]
    fn ipsec_offer_refuses_what_it_cannot_honour() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::ipsec_offer_refuses_what_it_cannot_honour"
            ),
            || {
                pyo3::Python::initialize();
                pyo3::Python::attach(|python| {
                    let value_error = |ipsec, alg, ealg, offer: &str| {
                        let error =
                            security_client_after_add(python, ipsec, alg, ealg, Some(offer))
                                .expect_err(offer);
                        assert!(
                            error.is_instance_of::<pyo3::exceptions::PyValueError>(python),
                            "{offer}: {error}"
                        );
                    };
                    value_error(true, None, None, "[]");
                    value_error(true, None, None, "[('hmac-sha-9-9', 'null')]");
                    value_error(true, None, None, "[('hmac-sha-1-96', 'rot13')]");
                    value_error(
                        true,
                        None,
                        None,
                        "[('hmac-sha-1-96', 'null'), ('hmac-sha-1-96', 'null')]",
                    );
                    // Algorithms named twice, or an offer without IPsec.
                    value_error(
                        true,
                        Some("hmac-md5-96"),
                        None,
                        "[('hmac-sha-1-96', 'null')]",
                    );
                    value_error(true, None, Some("aes-cbc"), "[('hmac-sha-1-96', 'null')]");
                    value_error(false, None, None, "[('hmac-sha-1-96', 'null')]");
                    // Wrong shapes are a TypeError.
                    for shape in ["'hmac-sha-1-96'", "[('hmac-sha-1-96',)]", "[1]", "5"] {
                        let error =
                            security_client_after_add(python, true, None, None, Some(shape))
                                .expect_err(shape);
                        assert!(
                            error.is_instance_of::<pyo3::exceptions::PyTypeError>(python),
                            "{shape}: {error}"
                        );
                    }
                });
            },
        );
    }

    #[test]
    fn parse_sqn_validates_length() {
        assert_eq!(parse_sqn("000000000000").unwrap(), [0u8; 6]);
        assert_eq!(
            parse_sqn("ff9bb4d0b607").unwrap(),
            [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]
        );
        assert!(parse_sqn("00").is_err());
        assert!(parse_sqn("zz").is_err());
    }
}
